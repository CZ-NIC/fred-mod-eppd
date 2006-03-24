/*
 * Copyright statement
 */

#include "httpd.h"
#include "http_log.h"
#define CORE_PRIVATE
#include "http_config.h"
#include "http_connection.h"	/* connection hooks */
#undef CORE_PRIVATE

#define APR_WANT_BYTEFUNC
#include "apr_want.h"
#include "apr_buckets.h"
#include "apr_file_io.h"
#include "apr_general.h"
#include "apr_lib.h"	/* apr_isdigit() */
#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_time.h"

#include "scoreboard.h"
#include "util_filter.h"

#include "epp_parser.h"

#define EPPD_VERSION	"testing"
#define MAX_FRAME_LENGTH	16000
#define EPP_HEADER_LENGTH	4

module AP_MODULE_DECLARE_DATA eppd_module;

/**
 * Configuration structure of eppd module.
 */
typedef struct {
	int	epp_enabled;
} eppd_server_conf;

/**
 * Reads epp request.
 * @param c Connection
 * @ret Status
 */
static char *epp_read_request(apr_pool_t *p, conn_rec *c)
{
		char *buf; /* buffer for user request */
		uint32_t	hbo_size; /* size of request in host byte order */
		uint32_t	nbo_size; /* size of request in network byte order */
		apr_bucket_brigade *bb;
		apr_status_t	status;
		apr_size_t	len;

		bb = apr_brigade_create(p, c->bucket_alloc);

		/* blocking read of first 4 bytes (message size) */
		status = ap_get_brigade(c->input_filters, bb, AP_MODE_READBYTES,
									APR_BLOCK_READ, EPP_HEADER_LENGTH);
		if (status != APR_SUCCESS) {
			ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
					"Error when reading epp header");
			return NULL;
		}

		/*
		 * convert bucket brigade to string
		 * In most cases there is just one bucket of size 4, which
		 * could be read directly. But we will do it more generally in case.
		 */
		len = EPP_HEADER_LENGTH;
		status = apr_brigade_pflatten(bb, &buf, &len, p);
		if (status != APR_SUCCESS) {
			ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
					"Could not flatten apr_brigade!");
			apr_brigade_destroy(bb);
			return NULL;
		}
		if (len != EPP_HEADER_LENGTH) {
			ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
					"Weird EPP header size! (%d bytes)", len);
			apr_brigade_destroy(bb);
			return NULL;
		}

		/* beware of alignment issues - this should be safe */
		for (len = 0; len < EPP_HEADER_LENGTH; len++)
			((char *) &nbo_size)[len] = buf[len];
		hbo_size = ntohl(nbo_size);

		status = apr_brigade_cleanup(bb);
		if (status != APR_SUCCESS) {
			ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
					"Could not cleanup brigade!");
			apr_brigade_destroy(bb);
			return NULL;
		}

		/* exclude header length */
		hbo_size -= EPP_HEADER_LENGTH;

		/*
		 * hbo_size needs to be checked, so that we know it's not total
		 * garbage
		 */
		if (hbo_size < 1 || hbo_size > MAX_FRAME_LENGTH) {
			ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
					"Invalid epp frame length (%ld bytes)", hbo_size);
			apr_brigade_destroy(bb);
			return NULL;
		}
		/* blocking read of request's body */
		len = hbo_size;
		status = ap_get_brigade(c->input_filters, bb, AP_MODE_READBYTES,
									APR_BLOCK_READ, len);
		if (status != APR_SUCCESS) {
			ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
					"Error when reading epp request's body");
			apr_brigade_destroy(bb);
			return NULL;
		}

		/* convert bucket brigade to string */
		status = apr_brigade_pflatten(bb, &buf, &len, p);
		if (status != APR_SUCCESS) {
			ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
					"Could not flatten apr_brigade!");
			apr_brigade_destroy(bb);
			return NULL;
		}
		if (len != hbo_size) {
			ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
					"EPP request's body size is other than claimed one:\n"
					"\treal size is %4d bytes\n\tclaimed size is %4d bytes",
					len, hbo_size);
			apr_brigade_destroy(bb);
			return NULL;
		}

		ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
				"epp request received (length %ld bytes)", hbo_size);

		apr_brigade_destroy(bb);
		return buf;
}

/**
 * EPP Connection handler.
 *
 * @param c Incoming connection
 * @ret Return code
 */
static int epp_process_connection(conn_rec *c)
{
	const char	*greeting;
	char	close_conn;	/* used as boolean */
	void	*ctx; /* connection context */
	apr_bucket_brigade	*bb;
	apr_size_t	len;
	apr_status_t	status;
	server_rec	*s = c->base_server;
	eppd_server_conf *sc = (eppd_server_conf *)
		ap_get_module_config(s->module_config, &eppd_module);

	/* do nothing if eppd is disabled */
	if (!sc->epp_enabled)
		return DECLINED;

	ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
			"epp connection handler enabled");
	ap_update_child_status(c->sbh, SERVER_BUSY_READ, NULL);

	/* add connection output filter */
	ap_add_output_filter("EPP_OUTPUT_FILTER", NULL, NULL, c);

	/*
	 * Send epp greeting - note that we don't even try to read <hello>
	 * message since epp-tcp mapping does not mention it (opening connection
	 * is enough).
	 */
	bb = apr_brigade_create(c->pool, c->bucket_alloc);
	greeting = "ahoj, toto je greeting";
	apr_brigade_puts(bb, NULL, NULL, greeting);

	status = ap_fflush(c->output_filters, bb);
	if (status != APR_SUCCESS) {
		ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
		"Error when sending greeting to client");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
			"epp greeting has been sent");

	status = apr_brigade_cleanup(bb);
	if (status != APR_SUCCESS) {
		ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
		"Could not cleanup bucket brigade used for greeting");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* create and initialize epp connetion context */
	if ((ctx = epp_parser_init()) == NULL) {
		ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
		"Could allocate epp_connection_ctx struct");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/*
	 * process requests loop
	 * termination conditions are embedded inside the loop
	 */
	while (1) {
		char *request;
		epp_parser_parms_out *parser_out;
		apr_pool_t	*rpool;

		/* allocate new pool for request */
		apr_pool_create(&rpool, c->pool);
		apr_pool_tag(rpool, "EPP_request");

		/* read request */
		request = epp_read_request(rpool, c);
		if (request == NULL) return HTTP_INTERNAL_SERVER_ERROR;

		/* allocate structure for return values from parser */
		parser_out = apr_pcalloc(rpool, sizeof (*parser_out));

		/* deliver request to XML parser */
		epp_parser_process_request(ctx, request, parser_out);

		/* analyze parser's answer */
		if (parser_out->err) {
			ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, c,
					"epp parser: %s", parser_out->err);
		}
		if (parser_out->response != NULL) {
			/* send response back to client */
			apr_brigade_puts(bb, NULL, NULL, parser_out->response);

			status = ap_fflush(c->output_filters, bb);
			if (status != APR_SUCCESS) {
				ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
				"Error when sending response to client");
				return HTTP_INTERNAL_SERVER_ERROR;
			}

			status = apr_brigade_cleanup(bb);
			if (status != APR_SUCCESS) {
				ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
				"Could not cleanup bucket brigade used for response");
				return HTTP_INTERNAL_SERVER_ERROR;
			}
		}

		epp_parser_cleanup_parms_out(parser_out);
		apr_pool_destroy(rpool);
	}

	epp_parser_cleanup_ctx(ctx);
	return OK;
}

/**
 * epp output filter.
 * compute message size and write the size in first two bytes of message
 */
static apr_status_t epp_output_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
	apr_bucket	*b, *bnew;
	apr_size_t	len;
	uint32_t	nbo_size; /* size in network byte order */

	for (b = APR_BRIGADE_FIRST(bb), len = 0;
		 b != APR_BRIGADE_SENTINEL(bb);
		 b = APR_BUCKET_NEXT(b)) {

		/* catch weird situation which will probably never happen */
		if (b->length == -1)
			ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c,
			"Bucket with unknown length ... weird");
		else
			len += b->length;
	}

	/* header size is included in total size */
	nbo_size = htonl(len + EPP_HEADER_LENGTH);
	bnew = apr_bucket_heap_create((char *) &nbo_size, EPP_HEADER_LENGTH,
			NULL, f->c->bucket_alloc);
	APR_BUCKET_INSERT_BEFORE(APR_BRIGADE_FIRST(bb), bnew);

	if (len > 0)
		ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c,
				"epp frame transmitted (length %ld bytes)", len);

	return ap_pass_brigade(f->next, bb);
}

static int epp_postconfig_hook(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp,
																server_rec *s)
{
	char	buf[101];
	char	*res;
	eppd_server_conf *sc;
	int	err_seen = 0;

	/*
	 * Iterate through available servers and if eppd is enabled
	 * do further checking
	 */
	while (s != NULL) {
		sc = (eppd_server_conf *) ap_get_module_config(s->module_config,
				&eppd_module);

		if (sc->epp_enabled) {
		}
		s = s->next;
	}

	return (err_seen) ? HTTP_INTERNAL_SERVER_ERROR : OK;
}

static const char *set_epp_protocol(cmd_parms *cmd, void *dummy, int flag)
{
    server_rec *s = cmd->server;
    eppd_server_conf *sc = (eppd_server_conf *)
		ap_get_module_config(s->module_config, &eppd_module);

	const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err) {
        return err;
    }

    sc->epp_enabled = flag;
    return NULL;
}

static const command_rec eppd_cmds[] = {
    AP_INIT_FLAG("EPPprotocol", set_epp_protocol, NULL, RSRC_CONF,
			 "Whether this server is serving the epp protocol"),
    { NULL }
};

static void *create_eppd_config(apr_pool_t *p, server_rec *s)
{
	eppd_server_conf *sc =
	    (eppd_server_conf *) apr_pcalloc(p, sizeof(*sc));

	return sc;
}

static void register_hooks(apr_pool_t *p)
{
	ap_hook_post_config(epp_postconfig_hook, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_process_connection(epp_process_connection, NULL, NULL, APR_HOOK_MIDDLE);

	/* register epp filters */
	ap_register_output_filter("EPP_OUTPUT_FILTER", epp_output_filter, NULL,
				                              AP_FTYPE_CONNECTION);
}

module AP_MODULE_DECLARE_DATA eppd_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    create_eppd_config,         /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    eppd_cmds,                  /* command apr_table_t */
    register_hooks              /* register hooks */
};

/* vi:set ts=4 sw=4: */
