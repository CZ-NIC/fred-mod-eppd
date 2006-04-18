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
	void	*parser_server_ctx;
} eppd_server_conf;

/**
 * This is wrapper function for compatibility reason. Apache 2.0 does
 * not have ap_log_cerror, instead we will use ap_log_error.
 */
#if AP_SERVER_MINORVERSION_NUMBER == 0
#define ap_log_cerror(mark, level, status, c, ...) \
	ap_log_error(mark, level, status, (c)->base_server, __VA_ARGS__)
#endif

/**
 * Reads epp request.
 * @par c Connection
 * @par p Pool from which to allocate memory
 * @par content The resulting message
 * @par bytes Number of bytes in message
 * @ret Status (1 = success, 0 = failure)
 */
static int
epp_read_request(apr_pool_t *p, conn_rec *c, char **content, int *bytes)
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
			return 0;
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
			return 0;
		}
		if (len != EPP_HEADER_LENGTH) {
			ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
					"Weird EPP header size! (%d bytes)", len);
			apr_brigade_destroy(bb);
			return 0;
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
			return 0;
		}

		/* exclude header length */
		hbo_size -= EPP_HEADER_LENGTH;

		/*
		 * hbo_size needs to be checked, so that we know it's not total
		 * garbage
		 */
		if (hbo_size < 1 || hbo_size > MAX_FRAME_LENGTH) {
			ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
					"Invalid epp frame length (%u bytes)", hbo_size);
			apr_brigade_destroy(bb);
			return 0;
		}
		/* blocking read of request's body */
		len = hbo_size;
		status = ap_get_brigade(c->input_filters, bb, AP_MODE_READBYTES,
									APR_BLOCK_READ, len);
		if (status != APR_SUCCESS) {
			ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
					"Error when reading epp request's body");
			apr_brigade_destroy(bb);
			return 0;
		}

		/* convert bucket brigade to string */
		status = apr_brigade_pflatten(bb, content, bytes, p);
		if (status != APR_SUCCESS) {
			ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
					"Could not flatten apr_brigade!");
			apr_brigade_destroy(bb);
			return 0;
		}
		if (*bytes != hbo_size) {
			ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
					"EPP request's body size is other than claimed one:\n"
					"\treal size is %4d bytes\n\tclaimed size is %4d bytes",
					*bytes, hbo_size);
			apr_brigade_destroy(bb);
			return 0;
		}

		ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
				"epp request received (length %u bytes)", hbo_size);

		apr_brigade_destroy(bb);
		return 1;
}

/**
 * EPP Connection handler.
 *
 * @param c Incoming connection
 * @ret Return code
 */
static int epp_process_connection(conn_rec *c)
{
	void	*ctx; /* connection context */
	void	*server_ctx;
	int	rc;
	apr_bucket_brigade	*bb;
	apr_status_t	status;
	epp_greeting_parms_out greeting_parms;
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
	bzero(&greeting_parms, sizeof greeting_parms);
	epp_parser_greeting("Server name (ID)", "nejaky datum", &greeting_parms);
	if (greeting_parms.error_msg != NULL) {
		ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
			"Error when creating epp greeting: %s", greeting_parms.error_msg);
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	apr_brigade_puts(bb, NULL, NULL, greeting_parms.greeting);

	status = ap_fflush(c->output_filters, bb);
	if (status != APR_SUCCESS) {
		ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
			"Error when sending greeting to client");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	epp_parser_greeting_cleanup(&greeting_parms);
	ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
			"epp greeting has been sent");

	status = apr_brigade_cleanup(bb);
	if (status != APR_SUCCESS) {
		ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
				"Could not cleanup bucket brigade used for greeting");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* get server context */
	server_ctx = sc->parser_server_ctx;

	/* create and initialize epp connetion context */
	if ((ctx = epp_parser_connection()) == NULL) {
		ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
				"Could allocate epp_connection_ctx struct");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/*
	 * process requests loop
	 * termination conditions are embedded inside the loop
	 */
	rc = OK;
	while (1) {
		char *request;
		unsigned	bytes;
		apr_pool_t	*rpool;
		epp_parser_log	*log_iter;
		epp_command_parms_out parser_out;

		/* allocate new pool for request */
		apr_pool_create(&rpool, c->pool);
		apr_pool_tag(rpool, "EPP_request");

		/* read request */
		if (!epp_read_request(rpool, c, &request, &bytes)) {
			rc = HTTP_INTERNAL_SERVER_ERROR;
			break;
		}

		/* initialize structure for return values from parser */
		bzero(&parser_out, sizeof parser_out);
		/* deliver request to XML parser */
		epp_parser_command(server_ctx, ctx, request, bytes, &parser_out);

		/* analyze parser's answer */
		log_iter = parser_out.head;
		while (log_iter) {
			int log_level;

			switch (log_iter->severity) {
				case EPP_LOG_INFO:
					log_level = APLOG_INFO;
					break;
				case EPP_LOG_WARNING:
					log_level = APLOG_WARNING;
					break;
				case EPP_LOG_ERROR:
					log_level = APLOG_ERR;
					break;
				default:
					log_level = APLOG_DEBUG;
					break;
			}
			ap_log_cerror(APLOG_MARK, log_level, status, c, "epp parser: %s",
					log_iter->msg);
			log_iter = log_iter->next;
		}
		if (parser_out.response != NULL) {
			/* send response back to client */
			apr_brigade_puts(bb, NULL, NULL, parser_out.response);

			status = ap_fflush(c->output_filters, bb);
			if (status != APR_SUCCESS) {
				ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
					"Error when sending response to client");
				epp_parser_command_cleanup(&parser_out);
				rc = HTTP_INTERNAL_SERVER_ERROR;
				break;
			}

			status = apr_brigade_cleanup(bb);
			if (status != APR_SUCCESS) {
				ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
					"Could not cleanup bucket brigade used for response");
				epp_parser_command_cleanup(&parser_out);
				rc = HTTP_INTERNAL_SERVER_ERROR;
				break;
			}
		}
		if (parser_out.status == EPP_CLOSE_CONN) {
			ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
					"Terminating epp session");
			epp_parser_command_cleanup(&parser_out);
			break;
		}

		epp_parser_command_cleanup(&parser_out);
		apr_pool_destroy(rpool);
	}

	epp_parser_connection_cleanup(ctx);
	/* XXX temporary */
	epp_parser_init_cleanup(server_ctx);

	return rc;
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
				"epp frame transmitted (length %u bytes)", len);

	return ap_pass_brigade(f->next, bb);
}

static int epp_postconfig_hook(apr_pool_t *p, apr_pool_t *plog,
		apr_pool_t *ptemp, server_rec *s)
{
	eppd_server_conf *sc;
	char	err_seen = 0;
	char	at_least_one = 0;
	void	*parser_ctx;

	/*
	 * do checking and initialization of libxml
	 */
	parser_ctx = epp_parser_init("schemas/all-1.0.xsd");
	if (parser_ctx == NULL)
		return HTTP_INTERNAL_SERVER_ERROR;

	/*
	 * Iterate through available servers and if eppd is enabled
	 * do further checking
	 */
	while (s != NULL) {
		sc = (eppd_server_conf *) ap_get_module_config(s->module_config,
				&eppd_module);

		if (sc->epp_enabled) {
			sc->parser_server_ctx = parser_ctx;
			at_least_one = 1;
		}
		s = s->next;
	}

	if (err_seen) return HTTP_INTERNAL_SERVER_ERROR;

	/*
	 * If parser server context has been used at least once - keep it.
	 * Otherwise free it.
	 */
	if (!at_least_one) epp_parser_init_cleanup(parser_ctx);

	return OK;
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
