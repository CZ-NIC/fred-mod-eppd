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
#ifndef APR_FOPEN_READ
#define APR_FOPEN_READ	APR_READ
#endif

#include "apr_general.h"
#include "apr_lib.h"	/* apr_isdigit() */
#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_time.h"

#include "scoreboard.h"
#include "util_filter.h"

/*
 * our header files
 */
#include "epp_common.h"
#include "epp_xml.h"
#include "epp-client.h"

#define EPPD_VERSION	"testing"
#define MAX_FRAME_LENGTH	16000
#define EPP_HEADER_LENGTH	4

module AP_MODULE_DECLARE_DATA eppd_module;

/**
 * Configuration structure of eppd module.
 */
typedef struct {
	int	epp_enabled;
	char	*servername;	/* epp server name in <greeting> */
	char	*iorfile;	/* file with corba object ref */
	char	*ior;	/* object reference */
	char	*schema;	/* URL of EPP schema */
	void	*xml_globs;	/* variables needed for xml parser and generator */
	void	*corba_globs;	/* variables needed for corba part */
}eppd_server_conf;

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
epp_read_request(apr_pool_t *p, conn_rec *c, char **content, unsigned *bytes)
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
					"Weird EPP header size! (%u bytes)", (unsigned int) len);
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
		status = apr_brigade_pflatten(bb, content, &len, p);
		if (status != APR_SUCCESS) {
			ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
					"Could not flatten apr_brigade!");
			apr_brigade_destroy(bb);
			return 0;
		}
		if (len != hbo_size) {
			ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
					"EPP request's body size is other than claimed one:\n"
					"\treal size is %4u bytes\n\tclaimed size is %4d bytes",
					(unsigned) len, hbo_size);
			apr_brigade_destroy(bb);
			return 0;
		}

		ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
				"epp request received (length %u bytes)", hbo_size);

		apr_brigade_destroy(bb);
		*bytes = (unsigned) len;
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
	char	*genstring;
	int	session;	/* session = 0 when not autenticated yet */
	int	rc;
	int	logout;	/* if true, terminate request loop */
	int	firsttime;	/* if true, generate greeting in request loop */

	apr_bucket_brigade	*bb;
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

	bb = apr_brigade_create(c->pool, c->bucket_alloc);
	/* session value 0 means that the user is not logged in yet */
	session = 0;

	/*
	 * process requests loop
	 * termination conditions are embedded inside the loop
	 */
	rc = OK;
	logout = 0;
	firsttime = 1;
	while (!logout) {
		char *request;
		unsigned	bytes;
		apr_pool_t	*rpool;
		parser_status	pstat;
		epp_command_data	cdata;
		corba_status	cstat = CORBA_OK;
		gen_status	gstat = GEN_OK;

		/* allocate new pool for request */
		apr_pool_create(&rpool, c->pool);
		apr_pool_tag(rpool, "EPP_request");

		if (!firsttime) {
			/* read request */
			if (!epp_read_request(rpool, c, &request, &bytes)) {
				rc = HTTP_INTERNAL_SERVER_ERROR;
				break;
			}

			/* initialize cdata structure */
			bzero(&cdata, sizeof cdata);
			/* deliver request to XML parser */
			pstat = epp_parse_command(session, sc->xml_globs, request, bytes,
					&cdata);
		}
		else {
			/*
			 * bogus branch in order to generate greeting when firsttime
			 * in request loop
			 */
			firsttime = 0;
			pstat = PARSER_HELLO;
		}

		/* is it <hello> frame? */
		if (pstat == PARSER_HELLO) {
			gstat = epp_gen_greeting(sc->servername, &genstring);
			if (gstat != GEN_OK) {
				ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
					"Error when creating epp greeting");
				return HTTP_INTERNAL_SERVER_ERROR;
			}
		}
		/* is it a command? */
		else if (pstat == PARSER_OK) {
			/* go ahead to corba function call */
			switch (cdata.type) {
			case EPP_DUMMY:
				cstat = epp_call_dummy(sc->corba_globs, session, &cdata);
				if (cstat == CORBA_OK) {
					gstat = epp_gen_dummy(sc->xml_globs, &cdata, &genstring);
				}
				break;
			case EPP_LOGIN:
				cstat = epp_call_login(sc->corba_globs, &session, &cdata);
				if (cstat == CORBA_OK) {
					gstat = epp_gen_login(sc->xml_globs, &cdata, &genstring);
				}
				break;
			case EPP_LOGOUT:
				cstat = epp_call_logout(sc->corba_globs, session, &cdata);
				if (cstat == CORBA_OK) {
					if (cdata.rc == 1500) logout = 1;
					gstat = epp_gen_logout(sc->xml_globs, &cdata, &genstring);
				}
				break;
			case EPP_CHECK_CONTACT:
				cstat = epp_call_check_contact(sc->corba_globs, session, &cdata);
				if (cstat == CORBA_OK) {
					gstat = epp_gen_check_contact(sc->xml_globs, &cdata,
							&genstring);
				}
				break;
			case EPP_CHECK_DOMAIN:
				cstat = epp_call_check_domain(sc->corba_globs, session, &cdata);
				if (cstat == CORBA_OK) {
					gstat = epp_gen_check_domain(sc->xml_globs, &cdata,
							&genstring);
				}
				break;
			case EPP_CHECK_NSSET:
				cstat = epp_call_check_nsset(sc->corba_globs, session, &cdata);
				if (cstat == CORBA_OK) {
					gstat = epp_gen_check_nsset(sc->xml_globs, &cdata,
							&genstring);
				}
				break;
			case EPP_INFO_CONTACT:
				cstat = epp_call_info_contact(sc->corba_globs, session, &cdata);
				if (cstat == CORBA_OK) {
					gstat = epp_gen_info_contact(sc->xml_globs, &cdata,
							&genstring);
				}
				break;
			case EPP_INFO_DOMAIN:
				cstat = epp_call_info_domain(sc->corba_globs, session, &cdata);
				if (cstat == CORBA_OK) {
					gstat = epp_gen_info_domain(sc->xml_globs, &cdata,
							&genstring);
				}
				break;
			case EPP_INFO_NSSET:
				cstat = epp_call_info_nsset(sc->corba_globs, session, &cdata);
				if (cstat == CORBA_OK) {
					gstat = epp_gen_info_nsset(sc->xml_globs, &cdata,
							&genstring);
				}
				break;
			case EPP_POLL_REQ:
				cstat = epp_call_poll_req(sc->corba_globs, session, &cdata);
				if (cstat == CORBA_OK) {
					gstat = epp_gen_poll_req(sc->xml_globs, &cdata,
							&genstring);
				}
				break;
			case EPP_POLL_ACK:
				cstat = epp_call_poll_ack(sc->corba_globs, session, &cdata);
				if (cstat == CORBA_OK) {
					gstat = epp_gen_poll_ack(sc->xml_globs, &cdata,
							&genstring);
				}
				break;
			default:
				ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
						"Unknown epp frame type - terminating session");
				epp_command_data_cleanup(&cdata);
				return HTTP_INTERNAL_SERVER_ERROR;
			}

			epp_command_data_cleanup(&cdata);

			/* catch corba failures */
			if (cstat != CORBA_OK) {
				if (cstat == CORBA_ERROR)
					ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
							"Corba call failed - terminating session");
				else if (cstat == CORBA_REMOTE_ERROR)
					ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
							"Unqualified answer from server - terminating session");
				else if (cstat == CORBA_INT_ERROR)
					ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
							"Malloc in corba wrapper failed");
				return HTTP_INTERNAL_SERVER_ERROR;
			}
			else if (gstat != GEN_OK) {
				/* catch xml generator failures */
				ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
						"XML Generator failed - terminating session");
				return HTTP_INTERNAL_SERVER_ERROR;
			}

		}
		/* failure which will close connection */
		else {
			switch (pstat) {
				case PARSER_NOT_XML:
					ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, c,
							"Request is not XML");
					rc = HTTP_BAD_REQUEST;
					break;
				case PARSER_NOT_VALID:
					ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, c,
							"Request doest not validate");
					rc = HTTP_BAD_REQUEST;
					break;
				case PARSER_NOT_COMMAND:
					ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, c,
							"Request is not a command");
					rc = HTTP_BAD_REQUEST;
					break;
				case PARSER_EINTERNAL:
					ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
						"Internal parser error occured when processing request");
					rc = HTTP_INTERNAL_SERVER_ERROR;
					break;
				default:
					ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
							"Unknown error occured during parsing stage");
					rc = HTTP_BAD_REQUEST;
					break;
			}
			return rc;
		}

		/* send response back to client */
		apr_brigade_puts(bb, NULL, NULL, genstring);
		status = ap_fflush(c->output_filters, bb);
		if (status != APR_SUCCESS) {
			ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
				"Error when sending response to client");
			epp_free_genstring(genstring);
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		epp_free_genstring(genstring);

		status = apr_brigade_cleanup(bb);
		if (status != APR_SUCCESS) {
			ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
				"Could not cleanup bucket brigade used for response");
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		apr_pool_destroy(rpool);
	}
	return HTTP_OK;
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
				"epp frame transmitted (length %u bytes)", (unsigned) len);

	return ap_pass_brigade(f->next, bb);
}

static int epp_postconfig_hook(apr_pool_t *p, apr_pool_t *plog,
		apr_pool_t *ptemp, server_rec *s)
{
	eppd_server_conf *sc;
	void	*xml_globs;
	void	*corba_globs;
	char	err_seen = 0;

	/*
	 * Iterate through available servers and if eppd is enabled
	 * do further checking
	 */
	while (s != NULL) {
		sc = (eppd_server_conf *) ap_get_module_config(s->module_config,
				&eppd_module);

		if (sc->epp_enabled) {
			if (sc->iorfile == NULL) {
				ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
						"EPPiorfile not configured");
				return HTTP_INTERNAL_SERVER_ERROR;
			}
			if (sc->schema == NULL) {
				ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
						"EPP schema not configured");
				return HTTP_INTERNAL_SERVER_ERROR;
			}
			if (sc->servername == NULL) {
				ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
						"EPP Servername not configured");
				return HTTP_INTERNAL_SERVER_ERROR;
			}

			/*
			 * do initialization of xml
			 */
			xml_globs = epp_xml_init(sc->schema);
			if (xml_globs == NULL) {
				ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
						"Could not initialize xml part");
				return HTTP_INTERNAL_SERVER_ERROR;
			}

			/*
			 * do initialization of corba
			 */
			corba_globs = epp_corba_init(sc->ior);
			if (corba_globs == NULL) {
				ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
						"Corba initialization failed");
				return HTTP_INTERNAL_SERVER_ERROR;
			}


			sc->xml_globs = xml_globs;
			sc->corba_globs = corba_globs;
		}
		s = s->next;
	}

	if (err_seen) return HTTP_INTERNAL_SERVER_ERROR;

	return OK;
}

static const char *set_epp_protocol(cmd_parms *cmd, void *dummy, int flag)
{
    server_rec *s = cmd->server;
    eppd_server_conf *sc = (eppd_server_conf *)
		ap_get_module_config(s->module_config, &eppd_module);

	const char *err = ap_check_cmd_context(cmd,
			NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);
    if (err) {
        return err;
    }

    sc->epp_enabled = flag;
    return NULL;
}

static const char *set_iorfile(cmd_parms *cmd, void *dummy,
		const char *a1)
{
	const char *err;
	char	buf[1001]; /* should be enough for ior */
	apr_file_t	*f;
	apr_size_t	nbytes;
	apr_status_t	status;
	server_rec *s = cmd->server;
	eppd_server_conf *sc = (eppd_server_conf *)
		ap_get_module_config(s->module_config, &eppd_module);

	err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err) return err;

	/*
	 * catch double definition of iorfile
	 * that's not serious fault so we will just print message in log
	 */
	if (sc->iorfile != NULL) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
			"mod_eppd: more than one definition of iorfile. All but\
			the first one will be ignored");
		return NULL;
	}

	sc->iorfile = apr_pstrdup(cmd->pool, a1);

	/* open file */
	status = apr_file_open(&f, sc->iorfile, APR_FOPEN_READ,
			APR_OS_DEFAULT, cmd->temp_pool);
	if (status != APR_SUCCESS) {
		return apr_psprintf(cmd->temp_pool,
					"mod_eppd: could not open file %s (IOR)",
					sc->iorfile);
	}

	/* read the file */
	nbytes = 1000;
	status = apr_file_read(f, (void *) buf, &nbytes);
	buf[nbytes] = 0;
	apr_file_close(f);
	if ((status != APR_SUCCESS) && (status != APR_EOF)) {
		return apr_psprintf(cmd->temp_pool,
				"mod_eppd: error when reading file %s (IOR)",
				sc->iorfile);
	}
	sc->ior = apr_pstrdup(cmd->pool, buf);

    return NULL;
}

static const char *set_schema(cmd_parms *cmd, void *dummy,
		const char *a1)
{
	const char *err;
	server_rec *s = cmd->server;
	eppd_server_conf *sc = (eppd_server_conf *)
		ap_get_module_config(s->module_config, &eppd_module);

	err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err) return err;

	/*
	 * catch double definition of iorfile
	 * that's not serious fault so we will just print message in log
	 */
	if (sc->schema != NULL) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
			"mod_eppd: more than one definition of schema URL. All but\
			the first one will be ignored");
		return NULL;
	}

	sc->schema = apr_pstrdup(cmd->pool, a1);

    return NULL;
}

static const char *set_servername(cmd_parms *cmd, void *dummy,
		const char *a1)
{
	const char *err;
	server_rec *s = cmd->server;
	eppd_server_conf *sc = (eppd_server_conf *)
		ap_get_module_config(s->module_config, &eppd_module);

	err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err) return err;

	/*
	 * catch double definition of servername
	 * that's not serious fault so we will just print message in log
	 */
	if (sc->servername != NULL) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
			"mod_eppd: more than one definition of servername. All but\
			the first one will be ignored");
		return NULL;
	}

	sc->servername = apr_pstrdup(cmd->pool, a1);

    return NULL;
}

static const command_rec eppd_cmds[] = {
    AP_INIT_FLAG("EPPprotocol", set_epp_protocol, NULL, RSRC_CONF,
			 "Whether this server is serving the epp protocol"),
	AP_INIT_TAKE1("EPPiorfile", set_iorfile, NULL, RSRC_CONF,
		 "File where is stored IOR of EPP service"),
	AP_INIT_TAKE1("EPPschema", set_schema, NULL, RSRC_CONF,
		 "URL of XML schema of EPP protocol"),
	AP_INIT_TAKE1("EPPservername", set_servername, NULL, RSRC_CONF,
		 "Name of server sent in EPP greeting"),
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
