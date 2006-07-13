/**
 * @file mod_eppd.c
 * mod_eppd.c is a true heart of the epp module which is called mod_eppd.
 *
 * The file contains typical apache-module-stuff (hooks, command table,
 * configuration table, filters, ...) and manages other components which
 * are used to parse/generate xml and call corba functions. There are good
 * reasons for parting the module in several components:
 * 	- Reduction of overall complexity.
 * 	- Component substitution and debugging is easier.
 * 	- Separation of sources which need to be linked with different libraries.
 * 	- Mangling apache memory pools and malloc()/free() used elsewhere is bad
 * 	idea. Every component is responsible for freeing memory allocated by
 * 	itself.
 * 	.
 * This file uses three interfaces in order to get work done.
 * 	- xml parser interface defined in epp_parser.h.
 * 	- xml generator interface defined in epp_gen.h.
 * 	- corba submodule interface defined in epp-client.h.
 * 	.
 * In addition the module uses openssl library to compute x509 certificate
 * fingerprint which is used when authenticating client.
 *
 * The task of this module is to handle any incomming request if epp engine
 * is turned on. It is a translator from xml to corba function calls. Request
 * processing consists of three stages:
 * 	- parsing of xml request
 * 	- actual corba call
 * 	- generating of xml response
 * 	.
 *
 * 	General information concerning configuration and installation of mod_eppd
 * 	module can be found in README file.
 */

#include "httpd.h"
#include "http_core.h"
#include "http_log.h"
#define CORE_PRIVATE
#include "http_config.h"
#include "http_connection.h"	/* connection hooks */
#undef CORE_PRIVATE

#define APR_WANT_BYTEFUNC
#include "apr_want.h"	/* ntohl/htonl-like functions */
#include "apr_buckets.h"
#include "apr_file_io.h"
#ifndef APR_FOPEN_READ
#define APR_FOPEN_READ	APR_READ
#endif
#include "apr_general.h"
#include "apr_global_mutex.h"
#include "apr_lib.h"	/* apr_isdigit() */
#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_time.h"

#include "scoreboard.h"
#include "util_filter.h"
//#ifdef AP_NEED_SET_MUTEX_PERMS
#include "unixd.h"
//#endif

#include "mod_ssl.h"	/* ssl_var_lookup */

/*
 * openssl header files
 * used for fingerprint computation
 */
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/x509.h>

/*
 * our header files
 */
#include "epp_common.h"
#include "epp_parser.h"
#include "epp_gen.h"
#include "epp-client.h"

#define EPPD_VERSION	"testing"
#define MAX_FRAME_LENGTH	16000
#define EPP_HEADER_LENGTH	4

module AP_MODULE_DECLARE_DATA eppd_module;

/**
 * SSL variable lookup function pointer used for client's PEM encoded
 * certificate retrieval.
 */
static APR_OPTIONAL_FN_TYPE(ssl_var_lookup) *epp_ssl_lookup = NULL;

/**
 * Log levels used for logging to eppd log file.
 */
typedef enum {
	EPP_FATAL = 1,	/**< Serious error, the module is not in operational state.*/
	EPP_ERROR,	/**< Error caused usually by client, module is operational. */
	EPP_WARNING,	/**< Errors which are not serious but should be logged. */
	EPP_INFO,	/**< This is the default log level. */
	EPP_DEBUG	/**< Contents of requests and responses are logged. */
}epp_loglevel;

/**
 * Configuration structure of eppd module.
 */
typedef struct {
	int	epp_enabled;	/**< Decides whether mod_eppd is enabled for host. */
	char	*servername;	/**< Epp server name used in <greeting> frame. */
	char	*iorfile;	/**< File containing corba object's reference. */
	char	*ior;	/**< Object's reference. */
	char	*schema;	/**< URL of EPP schema (use just path). */
	int	valid_resp;	/**< Validate responses before sending them to client. */
	epp_corba_globs	*corba_globs;	/**< Variables needed for corba submodule. */
	char	*epplog;	/**< Epp log filename. */
	apr_file_t	*epplogfp;	/**< File descriptor of epp log file. */
	epp_loglevel	loglevel;	/**< Epp log level #epp_loglevel. */
}eppd_server_conf;

/** Used for access serialization to epp log file. */
static apr_global_mutex_t *epp_log_lock;

/*
 * This is wrapper function for compatibility reason. Apache 2.0 does
 * not have ap_log_cerror, instead we will use ap_log_error.
 */
#if AP_SERVER_MINORVERSION_NUMBER == 0
#define ap_log_cerror(mark, level, status, c, ...) \
	ap_log_error(mark, level, status, (c)->base_server, __VA_ARGS__)
#endif

/**
 * Get well formatted time used in log file as a timestamp.
 * @param buf Buffer to print time into.
 * @param nbytes Size of the buffer.
 */
static void current_logtime(char *buf, int nbytes)
{
    apr_time_exp_t t;
    apr_size_t len;
 
    apr_time_exp_lt(&t, apr_time_now());
 
    apr_strftime(buf, &len, nbytes, "[%d/%b/%Y:%H:%M:%S ", &t);
    apr_snprintf(buf+len, nbytes-len, "%c%.2d%.2d]",
                 t.tm_gmtoff < 0 ? '-' : '+',
                 t.tm_gmtoff / (60*60), t.tm_gmtoff % (60*60));
}

/**
 * Write a log message to eppd log file.
 *
 * @param c Connection record.
 * @param p A pool from which to allocate strings for internal use.
 * @param session Session ID of the client.
 * @param level Log level #epp_loglevel.
 * @param fmt Printf-style format string.
 */
static void epplog(conn_rec *c, apr_pool_t *p, int session, epp_loglevel level,
						const char *fmt, ...)
{
    char	*logline;	/* the actual text written to log file */
	char	*text;	/* log message as passed from client */
	char	timestr[80];	/* buffer for timestamp */
    const char	*rhost;	/* ip address of remote host */
    apr_size_t	nbytes;	/* length of logline */
    apr_status_t	rv;
    va_list	ap;
    eppd_server_conf *sc = (eppd_server_conf *)
		ap_get_module_config(c->base_server->module_config, &eppd_module);
 
	/* cancel out messages with lower priority than configured loglevel */
    if (level > sc->loglevel) return;

    va_start(ap, fmt);
    text = apr_pvsprintf(p, fmt, ap);
    va_end(ap);
 
	/* if epp log file is not configured, log messages to apache's error log */
	if (!sc->epplogfp) {
		int	ap_level; /* apache's log level equivalent to eppd loglevel */

		/* convert between two scales */
		switch (level) {
			case EPP_FATAL:
				ap_level = APLOG_CRIT;
				break;
			case EPP_ERROR:
				ap_level = APLOG_ERR;
				break;
			case EPP_WARNING:
				ap_level = APLOG_WARNING;
				break;
			case EPP_INFO:
				ap_level = APLOG_INFO;
				break;
			case EPP_DEBUG:
			default:
				ap_level = APLOG_DEBUG;
				break;
		}
		ap_log_cerror(APLOG_MARK, level, 0, c, text);
		return;
	}

	/* get remote host's ip address - is not critical if it is not known */
    rhost = ap_get_remote_host(c, NULL, REMOTE_NOLOOKUP, NULL);
	/* get timestamp */
	current_logtime(timestr, 79);
	/* make up the whole log record */
    logline = apr_psprintf(p, "%s %s [sessionID %d] %s" APR_EOL_STR,
						timestr,
						rhost ? rhost : "UNKNOWN-HOST",
						session,
						text);

	/* serialize access to log file */
    rv = apr_global_mutex_lock(epp_log_lock);
    if (rv != APR_SUCCESS) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, c,
                      "apr_global_mutex_lock(epp_log_lock) failed");
    }

    nbytes = strlen(logline);
    apr_file_write(sc->epplogfp, logline, &nbytes);

    rv = apr_global_mutex_unlock(epp_log_lock);
    if (rv != APR_SUCCESS) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, c,
                      "apr_global_mutex_unlock(epp_log_lock) failed");
    }

    return;
}

/**
 * Read epp request.
 * Epp request consists of header, which contains frame length including
 * the header itself (4 bytes) and the actual request which is xml document.
 *
 * @param p Pool from which to allocate memory.
 * @param c Connection record.
 * @param content The read request without header.
 * @param bytes Length of request (excluding header length).
 * @param session Session ID is used only for logging.
 * @return 1 if successful and 0 when error occured.
 */
static int
epp_read_request(apr_pool_t *p, conn_rec *c, char **content, unsigned *bytes,
		int session)
{
		char	*buf;	/* buffer for request */
		uint32_t	hbo_size; /* size of request in host byte order */
		uint32_t	nbo_size; /* size of request in network byte order */
		apr_bucket_brigade *bb;
		apr_status_t	status;
		apr_size_t	len;

		bb = apr_brigade_create(p, c->bucket_alloc);

		/* blocking read of first 4 bytes (request's length) */
		status = ap_get_brigade(c->input_filters, bb, AP_MODE_READBYTES,
									APR_BLOCK_READ, EPP_HEADER_LENGTH);
		if (status != APR_SUCCESS) {
			/*
			 * this used to be logged at EPP_FATAL level, but later was
			 * changed to lower priority, because condition above catches also
			 * cases, when client simply aborts the connection without
			 * logging out first, which happens pretty often and is not
			 * "fatal" at all.
			 * TODO: the status should be further analysed in order to
			 * distinguish between the two cases.
			 */
			epplog(c, p, session, EPP_INFO, "Error when reading epp header");
			return 0;
		}

		/*
		 * convert bucket brigade into sequence of bytes
		 * In most cases there is just one bucket of size 4, which
		 * could be read directly. But we will not rely on it.
		 */
		len = EPP_HEADER_LENGTH;
		status = apr_brigade_pflatten(bb, &buf, &len, p);
		if (status != APR_SUCCESS) {
			epplog(c, p, session, EPP_FATAL, "Could not flatten apr_brigade!");
			apr_brigade_destroy(bb);
			return 0;
		}
		if (len != EPP_HEADER_LENGTH) {
			/* this should not ever happen */
			epplog(c, p, session, EPP_ERROR,
					"4 bytes of EPP header were read but after flatting of"
					" bucket brigade only %u bytes remained?!",
					(unsigned int) len);
			apr_brigade_destroy(bb);
			return 0;
		}

		/* beware of alignment issues - this should be safe */
		for (len = 0; len < EPP_HEADER_LENGTH; len++)
			((char *) &nbo_size)[len] = buf[len];
		hbo_size = ntohl(nbo_size);

		/* exclude header length */
		hbo_size -= EPP_HEADER_LENGTH;

		/*
		 * hbo_size needs to be checked, so that we know it's not total
		 * garbage
		 */
		if (hbo_size < 1 || hbo_size > MAX_FRAME_LENGTH) {
			epplog(c, p, session, EPP_ERROR,
					"Invalid epp frame length (%u bytes)", hbo_size);
			apr_brigade_destroy(bb);
			return 0;
		}

		/* we will reuse bucket brigade when reading the request */
		status = apr_brigade_cleanup(bb);
		if (status != APR_SUCCESS) {
			epplog(c, p, session, EPP_FATAL, "Could not cleanup brigade!");
			apr_brigade_destroy(bb);
			return 0;
		}

		/* blocking read of request's body */
		len = hbo_size;
		status = ap_get_brigade(c->input_filters, bb, AP_MODE_READBYTES,
									APR_BLOCK_READ, len);
		if (status != APR_SUCCESS) {
			epplog(c, p, session, EPP_ERROR,
					"Error when reading epp request's body");
			apr_brigade_destroy(bb);
			return 0;
		}

		/* convert bucket brigade to string */
		status = apr_brigade_pflatten(bb, content, &len, p);
		if (status != APR_SUCCESS) {
			epplog(c, p, session, EPP_FATAL, "Could not flatten apr_brigade!");
			apr_brigade_destroy(bb);
			return 0;
		}
		if (len != hbo_size) {
			epplog(c, p, session, EPP_ERROR,
				"EPP request's length (%u bytes) is other than the "
				"claimed one in header (%u bytes)",
					(unsigned) len, hbo_size);
			apr_brigade_destroy(bb);
			return 0;
		}

		epplog(c, p, session, EPP_DEBUG, "request received (length %u bytes)",
				hbo_size);
		epplog(c, p, session, EPP_DEBUG, "request content: %s", *content);

		apr_brigade_destroy(bb);
		*bytes = (unsigned) len;
		return 1;
}

/**
 * Get md5 signiture of given PEM encoded certificate.
 * The only function in module which uses openssl library.
 *
 * @param cert_md5 Allocated buffer for storing the resulting fingerprint
 * (should be at least 50 bytes long).
 * @param pem PEM encoded certificate in its string representation.
 * @return 1 if successful and 0 when error occured.
 */
static int get_md5(char *cert_md5, char *pem)
{
	X509	*x;	/* openssl's struture for representing x509 certificate */
    BIO	*bio;	/* openssl's basic input/output stream */
	unsigned char	md5[20];	/* fingerprint in binary form */
	unsigned len;	/* length of fingerprint in binary form */
    int i;

	/*
	 * This function is rather overcomplicated, because the interface
	 * of openssl library is somewhat cumbersome. At first we have to
	 * get PEM encoded ceritificate in BIO stream, which is input for
	 * routine which creates X509 struct. Only X509 struct can then be
	 * fed to X509_digest() function, which computes the fingerprint.
	 */
	if ((bio = BIO_new(BIO_s_mem())) == NULL) return 0;

	if (BIO_write(bio, pem, strlen(pem)) <= 0) {
		BIO_free(bio);
		return 0;
	}

	/* convert PEM to x509 struct */
	x = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
	if (x == NULL) {
		BIO_free_all(bio);
		return 0;
	}

	/* compute md5 hash of certificate */
	if (!X509_digest(x, EVP_md5(), md5, &len)) { 
		BIO_free_all(bio);
		X509_free(x);
		return 0;
	}
	/* convert binary representation to string representation of fingerprint */
	for (i = 0; i < len; i++) {
		sprintf(cert_md5, "%02X%c", md5[i], (i + 1 == len) ? '\0' : ':');
		cert_md5 += 3;
	}

	BIO_free_all(bio);
	X509_free(x);

    return 1;
}

/**
 * EPP Connection handler.
 * When EPP engine is turn on for connection, this handler takes care
 * of it for whole connection's lifetime duration. The connection is
 * taken out of reach of other handlers, this is important, since
 * EPP protocol and HTTP protocol are quite different and even if you
 * make EPP request as much as possible similar to HTTP request,
 * unexpectable influences from other modules occur.
 *
 * @param c Incoming connection.
 * @return Return code
 */
static int epp_process_connection(conn_rec *c)
{
	int	session;	/* session = 0 when not autenticated yet */
	unsigned	lang;	/* session's language */
	int	logout;	/* if true, terminate request loop */
	int	firsttime;	/* if true, generate greeting in request loop */
	apr_bucket_brigade	*bb;
	apr_status_t	status;	/* used to store return code from apr functions */
	server_rec	*s = c->base_server;
	eppd_server_conf *sc = (eppd_server_conf *)
		ap_get_module_config(s->module_config, &eppd_module);

	/* do nothing if eppd is disabled */
	if (!sc->epp_enabled)
		return DECLINED;

	/* update scoreboard's information */
	ap_update_child_status(c->sbh, SERVER_BUSY_READ, NULL);

	/* add connection output filter, which constructs EPP header */
	ap_add_output_filter("EPP_OUTPUT_FILTER", NULL, NULL, c);

	/* create bucket brigade for transmition of responses */
	bb = apr_brigade_create(c->pool, c->bucket_alloc);

	/* initialize variables used inside the loop */
	session = 0;
	lang = LANG_EN;	/* default language is english */
	firsttime = 1;	/* this will cause automatic generation of greeting */
	/*
	 * Loop in which are processed requests until client logs out or error
	 * appears.
	 */
	logout = 0;
	while (!logout) {
		apr_pool_t	*rpool;	/* memory pool used for duration of a request */
		epp_command_data	cdata;	/* self-descriptive data structure */
		epp_gen	gen;	/* generated answer and possibly encountered errors */
		parser_status	pstat;	/* parser's return code */

		/* allocate new pool for request */
		apr_pool_create(&rpool, c->pool);
		apr_pool_tag(rpool, "EPP_request");

		if (firsttime) {
			firsttime = 0;
			/*
			 * bogus branch in order to generate greeting when firsttime
			 * in request loop. We don't have much to do, we will
			 * just simulate <hello> frame arrival by setting pstat.
			 */
			pstat = PARSER_HELLO;
			epplog(c, rpool, session, EPP_DEBUG, "Client connected");
		}
		else {
			char *request;	/* raw request read from socket */
			unsigned	bytes;	/* length of request */

			/* read request */
			if (!epp_read_request(rpool, c, &request, &bytes, session)) {
				/*
				 * we used to return HTTP_INTERNAL_SERVER_ERROR here, but
				 * since epp_read_request is unsuccessfull each time client
				 * disconnects without first logging out, which happens quite
				 * often, we return OK.
				 */
				break;
			}

			/* initialize cdata structure */
			bzero(&cdata, sizeof cdata);

			/*
			 * deliver request to XML parser, the task of parser is to fill
			 * cdata structure with data
			 */
			pstat = epp_parse_command(session, sc->schema, request, bytes,
					&cdata);
		}

		switch (pstat) {
			case PARSER_NOT_XML:
				epplog(c, rpool, session, EPP_WARNING,
						"Request is not XML");
				return HTTP_BAD_REQUEST;
			case PARSER_NOT_COMMAND:
				epplog(c, rpool, session, EPP_WARNING,
						"Request is neither a command nor hello");
				return HTTP_BAD_REQUEST;
			case PARSER_ESCHEMA:
				epplog(c, rpool, session, EPP_WARNING,
						"Schema's parser error - check correctness of schema");
				return HTTP_INTERNAL_SERVER_ERROR;
			case PARSER_EINTERNAL:
				epplog(c, rpool, session, EPP_FATAL,
						"Internal parser error occured when processing request");
				return HTTP_INTERNAL_SERVER_ERROR;
			case PARSER_HELLO:
			case PARSER_NOT_VALID:
			case PARSER_CMD_LOGIN:
			case PARSER_CMD_LOGOUT:
			case PARSER_CMD_OTHER:
				/* theese return codes are ok - we can continue in processing */
				break;
			default:
				epplog(c, rpool, session, EPP_FATAL,
						"Unknown error occured during parsing stage");
				return HTTP_BAD_REQUEST;
		}

		/* is it <hello> frame? */
		if (pstat == PARSER_HELLO) {
			int	rc;
			char	version_buf[101];
			gen_status	gstat;	/* generator's return code */

			/* get info from CR used in <greeting> frame */
			rc = epp_call_hello(sc->corba_globs, version_buf, 100);

			if (rc == 0) {
				epplog(c, rpool, session, EPP_ERROR,
						"Could not obtain version string from CR");
				return HTTP_INTERNAL_SERVER_ERROR;
			}

			/*
			 * generate greeting (server name is concatenation of string
			 * given in apache's configuration file and string retrieved
			 * from corba server through version() function)
			 */
			gstat = epp_gen_greeting(
					apr_pstrcat(
						rpool,
						sc->servername,
						" (ccReg ",
						version_buf,
						") (mod_eppd SVN rev ",
						SVN_REV,
						" BUILT ",__DATE__," ",__TIME__,")",
						NULL),
					&gen.response);
			if (gstat != GEN_OK) {
				epplog(c, rpool, session, EPP_FATAL,
						"Error when creating epp greeting");
				return HTTP_INTERNAL_SERVER_ERROR;
			}
			gen.valerr = NULL;
		}
		/* it is a command */
		else {
			corba_status	cstat;	/* return code of corba component */
			gen_status	gstat;	/* generator's return code */

			/*
			 * we generate response for valid commands and requests which
			 * doesn't validate. Note that this is the only case in which
			 * cdata structure is filled and therefore needs to be freed.
			 */

			/* we will drop a line for requests which don't validate in log */
			if (pstat == PARSER_NOT_VALID) {
				epplog(c, rpool, session, EPP_WARNING,
						"Request doest not validate");
			}

			if (pstat == PARSER_CMD_LOGIN) {
				char	cert_md5[50]; /* should be enough for md5 hash of cert */
				char	*pem;	/* pem encoded client's certificate */

				/* we will compute fingerprint of client's certificate */
				bzero(cert_md5, 50);
				pem = epp_ssl_lookup(rpool, c->base_server, c, NULL,
						"SSL_CLIENT_CERT");
				if ((pem == NULL) || (*pem == '\0') || !get_md5(cert_md5, pem)) {
					epplog(c, rpool, session, EPP_ERROR,
							"Error when getting client's PEM certificate. "
							"Did you forget \"SSLVerifyClient require\" "
							"directive in apache's conf?");
					epp_command_data_cleanup(&cdata);
					return HTTP_INTERNAL_SERVER_ERROR;
				}

				epplog(c, rpool, session, EPP_DEBUG,
						"Fingerprint is: %s", cert_md5);

				/*
				 * corba login function is somewhat special
				 *   - session might be changed
				 *   - lang might be changed
				 *   - there is additional parameter identifing ssl certificate
				 *     in order to match login name with used certificate on
				 *     side of central repository. The identifing parameter
				 *     is md5 digest of client's certificate.
				 */
				cstat = epp_call_login(sc->corba_globs, &session, &lang,
						cert_md5, &cdata);
			}
			else if (pstat == PARSER_CMD_LOGOUT) {
				cstat = epp_call_logout(sc->corba_globs, session,
						&cdata, &logout);
			}
			else {
				/* go ahead to generic corba function call */
				cstat = epp_call_cmd(sc->corba_globs, session, &cdata);
			}

			/* catch corba failures */
			if (cstat != CORBA_OK) {
				epp_command_data_cleanup(&cdata);
				switch (cstat) {
					case CORBA_ERROR:
						epplog(c, rpool, session, EPP_ERROR,
								"Corba call failed - terminating session");
						break;
					case CORBA_REMOTE_ERROR:
						epplog(c, rpool, session, EPP_ERROR,
								"Unqualified answer from server - "
								"terminating session");
						break;
					case CORBA_INT_ERROR:
						epplog(c, rpool, session, EPP_FATAL,
								"Malloc in corba wrapper failed");
						break;
					default:
						epplog(c, rpool, session, EPP_ERROR,
								"Unknown return code from corba module");
						break;
				}
				return HTTP_INTERNAL_SERVER_ERROR;
			}

			/* generate xml response */
			gstat = epp_gen_response(sc->valid_resp, sc->schema,
					lang, &cdata, &gen);

			epp_command_data_cleanup(&cdata); /* not needed anymore */

			switch (gstat) {
				case GEN_OK:
					break;
				/*
				 * following errors are serious and response cannot be sent
				 * to client when any of them appears
				 */
				case GEN_EBUFFER:
				case GEN_EWRITER:
				case GEN_EBUILD:
					epplog(c, rpool, session, EPP_FATAL,
							"XML generator failed - terminating session");
					return HTTP_INTERNAL_SERVER_ERROR;
				/*
				 * following errors are only informative though serious.
				 * The connection persists and response is sent back to
				 * client.
				 */
				case GEN_NOT_XML:
					epplog(c, rpool, session, EPP_ERROR,
							"Generated response is not XML");
					break;
				case GEN_EINTERNAL:
					epplog(c, rpool, session, EPP_ERROR,
							"Malloc failure when validating response");
					break;
				case GEN_ESCHEMA:
					epplog(c, rpool, session, EPP_ERROR,
						"Error when parsing schema for validation of response");
					break;
				case GEN_NOT_VALID:
					epplog(c, rpool, session, EPP_ERROR,
							"Generated response does not validate");
					/* print more detailed information about validation errors */
					if (gen.valerr != NULL) {
						CL_FOREACH(gen.valerr) {
							epp_error	*e = CL_CONTENT(gen.valerr);
							epplog(c, rpool, session, EPP_ERROR,
									"Element: %s", e->value);
							epplog(c, rpool, session, EPP_ERROR,
									"Reason: %s", e->reason);
						}
					}
					break;
				default:
					epplog(c, rpool, session, EPP_ERROR,
							"Unknown return code from generator module");
					break;
			}
		}

		/* send response back to client */
		apr_brigade_puts(bb, NULL, NULL, gen.response);
		epplog(c, rpool, session, EPP_DEBUG, "Response content: %s",
				gen.response);
		epp_free_gen(&gen);
		status = ap_fflush(c->output_filters, bb);
		if (status != APR_SUCCESS) {
			epplog(c, rpool, session, EPP_FATAL,
				"Error when sending response to client");
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		/* prepare bucket brigade for reuse in next request */
		status = apr_brigade_cleanup(bb);
		if (status != APR_SUCCESS) {
			epplog(c, rpool, session, EPP_FATAL,
				"Could not cleanup bucket brigade used for response");
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		apr_pool_destroy(rpool);
	}

	/* client logged out or disconnected from server */
	epplog(c, c->pool, session, EPP_INFO, "Session ended");
	return HTTP_OK;
}

/**
 * epp output filter, which prefixes each response with length of the response.
 * @param f Apache filter structure.
 * @param bb Bucket brigade containing a response.
 * @return Return code of next filter in chain.
 */
static apr_status_t epp_output_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
	apr_bucket	*b, *bnew;
	apr_size_t	len;
	uint32_t	nbo_size; /* response length in network byte order */

	/*
	 * iterate through buckets in bucket brigade and compute total length
	 * of response.
	 */
	for (b = APR_BRIGADE_FIRST(bb), len = 0;
		 b != APR_BRIGADE_SENTINEL(bb);
		 b = APR_BUCKET_NEXT(b))
	{

		/* catch weird situation which will probably never happen */
		if (b->length == -1)
			ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c,
			"mod_eppd: in filter - Bucket with unknown length ... weird");
		else
			len += b->length;
	}

	/* header size is included in total size */
	nbo_size = htonl(len + EPP_HEADER_LENGTH);
	/* create new bucket containing only length of request */
	bnew = apr_bucket_heap_create((char *) &nbo_size, EPP_HEADER_LENGTH,
			NULL, f->c->bucket_alloc);
	/* insert the new bucket in front of the response */
	APR_BUCKET_INSERT_BEFORE(APR_BRIGADE_FIRST(bb), bnew);

	/* pass bucket brigade to next filter */
	return ap_pass_brigade(f->next, bb);
}

/**
 * Init child hook is run everytime a new thread (or process) is started.
 * Task of the hook is to initialize a lock which protects epp log file.
 * @param p Memory pool.
 * @param s Server record.
 */
static void epp_init_child_hook(apr_pool_t *p, server_rec *s)
{
	apr_status_t	rv;

	rv = apr_global_mutex_child_init(&epp_log_lock, NULL, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                     "mod_eppd: could not init epp log lock in child");
    }
}

/**
 * In post config hook is check consistensy of configuration (required
 * parameters, default values of parameters), components are initialized,
 * log file is setted up ...
 *
 * @param p Memory pool.
 * @param plog Memory pool used for logging.
 * @param ptemp Memory pool destroyed right after postconfig phase.
 * @param s Server record.
 */
static int epp_postconfig_hook(apr_pool_t *p, apr_pool_t *plog,
		apr_pool_t *ptemp, server_rec *s)
{
	eppd_server_conf *sc;
	apr_status_t	rv = 0;

	/*
	 * during authentication of epp client we need to get value of a
	 * SSL variable. For that we need ssl_var_lookup function.
	 */
	epp_ssl_lookup = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);
	if (epp_ssl_lookup == NULL) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                     "mod_eppd: could not retrieve ssl_var_lookup function. "
					 "Is mod_ssl loaded?");
        return HTTP_INTERNAL_SERVER_ERROR;
	}

    /* create the rewriting lockfiles in the parent */
    if ((rv = apr_global_mutex_create(&epp_log_lock, NULL,
                                      APR_LOCK_DEFAULT, p)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                     "mod_eppd: could not create epp_log_lock");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
 
//#ifdef AP_NEED_SET_MUTEX_PERMS  
    rv = unixd_set_global_mutex_perms(epp_log_lock);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                     "mod_eppd: Could not set permissions on "
                     "epp_log_lock; check User and Group directives");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
//#endif /* perms */

	/*
	 * Iterate through available servers and if eppd is enabled
	 * open epp log file initialize components and do further checking
	 */
	while (s != NULL) {
		epp_corba_globs	*corba_globs;
		char	*fname;

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
			/* set default loglevel */
			if (sc->loglevel == 0) sc->loglevel = EPP_INFO;
			/*
			 * do initialization of xml
			 */
			epp_parser_init();
			/*
			 * do initialization of corba
			 */
			corba_globs = epp_corba_init(sc->ior);
			if (corba_globs == NULL) {
				ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
						"Corba initialization failed");
				return HTTP_INTERNAL_SERVER_ERROR;
			}
			sc->corba_globs = corba_globs;

			/*
			 * open epp log file (if configured to do so)
			 */
			if (sc->epplog && !sc->epplogfp) {
				fname = ap_server_root_relative(p, sc->epplog);
				if (!fname) {
					ap_log_error(APLOG_MARK, APLOG_ERR, APR_EBADPATH, s,
							 "mod_eppd: Invalid EPPlog path %s", sc->epplog);
					return HTTP_INTERNAL_SERVER_ERROR; 
				}
				if ((rv = apr_file_open(&sc->epplogfp, fname,
							(APR_WRITE | APR_APPEND | APR_CREATE),
							( APR_UREAD | APR_UWRITE | APR_GREAD | APR_WREAD ),
							p))
						!= APR_SUCCESS) {
					ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
							 "mod_eppd: could not open EPPlog file %s", fname);
					return HTTP_INTERNAL_SERVER_ERROR;
				}
			}
		}
		s = s->next;
	}

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

static const char *set_epplog(cmd_parms *cmd, void *dummy,
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
	if (sc->epplog != NULL) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
			"mod_eppd: more than one definition of epplog file. All but\
			the first one will be ignored");
		return NULL;
	}

	sc->epplog = apr_pstrdup(cmd->pool, a1);

    return NULL;
}

static const char *set_loglevel(cmd_parms *cmd, void *dummy,
		const char *a1)
{
	const char *err;
	server_rec *s = cmd->server;
	eppd_server_conf *sc = (eppd_server_conf *)
		ap_get_module_config(s->module_config, &eppd_module);

	err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err) return err;

	/*
	 * catch double definition of loglevel
	 * that's not serious fault so we will just print message in log
	 */
	if (sc->loglevel != 0) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
			"mod_eppd: loglevel defined more than once. All but\
			the first definition will be ignored");
		return NULL;
	}

	/* translate loglevel name to loglevel number */
	if (!apr_strnatcmp("fatal", a1))
		sc->loglevel = EPP_FATAL;
	else if (!apr_strnatcmp("error", a1))
		sc->loglevel = EPP_ERROR;
	else if (!apr_strnatcmp("warning", a1))
		sc->loglevel = EPP_WARNING;
	else if (!apr_strnatcmp("info", a1))
		sc->loglevel = EPP_INFO;
	else if (!apr_strnatcmp("debug", a1))
		sc->loglevel = EPP_DEBUG;
	else {
		return "mod_eppd: log level must be one of "
				"fatal, error, warning, info, debug";
	}

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

static const char *set_valid_resp(cmd_parms *cmd, void *dummy, int flag)
{
    server_rec *s = cmd->server;
    eppd_server_conf *sc = (eppd_server_conf *)
		ap_get_module_config(s->module_config, &eppd_module);

	const char *err = ap_check_cmd_context(cmd,
			NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);
    if (err) {
        return err;
    }

    sc->valid_resp = flag;
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
	AP_INIT_TAKE1("EPPlog", set_epplog, NULL, RSRC_CONF,
			 "The file where come all log messages from mod_eppd"),
	AP_INIT_TAKE1("EPPloglevel", set_loglevel, NULL, RSRC_CONF,
		 "Log level setting for epp log (fatal, error, warning, info, debug)"),
    AP_INIT_FLAG("EPPvalidResponse", set_valid_resp, NULL, RSRC_CONF,
			 "Set to on, to validate every outcomming response."
			 "This will slow down the server and should be used only for"
			 " debugging purposes."),
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
	ap_hook_child_init(epp_init_child_hook, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_post_config(epp_postconfig_hook, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_process_connection(epp_process_connection, NULL, NULL,
			APR_HOOK_MIDDLE);

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
