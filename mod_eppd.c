/*
 *  Copyright (C) 2007  CZ.NIC, z.s.p.o.
 *
 *  This file is part of FRED.
 *
 *  FRED is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, version 2 of the License.
 *
 *  FRED is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with FRED.  If not, see <http://www.gnu.org/licenses/>.
 */
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
 * 	General information concerning configuration and installation of
 * 	mod_eppd module can be found in README file.
 */

#include "httpd.h"
#include "http_core.h"
#include "http_log.h"
#define CORE_PRIVATE
#include "http_config.h"
#include "http_connection.h"	/* connection hooks */
#undef CORE_PRIVATE

#define APR_WANT_BYTEFUNC
#define APR_WANT_STRFUNC
#include "apr_want.h"	/* ntohl/htonl-like functions */
#include "apr_buckets.h"
#include "apr_file_io.h"
#ifndef APR_FOPEN_READ
/** define which overcomes subtle difference between apache 2.0 and 2.2. */
#define APR_FOPEN_READ	APR_READ
#endif
#include "apr_general.h"
#include "apr_global_mutex.h"
#include "apr_lib.h"	/* apr_isdigit() */
#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_time.h"
#include "apr_hash.h"

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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/** Min and max time values (in msec) for deferring error responses  */
#define DEFER_MIN 		0
#define DEFER_MAX		10000

/** Length of EPP header containing message size. */
#define EPP_HEADER_LENGTH	4

/**
 * If client claims in EPP header that he is sending message which is longer
 * than this number of bytes, the message is omitted. It is also a limit for
 * maximal xml document length sent to CR to be saved.
 */
#define MAX_FRAME_LENGTH	16000

/**
 * eppd_module declaration.
 */
module AP_MODULE_DECLARE_DATA eppd_module;

/**
 * function for obtaining a reference to a CORBA object
 */
static void *get_corba_service(epp_context *epp_ctx, char *name);

/**
 * SSL variable lookup function pointer used for client's PEM encoded
 * certificate retrieval.
 */
static APR_OPTIONAL_FN_TYPE(ssl_var_lookup) *epp_ssl_lookup = NULL;

/**
 * Configuration structure of eppd module.
 */
typedef struct {
	int	epp_enabled;/**< Decides whether mod_eppd is enabled for host.*/
	char	*servername;/**< Epp server name used in <greeting> frame. */
	char	*ns_loc;    /**< Location of CORBA nameservice. */
	char	*object;    	   /**< Name under which the object is known. */
	char	*logger_object;    /**< Name of fred-logd object */
	void	*schema;    /**< URL of EPP schema (use just path). */
	int	valid_resp; /**< Validate response before sending it to client.*/
	char	*epplog;    /**< Epp log filename. */
	apr_file_t	*epplogfp; /**< File descriptor of epp log file. */
	epp_loglevel	loglevel;  /**< Epp log level. */
	int	defer_err;  /**< Time value for deferring error response. */
}eppd_server_conf;

/** Used for access serialization to epp log file. */
static apr_global_mutex_t *epp_log_lock;

#if AP_SERVER_MINORVERSION_NUMBER == 0
/**
 * ap_log_cerror is defined only if apache version is 2.0 because 2.0
 * contrary to 2.2 does not have this function.
 */
#define ap_log_cerror(mark, level, status, c, ...) \
	ap_log_error(mark, level, status, (c)->base_server, __VA_ARGS__)
#endif

/**
 * Wrapper around apache's apr_palloc() which allocates memory from
 * a pool.
 *
 * This function is exported in header file to be used
 * by other modules which are not aware of apache pools.
 *
 * @param pool Apache pool pointer.
 * @param size Size of chunk to allocate.
 * @return     Allocated chunk.
 */
void *epp_malloc(void *pool, unsigned size)
{
	apr_pool_t	*p = (apr_pool_t *) pool;

	return apr_palloc(p, size);
}

/**
 * Wrapper around apache's apr_pcalloc() which allocates memory from
 * a pool.
 *
 * This function is exported in header file to be used
 * by other modules which are not aware of apache pools.
 *
 * @param pool Apache pool pointer.
 * @param size Size of chunk to allocate.
 * @return     Allocated chunk.
 */
void *epp_calloc(void *pool, unsigned size)
{
	apr_pool_t	*p = (apr_pool_t *) pool;

	return apr_pcalloc(p, size);
}

/**
 * Wrapper around apache's apr_strdup() which allocates memory from
 * a pool.
 *
 * This function is exported in header file to be used
 * by other modules which are not aware of apache pools.
 *
 * @param pool Apache pool pointer.
 * @param str  String which is going to be duplicated.
 * @return     Duplicated string.
 */
char *epp_strdup(void *pool, const char *str)
{
	apr_pool_t	*p = (apr_pool_t *) pool;

	return apr_pstrdup(p, str);
}

/**
 * Wrapper around apache's apr_pstrcat() which concatenates strings.
 *
 * This function is exported in header file to be used
 * by other modules which are not aware of apache pools.
 *
 * @param pool Apache pool pointer.
 * @param str1 First concatenated string.
 * @param str2 Second concatenated string.
 * @return     Duplicated string.
 */
char *epp_strcat(void *pool, const char *str1, const char *str2)
{
	apr_pool_t	*p = (apr_pool_t *) pool;

	return apr_pstrcat(p, str1, str2, NULL);
}

/**
 * Wrapper around apache's apr_pvsprintf() which prints formated string.
 *
 * This function is exported in header file to be used
 * by other modules which are not aware of apache pools.
 *
 * @param pool Apache pool pointer.
 * @param fmt  Format of string.
 * @return     Formatted string allocated from pool.
 */
char *epp_sprintf(void *pool, const char *fmt, ...)
{
	va_list	 ap;
	char	*str;
	apr_pool_t	*p = (apr_pool_t *) pool;

	va_start(ap, fmt);
	str = apr_pvsprintf(p, fmt, ap);
	va_end(ap);

	return str;
}

/**
 * Get well formatted time used in log file as a timestamp.
 *
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

void epplog(epp_context *epp_ctx, epp_loglevel level, const char *fmt, ...)
{
	char	*logline;     /* the actual text written to log file */
	char	*text;        /* log message as passed from client */
	char	 timestr[80]; /* buffer for timestamp */
	int	 i, session;
	va_list	 ap;
	conn_rec	*conn;   /* apache connection struct pointer*/
	apr_pool_t	*pool;   /* apache pool struct pointer */
	const char	*rhost;  /* ip address of remote host */
	apr_size_t	 nbytes; /* length of logline */
	apr_status_t	 rv;
	eppd_server_conf *sc;

	/* copy items from context struct to individual variables */
	conn = epp_ctx->conn;
	pool = epp_ctx->pool;
	session = epp_ctx->session;
	/* get module config */
	sc = (eppd_server_conf *) ap_get_module_config(
			conn->base_server->module_config, &eppd_module);

	/* cancel out messages with lower priority than configured loglevel */
	if (level > sc->loglevel) return;

	va_start(ap, fmt);
	text = apr_pvsprintf(pool, fmt, ap);
	va_end(ap);

	/* substitute newlines in text */
	for (i = 0; text[i] != '\0'; i++) {
		if (text[i] == '\n') text[i] = ' ';
	}

	/* if epp log file is not configured, log msg to apache's error log */
	if (!sc->epplogfp) {
		int ap_level; /* apache log level equivalent to epp loglevel */

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
		ap_log_cerror(APLOG_MARK, ap_level, 0, conn, text);
		return;
	}

	/* get remote host's ip address - is not critical if it is not known */
	rhost = ap_get_remote_host(conn, NULL, REMOTE_NOLOOKUP, NULL);
	/* get timestamp */
	current_logtime(timestr, 79);
	/* make up the whole log record */
	logline = apr_psprintf(pool, "%s %s [sessionID %d] %s" APR_EOL_STR,
			timestr,
			rhost ? rhost : "UNKNOWN-HOST",
			session,
			text);

	/* serialize access to log file */
	rv = apr_global_mutex_lock(epp_log_lock);
	if (rv != APR_SUCCESS) {
		ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, conn,
			"apr_global_mutex_lock(epp_log_lock) failed");
	}

	nbytes = strlen(logline);
	apr_file_write(sc->epplogfp, logline, &nbytes);

	rv = apr_global_mutex_unlock(epp_log_lock);
	if (rv != APR_SUCCESS) {
		ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, conn,
			"apr_global_mutex_unlock(epp_log_lock) failed");
	}

	return;
}

/**
 * Cleanup routine, is merely wrapper around epp_parser_request_cleanup().
 *
 * @param cdata   Structure containing data to be freed.
 * @return        Always success.
 */
static apr_status_t epp_cleanup_request(void *cdata)
{
	epp_parser_request_cleanup(cdata);
	return APR_SUCCESS;
}

/**
 * Read epp request.
 *
 * Epp request consists of header, which contains frame length including
 * the header itself (4 bytes) and the actual request which is xml document.
 *
 * @param epp_ctx   EPP context struct.
 * @param content   The read request without header.
 * @param bytes     Length of request (excluding header length).
 * @return          0 if successful, 1 if EOF was red and 2 when error occured.
 */
static int
epp_read_request(epp_context *epp_ctx, char **content, unsigned *bytes)
{
	char	*buf;	/* buffer for request */
	uint32_t	 hbo_size; /* size of request in host byte order */
	uint32_t	 nbo_size; /* size of request in network byte order */
	apr_status_t	 status;
	apr_size_t	 len;
	apr_bucket_brigade *bb;
	conn_rec	*conn = epp_ctx->conn;
	apr_pool_t	*pool = epp_ctx->pool;
	char buff[120];

	bb = apr_brigade_create(pool, conn->bucket_alloc);

	/* blocking read of first 4 bytes (request's length) */
	status = ap_get_brigade(conn->input_filters, bb, AP_MODE_READBYTES,
			APR_BLOCK_READ, EPP_HEADER_LENGTH);
	if (status != APR_SUCCESS) {
		/*
		 * this used to be logged at EPP_FATAL level, but later was
		 * changed to lower priority, because condition above catches
		 * also cases, when client simply aborts the connection without
		 * logging out first, which happens pretty often and is not
		 * "fatal" at all.
		 */
		if (status == APR_EOF) {
			epplog(epp_ctx, EPP_INFO, "Client disconnected without "
					"proper logout.");
			return 1;
		}
		epplog(epp_ctx, EPP_ERROR, "Error when reading epp header "
				"(%d - %s)", status,
				apr_strerror(status, buff, sizeof(buff)));
		return 2;
	}

	/*
	 * convert bucket brigade into sequence of bytes
	 * In most cases there is just one bucket of size 4, which
	 * could be read directly. But we will not rely on it.
	 */
	len = EPP_HEADER_LENGTH;
	status = apr_brigade_pflatten(bb, &buf, &len, pool);
	if (status != APR_SUCCESS) {
		epplog(epp_ctx, EPP_FATAL, "Could not flatten apr_brigade!");
		apr_brigade_destroy(bb);
		return 2;
	}
	if (len != EPP_HEADER_LENGTH) {
		/* this should not ever happen */
		epplog(epp_ctx, EPP_ERROR, "4 bytes of EPP header were read "
				"but after flatting of bucket brigade only %u "
				"bytes remained?!", (unsigned int) len);
		apr_brigade_destroy(bb);
		return 2;
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
		epplog(epp_ctx, EPP_ERROR, "Invalid epp frame length (%u bytes)",
				hbo_size);
		apr_brigade_destroy(bb);
		return 2;
	}

	/* we will reuse bucket brigade when reading the request */
	status = apr_brigade_cleanup(bb);
	if (status != APR_SUCCESS) {
		epplog(epp_ctx, EPP_FATAL, "Could not cleanup brigade!");
		apr_brigade_destroy(bb);
		return 2;
	}

	/* blocking read of request's body */
	len = hbo_size;
	status = ap_get_brigade(conn->input_filters, bb, AP_MODE_READBYTES,
			APR_BLOCK_READ, len);
	if (status != APR_SUCCESS) {
		epplog(epp_ctx, EPP_ERROR, "Error when reading epp request's "
				"body (%d)", status);
		apr_brigade_destroy(bb);
		return 2;
	}

	/* convert bucket brigade to string */
	/* Don't use apr_brigade_flatten otherwise mysterious segfault occurs */
	status = apr_brigade_pflatten(bb, content, &len, pool);
	if (status != APR_SUCCESS) {
		epplog(epp_ctx, EPP_FATAL, "Could not flatten apr_brigade!");
		apr_brigade_destroy(bb);
		return 2;
	}
	if (len != hbo_size) {
		epplog(epp_ctx, EPP_ERROR, "EPP request's length (%u bytes) is "
				"other than the claimed one in header "
				"(%u bytes)", (unsigned) len, hbo_size);
		apr_brigade_destroy(bb);
		return 2;
	}
	/* NULL terminate the request - needed for request logging */
	{
		char	*newcontent;

		newcontent = apr_palloc(pool, len + 1);
		if (newcontent == NULL) {
			epplog(epp_ctx, EPP_FATAL, "Could not allocate space "
					"for request.");
			apr_brigade_destroy(bb);
			return 2;
		}
		memcpy(newcontent, *content, len);
		newcontent[len] = '\0';
		*content = newcontent;
	}

	epplog(epp_ctx, EPP_DEBUG, "request received (length %u bytes)",
			hbo_size);
	epplog(epp_ctx, EPP_DEBUG, "request content: %s", *content);

	apr_brigade_destroy(bb);
	*bytes = (unsigned) len;
	return 0;
}

/**
 * Get md5 signature of given PEM encoded certificate.
 *
 * The only function in module which uses openssl library.
 *
 * @param cert_md5   Allocated buffer for storing the resulting fingerprint
 *                   (should be at least 50 bytes long).
 * @param pem        PEM encoded certificate in its string representation.
 * @return           1 if successful and 0 when error occured.
 */
static int get_md5(char *cert_md5, char *pem)
{
	X509	*x;   /* openssl's struture for representing x509 certificate */
	BIO	*bio; /* openssl's basic input/output stream */
	int	 i;
	unsigned int	len;	 /* length of fingerprint in binary form */
	unsigned char	md5[20]; /* fingerprint in binary form */

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
	/* convert binary representation to string repr of fingerprint */
	for (i = 0; i < len; i++) {
		snprintf(cert_md5, 4, "%02X%c", md5[i], (i + 1 == len) ? '\0' : ':');
		cert_md5 += 3;
	}

	BIO_free_all(bio);
	X509_free(x);
	return 1;
}

/**
 * Function calls login over corba and before it computes fingerprint
 * of client's SSL certificate.
 *
 * @param epp_ctx   EPP context.
 * @param service   CORBA object reference.
 * @param cdata     EPP data.
 * @param loginid   Login id assigned by fred_rifd.
 * @param lang      Language selected by client.
 * @param cstat     Corba status.
 * @return          0 in case of internal error, 1 if ok.
 */
static int call_login(epp_context *epp_ctx, service_EPP *service,
		epp_command_data *cdata, unsigned int *loginid,
		epp_lang *lang, corba_status *cstat)
{
	char	 cert_md5[80];/* should be enough for md5 hash of cert */
	char	*pem;         /* pem encoded client's certificate */
	conn_rec	*conn;/* apache connection */
	apr_pool_t	*pool;/* memory pool */

	conn = epp_ctx->conn;
	pool = epp_ctx->pool;
	/* we will compute fingerprint of client's certificate */
	bzero(cert_md5, 80);
	pem = epp_ssl_lookup(pool, conn->base_server, conn, NULL,
			"SSL_CLIENT_CERT");
	if ((pem == NULL) || (*pem == '\0') || !get_md5(cert_md5, pem))
	{
		epplog(epp_ctx, EPP_ERROR, "Error when getting client's "
				"PEM certificate. Did you forget "
				"\"SSLVerifyClient require\" directive "
				"in apache conf file?");
		return 0;
	}

	epplog(epp_ctx, EPP_DEBUG, "Fingerprint is: %s", cert_md5);

	/*
	 * corba login function is somewhat special
	 *   - session might be changed
	 *   - lang might be changed
	 *   - there is additional parameter identifing ssl certificate
	 *     in order to match login name with used certificate on
	 *     side of central repository. The identifing parameter
	 *     is md5 digest of client's certificate.
	 */
	*cstat = epp_call_login(epp_ctx, service, loginid, lang, cert_md5,
			cdata);
	return 1;
}

/**
 * Function calls command from corba backend.
 *
 * @param epp_ctx   EPP context.
 * @param service   CORBA object reference.
 * @param cdata     EPP data.
 * @param pstat     Parser return status.
 * @param loginid   Login id assigned by fred_rifd.
 * @param lang      Language selected by client.
 * @return          0 in case of internal error, 1 if ok.
 */
static int call_corba(epp_context *epp_ctx, service_EPP *service,
		epp_command_data *cdata, parser_status pstat,
		unsigned int *loginid, epp_lang *lang)
{
	corba_status	cstat; /* ret code of corba component */

	if (pstat == PARSER_CMD_LOGIN) {
		if (!call_login(epp_ctx, service, cdata, loginid, lang, &cstat))
			return 0;
	}
	else if (pstat == PARSER_CMD_LOGOUT) {
		cstat = epp_call_logout(epp_ctx, service, loginid, cdata);
		epplog(epp_ctx, EPP_DEBUG, "login id after logout command is %d", *loginid);
	}
	else {
		/* go ahead to generic corba function call */
		cstat = epp_call_cmd(epp_ctx, service, *loginid, cdata);
	}

	/* catch corba failures */
	if (cstat == CORBA_INT_ERROR) {
		epplog(epp_ctx, EPP_FATAL, "Malloc in corba wrapper failed");
		return 0;
	}

	switch (cstat) {
		case CORBA_ERROR:
			epplog(epp_ctx, EPP_ERROR, "Corba call failed");
			break;
		case CORBA_REMOTE_ERROR:
			epplog(epp_ctx, EPP_ERROR, "Unqualified answer "
				"from CORBA server!");
			break;
		case CORBA_OK:
		default:
			break;
	}

	return 1;
}

/**
 * Function generates XML response.
 *
 * @param epp_ctx   EPP context.
 * @param service   CORBA object reference.
 * @param cdata     Command data.
 * @param validate  Validate responses.
 * @param schema    Parsed XML schema.
 * @param lang      Language of session.
 * @param response  On return holds response if ret code is 1.
 * @return          0 in case of internal error, 1 if ok.
 */
static int gen_response(epp_context *epp_ctx, service_EPP *service,
		epp_command_data *cdata, int validate, void *schema,
		epp_lang lang, char **response)
{

	qhead	 valerr; /* encountered errors when validating response */
	gen_status	gstat; /* generator's return code */

	valerr.body = NULL;
	valerr.count = 0;

	/* generate xml response */
	gstat = epp_gen_response(epp_ctx, validate, schema, lang, cdata,
			response, &valerr);

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
			epplog(epp_ctx, EPP_FATAL, "XML generator failed - "
					"terminating session");
			return 0;
		/*
		 * following errors are only informative though serious.
		 * The connection persists and response is sent back to
		 * client.
		 */
		case GEN_NOT_XML:
			epplog(epp_ctx, EPP_ERROR,
					"Generated response is not XML");
			break;
		case GEN_EINTERNAL:
			epplog(epp_ctx, EPP_ERROR, "Malloc failure when "
					"validating response");
			break;
		case GEN_ESCHEMA:
			epplog(epp_ctx, EPP_ERROR, "Error when parsing XML "
					"schema during response validation");
			break;
		case GEN_NOT_VALID:
			epplog(epp_ctx, EPP_ERROR,
					"Generated response does not validate");
			/* print more information about validation errors */
			q_foreach(&valerr) {
				epp_error *e = q_content(&valerr);

				epplog(epp_ctx, EPP_ERROR, "Element: %s",
						e->value);
				epplog(epp_ctx, EPP_ERROR, "Reason: %s",
						e->reason);
			}
			break;
		default:
			epplog(epp_ctx, EPP_ERROR, "Unknown return code from "
					"generator module");
			break;
	}
	/* XXX ugly hack */
	if (strcmp(cdata->svTRID, "DUMMY-SVTRID"))
		epp_call_save_output_xml(epp_ctx, service, cdata, *response);
	return 1;
}

/**
 * Add qhead with ds records to properties
 *
 * @param c_props	log entry properties or a NULL pointer (in which
 * 					case a new data structure is allocated and returned)
 * @param list		list of ds records
 * @param list_name	base name for the inserted properties
 *
 * @returns 		log entry properties or NULL in case of an allocation error
 *
 */
ccReg_LogProperties *epp_property_push_ds(ccReg_LogProperties *c_props, qhead *list, char *list_name)
{
#define NUM_BEGIN 1
	int  i;						/* index of a record */
	char str[LOG_PROP_NAME_LENGTH]; /* property name */

	epp_ds *value;				/* ds record data structure */
	ccReg_LogProperties *ret;	/* return value in case the list is not empty	*/

	i = NUM_BEGIN;
	q_foreach(list) {
		value = (epp_ds*)q_content(list);

		str[0] = '\0';
		snprintf(str, LOG_PROP_NAME_LENGTH, "%s%i.%s", list_name, i, "keytag");
		if ((ret = epp_property_push_int(c_props, str, value->keytag)) == NULL) {
			return NULL;
		}

		str[0] = '\0';
		snprintf(str, LOG_PROP_NAME_LENGTH, "%s%i.%s", list_name, i, "alg");
		if ((ret = epp_property_push_int(c_props, str, value->alg)) == NULL) {
			return NULL;
		}

		str[0] = '\0';
		snprintf(str, LOG_PROP_NAME_LENGTH, "%s%i.%s", list_name, i, "digestType");
		if ((ret = epp_property_push_int(c_props, str, value->digestType)) == NULL) {
			return NULL;
		}

		str[0] = '\0';
		snprintf(str, LOG_PROP_NAME_LENGTH, "%s%i.%s", list_name, i, "digest");
		if ((ret = epp_property_push(c_props, str, value->digest)) == NULL) {
			return NULL;
		}

		str[0] = '\0';
		snprintf(str, LOG_PROP_NAME_LENGTH, "%s%i.%s", list_name, i, "maxSigLife");
		if ((ret = epp_property_push_int(c_props, str, value->maxSigLife)) == NULL) {
			return NULL;
		}

		i++;
	}

	if(i == NUM_BEGIN) {
		return c_props;
	} else {
		return ret;
	}
#undef NUM_BEGIN
}

/**
 * Add qhead with ns records to properties
 *
 * @param c_props	log entry properties or a NULL pointer (in which
 * 					case a new data structure is allocated and returned)
 * @param list		list of ns records
 * @param list_name	base name for the inserted properties
 *
 * @returns 		log entry properties or NULL in case of an allocation error
 *
 */
ccReg_LogProperties *epp_property_push_nsset(ccReg_LogProperties *c_props, qhead *list, char *list_name)
{
#define NUM_BEGIN 1
	int  i;						/* index of a record */
	char str[LOG_PROP_NAME_LENGTH]; /* property name */

	epp_ns *value;				/* ds record data structure */
	ccReg_LogProperties *ret;	/* return value in case the list is not empty	*/

	i = NUM_BEGIN;
	q_foreach(list) {
		value = (epp_ds*)q_content(list);

		str[0] = '\0';
		snprintf(str, LOG_PROP_NAME_LENGTH, "%s%i.%s", list_name, i, "name");
		if ((ret = epp_property_push(c_props, str, value->name)) == NULL) {
			return NULL;
		}

		str[0] = '\0';
		snprintf(str, LOG_PROP_NAME_LENGTH, "%s%i.%s", list_name, i, "addr");
		if ((ret = epp_property_push_qhead(c_props, &value->addr, str)) == NULL) {
			return NULL;
		}

		i++;
	}

	if(i == NUM_BEGIN) {
		return c_props;
	} else {
		return ret;
	}
#undef NUM_BEGIN
}

/**
 * Add dnskey list to log item properties
 *
 * @param c_props	log entry properties or a NULL pointer (in which
 * 					case a new data structure is allocated and returned)
 * @param list		list of dnskey records
 * @param list_name	base name for the inserted properties
 *
 * @returns 		log entry properties or NULL in case of an allocation error
 *
 */
ccReg_LogProperties *epp_property_push_dnskey(ccReg_LogProperties *c_props, qhead *list, char *list_name)
{
#define NUM_BEGIN 1
	int  i;
	char str[LOG_PROP_NAME_LENGTH];
	epp_dnskey *value;
	ccReg_LogProperties *ret;

	i = NUM_BEGIN;
	q_foreach(list) {
		value = (epp_dnskey*)q_content(list);

		str[0] = '\0';
		snprintf(str, LOG_PROP_NAME_LENGTH, "%s%i.%s", list_name, i, "flags");
		if ((ret = epp_property_push_int(c_props, str, value->flags)) == NULL) {
			return NULL;
		}

		str[0] = '\0';
		snprintf(str, LOG_PROP_NAME_LENGTH, "%s%i.%s", list_name, i, "protocol");
		if ((ret = epp_property_push_int(c_props, str, value->protocol)) == NULL) {
			return NULL;
		}

		str[0] = '\0';
		snprintf(str, LOG_PROP_NAME_LENGTH, "%s%i.%s", list_name, i, "alg");
		if ((ret = epp_property_push_int(c_props, str, value->alg)) == NULL) {
			return NULL;
		}

		str[0] = '\0';
		snprintf(str, LOG_PROP_NAME_LENGTH, "%s%i.%s", list_name, i, "public_key");
		if ((ret = epp_property_push(c_props, str, value->public_key)) == NULL) {
			return NULL;
		}

		i++;
	}

	if(i == NUM_BEGIN) {
		return c_props;
	} else {
		return ret;
	}
#undef NUM_BEGIN
}

/**
 * 	Add postal info to log item properties
 *  @param 	p 	log entry properties or a NULL pointer (in which
 * 					case a new data structure is allocated and returned)
 *  @param  pi	postal info
 *
 *  @returns 	log entry properties or NULL in case of an allocation error
 */
ccReg_LogProperties *epp_log_postal_info(ccReg_LogProperties *p, epp_postalInfo *pi)
{
	if(pi == NULL) return p;

	p = epp_property_push(p, "pi.name", pi->name);
	if (p == NULL) return p;
	p = epp_property_push(p, "pi.organization", pi->org);
	if (p == NULL) return p;
	p = epp_property_push_qhead(p, &pi->streets, "pi.street");
	if (p == NULL) return p;
	p = epp_property_push(p, "pi.city", pi->city);
	if (p == NULL) return p;
	p = epp_property_push(p, "pi.state", pi->sp);
	if (p == NULL) return p;
	p = epp_property_push(p, "pi.postal_code", pi->pc);
	if (p == NULL) return p;
	p = epp_property_push(p, "pi.country_code", pi->cc);
	if (p == NULL) return p;

	return p;
}

/**
 * 	Add disclose info to log item properties
 *  @param 	p 	log entry properties or a NULL pointer (in which
 * 					case a new data structure is allocated and returned)
 *  @param  pi	disclose info
 *
 *  @returns 	log entry properties or NULL in case of an allocation error
 */
ccReg_LogProperties *epp_log_disclose_info(ccReg_LogProperties *p, epp_discl *ed)
{
	if(ed->flag == 1) {
		p = epp_property_push(p, "discl.policy", "private");
	} else if(ed->flag == 0) {
		p = epp_property_push(p, "discl.policy", "public");
	} else {
		p = epp_property_push(p, "discl.policy", "no exceptions");
	}

	if (p == NULL) return p;

	p = epp_property_push(p, "discl.name", ed->name ? "true" : "false");
	if (p == NULL) return p;
	p = epp_property_push(p, "discl.org", ed->org ? "true" : "false");
	if (p == NULL) return p;
	p = epp_property_push(p, "discl.addr", ed->addr ? "true" : "false");
	if (p == NULL) return p;
	p = epp_property_push(p, "discl.voice", ed->voice ? "true" : "false");
	if (p == NULL) return p;
	p = epp_property_push(p, "discl.fax", ed->fax ? "true" : "false");
	if (p == NULL) return p;
	p = epp_property_push(p, "discl.email", ed->email ? "true" : "false");
	if (p == NULL) return p;
	p = epp_property_push(p, "discl.vat", ed->vat ? "true" : "false");
	if (p == NULL) return p;
	p = epp_property_push(p, "discl.ident", ed->ident ? "true" : "false");
	if (p == NULL) return p;
	p = epp_property_push(p, "discl.notifyEmail", ed->notifyEmail ? "true" : "false");
	if (p == NULL) return p;

	return p;
}

/**
 * Log an epp command using fred-logd service. Raw content as well as
 * parsed values inserted as properties are sent to the logging facility
 *
 * @param	service 	a reference to the logging service CORBA object
 * @param	c			connection record
 * @param	request		raw content of the request
 * @param 	cdata		command data, parsed content
 * @param   cmdtype 	command type returned by parse_command function
 *
 * @return  status
 */
static apr_status_t log_epp_command(service_Logger *service, conn_rec *c, char *request, epp_command_data *cdata, epp_red_command_type cmdtype)
{
#define PUSH_PROPERTY(seq, name, value)								\
	seq = epp_property_push(seq, name, value);						\
	if(seq == NULL) {												\
		return HTTP_INTERNAL_SERVER_ERROR;							\
	}

#define PUSH_PROPERTY_INT(seq, name, value)							\
	seq = epp_property_push_int(seq, name, value);					\
	if(seq == NULL) {												\
		return HTTP_INTERNAL_SERVER_ERROR;							\
	}

#define PUSH_QHEAD(seq, list, name)									\
	seq = epp_property_push_qhead(seq, list, name);			 		\
	if(seq == NULL) {												\
		return HTTP_INTERNAL_SERVER_ERROR;							\
	}

	char *cmd_name = NULL;					/* command name to be used
												one of the basic properties */
	char errmsg[MAX_ERROR_MSG_LEN];			/* error message returned from corba call */
	ccReg_LogProperties *c_props = NULL;	/* properties to be sent to the log */
	/* data structures for every command */
	epps_create_contact *cc;
	epps_create_domain *cd;
	epps_create_nsset *cn;
	epps_create_keyset *ck;
	epps_delete *ed;
	epps_renew *er;
	epps_update_contact *uc;
	epps_update_domain *ud;
	epps_update_nsset *un;
	epps_update_keyset *uk;
	epps_transfer *et;
	epps_login *el;
	epps_check *ec;

	errmsg[0] = '\0';
	if(cdata->type == EPP_DUMMY) {
		PUSH_PROPERTY (c_props, "command", "dummy");
		PUSH_PROPERTY (c_props, "clTRID", cdata->clTRID);
		PUSH_PROPERTY (c_props, "svTRID", cdata->svTRID);
		PUSH_PROPERTY_INT (c_props, "rc", cdata->rc);
		PUSH_PROPERTY (c_props, "msg", cdata->msg);

		epp_log_message(service, c->remote_ip, ccReg_LT_REQUEST, request, c_props, &errmsg);

		return;
	}

	switch(cmdtype) {
		case EPP_RED_LOGIN:
			if (cdata->type == EPP_LOGIN){
				cmd_name = "login";

				el = cdata->data;

				PUSH_PROPERTY(c_props, "client_id", el->clID);
				// type epp_lang:
				if (el->lang == LANG_CS) {
					PUSH_PROPERTY(c_props, "lang", "CZ");
				} else if (el->lang == LANG_EN) {
					PUSH_PROPERTY(c_props, "lang", "EN");
				} else {
					PUSH_PROPERTY_INT(c_props, "lang", el->lang);
				}
				PUSH_PROPERTY(c_props, "password", el->pw);
				PUSH_PROPERTY(c_props, "new password", el->newPW);
			} else {
				return HTTP_OK;
			}
			break;

		case EPP_RED_LOGOUT:
			cmd_name = "logout";
			break;

		case EPP_RED_CHECK:
			cmd_name = "check";
			ec = cdata->data;
			PUSH_QHEAD(c_props, &ec->ids, "check_id");
			break;

		case EPP_RED_INFO:
			cmd_name = "info";

	/*		----------------------
#define _QUOTE_STR(s) #s

#define INFO_CMD_CASE(lower, upper, field)									\
			case EPP_INFO_##upper:											\
			{ 																\
				epps_info_##lower *i = cdata->data;							\
				PUSH_PROPERTY(c_props, _QUOTE_STR(field), i->field);		\
				cmd_name = _QUOTE_STR(info_ ## lower);						\
				break;														\
			}

#define LIST_CMD_CASE(lower, upper)						\
			case EPP_LIST_##upper:						\
				cmd_name = _QUOTE_STR(list_ ## lower);	\
				break;

			switch(cdata->type) {
				LIST_CMD_CASE(contact, CONTACT);
				LIST_CMD_CASE(keyset, KEYSET);
				LIST_CMD_CASE(nsset, NSSET);
				LIST_CMD_CASE(domain, DOMAIN);
				INFO_CMD_CASE(contact, CONTACT, id);
				INFO_CMD_CASE(keyset, KEYSET,   id);
				INFO_CMD_CASE(nsset, NSSET,     id);
				INFO_CMD_CASE(domain, DOMAIN,   name);
			}
*/

			switch(cdata->type) {
				case EPP_LIST_CONTACT:
					cmd_name = "list_contact";
					break;
				case EPP_LIST_KEYSET:
					cmd_name = "list_keyset";
					break;
				case EPP_LIST_NSSET:
					cmd_name = "list_nsset";
					break;
				case EPP_LIST_DOMAIN:
					cmd_name = "list_domain";
					break;

				case EPP_INFO_CONTACT: {
					epps_info_contact *i = cdata->data;
					c_props = epp_property_push(c_props, "id", i->id);
					if (c_props == NULL) {
						return HTTP_INTERNAL_SERVER_ERROR;
					}
					cmd_name = "info_contact";
					break;
				}
				case EPP_INFO_KEYSET: {
					epps_info_keyset *i = cdata->data;
					c_props = epp_property_push(c_props, "id", i->id);
					if (c_props == NULL) {
						return HTTP_INTERNAL_SERVER_ERROR;
					}
					cmd_name = "info_keyset";
					break;
				}
				case EPP_INFO_NSSET: {
					epps_info_nsset *i = cdata->data;
					c_props = epp_property_push(c_props, "id", i->id);
					if (c_props == NULL) {
						return HTTP_INTERNAL_SERVER_ERROR;
					}
					cmd_name = "info_nsset";
					break;
				}
				case EPP_INFO_DOMAIN: {
					epps_info_domain *i = cdata->data;
					c_props = epp_property_push(c_props, "name", i->name);
					if (c_props == NULL) {
						return HTTP_INTERNAL_SERVER_ERROR;
					}
					cmd_name = "info_domain";
					break;
				}
			}
			break;

		case EPP_RED_POLL:
			cmd_name = "poll";
			if(cdata->type == EPP_POLL_ACK) {
				epps_poll_ack *pa = cdata->data;
				PUSH_PROPERTY(c_props, "msgID", pa->msgid);
			}
			break;

		case EPP_RED_CREATE:
			switch(cdata->type) {
				case EPP_CREATE_CONTACT:
					cmd_name = "create contact";
					cc = cdata->data;

					PUSH_PROPERTY(c_props, "id", cc->id);

					// postal info
					if ((c_props = epp_log_postal_info(c_props, &cc->pi)) == NULL) {
						return HTTP_INTERNAL_SERVER_ERROR;
					}

					PUSH_PROPERTY(c_props, "voice", cc->voice);
					PUSH_PROPERTY(c_props, "fax", cc->fax);
					PUSH_PROPERTY(c_props, "email", cc->email);
					PUSH_PROPERTY(c_props, "authInfo", cc->authInfo);

					// disclose info
					if ((c_props = epp_log_disclose_info(c_props, &cc->discl)) == NULL) {
						return HTTP_INTERNAL_SERVER_ERROR;
					}

					PUSH_PROPERTY(c_props, "vat", cc->vat);
					PUSH_PROPERTY(c_props, "ident", cc->ident);
					switch(cc->identtype) {
						case ident_UNKNOWN: PUSH_PROPERTY(c_props, "identtype", "unknown"); break;
						case ident_OP:      PUSH_PROPERTY(c_props, "identtype", "ID card"); break;
						case ident_PASSPORT: PUSH_PROPERTY(c_props, "identtype", "passport"); break;
						case ident_MPSV:    PUSH_PROPERTY(c_props, "identtype", "number assinged by ministry"); break;
						case ident_ICO:     PUSH_PROPERTY(c_props, "identtype", "ICO"); break;
						case ident_BIRTHDAY: PUSH_PROPERTY(c_props, "identtype", "birthdate"); break;
					}
					PUSH_PROPERTY(c_props, "notify_email", cc->notify_email);
						// COMMON

					PUSH_PROPERTY(c_props, "creation_date", cc->crDate);
					break;

				case EPP_CREATE_DOMAIN:
					cmd_name = "create domain";
					cd = cdata->data;

					PUSH_PROPERTY(c_props, "name", cd->name);
					PUSH_PROPERTY(c_props, "registrant", cd->registrant);
					PUSH_PROPERTY(c_props, "nsset", cd->nsset);
					PUSH_PROPERTY(c_props, "keyset", cd->keyset);
					// qhead	 extensions;   /**< List of domain extensions.
					PUSH_PROPERTY(c_props, "authInfo", cd->authInfo);
					// COMMON

					PUSH_QHEAD(c_props, &cd->admin, "admin");
					PUSH_PROPERTY_INT(c_props, "period", cd->period);
					if (cd->unit == TIMEUNIT_MONTH) {
						PUSH_PROPERTY(c_props, "timeunit", "Month");
					} else if(cd->unit == TIMEUNIT_YEAR) {
						PUSH_PROPERTY(c_props, "timeunit", "Year");
					}
					PUSH_PROPERTY(c_props, "creation_date", cd->crDate);
					PUSH_PROPERTY(c_props, "expiration_date", cd->exDate);
					break;

				case EPP_CREATE_NSSET:
					cmd_name = "create nsset";
					cn = cdata->data;

					PUSH_PROPERTY(c_props, "id", cn->id);
					PUSH_PROPERTY(c_props, "authInfo", cn->authInfo);
					PUSH_PROPERTY_INT(c_props, "report_level", cn->level);
									// COMMON
					if((c_props = epp_property_push_nsset(c_props, &cn->ns, "ns")) == NULL) {
						return HTTP_INTERNAL_SERVER_ERROR;
					}
					PUSH_QHEAD(c_props, &cn->tech, "tech_c");

					PUSH_PROPERTY(c_props, "creation_date", cn->crDate);

					break;
				case EPP_CREATE_KEYSET:
					cmd_name = "create keyset";
					ck = cdata->data;

					PUSH_PROPERTY(c_props, "id", ck->id);
					PUSH_PROPERTY(c_props, "authInfo", ck->authInfo);
					// COMMON

					PUSH_PROPERTY(c_props, "creation_date", ck->crDate);

					if((c_props=epp_property_push_ds(c_props, &ck->ds, "ds")) == NULL) {
						return HTTP_INTERNAL_SERVER_ERROR;
					}
					if((c_props=epp_property_push_dnskey(c_props, &ck->keys, "keys")) == NULL) {
						return HTTP_INTERNAL_SERVER_ERROR;
					}

					PUSH_QHEAD(c_props, &ck->tech, "tech_contact");
					break;
				default:
					break;
			}

			break;
		case EPP_RED_DELETE:
			cmd_name = "delete";
			ed = cdata->data;

			PUSH_PROPERTY(c_props, "id", ed->id);
			break;

		case EPP_RED_RENEW:
			cmd_name = "renew";
			er = cdata->data;

			PUSH_PROPERTY(c_props, "name", er->name);
			PUSH_PROPERTY(c_props, "cur_exdate", er->curExDate);
			PUSH_PROPERTY_INT(c_props, "renew_period", er->period);
			if (er->unit == TIMEUNIT_MONTH) {
				PUSH_PROPERTY(c_props, "timeunit", "Month");
			} else if(cd->unit == TIMEUNIT_YEAR) {
				PUSH_PROPERTY(c_props, "timeunit", "Year");
			}
			PUSH_PROPERTY(c_props, "expiration_date", er->exDate);
			break;

		case EPP_RED_UPDATE:

			switch(cdata->type) {
				case EPP_UPDATE_CONTACT:
					cmd_name = "update contact";

					uc = cdata->data;

					PUSH_PROPERTY(c_props, "id", uc->id);

					if ( (c_props=epp_log_postal_info(c_props, uc->pi)) == NULL) {
						return HTTP_INTERNAL_SERVER_ERROR;
					}

					PUSH_PROPERTY(c_props, "voice", uc->voice);
					PUSH_PROPERTY(c_props, "fax", uc->fax);
					PUSH_PROPERTY(c_props, "email", uc->email);
					PUSH_PROPERTY(c_props, "authInfo", uc->authInfo);

					if ( (c_props=epp_log_disclose_info(c_props, &uc->discl)) == NULL) {
						return HTTP_INTERNAL_SERVER_ERROR;
					}

					PUSH_PROPERTY(c_props, "vat", uc->vat);
					PUSH_PROPERTY(c_props, "ident", uc->ident);

					switch(uc->identtype) {
						case ident_UNKNOWN: PUSH_PROPERTY(c_props, "identtype", "unknown"); break;
						case ident_OP:      PUSH_PROPERTY(c_props, "identtype", "ID card"); break;
						case ident_PASSPORT: PUSH_PROPERTY(c_props, "identtype", "passport"); break;
						case ident_MPSV:    PUSH_PROPERTY(c_props, "identtype", "number assinged by ministry"); break;
						case ident_ICO:     PUSH_PROPERTY(c_props, "identtype", "ICO"); break;
						case ident_BIRTHDAY: PUSH_PROPERTY(c_props, "identtype", "birthdate"); break;
					}

					PUSH_PROPERTY(c_props, "notify_email", uc->notify_email);
						// COMMON
					break;

				case EPP_UPDATE_DOMAIN:
					cmd_name = "update domain";

					ud = cdata->data;

					PUSH_PROPERTY(c_props, "name", ud->name);
					PUSH_PROPERTY(c_props, "registrant", ud->registrant);
					PUSH_PROPERTY(c_props, "nsset", ud->nsset);
					PUSH_PROPERTY(c_props, "keyset", ud->keyset);
					// qhead	 extensions;   /**< List of domain extensions.
					PUSH_PROPERTY(c_props, "authInfo", ud->authInfo);
					// COMMONs

					PUSH_QHEAD(c_props, &ud->add_admin, "add_admin");
					PUSH_QHEAD(c_props, &ud->rem_admin, "rem_admin");
					PUSH_QHEAD(c_props, &ud->rem_tmpcontact, "rem_tmpcontact");

					break;

				case EPP_UPDATE_NSSET:
					cmd_name = "update nsset";
					un = cdata->data;

					PUSH_PROPERTY(c_props, "id", un->id);
					PUSH_PROPERTY(c_props, "authInfo", un->authInfo);
					PUSH_PROPERTY_INT(c_props, "report_level", un->level);
					// COMMON

					PUSH_QHEAD(c_props, &un->add_tech, "add_tech_c");
					PUSH_QHEAD(c_props, &un->rem_tech, "rem_tech_c");
					if((c_props = epp_property_push_nsset(c_props, &un->add_ns, "add_ns")) == NULL) {
						return HTTP_INTERNAL_SERVER_ERROR;
					}
					PUSH_QHEAD(c_props, &un->rem_ns, "rem_ns");

					break;

				case EPP_UPDATE_KEYSET:
					cmd_name = "update keyset";
					uk = cdata->data;

					PUSH_PROPERTY(c_props, "id", uk->id);
					PUSH_PROPERTY(c_props, "authInfo", uk->authInfo);
					// COMMON

					PUSH_QHEAD(c_props, &uk->add_tech, "add_tech");
					PUSH_QHEAD(c_props, &uk->rem_tech, "rem_tech");
					if((c_props = epp_property_push_ds(c_props, &uk->add_ds, "add_ds")) == NULL) {
						return HTTP_INTERNAL_SERVER_ERROR;
					}
					if((c_props = epp_property_push_ds(c_props, &uk->rem_ds, "rem_ds")) == NULL) {
						return HTTP_INTERNAL_SERVER_ERROR;
					}

					if((c_props = epp_property_push_dnskey(c_props, &uk->add_dnskey, "add_key")) == NULL) {
						return HTTP_INTERNAL_SERVER_ERROR;
					}
					if((c_props = epp_property_push_dnskey(c_props, &uk->rem_dnskey, "rem_key")) == NULL) {
						return HTTP_INTERNAL_SERVER_ERROR;
					}

					break;
			}
			break;

		case EPP_RED_TRANSFER:
			cmd_name = "transfer";
			et = cdata->data;

			PUSH_PROPERTY(c_props, "id", et->id);
			break;

		default:
			break;
	}

	PUSH_PROPERTY (c_props, "command", cmd_name);
  	PUSH_PROPERTY (c_props, "clTRID", cdata->clTRID);
	PUSH_PROPERTY (c_props, "svTRID", cdata->svTRID);
	PUSH_PROPERTY_INT (c_props, "rc", cdata->rc);
	PUSH_PROPERTY (c_props, "msg", cdata->msg);

	epp_log_message(service, c->remote_ip, ccReg_LT_REQUEST, request, c_props, &errmsg);

#undef _QUOTE_STR
#undef INFO_CMD_CASE
}

/** Read and process EPP requests waiting in the queue */
static int epp_request_loop(epp_context *epp_ctx, apr_bucket_brigade *bb,
		service_EPP *EPPservice, eppd_server_conf *sc,
		unsigned int *loginid_save)
{
	epp_lang	 lang;   /* session's language */
	apr_pool_t	*rpool;  /* connection memory pool */
	parser_status	 pstat;  /* parser's return code */
	apr_status_t	 status; /* used to store rc of apr functions */
	epp_command_data *cdata; /* command data structure */
	epp_red_command_type cmd_type; /* command type determined by the parser */
	unsigned int	 bytes;  /* length of request */
	char	*request;        /* raw request read from socket */
	char	*response;       /* generated XML answer to client */
	int	 retval;         /* return code of read_request */
	unsigned int	 loginid;        /* login id of client's session */
	service_Logger   *logger_service;  /* reference to the fred-logd service */


#ifdef EPP_PERF
	/*
	 * array of timestamps for perf measurement:
	 *     time[0] - before parsing
	 *     time[1] - after parsing and before corba call
	 *     time[2] - after corba call and before response generation
	 *     time[3] - after response generation
	 */
	apr_time_t	times[4];
#endif


	/* initialize variables used inside the loop */
	*loginid_save = loginid = 0; /* zero means that client isn't logged in*/
	lang = LANG_EN;	/* default language is english */

	/*
	 * The loop in which are processed requests until client logs out or
	 * error appears.
	 */
	while (1) {
#ifdef EPP_PERF
		bzero(times, 4 * sizeof(times[0]));
#endif
		/* allocate new pool for request */
		apr_pool_create(&rpool, ((conn_rec *) epp_ctx->conn)->pool);
		apr_pool_tag(rpool, "EPP_request");
		epp_ctx->pool = rpool;
		/* possible previous content is gone with request pool */
		cdata = NULL;

		/* read request */
		retval = epp_read_request(epp_ctx, &request, &bytes);
		if (retval == 1)
			/*
			 * epp_read_request red EOF, this results in OK status
			 * being returned from connection handler, since it's
			 * not counted as an error, if client ends connection
			 * without proper logout.
			 */
			break;
		else if (retval == 2)
			return HTTP_INTERNAL_SERVER_ERROR;
#ifdef EPP_PERF
		times[0] = apr_time_now(); /* before parsing */
#endif
		/*
		 * Deliver request to XML parser, the task of parser is
		 * to fill cdata structure with data.
		 */
		pstat = epp_parse_command(epp_ctx, (loginid != 0), sc->schema,
				request, bytes, &cdata, &cmd_type);

		logger_service = get_corba_service(epp_ctx, sc->logger_object);
		if (logger_service == NULL) {
			epplog(epp_ctx, EPP_ERROR, "Could not obtain object reference "
					"for alias '%s'.", sc->logger_object);
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		log_epp_command(logger_service, epp_ctx->conn, request, cdata, cmd_type);

#ifdef EPP_PERF
		times[1] = apr_time_now(); /* after parsing */
#endif
		/*
		 * Register cleanup for cdata structure. The most of the
		 * items in this structure are allocated from pool, but
		 * parsed document tree and xpath context must be
		 * explicitly released.
		 */
		apr_pool_cleanup_register(rpool, (void *) cdata,
				epp_cleanup_request, apr_pool_cleanup_null);

		/* test if the failure is serious enough to close connection */
		if (pstat > PARSER_HELLO) {
			switch (pstat) {
				case PARSER_NOT_XML:
					epplog(epp_ctx, EPP_WARNING,
						"Request is not XML");
					return HTTP_BAD_REQUEST;
				case PARSER_NOT_COMMAND:
					epplog(epp_ctx, EPP_WARNING,
						"Request is neither a command "
						"nor hello");
					return HTTP_BAD_REQUEST;
				case PARSER_ESCHEMA:
					epplog(epp_ctx, EPP_WARNING,
						"Schema's parser error - check "
						"correctness of schema");
					return HTTP_INTERNAL_SERVER_ERROR;
				case PARSER_EINTERNAL:
					epplog(epp_ctx, EPP_FATAL,
						"Internal parser error occured "
						"when processing request");
					return HTTP_INTERNAL_SERVER_ERROR;
				default:
					epplog(epp_ctx, EPP_FATAL,
						"Unknown error occured "
						"during parsing stage");
					return HTTP_BAD_REQUEST;
			}
		}

		/* hello and other frames are processed in different way */
		if (pstat == PARSER_HELLO) {
			int	 rc;      /* corba ret code */
			char	*version; /* version of fred_rifd */
			char	*curdate; /* cur. date returned from fred_rifd */
			gen_status gstat; /* generator's return code */

			/* get info from CR needed for <greeting> frame */
			rc = epp_call_hello(epp_ctx, EPPservice, &version,
					&curdate);
			if (rc != CORBA_OK) {
				epplog(epp_ctx, EPP_ERROR, "Could not get "
						"greeting data from fred_rifd");
				return HTTP_INTERNAL_SERVER_ERROR;
			}
#ifdef EPP_PERF
			times[2] = apr_time_now();
#endif
			/*
			 * generate greeting (server name is concatenation of
			 * string from apache conf file and string retrieved
			 * from corba server through version() function)
			 */
			gstat = epp_gen_greeting(epp_ctx->pool,
					apr_pstrcat(rpool, sc->servername, " (",
						version, ")", NULL),
					curdate, &response);
			if (gstat != GEN_OK) {
				epplog(epp_ctx, EPP_FATAL, "Error when "
						"creating epp greeting");
				return HTTP_INTERNAL_SERVER_ERROR;
			}
		}
		/* it is a command */
		else {
			/* log request which doesn't validate */
			if (pstat == PARSER_NOT_VALID) {
				epplog(epp_ctx, EPP_WARNING,
						"Request does not validate");
			}

			/*
			 * TODO probably improper spot for logging
			logger_service = get_corba_service(epp_ctx, sc->logger_object);
			if (logger_service == NULL) {
				epplog(epp_ctx, EPP_ERROR, "Could not obtain object reference "
						"for alias '%s'.", sc->logger_object);
				return HTTP_INTERNAL_SERVER_ERROR;
			}

			log_epp_command(logger_service, epp_ctx->conn, request, cdata);
			*/

			/* call function from corba backend */
			if (!call_corba(epp_ctx, EPPservice, cdata, pstat,
						&loginid, &lang))
				return HTTP_INTERNAL_SERVER_ERROR;
			/* did successfull login occured? */
			epplog(epp_ctx, EPP_DEBUG, "after corba call command "
				"saved login id is %d, login id is %d", *loginid_save, loginid);
			if (*loginid_save == 0 && loginid != 0) {
				*loginid_save = loginid;
				/*
				 * this event should be logged explicitly if
				 * login was successfull
				 */
				epplog(epp_ctx, EPP_INFO, "Logged in "
					"successfully, login id is %d",loginid);
			}
#ifdef EPP_PERF
			times[2] = apr_time_now();
#endif
			/* error response will be deferred */
			if (cdata->rc >= 2000) {
				epplog(epp_ctx, EPP_DEBUG, "(epp-cmd %d) response code %d: sleeping for %d ms",
					cdata->type, cdata->rc, sc->defer_err);
				/* sleep time conversion to microsec */
				apr_sleep(sc->defer_err * 1000);
			}
			/* generate response */
			if (!gen_response(epp_ctx, EPPservice, cdata,
						sc->valid_resp, sc->schema,
						lang, &response))
				return HTTP_INTERNAL_SERVER_ERROR;
		}
#ifdef EPP_PERF
		times[3] = apr_time_now();
#endif
		/* send response back to client */
		apr_brigade_puts(bb, NULL, NULL, response);
		epplog(epp_ctx, EPP_DEBUG, "Response content: %s", response);
#ifdef EPP_PERF
		/*
		 * record perf data
		 * Apache 2.0 has problem with processing %llu formating,
		 * therefore we overtype the results to a more common numeric
		 * values.
		 */
		epplog(epp_ctx, EPP_DEBUG, "Perf data: p(%u), c(%u), "
				"g(%u), s(%u)",
				(unsigned) (times[1] - times[0]),/* parser */
				(unsigned) (times[2] - times[1]),/* CORBA */
				(unsigned) (times[3] - times[2]),/* generator */
				(unsigned) (apr_time_now() - times[3]));/*send*/
#endif
		status = ap_fflush(((conn_rec *) epp_ctx->conn)->output_filters,
			       bb);
		if (status != APR_SUCCESS) {
			/* happens on every greeting when client just tests
			 * the port. Not severe. */
			epplog(epp_ctx, EPP_INFO,
					"Error when sending response to client");
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		/* check if successful logout appeared */
		if (pstat == PARSER_CMD_LOGOUT && loginid == 0) {
			*loginid_save = 0;
			break;
		}

		/* prepare bucket brigade for reuse in next request */
		status = apr_brigade_cleanup(bb);
		if (status != APR_SUCCESS) {
			epplog(epp_ctx, EPP_FATAL, "Could not cleanup bucket "
					"brigade used for response");
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		/*
		 * XXX TEMPORARY HACK -disconnect on certain EPP return codes.
		 */
		switch (cdata->rc) {
			case 2500:
			case 2501:
			case 2502:
				return HTTP_OK;
			default:
				break;
		}

		/*XXX
		 * if server is going down non-gracefully we will try to say
		 * good-bye before we will be killed.
		if (ap_graceful_stop_signalled()
		 */

		apr_pool_destroy(rpool);
	}
	return HTTP_OK;
}

/**
 * Get a reference to the CORBA service with the given name
 *
 * @param c   	Connection.
 * @param name  Name of the service.
 */
static void *get_corba_service(epp_context *epp_ctx, char *name)
{
	int 		i;
	apr_hash_t	*references;
	module		*corba_module;
	void		*service;
	conn_rec 	*c = (conn_rec*)epp_ctx->conn;

	/*
	 * get module structure for mod_corba, in order to retrieve service
	 * stored by that module in connection config.
	 */
	corba_module = NULL;
	for (i = 0; ap_loaded_modules[i] != NULL; i++)
		if (!strcmp(ap_loaded_modules[i]->name, "mod_corba.c")) {
			corba_module = ap_loaded_modules[i];
			break;
		}

	if (corba_module == NULL) {
		epplog(epp_ctx, EPP_FATAL,
				"mod_corba module was not loaded - unable to "
				"handle a whois request");
		return NULL;
	}

	references = (apr_hash_t *)
		ap_get_module_config(c->conn_config, corba_module);
	if (references == NULL) {
		epplog(epp_ctx, EPP_FATAL,
			"mod_corba is not enabled for this server though it "
			"should be! Cannot handle whois request.");
		return NULL;
	}

	service = (void *) apr_hash_get(references, name, strlen(name));
	if (service == NULL) {
		epplog(epp_ctx, EPP_ERROR,
			"Could not obtain object reference for alias '%s'. "
			"Check mod_corba's configuration.", name);
		return NULL;
	}

	return service;
}

/**
 * EPP Connection handler.
 *
 * When EPP engine is turn on for connection, this handler takes care
 * of it for whole connection's lifetime duration. The connection is
 * taken out of reach of other handlers, this is important, since
 * EPP protocol and HTTP protocol are quite different and even if you
 * make EPP request as much as possible similar to HTTP request,
 * unexpectable influences from other modules occur.
 *
 * @param c   Incoming connection.
 * @return    Return code
 */
static int epp_process_connection(conn_rec *c)
{
	int	 i;
	unsigned int	 loginid; /* login id of client */
	int	 rc;      /* corba ret code */
	int	 ret;     /* command loop return code */
	char	*version; /* version of fred_rifd */
	char	*curdate; /* cur. date returned from fred_rifd */
	char	*response;/* greeting response */
	apr_status_t	 status;/* used to store rc of apr functions */
	gen_status	 gstat; /* generator's return code */
	epp_context	 epp_ctx;    /* context (session , connection, pool) */
	service_EPP	 EPPservice; /* CORBA object reference */
	apr_hash_t	*references; /* directory of CORBA object references */
	module	*corba_module;
	apr_bucket_brigade *bb;
	server_rec	*s = c->base_server;
	eppd_server_conf *sc = (eppd_server_conf *)
	ap_get_module_config(s->module_config, &eppd_module);

	/* do nothing if eppd is disabled */
	if (!sc->epp_enabled)
		return DECLINED;

	/* Initialize epp context structure (used mainly for logging) */
	epp_ctx.conn = c;
	epp_ctx.pool = c->pool;
	/*
	 * combination of timestamp and connection id should
	 * provide mostly unique identifier
	 */
	epp_ctx.session = (apr_time_now() * (c->id + 1)) % 524288;

	EPPservice = get_corba_service(&epp_ctx, sc->object);
	if (EPPservice == NULL) {
		epplog(&epp_ctx, EPP_ERROR, "Could not obtain object reference "
				"for alias '%s'.", sc->object);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* update scoreboard's information */
	ap_update_child_status(c->sbh, SERVER_BUSY_READ, NULL);

	/* add connection output filter, which constructs EPP header */
	ap_add_output_filter("EPP_OUTPUT_FILTER", NULL, NULL, c);

	/* create bucket brigade for transmition of responses */
	bb = apr_brigade_create(c->pool, c->bucket_alloc);

	epplog(&epp_ctx, EPP_DEBUG, "Client connected");

	/* Send greeting - this is the first message of session automatically
	 * sent by server. */

	/* get info from CR needed for <greeting> frame */
	rc = epp_call_hello(&epp_ctx, EPPservice, &version, &curdate);
	if (rc != CORBA_OK) {
		epplog(&epp_ctx, EPP_ERROR, "Could not get greeting data "
				"from fred_rifd");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	/*
	 * generate greeting (server name is concatenation of string from
	 * apache conf file and string retrieved from corba server through
	 * version() function)
	 */
	gstat = epp_gen_greeting(epp_ctx.pool,
			apr_pstrcat(epp_ctx.pool, sc->servername,
				" (", version, ")", NULL),
			curdate, &response);
	if (gstat != GEN_OK) {
		epplog(&epp_ctx, EPP_FATAL, "Error when creating epp greeting");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	apr_brigade_puts(bb, NULL, NULL, response);
	status = ap_fflush(c->output_filters, bb);
	if (status != APR_SUCCESS) {
		epplog(&epp_ctx, EPP_FATAL,
				"Error when sending response to client");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* prepare bucket brigade for reuse in next request */
	status = apr_brigade_cleanup(bb);
	if (status != APR_SUCCESS) {
		epplog(&epp_ctx, EPP_FATAL, "Could not cleanup bucket "
				"brigade used for response");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	ret = epp_request_loop(&epp_ctx, bb, EPPservice, sc, &loginid);
	/* send notification about session end to CR */
	if (loginid > 0)
		epp_call_end_session(&epp_ctx, EPPservice, loginid);

	epp_ctx.pool = c->pool;

	/* client logged out or disconnected from server */
	epplog(&epp_ctx, EPP_INFO, "Session ended");
	return ret;
}

/**
 * EPP output filter, which prefixes each response with length of the response.
 *
 * @param f    Apache filter structure.
 * @param bb   Bucket brigade containing a response.
 * @return     Return code of next filter in chain.
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
			ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "mod_eppd:"
					" in filter - Bucket with unknown length"
					" ... weird");
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
 *
 * @param p    Memory pool.
 * @param s    Server record.
 */
static void epp_init_child_hook(apr_pool_t *p, server_rec *s)
{
	apr_status_t	rv;

	rv = apr_global_mutex_child_init(&epp_log_lock, NULL, p);
	if (rv != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, "mod_eppd: could "
				"not init epp log lock in child");
	}
}

/**
 * Cleanup routine, is merely wrapper around epp_parser_init_cleanup().
 *
 * @param data   XML schema.
 * @return       Always success.
 */
static apr_status_t epp_cleanup_xml(void *data)
{
	epp_parser_init_cleanup(data);
	return APR_SUCCESS;
}

/**
 * In post config hook is check consistency of configuration (required
 * parameters, default values of parameters), components are initialized,
 * log file is setted up ...
 *
 * @param p     Memory pool.
 * @param plog  Memory pool used for logging.
 * @param ptemp Memory pool destroyed right after postconfig phase.
 * @param s     Server record.
 * @return      Status.
 */
static int epp_postconfig_hook(apr_pool_t *p, apr_pool_t *plog,
		apr_pool_t *ptemp, server_rec *s)
{
	apr_status_t	 	rv = 0;
	eppd_server_conf	*sc;

	/*
	 * during authentication of epp client we need to get value of a
	 * SSL variable. For that we need ssl_var_lookup function.
	 */
	epp_ssl_lookup = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);
	if (epp_ssl_lookup == NULL) {
		ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
				"mod_eppd: could not retrieve ssl_var_lookup "
				"function. Is mod_ssl loaded?");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* create the rewriting lockfiles in the parent */
	if ((rv = apr_global_mutex_create(&epp_log_lock, NULL,
			APR_LOCK_DEFAULT, p)) != APR_SUCCESS)
	{
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
		char	*fname;

		sc = (eppd_server_conf *) ap_get_module_config(s->module_config,
				&eppd_module);

		if (sc->epp_enabled) {
			if (sc->servername == NULL) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
						"EPP Servername not configured");
				return HTTP_INTERNAL_SERVER_ERROR;
			}
			if (sc->schema == NULL) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
						"EPP schema not configured");
				return HTTP_INTERNAL_SERVER_ERROR;
			}
			/* set default values for object lookup data */
			if (sc->object == NULL)
				sc->object = apr_pstrdup(p, "EPP");
			/* set default loglevel */
			if (sc->loglevel == 0) sc->loglevel = EPP_INFO;

			if (sc->defer_err < DEFER_MIN || sc->defer_err > DEFER_MAX)
				sc->defer_err = 0;

			/*
			 * open epp log file (if configured to do so)
			 */
			if (sc->epplog && !sc->epplogfp) {
				fname = ap_server_root_relative(p, sc->epplog);
				if (!fname) {
					ap_log_error(APLOG_MARK, APLOG_ERR,
						APR_EBADPATH, s,
						"mod_eppd: Invalid "
						"EPPlog path %s", sc->epplog);
					return HTTP_INTERNAL_SERVER_ERROR;
				}
				if ((rv = apr_file_open(&sc->epplogfp, fname,
					(APR_WRITE | APR_APPEND | APR_CREATE),
					( APR_UREAD | APR_UWRITE | APR_GREAD |
					  APR_WREAD ), p)) != APR_SUCCESS)
				{
					ap_log_error(APLOG_MARK, APLOG_ERR, rv,
						s, "mod_eppd: could not open "
						"EPPlog file %s", fname);
					return HTTP_INTERNAL_SERVER_ERROR;
				}
			}
		}
		s = s->next;
	}
	ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "mod_eppd started (mod_eppd "
			"version %s, SVN revision %s, BUILT %s %s)",
			PACKAGE_VERSION, SVN_REV, __DATE__, __TIME__);

	return OK;
}

/**
 * Handler for apache's configuration directive "EPPprotocol".
 *
 * @param cmd      Command structure.
 * @param dummy    Not used parameter.
 * @param flag     1 means EPPprotocol is turned on, 0 means turned off.
 * @return         Error string in case of failure otherwise NULL.
 */
static const char *set_epp_protocol(cmd_parms *cmd, void *dummy, int flag)
{
	server_rec *s = cmd->server;
	eppd_server_conf *sc = (eppd_server_conf *)
			ap_get_module_config(s->module_config, &eppd_module);

	const char *err = ap_check_cmd_context(cmd,
			NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);
	if (err) return err;

	sc->epp_enabled = flag;
	return NULL;
}

/**
 * Handler for apache's configuration directive "EPPObject".
 * Sets the name under which is EPP object known to nameservice.
 *
 * @param cmd       Command structure.
 * @param dummy     Not used parameter.
 * @param obj_name  A name of object.
 * @return          Error string in case of failure otherwise NULL.
 */
static const char *set_epp_object(cmd_parms *cmd, void *dummy,
		const char *obj_name)
{
	const char *err;
	server_rec *s = cmd->server;
	eppd_server_conf *sc = (eppd_server_conf *)
		ap_get_module_config(s->module_config, &eppd_module);

	err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
	if (err) return err;

	/*
	 * catch double definition of object's name
	 * that's not serious fault so we will just print message in log
	 */
	if (sc->object != NULL) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
				"mod_eppd: more than one definition of object's "
				"name. All but the first one will be ignored");
		return NULL;
	}

	sc->object = apr_pstrdup(cmd->pool, obj_name);

	return NULL;
}

/**
 * Handler for apache's configuration directive "EPPlogdObject".
 * Sets the name under which is Logger object known to nameservice.
 *
 * @param cmd       Command structure.
 * @param dummy     Not used parameter.
 * @param obj_name  A name of object.
 * @return          Error string in case of failure otherwise NULL.
 */
static const char *set_logger_object(cmd_parms *cmd, void *dummy,
		const char *obj_name)
{
	const char *err;
	server_rec *s = cmd->server;
	eppd_server_conf *sc = (eppd_server_conf *)
		ap_get_module_config(s->module_config, &eppd_module);

	err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
	if (err) return err;

	/*
	 * catch double definition of object's name
	 * that's not serious fault so we will just print message in log
	 */
	if (sc->logger_object != NULL) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
				"mod_eppd: more than one definition of object's "
				"name. All but the first one will be ignored");
		return NULL;
	}

	sc->logger_object = apr_pstrdup(cmd->pool, obj_name);

	return NULL;
}

/**
 * Handler for apache's configuration directive "EPPschema".
 *
 * The xml schema file is herewith read and parsed and stays in use for life-time
 * of apache. So you have to restart the apache if you want to change schema.
 *
 * @param cmd       Command structure.
 * @param dummy     Not used parameter.
 * @param schemaurl The file with xml schema of EPP protocol.
 * @return          Error string in case of failure otherwise NULL.
 */
static const char *set_schema(cmd_parms *cmd, void *dummy,
		const char *schemaurl)
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
			"mod_eppd: more than one definition of schema URL. All "
			"but the first one will be ignored");
		return NULL;
	}

	/*
	 * do initialization of xml and parsing of xml schema
	 */
	sc->schema = epp_parser_init(schemaurl);
	if (sc->schema == NULL) {
		return apr_psprintf(cmd->temp_pool,
				"mod_eppd: error in xml parser initialization. "
				"It is likely that xml schema '%s' is corupted, "
				"check it with xmllint or other similar tool.",
				schemaurl);
	}
	/*
	 * Register cleanup for xml
	 */
	apr_pool_cleanup_register(cmd->pool, sc->schema, epp_cleanup_xml,
			apr_pool_cleanup_null);

	return NULL;
}

/**
 * Handler for apache's configuration directive "EPPlog".
 *
 * @param cmd     Command structure.
 * @param dummy   Not used parameter.
 * @param a1      The file where log messages from mod_eppd should be logged.
 * @return        Error string in case of failure otherwise NULL.
 */
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
				"mod_eppd: more than one definition of epplog "
				"file. All but the first one will be ignored");
		return NULL;
	}

	sc->epplog = apr_pstrdup(cmd->pool, a1);

	return NULL;
}

/**
 * Handler for apache's configuration directive "EPPloglevel".
 *
 * @param cmd     Command structure.
 * @param dummy   Not used parameter.
 * @param a1      Loglevel is one of fatal, error, warning, info, debug.
 * @return        Error string in case of failure otherwise NULL.
 */
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
				"mod_eppd: loglevel defined more than once. All "
				"but the first definition will be ignored");
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
		return "mod_eppd: log level must be one of fatal, error, "
			"warning, info, debug";
	}

	return NULL;
}

/**
 * Handler for apache's configuration directive "EPPservername".
 *
 * @param cmd    Command structure.
 * @param dummy  Not used parameter.
 * @param a1     Server name of length less than 30 characters.
 * @return       Error string in case of failure otherwise NULL.
 */
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
				"mod_eppd: more than one definition of server"
				"name. All but the first one will be ignored");
		return NULL;
	}

	/* because of xml schema, the server name's length is limited */
	sc->servername = apr_pstrndup(cmd->pool, a1, 29);

	return NULL;
}

/**
 * Handler for apache's configuration directive "EPPvalidResponse".
 *
 * @param cmd     Command structure.
 * @param dummy   Not used parameter.
 * @param flag    1 if mod_eppd's responses should be validated, otherwise 0.
 * @return        Error string in case of failure otherwise NULL.
 */
static const char *set_valid_resp(cmd_parms *cmd, void *dummy, int flag)
{
	server_rec *s = cmd->server;
	eppd_server_conf *sc = (eppd_server_conf *)
		ap_get_module_config(s->module_config, &eppd_module);

	const char *err = ap_check_cmd_context(cmd,
			NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);
	if (err) return err;

	sc->valid_resp = flag;
	return NULL;
}

/**
 * Handler for apache's configuration directive "EPPdeferErrors".
 *
 * @param cmd     Command structure.
 * @param dummy   Not used parameter.
 * @param a1      Integer value representing time for
 *                deferring error responses from CR
 * @return        Error string in case of failure otherwise NULL.
 */
static const char *set_defer_errors(cmd_parms *cmd, void *dummy,
		const char *a1)
{
	const char 	*err;
	int 		val;

	val = atoi(a1);
	/* don't allow negative and to high values */
	if (val < DEFER_MIN || val > DEFER_MAX)
		return "Defer time for error responses out of range";

	server_rec *s = cmd->server;
	eppd_server_conf *sc = (eppd_server_conf *)
		ap_get_module_config(s->module_config, &eppd_module);

	err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
	if (err) return err;

	sc->defer_err = val;

	return NULL;
}

/**
 * Structure containing mod_eppd's configuration directives and their
 * handler references.
 */
static const command_rec eppd_cmds[] = {
	AP_INIT_FLAG("EPPprotocol", set_epp_protocol, NULL, RSRC_CONF,
			"Whether this server is serving the epp protocol"),
	AP_INIT_TAKE1("EPPschema", set_schema, NULL, RSRC_CONF,
			"URL of XML schema of EPP protocol"),
	AP_INIT_TAKE1("EPPservername", set_servername, NULL, RSRC_CONF,
			"Name of server sent in EPP greeting"),
	AP_INIT_TAKE1("EPPlog", set_epplog, NULL, RSRC_CONF,
			"The file where come all log messages from mod_eppd"),
	AP_INIT_TAKE1("EPPloglevel", set_loglevel, NULL, RSRC_CONF,
			"Log level setting for epp log (fatal, error, warning, "
			"info, debug)"),
	AP_INIT_FLAG("EPPvalidResponse", set_valid_resp, NULL, RSRC_CONF,
			"Set to on, to validate every outcomming response."
			"This will slow down the server and should be used "
			"only for debugging purposes."),
	AP_INIT_TAKE1("EPPobject", set_epp_object, NULL, RSRC_CONF,
			"Alias under which is the reference to EPP object "
			"exported from mod_corba module. Default is \"EPP\"."),
    	AP_INIT_TAKE1("EPPlogdObject", set_logger_object, NULL, RSRC_CONF,
			"Alias under which is the reference to Logger object "
			"exported from mod_corba module. Default is \"Logger\"."),
	AP_INIT_TAKE1("EPPdeferErrors", set_defer_errors, NULL, RSRC_CONF,
			"Integer value representing time value (in miliseconds)"
			"for deferring error response from Central Registry."
			"Default is 0 (zero)."),

	{ NULL }
};

/**
 * Initialization of of mod_eppd's configuration structure.
 */
static void *create_eppd_config(apr_pool_t *p, server_rec *s)
{
	eppd_server_conf *sc = (eppd_server_conf *) apr_pcalloc(p, sizeof(*sc));
	return sc;
}

/**
 * Registration of various hooks which the mod_eppd is interested in.
 */
static void register_hooks(apr_pool_t *p)
{
	static const char * const aszPre[]={ "mod_corba.c", NULL };

	ap_hook_child_init(epp_init_child_hook, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_post_config(epp_postconfig_hook, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_process_connection(epp_process_connection, aszPre, NULL,
			APR_HOOK_MIDDLE);

	/* register epp filters */
	ap_register_output_filter("EPP_OUTPUT_FILTER", epp_output_filter, NULL,
			AP_FTYPE_CONNECTION);
}

/**
 * eppd_module definition.
 */
module AP_MODULE_DECLARE_DATA eppd_module = {
	STANDARD20_MODULE_STUFF,
	NULL,                       /* create per-directory config structure */
	NULL,                       /* merge per-directory config structures */
	create_eppd_config,         /* create per-server config structure */
	NULL,                       /* merge per-server config structures */
	eppd_cmds,                  /* command apr_table_t */
	register_hooks              /* register hooks */
};

/* vi:set ts=8 sw=8: */
