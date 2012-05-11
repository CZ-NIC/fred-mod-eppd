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

#include <unistd.h>
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
#include "logd-client.h"

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
 * Many errors in logging will be logged to epplog with this severity,
 * If logging is mandatory, it should be rised much higher than EPP_DEBUG
*/
#define EPP_LOGD_ERRLVL EPP_ERROR

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
	int logd_mandatory;        /**< Whether fred-logd failure is fatal to EPP */
	void	*schema;    /**< URL of EPP schema (use just path). */
	int	valid_resp; /**< Validate response before sending it to client.*/
	char	*epplog;    /**< Epp log filename. */
	apr_file_t	*epplogfp; /**< File descriptor of epp log file. */
	epp_loglevel	loglevel;  /**< Epp log level. */
	int	defer_err;  /**< Time value for deferring error response. */
} eppd_server_conf;

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
		ap_log_cerror(APLOG_MARK, ap_level, 0, conn, "%s", text);
		return;
	}

	/* get remote host's ip address - is not critical if it is not known */
	rhost = ap_get_remote_host(conn, NULL, REMOTE_NOLOOKUP, NULL);
	/* get timestamp */
	current_logtime(timestr, 79);
	/* make up the whole log record */
	logline = apr_psprintf(pool, "%s %s (process:%" APR_PID_T_FMT ") "
			"[sessionID %d] %s" APR_EOL_STR,
			timestr,
			rhost ? rhost : "UNKNOWN-HOST",
			getpid(),
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

	bb = apr_brigade_create(pool, conn->bucket_alloc);

	/* blocking read of first 4 bytes (request's length) */
	status = ap_get_brigade(conn->input_filters, bb, AP_MODE_READBYTES,
			APR_BLOCK_READ, EPP_HEADER_LENGTH);
	if (status != APR_SUCCESS) {
    char err_msg[256];
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
				"(%d - %s)", status, apr_strerror(status, err_msg, sizeof(err_msg)));
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
	epplog(epp_ctx, EPP_DEBUG, "raw request content: %s", *content);

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
 * @param request_id      fred-logd request ID
 * @param lang      Language selected by client.
 * @param cstat     Corba status.
 * @return          0 in case of internal error, 1 if ok.
 */
static int call_login(epp_context *epp_ctx, service_EPP *service,
		epp_command_data *cdata, unsigned long long *loginid, const ccReg_TID request_id,
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
	*cstat = epp_call_login(epp_ctx, service, loginid, request_id, lang, cert_md5,
			cdata);
	return 1;
}

/**
 * Function calls command from corba backend.
 *
 * Return 0 only in case of a serious error.
 *
 *
 *
 * @param epp_ctx   EPP context.
 * @param service   CORBA object reference - rifd.
 * @param service_log CORBA object reference - logd
 * @param cdata     EPP data.
 * @param pstat     Parser return status.
 * @param loginid   Login id assigned by fred_rifd.
 * @param session_id  output - fred-logd session ID
 * @param request_id  fred-logd request ID
 * @param lang      Language selected by client.
 * @param logd_mandatory nonzero if all logd related errors are fatal
 * @return          0 in case of internal error, 1 if ok.
 */
static int call_corba(epp_context *epp_ctx, service_EPP *service, service_Logger *service_log,
		epp_command_data *cdata, parser_status pstat,
		unsigned long long *loginid, ccReg_TID * const session_id, const ccReg_TID request_id, epp_lang *lang,
		unsigned int logd_mandatory)
{
	corba_status	cstat; /* ret code of corba component */
        corba_status    log_cstat = CORBA_OK; /* ret code of corba for logd create/close session */
	char errmsg[MAX_ERROR_MSG_LEN];		/* error message returned from corba call */

	errmsg[0] = '\0';
	if (pstat == PARSER_CMD_LOGIN) {
		if (!call_login(epp_ctx, service, cdata, loginid, request_id, lang, &cstat)) {
			return 0;
		}

		// if logged in successfully and fred-logd service is available
		if (cstat == CORBA_OK) {
			char *registrar_name;

			if(service_log != NULL) {
                registrar_name = ((epps_login*)cdata->data)->clID;
                log_cstat = epp_log_CreateSession(epp_ctx, service_log, registrar_name, 0, session_id, errmsg);
			}

            if(log_cstat == CORBA_ERROR || log_cstat == CORBA_REMOTE_ERROR) {

                if (errmsg[0] != '\0') {
                    epplog(epp_ctx, EPP_ERROR, "Fatal error when logging CreateSession: %s ", errmsg);
                } else {
                    epplog(epp_ctx, EPP_ERROR, "Fatal error when logging CreateSession.");
                }



                if (logd_mandatory) {
                    if(loginid != 0) {
                        epplog(epp_ctx, EPP_ERROR, "Terminating session because of logging failure.");
                        epp_call_CloseSession(epp_ctx, service, *loginid);
                    }
                    return 0;
                }
            }
		}
	} else if (pstat == PARSER_CMD_LOGOUT) {
		cstat = epp_call_logout(epp_ctx, service, loginid, request_id, cdata);
		epplog(epp_ctx, EPP_DEBUG, "login id after logout command is %lld", *loginid);

		// if logged out successfully and fred-logd service is available
		if(cstat == CORBA_OK && service_log != NULL) {
			log_cstat = epp_log_CloseSession(epp_ctx, service_log, *session_id, errmsg);
		}
	} else {
		/* go ahead to generic corba function call */
		cstat = epp_call_cmd(epp_ctx, service, *loginid, request_id, cdata);
	}

	/* catch corba failures */
	if (cstat == CORBA_INT_ERROR || log_cstat == CORBA_INT_ERROR) {
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
                        epplog(epp_ctx, EPP_DEBUG, "Corba call ok");
                        break;
		default:
			break;
	}

        switch(log_cstat) {
                case CORBA_ERROR:
			epplog(epp_ctx, EPP_LOGD_ERRLVL, "Logd: Corba call failed");
			break;
		case CORBA_REMOTE_ERROR:
			epplog(epp_ctx, EPP_LOGD_ERRLVL, "Logd: Unqualified answer "
				"from CORBA server!");
			break;
		case CORBA_OK:
                        epplog(epp_ctx, EPP_DEBUG, "Logd: Corba call ok");
                        break;
		default:
			break;
        }

	return 1;
}

/**
 * Function generates XML response.
 *
 * @param epp_ctx   EPP context.
 * @param service   EPP CORBA object reference.
 * @param cdata     Command data.
 * @param validate  Validate responses.
 * @param schema    Parsed XML schema.
 * @param lang      Language of session.
 * @param response  On return holds response if ret code is 1.
 * @param gstat		generator's return code
 * @param valerr    encountered errors when validating response
 * @return          0 in case of internal error, 1 if ok.
 */
static int gen_response(epp_context *epp_ctx, service_EPP *service,
		epp_command_data *cdata, int validate, void *schema,
		epp_lang lang, char **response, gen_status *gstat, qhead *valerr)
{

	valerr->body = NULL;
	valerr->count = 0;

	/* generate xml response */
	*gstat = epp_gen_response(epp_ctx, validate, schema, lang, cdata,
			response, valerr);

	switch (*gstat) {
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
			q_foreach(valerr) {
				epp_error *e = q_content(valerr);

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

	return 1;
}



/** Read and process EPP requests waiting in the queue */
static int epp_request_loop(epp_context *epp_ctx, apr_bucket_brigade *bb,
		service_EPP *EPPservice, service_Logger *logger_service, eppd_server_conf *sc,
		unsigned long long *login_id_save, ccReg_TID *session_id_save)
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
	unsigned long long     login_id;        /* login id of client's session */
	ccReg_TID 	 session_id;	  /* id for log_session table */
        char *remote_ipaddr;


#ifdef EPP_PERF
	/*
	 * array of timestamps for perf measurement:
	 *     time[0] - before parsing
	 *     time[1] - after parsing and before corba call
	 *     time[2] - after corba call and before response generation
	 *     time[3] - after response generation
	 */
	apr_time_t	times[5];
#endif


	/* initialize variables used inside the loop */
	*login_id_save = login_id = 0;       /* zero means that client isn't logged in*/
    *session_id_save = session_id = 0;
	lang = LANG_EN;	/* default language is english */

	/*
	 * The loop in which are processed requests until client logs out or
	 * error appears.
	 */
	while (1) {
        ccReg_TID act_log_entry_id = 0;

#ifdef EPP_PERF
		bzero(times, 5 * sizeof(times[0]));
#endif
		/* allocate new pool for request */
		apr_pool_create(&rpool, ((conn_rec *) epp_ctx->conn)->pool);
		apr_pool_tag(rpool, "EPP_request");
		epp_ctx->pool = rpool;
		/* possible previous content is gone with request pool */
		cdata = NULL;

		/* read request */
		retval = epp_read_request(epp_ctx, &request, &bytes);
		if (retval == 1) {
            /*
             * epp_read_request red EOF, this results in OK status
             * being returned from connection handler, since it's
             * not counted as an error, if client ends connection
             * without proper logout.
             */
            corba_status log_cstat;
            char errmsg[MAX_ERROR_MSG_LEN];

            // if logged out successfully and fred-logd service is available
            if(session_id != 0 && logger_service != NULL) {
                log_cstat = epp_log_CloseSession(epp_ctx, logger_service, session_id, errmsg);

                session_id = 0;

                switch(log_cstat) {
                    case CORBA_ERROR:
                        epplog(epp_ctx, EPP_LOGD_ERRLVL, "Logd: Corba call failed");
                        break;
                    case CORBA_REMOTE_ERROR:
                        epplog(epp_ctx, EPP_LOGD_ERRLVL, "Logd: Unqualified answer from CORBA server!");
                        break;
                }
            }

            break;
		} else if (retval == 2)
			return HTTP_INTERNAL_SERVER_ERROR;
#ifdef EPP_PERF
		times[0] = apr_time_now(); /* before parsing */
#endif
		/*
		 * Deliver request to XML parser, the task of parser is
		 * to fill cdata structure with data.
		 */

		
		pstat = epp_parse_command(epp_ctx, (login_id != 0), sc->schema,
				request, bytes, &cdata, &cmd_type);

                if(pstat == PARSER_HELLO) cmd_type = EPP_RED_HELLO;
                
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

#ifdef EPP_PERF
		times[1] = apr_time_now(); /* after parsing */
#endif


		// if there wasn't anything seriously wrong, log the request
        if (epp_ctx == NULL) {
            remote_ipaddr = NULL;
        } else {
            remote_ipaddr = ((conn_rec*) epp_ctx->conn)->remote_ip;
        }

        if (logger_service != NULL) {
            act_log_entry_id = log_epp_command(epp_ctx, logger_service, remote_ipaddr,
                    cdata->xml_in, cdata, cmd_type, session_id);

            if (act_log_entry_id == 0) {
                epplog(epp_ctx, EPP_LOGD_ERRLVL,
                        "Error while logging the request");
                if (sc->logd_mandatory) {
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
            } else {
                epplog(epp_ctx, EPP_DEBUG,
                        "Request in fred-logd created, id: %" APR_UINT64_T_FMT,
                        act_log_entry_id);
            }
        }

#ifdef EPP_PERF
		times[2] = apr_time_now(); /* after logging */
#endif

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
			times[3] = apr_time_now();	/* after corba calls */
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

			// hello doesn't fill any return data into cdata,
			// so we have to use a little hack like this for logger:
			cdata->rc = 1000;

            if (logger_service != NULL
                && act_log_entry_id != 0) {

                    epplog(epp_ctx, EPP_DEBUG, "Closing logging request with requestID: %" APR_UINT64_T_FMT, act_log_entry_id);
                    if(log_epp_response(epp_ctx, logger_service, NULL, response, cdata, 0, act_log_entry_id)
                            == LOG_INTERNAL_ERROR) {

                        epplog(epp_ctx, EPP_LOGD_ERRLVL, "Could not log EPP hello response in fred-logd");
                        // TODO cannot return error code - 2-phase commit should be used
                    }
            }

			if (gstat != GEN_OK) {
				epplog(epp_ctx, EPP_FATAL, "Error when "
						"creating epp greeting");
				return HTTP_INTERNAL_SERVER_ERROR;
			}

		/* it is a command */
		} else {
			gen_status gstat; /* XML generator return status */
			qhead valerr;	/* encountered errors when validating response */
			int gret;     /* return value from XML generator */
                        int log_ret;    /* return value from fred-logd close request */

			/* log request which doesn't validate */
			if (pstat == PARSER_NOT_VALID) {
				epplog(epp_ctx, EPP_WARNING,
						"Request does not validate");
			}

			/* call function from corba backend */
			if (!call_corba(epp_ctx, EPPservice, logger_service, cdata, pstat,
						&login_id, &session_id, act_log_entry_id, &lang, sc->logd_mandatory))
				return HTTP_INTERNAL_SERVER_ERROR;
			/* did successfull login occured? */
			epplog(epp_ctx, EPP_DEBUG, "after corba call command "
				"saved login id is %lld, login id is %d", *login_id_save, login_id);
			if (*login_id_save == 0 && login_id != 0) {
			    // login_id and session_id must be both set or not set
			    // at the same time
				*login_id_save = login_id;
				*session_id_save = session_id;
				/*
				 * this event should be logged explicitly if
				 * login was successfull
				 */
				epplog(epp_ctx, EPP_INFO, "Logged in "
					"successfully, login id is %lld",login_id);
			}

                        epplog(epp_ctx, EPP_INFO, "using fred-logd session id: %" APR_UINT64_T_FMT, session_id);
#ifdef EPP_PERF
			times[3] = apr_time_now(); /* after corba calls */
#endif
			/* error response will be deferred */
			if (cdata->rc >= 2000) {
				epplog(epp_ctx, EPP_DEBUG, "(epp-cmd %d) response code %d: sleeping for %d ms",
					cdata->type, cdata->rc, sc->defer_err);
				/* sleep time conversion to microsec */
				apr_sleep(sc->defer_err * 1000);
			}

			/* generate response */
			gret = gen_response(epp_ctx, EPPservice, cdata,
						sc->valid_resp, sc->schema,
						lang, &response, &gstat, &valerr);

			/* put login id to the log record if it's not already there
			 * (i.e. only in case we just logged in)
			 */

			if(logger_service != NULL && act_log_entry_id != 0) {
			    epplog(epp_ctx, EPP_DEBUG, "Closing logging request with requestID: %" APR_UINT64_T_FMT, act_log_entry_id);

                log_ret = log_epp_response(epp_ctx, logger_service, &valerr, response, cdata,
                        pstat == PARSER_CMD_LOGIN ? session_id : 0,
                        act_log_entry_id);

                if (log_ret == LOG_INTERNAL_ERROR) {
                    epplog(epp_ctx, EPP_LOGD_ERRLVL, "Could not log EPP command response in fred-logd");
                        // TODO cannot return error code - 2-phase commit should be used
                }
			}

			if (!gret) return HTTP_INTERNAL_SERVER_ERROR;
		}
#ifdef EPP_PERF
		times[4] = apr_time_now();
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
		epplog(epp_ctx, EPP_DEBUG, "Perf data: p(%u), l(%u), c(%u), "
				"g(%u), s(%u)",
				(unsigned) (times[1] - times[0]),/* parser */
				(unsigned) (times[2] - times[1]),/* logging */
				(unsigned) (times[3] - times[2]),/* CORBA */
				(unsigned) (times[4] - times[3]),/* generator */
				(unsigned) (apr_time_now() - times[4]));/*send*/
#endif
		status = ap_fflush(((conn_rec *) epp_ctx->conn)->output_filters,
			       bb);
		if (status != APR_SUCCESS) {
			/* happens on every greeting when client just tests
			 * the port. Not severe. */
      char err_msg[256];
			epplog(epp_ctx, EPP_INFO,
					"Error when sending response to client "
          "(%d - %s)", status, apr_strerror(status, err_msg, sizeof(err_msg)));
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		/* check if successful logout appeared */
		if (pstat == PARSER_CMD_LOGOUT && login_id == 0) {
			*login_id_save = 0;
			session_id = 0;
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
 * @param epp_ctx   EPP context.
 * @param name  	Name of the service.
 */
static void *get_corba_service(epp_context *epp_ctx, char *name)
{
	int 		i;
	apr_hash_t	*references; /* directory of CORBA object references */
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
	unsigned long long	     loginid; /* login id of client */
	ccReg_TID        sessionid; /* session id from fred-logd */
	int	 rc;      /* corba ret code */
	int	 ret;     /* command loop return code */
	char	*version; /* version of fred_rifd */
	char	*curdate; /* cur. date returned from fred_rifd */
	char	*response;/* greeting response */
	apr_status_t	 status;/* used to store rc of apr functions */
	gen_status	 gstat; /* generator's return code */
	epp_context	 epp_ctx;    /* context (session , connection, pool) */
	service_EPP	 EPPservice; /* CORBA object reference for fred-rifd */
        service_Logger   logger_service; /* CORBA object reference for fred-logd */
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

    if (sc->logger_object == NULL || *sc->logger_object == '\0') {
        // TODO maybe change loglevel depending on sc->logd_mandatory flag
        epplog(&epp_ctx, EPP_ERROR,
                "Reference to logger object not set in config");
        logger_service = NULL;
        if (sc->logd_mandatory) {
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    } else {
        logger_service = get_corba_service(&epp_ctx, sc->logger_object);
        if (logger_service == NULL) {
            epplog(&epp_ctx, EPP_ERROR, "Could not obtain object reference "
                "for alias '%s'.", sc->logger_object);
            if (sc->logd_mandatory) {
                return HTTP_INTERNAL_SERVER_ERROR;
            }
        }
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
    char err_msg[256];
		epplog(&epp_ctx, EPP_FATAL,
        "Error when sending response to client "
        "(%d - %s)", status, apr_strerror(status, err_msg, sizeof(err_msg)));
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* prepare bucket brigade for reuse in next request */
	status = apr_brigade_cleanup(bb);
	if (status != APR_SUCCESS) {
		epplog(&epp_ctx, EPP_FATAL, "Could not cleanup bucket "
				"brigade used for response");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	ret = epp_request_loop(&epp_ctx, bb, EPPservice, logger_service, sc, &loginid, &sessionid);
	/* send notification about session end to CR */
	if (loginid > 0) {
		epp_call_CloseSession(&epp_ctx, EPPservice, loginid);

		if (sessionid != 0 && logger_service != NULL) {
            corba_status log_cstat = CORBA_OK;
            char errmsg[MAX_ERROR_MSG_LEN];

            epplog(&epp_ctx, EPP_INFO, "EPP session terminated, calling CloseSession in logd");
            log_cstat = epp_log_CloseSession(&epp_ctx, logger_service, sessionid, errmsg);

            switch(log_cstat) {
                case CORBA_ERROR:
                    epplog(&epp_ctx, EPP_LOGD_ERRLVL, "Logd: Corba call failed");
                    break;
                case CORBA_REMOTE_ERROR:
                    epplog(&epp_ctx, EPP_LOGD_ERRLVL, "Logd: Unqualified answer from CORBA server!");
                    break;
                case CORBA_OK:
                    epplog(&epp_ctx, EPP_DEBUG, "Logd: Corba call ok");
                    break;
                default:
                    break;
            }
		}
	}

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

static const char *set_epp_logd_mandatory(cmd_parms *cmd, void *dummy, int flag)
{
    server_rec *s = cmd->server;
    eppd_server_conf *sc = (eppd_server_conf *)
            ap_get_module_config(s->module_config, &eppd_module);

    const char *err = ap_check_cmd_context(cmd,
            NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);
    if(err) return err;

    sc->logd_mandatory = flag;
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
    AP_INIT_FLAG("EPPlogdMandatory", set_epp_logd_mandatory, NULL, RSRC_CONF,
            "Whether fred-logd failure is fatal to EPP"),
	AP_INIT_FLAG("EPPvalidResponse", set_valid_resp, NULL, RSRC_CONF,
			"Set to on, to validate every outcomming response."
			"This will slow down the server and should be used "
			"only for debugging purposes."),
	AP_INIT_TAKE1("EPPobject", set_epp_object, NULL, RSRC_CONF,
			"Alias under which is the reference to EPP object "
			"exported from mod_corba module. Default is \"EPP\"."),
    	AP_INIT_TAKE1("EPPlogdObject", set_logger_object, NULL, RSRC_CONF,
			"Alias under which is the reference to Logger object "
			"exported from mod_corba module. Default is \"\"."),
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
