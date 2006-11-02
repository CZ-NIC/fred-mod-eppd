/**
 * @file epp-client.c
 *
 * Corba component is used for communication between apache module and
 * central repository.
 *
 * Input are self-descriptive data stored in structure
 * ussually called cdata. Output data are returned via the same structure.
 * Purpose of this module is to hide the complexity of communication behind
 * simple API defined in epp-client.h. The function names are analogical
 * to names defined in EPP protocol standard.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <orbit/orbit.h>
#include <ORBitservices/CosNaming.h>

#include "epp_common.h"
#include "epp-client.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/** Quick test if corba exception was raised. */
#define raised_exception(ev)	((ev)->_major != CORBA_NO_EXCEPTION)
/**
 * Maximum number of retries when connection failure occurs before
 * the failure is announced to a caller.
 */
#define MAX_RETRIES	3
/** Number of microseconds between retries when connection failure occurs. */
#define RETR_SLEEP  100000

/** True if exception is COMM_FAILURE, which is used in retry loop. */
#define IS_NOT_COMM_FAILURE_EXCEPTION(_ev)                             \
	(strcmp((_ev)->_id, "IDL:omg.org/CORBA/COMM_FAILURE:1.0"))
/** True if exception is INT_ERROR (internal error on server's side). */
#define IS_INTSERV_ERROR(_ev)                             \
	(!strcmp((_ev)->_id, "IDL:ccReg/EPP/ServerIntError:1.0"))

/** Clear errno variable to non-error state. */
#define CLEAR_CERRNO(_cerrno)	(_cerrno = 0)

/**
 * Persistent structure initialized at startup, needed for corba function calls.
 */
struct epp_corba_globs_t {
	CORBA_ORB	corba;   /**< Corba is global corba object. */
	ccReg_EPP	service; /**< Service is ccReg object stub. */
};

/**
 * Error code translation table.
 */
static int error_translator[][2] =
{
  {ccReg_unknow,                   errspec_unknown},
  {ccReg_pollAck_msgID,            errspec_pollAck_msgID},
  {ccReg_pollAck_msgID_missing,    errspec_pollAck_msgID_missing},
  {ccReg_contactCreate_handle,     errspec_contactCreate_handle},
  {ccReg_contactCreate_cc,         errspec_contactCreate_cc},
  {ccReg_contactInfo_handle,       errspec_contactInfo_handle},
  {ccReg_contactUpdate_cc,         errspec_contactUpdate_cc},
  {ccReg_contactUpdate_status_add, errspec_contactUpdate_status_add},
  {ccReg_contactUpdate_status_rem, errspec_contactUpdate_status_rem},
  {ccReg_contactUpdate_ssntype_missing, errspec_contactUpdate_ssntype_missing},
  {ccReg_nssetCreate_handle,       errspec_nssetCreate_handle},
  {ccReg_nssetCreate_tech,         errspec_nssetCreate_tech},
  {ccReg_nssetCreate_ns_name,      errspec_nssetCreate_ns_name},
  {ccReg_nssetCreate_ns_addr,      errspec_nssetCreate_ns_addr},
  {ccReg_nssetInfo_handle,         errspec_nssetInfo_handle},
  {ccReg_nssetUpdate_ns_name_add,  errspec_nssetUpdate_ns_name_add},
  {ccReg_nssetUpdate_ns_addr_add,  errspec_nssetUpdate_ns_addr_add},
  {ccReg_nssetUpdate_ns_name_rem,  errspec_nssetUpdate_ns_name_rem},
  {ccReg_nssetUpdate_ns_addr_rem,  errspec_nssetUpdate_ns_addr_rem},
  {ccReg_nssetUpdate_tech_add,     errspec_nssetUpdate_tech_add},
  {ccReg_nssetUpdate_tech_rem,     errspec_nssetUpdate_tech_rem},
  {ccReg_nssetUpdate_status_add,   errspec_nssetUpdate_status_add},
  {ccReg_nssetUpdate_status_rem,   errspec_nssetUpdate_status_rem},
  {ccReg_domainCreate_fqdn,        errspec_domainCreate_fqdn},
  {ccReg_domainCreate_registrant,  errspec_domainCreate_registrant},
  {ccReg_domainCreate_nsset,       errspec_domainCreate_nsset},
  {ccReg_domainCreate_period,      errspec_domainCreate_period},
  {ccReg_domainCreate_admin,       errspec_domainCreate_admin},
  {ccReg_domainCreate_ext_valDate, errspec_domainCreate_ext_valDate},
  {ccReg_domainInfo_fqdn,          errspec_domainInfo_fqdn},
  {ccReg_domainRenew_fqdn,         errspec_domainRenew_fqdn},
  {ccReg_domainRenew_curExpDate,   errspec_domainRenew_curExpDate},
  {ccReg_domainRenew_period,       errspec_domainRenew_period},
  {ccReg_domainRenew_ext_valDate,  errspec_domainRenew_ext_valDate},
  {ccReg_domainUpdate_fqdn,        errspec_domainUpdate_fqdn},
  {ccReg_domainUpdate_registrant,  errspec_domainUpdate_registrant},
  {ccReg_domainUpdate_nsset,       errspec_domainUpdate_nsset},
  {ccReg_domainUpdate_admin_add,   errspec_domainUpdate_admin_add},
  {ccReg_domainUpdate_admin_rem,   errspec_domainUpdate_admin_rem},
  {ccReg_domainUpdate_status_add,  errspec_domainUpdate_status_add},
  {ccReg_domainUpdate_status_rem,  errspec_domainUpdate_status_rem},
  {ccReg_domainUpdate_ext_valDate, errspec_domainUpdate_ext_valDate},
  {ccReg_transfer_op,              errspec_transfer_op},
  {-1, -1}
};

/**
 * Translate error code from IDL code to mod_eppd's code.
 *
 * @param idlcode   IDL code.
 * @return          mod_eppd's code.
 */
static int
err_idl2epp(int idlcode)
{
	int	i = 0;
	int	var;

	while ((var = error_translator[i][0]) != -1)
		if (var == idlcode)
			return error_translator[i][1];

	return -1;
}

/**
 * Translate error code from mod_eppd's code to IDL code.
 *
 * @param eppcode   mod_eppd's code.
 * @return          IDL code.
 */
static int
err_epp2idl(int eppcode)
{
	int	i = 0;
	int	var;

	while ((var = error_translator[i][1]) != -1)
		if (var == eppcode)
			return error_translator[i][0];

	return -1;
}

/**
 * Function wraps strings passed from XML parser into strings accepted
 * by CORBA.
 *
 * Null strings are transformed to empty strings. The resulting string
 * must be freed with CORBA_free().
 *
 * @param str	Input string.
 * @return      Output string.
 */
static char *
wrap_str(const char *str)
{
	if (str == NULL)
		return CORBA_string_dup("");

	return CORBA_string_dup(str);
}

/**
 * Function works the same way as wrap_str(), but empty strings are substituted
 * by IDL-defined string with special meaning.
 *
 * In update functions we need to distinguish between empty string and NULL.
 *
 * @param str	Input string.
 * @return      Output string.
 */
static char *
wrap_str_upd(const char *str)
{
	if (str == NULL)
		return CORBA_string_dup("");

	if (*str == '\0')
		/* XXX what to put instead of \b?? */
		return CORBA_string_dup("\b");

	return CORBA_string_dup(str);
}

/**
 * Function unwraps strings passed through CORBA - empty strings are
 * transformed to NULL strings.
 *
 * @param pool	 Memory pool.
 * @param str	 Input string.
 * @param cerrno Set to 1 if malloc failed.
 * @return       Output string.
 */
static char *
unwrap_str(void *pool, const char *str, int *cerrno)
{
	char	*res;

	assert(str != NULL);

	if (*str == '\0')
		return NULL;

	res = epp_strdup(pool, str);
	if (res == NULL)
		*cerrno = 1;

	return res;
}

/**
 * Does the same thing as unwrap_str() but in addition input string is
 * required not to be empty.
 *
 * @param pool	  Memory pool.
 * @param str	  Input string.
 * @param cerrno  Set to 1 if malloc failed and to 2 if string is empty.
 * @return        Output string.
 */
static char *
unwrap_str_req(void *pool, const char *str, int *cerrno)
{
	char	*res;

	assert(str != NULL);

	if (*str == '\0') {
		*cerrno = 2;
		return NULL;
	}
	res = epp_strdup(pool, str);
	if (res == NULL)
		*cerrno = 1;

	return res;
}

epp_corba_globs *
epp_corba_init(const char *ns_loc, const char *obj_name)
{
	CORBA_ORB	global_orb = CORBA_OBJECT_NIL;	/* global orb */
	ccReg_EPP	service = CORBA_OBJECT_NIL;	/* object's stub */
	epp_corba_globs	*globs;	/* used to store global_orb and service */
	CORBA_Environment	ev[1];
	CosNaming_NamingContext	ns; /* used for nameservice */
	CosNaming_NameComponent	*name_component; /* EPP's name */
	CosNaming_Name	*cos_name; /* Cos name used in service lookup */
	char	ns_string[150];
 
	CORBA_exception_init(ev);

	assert(ns_loc != NULL);
	assert(obj_name != NULL);

	/* build a name of EPP object */
	name_component = (CosNaming_NameComponent *)
		malloc(2 * sizeof(CosNaming_NameComponent));
	name_component[0].id = CORBA_string_dup("ccReg");
	name_component[0].kind = CORBA_string_dup("context");
	name_component[1].id = CORBA_string_dup(obj_name);
	name_component[1].kind = CORBA_string_dup("Object");
	cos_name = (CosNaming_Name *) malloc (sizeof(CosNaming_Name));
	cos_name->_maximum = cos_name->_length = 2;
	cos_name->_buffer = name_component;
	CORBA_sequence_set_release(cos_name, CORBA_TRUE);

	ns_string[149] = 0;
	snprintf(ns_string, 149, "corbaloc::%s/NameService", ns_loc);
	CORBA_exception_init(ev);
	/* create orb object */
	global_orb = CORBA_ORB_init(0, NULL, "orbit-local-orb", ev);
	if (raised_exception(ev)) {
		CORBA_exception_free(ev);
		return NULL;
	}

	/* get nameservice */
	ns = (CosNaming_NamingContext) CORBA_ORB_string_to_object(global_orb,
			ns_string, ev);
	if (ns == CORBA_OBJECT_NIL || raised_exception(ev)) {
		CORBA_exception_free(ev);
		/* tear down the ORB */
		CORBA_ORB_destroy(global_orb, ev);
		CORBA_exception_free(ev);
		return NULL;
	}
	/* get EPP object */
	service =(ccReg_EPP) CosNaming_NamingContext_resolve(ns, cos_name, ev);
	if (service == CORBA_OBJECT_NIL || raised_exception(ev)) {
		CORBA_exception_free(ev);
		/* release nameservice */
		CORBA_Object_release(ns, ev);
		CORBA_exception_free(ev);
		/* tear down the ORB */
		CORBA_ORB_destroy(global_orb, ev);
		CORBA_exception_free(ev);
		return NULL;
	}
	/* release nameservice */
	CORBA_Object_release(ns, ev);
	CORBA_exception_free(ev);

	/* wrap orb and service in one struct */
	if ((globs = malloc(sizeof *globs)) == NULL) {
		/* releasing managed object */
		CORBA_Object_release(service, ev);
		CORBA_exception_free(ev);
		/* tear down the ORB */
		CORBA_ORB_destroy(global_orb, ev);
		CORBA_exception_free(ev);
		return NULL;
	}
	globs->corba = global_orb;
	globs->service = service;

	return globs;
}

void
epp_corba_init_cleanup(epp_corba_globs *globs)
{
	CORBA_Environment ev[1];
	CORBA_exception_init(ev);

	/* releasing managed object */
	CORBA_Object_release(globs->service, ev);
	CORBA_exception_free(ev);
	/* tear down the ORB */
	CORBA_ORB_destroy(globs->corba, ev);
	CORBA_exception_free(ev);

	free(globs);
}

/**
 * This function helps to convert error codes for incorrect parameter location
 * used in IDL to error codes understandable by the rest of the module.
 *
 * @param pool     Pool for memory allocations.
 * @param errors   List of errors - converted errors (output).
 * @param c_errors Buffer of errors used as input.
 * @return         0 if successful, 1 otherwise.
 */
static int
get_errors(void *pool, qhead *errors, ccReg_Error *c_errors)
{
	CORBA_Environment ev[1];
	int	i;

	CORBA_exception_init(ev);

	/* process all errors one by one */
	for (i = 0; i < c_errors->_length; i++) {
		int	cerrno;
		epp_error	*err_item;
		ccReg_Error_seq *c_error = &c_errors->_buffer[i];

		CLEAR_CERRNO(cerrno);

		err_item = epp_malloc(pool, sizeof *err_item);
		if (err_item == NULL) {
			return 1;
		}
		err_item->reason = unwrap_str_req(pool, c_error->reason,&cerrno);
		if (cerrno != 0)
			return 1;

		err_item->value = unwrap_str_req(pool, c_error->value, &cerrno);
		if (cerrno != 0) return 1;

		/* convert error code */
		err_item->spec = err_idl2epp(c_error->code);

		if (q_add(pool, errors, err_item))
			return 1;
	}

	return 0;
}

int
epp_call_hello(void *pool,
		epp_corba_globs *globs,
		char **version,
		char **curdate)
{
	CORBA_Environment ev[1];
	CORBA_char	*c_version;
	CORBA_char	*c_curdate;
	int	retr, cerrno;

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		c_version = ccReg_EPP_version(globs->service, &c_curdate, ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

	if (raised_exception(ev)) {
		int	ret;

		if (IS_INTSERV_ERROR(ev)) {
			ret  = CORBA_REMOTE_ERROR;
		}
		else {
			ret  = CORBA_ERROR;
		}
		CORBA_exception_free(ev);
		return ret;
	}

	CLEAR_CERRNO(cerrno);

	*version = unwrap_str(pool, c_version, &cerrno);
	if (cerrno != 0) {
		CORBA_free(c_version);
		CORBA_free(c_curdate);
		return CORBA_INT_ERROR;
	}
	*curdate = unwrap_str(pool, c_curdate, &cerrno);
	if (cerrno != 0) {
		CORBA_free(c_version);
		CORBA_free(c_curdate);
		return CORBA_INT_ERROR;
	}
	CORBA_free(c_version);
	CORBA_free(c_curdate);
	return CORBA_OK;
}

/**
 * This is common routine for all corba function calls (except hello call)
 * executed at the end of command.
 *
 * Structure response is freed in any case (success or failure).
 *
 * @param pool     Memory pool for allocations.
 * @param cdata    Command input and output data.
 * @param response Response returned from CORBA call.
 * @return         0 in case of success, 1 otherwise.
 */
static int
corba_call_epilog(void *pool, epp_command_data *cdata, ccReg_Response *response)
{
	int	cerrno;

	CLEAR_CERRNO(cerrno);

	if (get_errors(pool, &cdata->errors, &response->errors)) {
		CORBA_free(response);
		return 1;
	}
	cdata->svTRID = unwrap_str_req(pool, response->svTRID, &cerrno);
	if (cerrno != 0) {
		CORBA_free(response);
		return 1;
	}
	cdata->msg = unwrap_str_req(pool, response->errMsg, &cerrno);
	if (cerrno != 0) {
		CORBA_free(response);
		return 1;
	}
	cdata->rc = response->errCode;
	return 0;
}

/**
 * "dummy" call is dummy because it only retrieves unique svTRID and
 * error message from central repository and by this way informs repository
 * about the error. This call is used for failures detected already on side
 * of mod_eppd.
 *
 * @param pool    Pool for memory allocations.
 * @param globs   Corba context.
 * @param session Session identifier.
 * @param cdata   Data from xml request.
 * @return        Status.
 */
static corba_status
epp_call_dummy(void *pool,
		epp_corba_globs *globs,
		int session,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	CORBA_char	*c_clTRID;
	ccReg_Error	*c_errors;
	ccReg_Response	*response;
	int	len, i, retr;

	/*
	 * Input parameters:
	 *    cdata->rc
	 *    c_errors (*)
	 *    session
	 *    c_clTRID (*)
	 * Output parameters: none
	 */
	c_clTRID = wrap_str(cdata->clTRID);
	if (c_clTRID == NULL)
		return CORBA_INT_ERROR;

	/* get number of errors */
	c_errors = ccReg_Error__alloc();
	if (c_errors == NULL) {
		CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}
	len = q_length(cdata->errors);
	c_errors->_buffer = ccReg_Error_allocbuf(len);
	if (c_errors->_buffer == NULL) {
		CORBA_free(c_clTRID);
		CORBA_free(c_errors);
		return CORBA_INT_ERROR;
	}
	c_errors->_maximum = c_errors->_length = len;
	c_errors->_release = CORBA_TRUE;

	/* copy each error in corba buffer */
	i = 0;
	q_foreach(&cdata->errors) {
		epp_error	*err_item;

		err_item = q_content(&cdata->errors);
		c_errors->_buffer[i].code = err_epp2idl(err_item->spec);
		c_errors->_buffer[i].value = wrap_str(err_item->value);
		if (c_errors->_buffer[i].value == NULL) {
			CORBA_free(c_errors);
			CORBA_free(c_clTRID);
			return CORBA_INT_ERROR;
		}
		c_errors->_buffer[i].reason = wrap_str(err_item->reason);
		if (c_errors->_buffer[i].reason == NULL) {
			CORBA_free(c_errors);
			CORBA_free(c_clTRID);
			return CORBA_INT_ERROR;
		}
		i++;
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		response = ccReg_EPP_GetTransaction(globs->service,
				cdata->rc,
				c_errors,
				session,
				c_clTRID,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_clTRID);
	CORBA_free(c_errors);

	if (raised_exception(ev)) {
		int	ret;

		if (IS_INTSERV_ERROR(ev)) {
			ret  = CORBA_REMOTE_ERROR;
		}
		else {
			ret  = CORBA_ERROR;
		}
		CORBA_exception_free(ev);
		return ret;
	}

	/*
	 * Simply get rid of old errors, don't bother with free() - memory
	 * pool will handle that.
	 */
	cdata->errors.body  = NULL;
	cdata->errors.count = 0;

	if (corba_call_epilog(pool, cdata, response))
		return CORBA_INT_ERROR;

	return CORBA_OK;
}

corba_status
epp_call_login(void *pool,
		epp_corba_globs *globs,
		int *session,
		epp_lang *lang,
		const char *certID,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	CORBA_long	c_session;
	CORBA_char	*c_clID, *c_pw, *c_newPW, *c_clTRID;
	ccReg_Languages	c_lang;
	ccReg_Response *response;
	int	retr;
	epps_login	*login;

	login = cdata->data;
	/*
	 * Input parameters:
	 *    c_clID (*)
	 *    c_pw (*)
	 *    c_newPW (*)
	 *    c_clTRID (*)
	 *    xml_in (a)
	 *    certID (a)
	 *    c_lang
	 * Output parameters:
	 *    c_session
	 */
	assert(cdata->xml_in != NULL);
	assert(certID != NULL);
	c_clTRID = wrap_str(cdata->clTRID);
	if (c_clTRID == NULL)
		return CORBA_INT_ERROR;
	c_clID = wrap_str(login->clID);
	if (c_clID == NULL) {
		CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}
	c_pw = wrap_str(login->pw);
	if (c_pw == NULL) {
		CORBA_free(c_clID);
		CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}
	c_newPW = wrap_str(login->newPW);
	if (c_newPW == NULL) {
		CORBA_free(c_pw);
		CORBA_free(c_clID);
		CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}
	c_lang = (login->lang == LANG_EN) ? ccReg_EN : ccReg_CS;

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		response = ccReg_EPP_ClientLogin(globs->service,
				c_clID,
				c_pw,
				c_newPW,
				c_clTRID,
				cdata->xml_in,
				&c_session,
				certID,
				c_lang,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_newPW);
	CORBA_free(c_pw);
	CORBA_free(c_clID);
	CORBA_free(c_clTRID);

	/* if it is exception then return */
	if (raised_exception(ev)) {
		int	ret;

		if (IS_INTSERV_ERROR(ev)) {
			ret  = CORBA_REMOTE_ERROR;
		}
		else {
			ret  = CORBA_ERROR;
		}
		CORBA_exception_free(ev);
		return ret;
	}

	if (corba_call_epilog(pool, cdata, response))
		return CORBA_INT_ERROR;

	if (cdata->rc == 1000) {
		*session = c_session;
		*lang = login->lang;
	}

	return CORBA_OK;
}

corba_status
epp_call_logout(void *pool,
		epp_corba_globs *globs,
		int session,
		epp_command_data *cdata,
		int *logout)
{
	CORBA_Environment ev[1];
	CORBA_char	*c_clTRID;
	ccReg_Response *response;
	int	retr;

	/*
	 * Input parameters:
	 *    session
	 *    c_clTRID (*)
	 *    xml_in (a)
	 * Output parameters: none
	 */
	assert(cdata->xml_in != NULL);
	*logout = 0;
	c_clTRID = wrap_str(cdata->clTRID);
	if (c_clTRID == NULL)
		return CORBA_INT_ERROR;

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		response = ccReg_EPP_ClientLogout(globs->service,
				session,
				c_clTRID,
				cdata->xml_in,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_clTRID);

	if (raised_exception(ev)) {
		int	ret;

		if (IS_INTSERV_ERROR(ev)) {
			ret  = CORBA_REMOTE_ERROR;
		}
		else {
			ret  = CORBA_ERROR;
		}
		CORBA_exception_free(ev);
		return ret;
	}

	if (corba_call_epilog(pool, cdata, response))
		return CORBA_INT_ERROR;

	/* propagate information about logout upwards */
	if (cdata->rc == 1500)
		*logout = 1;

	return CORBA_OK;
}

/**
 * EPP check for domain, nsset and contact is so similar that it is worth of
 * having the code in one function and pass object type as parameter.
 *
 * @param pool    Pool for memory allocations.
 * @param globs   Corba context.
 * @param session Session identifier.
 * @param cdata   Data from xml request.
 * @param obj     Object type (see #epp_object_type)
 * @return        Status.
 */
static corba_status
epp_call_check(void *pool,
		epp_corba_globs *globs,
		int session,
		epp_command_data *cdata,
		epp_object_type obj)
{
	CORBA_Environment ev[1];
	CORBA_char	*c_clTRID;
	ccReg_CheckResp	*c_avails;
	ccReg_Check	*c_ids;
	ccReg_Response *response;
	int	len, i, retr;
	epps_check	*check;

	check = cdata->data;
	/*
	 * Input parameters:
	 *    c_ids (*)
	 *    session
	 *    c_clTRID (*)
	 *    xml_in (a)
	 * Output parameters:
	 *    c_avails (f)
	 */
	assert(cdata->xml_in != NULL);
	c_clTRID = wrap_str(cdata->clTRID);
	if (c_clTRID == NULL)
		return CORBA_INT_ERROR;

	/* get number of contacts */
	len = q_length(check->ids);
	c_ids = ccReg_Check__alloc();
	if (c_ids == NULL) {
		CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}
	c_ids->_buffer = ccReg_Check_allocbuf(len);
	if (c_ids->_buffer == NULL) {
		CORBA_free(c_ids);
		CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}
	c_ids->_maximum = c_ids->_length = len;
	c_ids->_release = CORBA_TRUE;
	/* copy each requested object in corba buffer */
	i = 0;
	q_foreach(&check->ids) {
		c_ids->_buffer[i] = wrap_str(q_content(&check->ids));
		if (c_ids->_buffer[i++] == NULL) {
			CORBA_free(c_ids);
			CORBA_free(c_clTRID);
			return CORBA_INT_ERROR;
		}
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		if (obj == EPP_CONTACT)
			response = ccReg_EPP_ContactCheck(globs->service,
					c_ids,
					&c_avails,
					session,
					c_clTRID,
					cdata->xml_in,
					ev);
		else if (obj == EPP_DOMAIN)
			response = ccReg_EPP_DomainCheck(globs->service,
					c_ids,
					&c_avails,
					session,
					c_clTRID,
					cdata->xml_in,
					ev);
		else {
			assert(obj == EPP_NSSET);
			response = ccReg_EPP_NSSetCheck(globs->service,
					c_ids,
					&c_avails,
					session,
					c_clTRID,
					cdata->xml_in,
					ev);
		}

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_clTRID);
	CORBA_free(c_ids);

	if (raised_exception(ev)) {
		int	ret;

		if (IS_INTSERV_ERROR(ev)) {
			ret  = CORBA_REMOTE_ERROR;
		}
		else {
			ret  = CORBA_ERROR;
		}
		CORBA_exception_free(ev);
		return ret;
	}

	/*
	 * Length of results returned should be same as lenght of input
	 * objects.
	 *
	 * TODO: after logging will be in place, turn assert into error!
	 */
	assert(len == c_avails->_length);

	for (i = 0; i < c_avails->_length; i++) {
		epp_avail	*avail;
		int	cerrno;

		CLEAR_CERRNO(cerrno);

		avail = epp_malloc(pool, sizeof *avail);
		if (avail == NULL)
			break;

		avail->avail =
			(c_avails->_buffer[i].avail == ccReg_NotExist) ? 1 : 0;
		avail->reason = unwrap_str(pool, c_avails->_buffer[i].reason,
				&cerrno);
		if (cerrno != 0)
			break;

		/*
		 * TODO: after logging will be in place, turn assert into error!
		 */
		assert(avail->avail || (!avail->avail && avail->reason != NULL));
		if (q_add(pool, &check->avails, avail))
			break;
	}
	/* handle situation when allocation in for-cycle above failed */
	if (i < c_avails->_length) {
		CORBA_free(c_avails);
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}
	CORBA_free(c_avails);

	if (corba_call_epilog(pool, cdata, response))
		return CORBA_INT_ERROR;

	return CORBA_OK;
}

/**
 * EPP info contact.
 *
 * @param pool    Pool for memory allocations.
 * @param globs   Corba context.
 * @param session Session identifier.
 * @param cdata   Data from xml request.
 * @return        Status.
 */
static corba_status
epp_call_info_contact(void *pool,
		epp_corba_globs *globs,
		int session,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	CORBA_char	*c_clTRID;
	ccReg_Contact	*c_contact;
	ccReg_Response	*response;
	int	i, retr, cerrno;
	epps_info_contact	*info_contact;

	info_contact = cdata->data;
	/*
	 * Input parameters:
	 *    id (a)
	 *    session
	 *    c_clTRID (*)
	 *    xml_in (a)
	 * Output parameters:
	 *    c_contact (*)
	 */
	assert(cdata->xml_in);
	assert(info_contact->id);
	c_clTRID = wrap_str(cdata->clTRID);
	if (c_clTRID == NULL)
		return CORBA_INT_ERROR;

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		/* get information about contact from central repository */
		response = ccReg_EPP_ContactInfo(globs->service,
				info_contact->id,
				&c_contact,
				session,
				c_clTRID,
				cdata->xml_in,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_clTRID);

	if (raised_exception(ev)) {
		int	ret;

		if (IS_INTSERV_ERROR(ev)) {
			ret  = CORBA_REMOTE_ERROR;
		}
		else {
			ret  = CORBA_ERROR;
		}
		CORBA_exception_free(ev);
		return ret;
	}

	CLEAR_CERRNO(cerrno);

	/* ok, now everything was successfully allocated */
	info_contact->roid = unwrap_str_req(pool, c_contact->ROID, &cerrno);
	if (cerrno != 0) goto error;
	info_contact->handle = unwrap_str_req(pool, c_contact->handle, &cerrno);
	if (cerrno != 0) goto error;
	info_contact->authInfo = unwrap_str(pool, c_contact->AuthInfoPw,&cerrno);
	if (cerrno != 0) goto error;
	info_contact->clID = unwrap_str_req(pool, c_contact->ClID, &cerrno);
	if (cerrno != 0) goto error;
	info_contact->crID = unwrap_str_req(pool, c_contact->CrID, &cerrno);
	if (cerrno != 0) goto error;
	info_contact->upID = unwrap_str(pool, c_contact->UpID, &cerrno);
	if (cerrno != 0) goto error;
	info_contact->crDate = unwrap_str_req(pool, c_contact->CrDate, &cerrno);
	if (cerrno != 0) goto error;
	info_contact->upDate = unwrap_str(pool, c_contact->UpDate, &cerrno);
	if (cerrno != 0) goto error;
	info_contact->trDate = unwrap_str(pool, c_contact->TrDate, &cerrno);
	if (cerrno != 0) goto error;
	/* contact status */
	for (i = 0; i < c_contact->stat._length; i++) {
		char	*status;

		status = unwrap_str_req(pool, c_contact->stat._buffer[i],
						&cerrno);
		if (cerrno != 0) goto error;
		if (q_add(pool, &info_contact->status, status))
			goto error;
	}
	/* postal info */
	info_contact->pi.name = unwrap_str_req(pool, c_contact->Name, &cerrno);
	if (cerrno != 0) goto error;
	info_contact->pi.org = unwrap_str(pool, c_contact->Organization,&cerrno);
	if (cerrno != 0) goto error;
	info_contact->pi.street[0] = unwrap_str(pool, c_contact->Street1,
			&cerrno);
	if (cerrno != 0) goto error;
	info_contact->pi.street[1] = unwrap_str(pool, c_contact->Street2,
			&cerrno);
	if (cerrno != 0) goto error;
	info_contact->pi.street[2] = unwrap_str(pool, c_contact->Street3,
			&cerrno);
	if (cerrno != 0) goto error;
	info_contact->pi.city = unwrap_str_req(pool, c_contact->City, &cerrno);
	if (cerrno != 0) goto error;
	info_contact->pi.sp = unwrap_str(pool, c_contact->StateOrProvince,
			&cerrno);
	if (cerrno != 0) goto error;
	info_contact->pi.pc = unwrap_str(pool, c_contact->PostalCode, &cerrno);
	if (cerrno != 0) goto error;
	info_contact->pi.cc = unwrap_str_req(pool, c_contact->CountryCode,
			&cerrno);
	if (cerrno != 0) goto error;
	/* other attributes */
	info_contact->voice = unwrap_str(pool, c_contact->Telephone, &cerrno);
	if (cerrno != 0) goto error;
	info_contact->fax = unwrap_str(pool, c_contact->Fax, &cerrno);
	if (cerrno != 0) goto error;
	info_contact->email = unwrap_str_req(pool, c_contact->Email, &cerrno);
	if (cerrno != 0) goto error;
	info_contact->notify_email = unwrap_str(pool, c_contact->NotifyEmail,
			&cerrno);
	if (cerrno != 0) goto error;
	info_contact->vat = unwrap_str(pool, c_contact->VAT, &cerrno);
	if (cerrno != 0) goto error;
	info_contact->ssn = unwrap_str(pool, c_contact->SSN, &cerrno);
	if (cerrno != 0) goto error;
	/* convert ssntype from idl's enum to our enum */
	switch (c_contact->SSNtype) {
		case ccReg_RC:
			info_contact->ssntype = SSN_RC;
			break;
		case ccReg_OP:
			info_contact->ssntype = SSN_OP;
			break;
		case ccReg_PASS:
			info_contact->ssntype = SSN_PASSPORT;
			break;
		case ccReg_MPSV:
			info_contact->ssntype = SSN_MPSV;
			break;
		case ccReg_ICO:
			info_contact->ssntype = SSN_ICO;
			break;
		default:
			info_contact->ssntype = SSN_UNKNOWN;
			break;
	}
	/* disclose info */
	if (c_contact->DiscloseFlag == ccReg_DISCL_HIDE)
		info_contact->discl.flag = 0;
	else if (c_contact->DiscloseFlag == ccReg_DISCL_DISPLAY)
		info_contact->discl.flag = 1;
	else
		info_contact->discl.flag = -1;
	/* init discl values only if there is exceptional behaviour */
	if (info_contact->discl.flag != -1) {
		info_contact->discl.name =
			(c_contact->DiscloseName == CORBA_TRUE) ? 1 : 0;
		info_contact->discl.org =
			(c_contact->DiscloseOrganization == CORBA_TRUE) ? 1 : 0;
		info_contact->discl.addr =
			(c_contact->DiscloseAddress == CORBA_TRUE) ? 1 : 0;
		info_contact->discl.voice =
			(c_contact->DiscloseTelephone == CORBA_TRUE) ? 1 : 0;
		info_contact->discl.fax =
			(c_contact->DiscloseFax == CORBA_TRUE) ? 1 : 0;
		info_contact->discl.email =
			(c_contact->DiscloseEmail == CORBA_TRUE) ? 1 : 0;
	}

	CORBA_free(c_contact);
	if (corba_call_epilog(pool, cdata, response))
		return CORBA_INT_ERROR;

	return CORBA_OK;

error:
	CORBA_free(c_contact);
	CORBA_free(response);
	return CORBA_INT_ERROR;
}

/**
 * EPP info domain.
 *
 * @param pool    Pool for memory allocations.
 * @param globs   Corba context.
 * @param session Session identifier.
 * @param cdata   Data from xml request.
 * @return        Status.
 */
static corba_status
epp_call_info_domain(void *pool,
		epp_corba_globs *globs,
		int session,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	CORBA_char	*c_clTRID;
	ccReg_Response	*response;
	ccReg_Domain	*c_domain;
	int	i, retr, cerrno;
	epps_info_domain	*info_domain;

	info_domain = cdata->data;
	/*
	 * Input parameters:
	 *    name (a)
	 *    session
	 *    c_clTRID (*)
	 *    xml_in (a)
	 * Output parameters:
	 *    c_domain (*)
	 */
	assert(info_domain->name);
	assert(cdata->xml_in);
	c_clTRID = wrap_str(cdata->clTRID);
	if (c_clTRID == NULL)
		return CORBA_INT_ERROR;

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		/* get information about domain */
		response = ccReg_EPP_DomainInfo(globs->service,
				info_domain->name,
				&c_domain,
				session,
				c_clTRID,
				cdata->xml_in,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_clTRID);

	if (raised_exception(ev)) {
		int	ret;

		if (IS_INTSERV_ERROR(ev)) {
			ret  = CORBA_REMOTE_ERROR;
		}
		else {
			ret  = CORBA_ERROR;
		}
		CORBA_exception_free(ev);
		return ret;
	}

	CLEAR_CERRNO(cerrno);

	/* copy output parameters */
	info_domain->roid   = unwrap_str_req(pool, c_domain->ROID, &cerrno);
	if (cerrno != 0) goto error;
	info_domain->handle = unwrap_str_req(pool, c_domain->name, &cerrno);
	if (cerrno != 0) goto error;
	info_domain->clID   = unwrap_str_req(pool, c_domain->ClID, &cerrno);
	if (cerrno != 0) goto error;
	info_domain->crID   = unwrap_str_req(pool, c_domain->CrID, &cerrno);
	if (cerrno != 0) goto error;
	info_domain->upID   = unwrap_str(pool, c_domain->UpID, &cerrno);
	if (cerrno != 0) goto error;
	info_domain->crDate = unwrap_str_req(pool, c_domain->CrDate, &cerrno);
	if (cerrno != 0) goto error;
	info_domain->upDate = unwrap_str(pool, c_domain->UpDate, &cerrno);
	if (cerrno != 0) goto error;
	info_domain->trDate = unwrap_str(pool, c_domain->TrDate, &cerrno);
	if (cerrno != 0) goto error;
	info_domain->exDate = unwrap_str(pool, c_domain->ExDate, &cerrno);
	if (cerrno != 0) goto error;
	info_domain->registrant = unwrap_str(pool, c_domain->Registrant,&cerrno);
	if (cerrno != 0) goto error;
	info_domain->nsset  = unwrap_str(pool, c_domain->nsset, &cerrno);
	if (cerrno != 0) goto error;
	info_domain->authInfo = unwrap_str(pool, c_domain->AuthInfoPw, &cerrno);
	if (cerrno != 0) goto error;

	/* allocate and initialize status, admin lists */
	for (i = 0; i < c_domain->stat._length; i++) {
		char	*status;

		status = unwrap_str_req(pool, c_domain->stat._buffer[i],&cerrno);
		if (cerrno != 0) goto error;
		if (q_add(pool, &info_domain->status, status))
			goto error;
	}
	for (i = 0; i < c_domain->admin._length; i++) {
		char	*admin;

		admin = unwrap_str_req(pool, c_domain->admin._buffer[i],&cerrno);
		if (cerrno != 0) goto error;
		if (q_add(pool, &info_domain->admin, admin))
			goto error;
	}

	/* look for extensions */
	for (i = 0; i < c_domain->ext._length; i++) {
		epp_ext_item	*ext_item;

		/* is it enumval extension? */
		if (CORBA_TypeCode_equal(c_domain->ext._buffer[i]._type,
				TC_ccReg_ENUMValidationExtension, ev))
		{
			ccReg_ENUMValidationExtension	*c_enumval;

			c_enumval = c_domain->ext._buffer[i]._value;

			ext_item = epp_malloc(pool, sizeof *ext_item);
			if (ext_item == NULL) goto error;
			ext_item->extType = EPP_EXT_ENUMVAL;
			ext_item->ext.ext_enumval = unwrap_str_req(pool,
					c_enumval->valExDate, &cerrno);
			if (cerrno != 0) goto error;
			if (q_add(pool, &info_domain->extensions, ext_item))
				goto error;
		}
	}

	CORBA_free(c_domain);
	if (corba_call_epilog(pool, cdata, response))
		return CORBA_INT_ERROR;

	return CORBA_OK;

error:
	CORBA_free(c_domain);
	CORBA_free(response);
	return CORBA_INT_ERROR;
}

/**
 * EPP info nsset.
 *
 * @param pool    Pool for memory allocations.
 * @param globs   Corba context.
 * @param session Session identifier.
 * @param cdata   Data from xml request.
 * @return        Status.
 */
static corba_status
epp_call_info_nsset(void *pool,
		epp_corba_globs *globs,
		int session,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	CORBA_char	*c_clTRID;
	ccReg_NSSet	*c_nsset;
	ccReg_Response	*response;
	int	i, retr, cerrno;
	epps_info_nsset	*info_nsset;

	info_nsset = cdata->data;
	/*
	 * Input parameters:
	 *    id (a)
	 *    session
	 *    c_clTRID (*)
	 *    xml_in (a)
	 * Output parameters:
	 *    c_contact (*)
	 */
	assert(info_nsset->id);
	assert(cdata->xml_in);
	c_clTRID = wrap_str(cdata->clTRID);
	if (c_clTRID == NULL)
		return CORBA_INT_ERROR;

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		/* get information about nsset */
		response = ccReg_EPP_NSSetInfo(globs->service,
				info_nsset->id,
				&c_nsset,
				session,
				c_clTRID,
				cdata->xml_in,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_clTRID);

	if (raised_exception(ev)) {
		int	ret;

		if (IS_INTSERV_ERROR(ev)) {
			ret  = CORBA_REMOTE_ERROR;
		}
		else {
			ret  = CORBA_ERROR;
		}
		CORBA_exception_free(ev);
		return ret;
	}

	CLEAR_CERRNO(cerrno);

	/* copy output data */
	info_nsset->roid   = unwrap_str_req(pool, c_nsset->ROID, &cerrno);
	if (cerrno != 0) goto error;
	info_nsset->handle = unwrap_str_req(pool, c_nsset->handle, &cerrno);
	if (cerrno != 0) goto error;
	info_nsset->clID   = unwrap_str_req(pool, c_nsset->ClID, &cerrno);
	if (cerrno != 0) goto error;
	info_nsset->crID   = unwrap_str_req(pool, c_nsset->CrID, &cerrno);
	if (cerrno != 0) goto error;
	info_nsset->upID   = unwrap_str(pool, c_nsset->UpID, &cerrno);
	if (cerrno != 0) goto error;
	info_nsset->crDate = unwrap_str_req(pool, c_nsset->CrDate, &cerrno);
	if (cerrno != 0) goto error;
	info_nsset->upDate = unwrap_str(pool, c_nsset->UpDate, &cerrno);
	if (cerrno != 0) goto error;
	info_nsset->trDate = unwrap_str(pool, c_nsset->TrDate, &cerrno);
	if (cerrno != 0) goto error;
	info_nsset->authInfo = unwrap_str(pool, c_nsset->AuthInfoPw, &cerrno);
	if (cerrno != 0) goto error;

	/* initialize status list */
	for (i = 0; i < c_nsset->stat._length; i++) {
		char	*status;

		status = unwrap_str_req(pool, c_nsset->stat._buffer[i], &cerrno);
		if (cerrno != 0) goto error;
		if (q_add(pool, &info_nsset->status, status))
			goto error;
	}
	/* initialize tech list */
	for (i = 0; i < c_nsset->tech._length; i++) {
		char	*tech;

		tech = unwrap_str_req(pool, c_nsset->tech._buffer[i], &cerrno);
		if (cerrno != 0) goto error;
		if (q_add(pool, &info_nsset->tech, tech))
			goto error;
	}
	/* initialize required number of ns items */
	for (i = 0; i < c_nsset->dns._length; i++) {
		epp_ns	*ns_item;
		int	j;

		ns_item = epp_calloc(pool, sizeof *ns_item);
		if (ns_item == NULL) goto error;

		/* process of ns item */
		ns_item->name = unwrap_str_req(pool,
				c_nsset->dns._buffer[i].fqdn, &cerrno);
		if (cerrno != 0) goto error;
		for (j = 0; j < c_nsset->dns._buffer[i].inet._length; j++) {
			char	*addr;

			addr = unwrap_str_req(pool,
					c_nsset->dns._buffer[i].inet._buffer[j],
					&cerrno);
			if (cerrno != 0) goto error;
			if (q_add(pool, &ns_item->addr, addr))
				goto error;
		}
		/* enqueue ns item */
		if (q_add(pool, &info_nsset->ns, ns_item))
			goto error;
	}

	CORBA_free(c_nsset);
	if (corba_call_epilog(pool, cdata, response))
		return CORBA_INT_ERROR;

	return CORBA_OK;

error:
	CORBA_free(c_nsset);
	CORBA_free(response);
	return CORBA_INT_ERROR;
}

/**
 * EPP poll request.
 *
 * @param pool    Pool for memory allocations.
 * @param globs   Corba context.
 * @param session Session identifier.
 * @param cdata   Data from xml request.
 * @return        Status.
 */
static corba_status
epp_call_poll_req(void *pool,
		epp_corba_globs *globs,
		int session,
		epp_command_data *cdata)
{
	ccReg_Response	*response;
	CORBA_Environment	ev[1];
	CORBA_short	c_count;
	CORBA_char	*c_qdate, *c_msg, *c_clTRID, *c_msgID;
	int	retr, cerrno;
	epps_poll_req	*poll_req;

	poll_req = cdata->data;
	/*
	 * Input parameters:
	 *    session
	 *    c_clTRID (*)
	 *    xml_in (a)
	 * Output parameters:
	 *    c_msgID (*)
	 *    c_count
	 *    c_qdate (*)
	 *    c_msg (*)
	 */
	assert(cdata->xml_in);
	c_clTRID = wrap_str(cdata->clTRID);
	if (c_clTRID == NULL)
		return CORBA_INT_ERROR;

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		/* get message from repository */
		response = ccReg_EPP_PollRequest(globs->service,
				&c_msgID,
				&c_count,
				&c_qdate,
				&c_msg,
				session,
				c_clTRID,
				cdata->xml_in,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_clTRID);

	if (raised_exception(ev)) {
		int	ret;

		if (IS_INTSERV_ERROR(ev)) {
			ret  = CORBA_REMOTE_ERROR;
		}
		else {
			ret  = CORBA_ERROR;
		}
		CORBA_exception_free(ev);
		return ret;
	}

	CLEAR_CERRNO(cerrno);

	poll_req->count = c_count;
	poll_req->msgid = unwrap_str_req(pool, c_msgID, &cerrno);
	if (cerrno != 0) goto error;
	poll_req->qdate = unwrap_str_req(pool, c_qdate, &cerrno);
	if (cerrno != 0) goto error;
	poll_req->msg = unwrap_str_req(pool, c_msg, &cerrno);
	if (cerrno != 0) goto error;

	CORBA_free(c_msgID);
	CORBA_free(c_msg);
	CORBA_free(c_qdate);
	if (corba_call_epilog(pool, cdata, response))
		return CORBA_INT_ERROR;

	return CORBA_OK;

error:
	CORBA_free(c_msgID);
	CORBA_free(c_qdate);
	CORBA_free(c_msg);
	CORBA_free(response);
	return CORBA_OK;
}

/**
 * EPP poll acknowledge.
 *
 * @param pool    Pool for memory allocations.
 * @param globs   Corba context.
 * @param session Session identifier.
 * @param cdata   Data from xml request.
 * @return        Status.
 */
static corba_status
epp_call_poll_ack(void *pool,
		epp_corba_globs *globs,
		int session,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	CORBA_char	*c_msgID;
	CORBA_short	 c_count;
	CORBA_char	*c_clTRID;
	ccReg_Response	*response;
	int	retr, cerrno;
	epps_poll_ack	*poll_ack;

	poll_ack = cdata->data;
	/*
	 * Input parameters:
	 *    msgid (a)
	 *    session
	 *    c_clTRID (*)
	 *    xml_in (a)
	 * Output parameters:
	 *    c_count
	 *    c_msgID (*)
	 */
	assert(poll_ack->msgid);
	assert(cdata->xml_in);
	c_clTRID = wrap_str(cdata->clTRID);
	if (c_clTRID == NULL)
		return CORBA_INT_ERROR;

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		/* send acknoledgement */
		response = ccReg_EPP_PollAcknowledgement(globs->service,
				poll_ack->msgid,
				&c_count,
				&c_msgID,
				session,
				c_clTRID,
				cdata->xml_in,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_clTRID);

	if (raised_exception(ev)) {
		int	ret;

		if (IS_INTSERV_ERROR(ev)) {
			ret  = CORBA_REMOTE_ERROR;
		}
		else {
			ret  = CORBA_ERROR;
		}
		CORBA_exception_free(ev);
		return ret;
	}

	CLEAR_CERRNO(cerrno);

	poll_ack->count = c_count;
	poll_ack->msgid = unwrap_str_req(pool, c_msgID, &cerrno);
	if (cerrno != 0) goto error;

	CORBA_free(c_msgID);
	if (corba_call_epilog(pool, cdata, response))
		return CORBA_INT_ERROR;

	return CORBA_OK;

error:
	CORBA_free(c_msgID);
	CORBA_free(response);
	return CORBA_INT_ERROR;
}

/**
 * EPP create domain.
 *
 * @param pool    Pool for memory allocations.
 * @param globs   Corba context.
 * @param session Session identifier.
 * @param cdata   Data from xml request.
 * @return        Status.
 */
static corba_status
epp_call_create_domain(void *pool,
		epp_corba_globs *globs,
		int session,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	CORBA_char	*c_crDate, *c_exDate;
	CORBA_char	*c_registrant, *c_nsset, *c_authInfo, *c_clTRID;
	ccReg_Response	*response;
	ccReg_AdminContact	*c_admin;
	ccReg_ExtensionList	*c_ext_list;
	int	len, i, retr, cerrno;
	epps_create_domain	*create_domain;

	create_domain = cdata->data;
	/* init corba input parameters to NULL, because CORBA_free(NULL) is ok */
	c_ext_list = NULL;
	c_admin = NULL;
	c_authInfo = NULL;
	c_nsset = NULL;
	c_registrant = NULL;
	c_clTRID = NULL;
	c_admin = NULL;
	c_ext_list = NULL;
	/*
	 * Input parameters:
	 *    name (a)
	 *    c_registrant (*)
	 *    c_nsset    (*)
	 *    c_authInfo (*)
	 *    period
	 *    c_admin  (*)
	 *    session
	 *    c_clTRID (*)
	 *    xml_in (a)
	 *    c_ext_list (*)
	 * Output parameters:
	 *    c_crDate (*)
	 *    c_exDate (*)
	 */
	assert(create_domain->name);
	assert(cdata->xml_in);
	c_clTRID = wrap_str(cdata->clTRID);
	if (c_clTRID == NULL) goto error_input;
	c_registrant = wrap_str(create_domain->registrant);
	if (c_registrant == NULL) goto error_input;
	c_nsset = wrap_str(create_domain->nsset);
	if (c_nsset == NULL) goto error_input;
	c_authInfo = wrap_str(create_domain->authInfo);
	if (c_authInfo == NULL) goto error_input;
	c_admin = ccReg_AdminContact__alloc();
	if (c_admin == NULL) goto error_input;
	len = q_length(create_domain->admin);
	c_admin->_buffer = ccReg_AdminContact_allocbuf(len);
	if (c_admin->_buffer == NULL) goto error_input;
	c_admin->_maximum = c_admin->_length = len;
	c_admin->_release = CORBA_TRUE;
	i = 0;
	q_foreach(&create_domain->admin) {
		c_admin->_buffer[i] = wrap_str(q_content(&create_domain->admin));
		if (c_admin->_buffer[i++] == NULL) goto error_input;
	}
	c_ext_list = ccReg_ExtensionList__alloc();
	if (c_ext_list == NULL) goto error_input;
	len = q_length(create_domain->extensions);
	c_ext_list->_buffer = ccReg_ExtensionList_allocbuf(len);
	if (c_ext_list->_buffer == NULL) goto error_input;
	c_ext_list->_release = CORBA_TRUE;
	c_ext_list->_maximum = c_ext_list->_length = len;
	/* fill extension list */
	i = 0;
	q_foreach(&create_domain->extensions) {
		epp_ext_item	*ext_item;

		ext_item = q_content(&create_domain->extensions);
		if (ext_item->extType == EPP_EXT_ENUMVAL) {
			ccReg_ENUMValidationExtension	*c_enumval;

			c_enumval = ccReg_ENUMValidationExtension__alloc();
			if (c_enumval == NULL) goto error_input;
			c_enumval->valExDate =
				wrap_str(ext_item->ext.ext_enumval);
			if (c_enumval->valExDate == NULL) {
				CORBA_free(c_enumval);
				goto error_input;
			}
			c_ext_list->_buffer[i]._type =
				TC_ccReg_ENUMValidationExtension;
			c_ext_list->_buffer[i]._value = c_enumval;
			c_ext_list->_buffer[i]._release = CORBA_TRUE;
		}
		i++;
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		/* send new domain in central repository */
		response = ccReg_EPP_DomainCreate(globs->service,
				create_domain->name,
				c_registrant,
				c_nsset,
				c_authInfo,
				create_domain->period,
				c_admin,
				&c_crDate,
				&c_exDate,
				session,
				c_clTRID,
				cdata->xml_in,
				c_ext_list,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_ext_list);
	CORBA_free(c_admin);
	CORBA_free(c_authInfo);
	CORBA_free(c_nsset);
	CORBA_free(c_registrant);
	CORBA_free(c_clTRID);
	CORBA_free(c_admin);
	CORBA_free(c_ext_list);

	if (raised_exception(ev)) {
		int	ret;

		if (IS_INTSERV_ERROR(ev)) {
			ret  = CORBA_REMOTE_ERROR;
		}
		else {
			ret  = CORBA_ERROR;
		}
		CORBA_exception_free(ev);
		return ret;
	}

	CLEAR_CERRNO(cerrno);

	create_domain->crDate = unwrap_str_req(pool, c_crDate, &cerrno);
	if (cerrno != 0) goto error;
	create_domain->exDate = unwrap_str_req(pool, c_exDate, &cerrno);
	if (cerrno != 0) goto error;

	CORBA_free(c_crDate);
	CORBA_free(c_exDate);
	if (corba_call_epilog(pool, cdata, response))
		return CORBA_INT_ERROR;

	return CORBA_OK;

error:
	CORBA_free(c_crDate);
	CORBA_free(c_exDate);
	CORBA_free(response);
	return CORBA_INT_ERROR;

error_input:
	CORBA_free(c_ext_list);
	CORBA_free(c_admin);
	CORBA_free(c_authInfo);
	CORBA_free(c_nsset);
	CORBA_free(c_registrant);
	CORBA_free(c_clTRID);
	CORBA_free(c_admin);
	CORBA_free(c_ext_list);
	return CORBA_INT_ERROR;
}

/**
 * Convert our SSN enum to IDL's SSNtyp enum.
 *
 * @param our_ssn Our ssn's type.
 * @return        SSN type as defined in IDL.
 */
static ccReg_SSNtyp
convSSNType(epp_ssnType our_ssn)
{
	switch (our_ssn) {
		case SSN_ICO: return ccReg_ICO; break;
		case SSN_OP: return ccReg_OP; break;
		case SSN_RC: return ccReg_RC; break;
		case SSN_PASSPORT: return ccReg_PASS; break;
		case SSN_MPSV: return ccReg_MPSV; break;
		default: return ccReg_EMPTY; break;
	}
}

/**
 * Function for conversion of our disclose flag to IDL's disclose flag.
 *
 * @param flag Disclose flag to be converted.
 * @return     Disclose flag of type defined in IDL.
 */
static ccReg_Disclose
convDiscl(char flag)
{
	switch (flag) {
		case  1: return ccReg_DISCL_DISPLAY; break;
		case  0: return ccReg_DISCL_HIDE; break;
		case -1: return ccReg_DISCL_EMPTY; break;
		default: assert(0); break;
	}
	/* never reached */
	return ccReg_DISCL_EMPTY;
}

/**
 * EPP create contact.
 *
 * @param pool    Pool for memory allocations.
 * @param globs   Corba context.
 * @param session Session identifier.
 * @param cdata   Data from xml request.
 * @return        Status.
 */
static corba_status
epp_call_create_contact(void *pool,
		epp_corba_globs *globs,
		int session,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	CORBA_char	*c_crDate, *c_clTRID;
	ccReg_ContactChange	*c_contact;
	ccReg_Response *response;
	int	retr, cerrno;
	epps_create_contact	*create_contact;

	create_contact = cdata->data;
	/*
	 * Input parameters:
	 *    id (a)
	 *    c_contact (*)
	 *    session
	 *    c_clTRID (*)
	 *    xml_in (a)
	 * Output parameters:
	 *    c_crDate (*)
	 */
	assert(create_contact->id);
	assert(cdata->xml_in);
	c_clTRID = wrap_str(cdata->clTRID);
	if (c_clTRID == NULL)
		return CORBA_INT_ERROR;

	/* fill in corba input values */
	c_contact = ccReg_ContactChange__alloc();
	if (c_contact == NULL) {
		CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}
	c_contact->AuthInfoPw = wrap_str(create_contact->authInfo);
	if (c_contact->AuthInfoPw == NULL) {
		CORBA_free(c_contact);
		CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}
	c_contact->Telephone = wrap_str(create_contact->voice);
	if (c_contact->AuthInfoPw == NULL) {
		CORBA_free(c_contact);
		CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}
	c_contact->Fax = wrap_str(create_contact->fax);
	if (c_contact->Fax == NULL) {
		CORBA_free(c_contact);
		CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}
	c_contact->Email = wrap_str(create_contact->email);
	if (c_contact->Email == NULL) {
		CORBA_free(c_contact);
		CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}
	c_contact->NotifyEmail =
			wrap_str(create_contact->notify_email);
	if (c_contact->NotifyEmail == NULL) {
		CORBA_free(c_contact);
		CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}
	c_contact->VAT = wrap_str(create_contact->vat);
	if (c_contact->VAT == NULL) {
		CORBA_free(c_contact);
		CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}
	c_contact->SSN = wrap_str(create_contact->ssn);
	if (c_contact->SSN == NULL) {
		CORBA_free(c_contact);
		CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}
	c_contact->SSNtype = convSSNType(create_contact->ssntype);
	/* disclose */
	c_contact->DiscloseFlag = convDiscl(create_contact->discl.flag);
	if (c_contact->DiscloseFlag != ccReg_DISCL_EMPTY) {
		c_contact->DiscloseName =
			(create_contact->discl.name ? CORBA_TRUE : CORBA_FALSE);
		c_contact->DiscloseOrganization =
			(create_contact->discl.org ? CORBA_TRUE :CORBA_FALSE);
		c_contact->DiscloseAddress =
			(create_contact->discl.addr ? CORBA_TRUE : CORBA_FALSE);
		c_contact->DiscloseTelephone =
			(create_contact->discl.voice ? CORBA_TRUE : CORBA_FALSE);
		c_contact->DiscloseFax =
			(create_contact->discl.fax ? CORBA_TRUE : CORBA_FALSE);
		c_contact->DiscloseEmail =
			(create_contact->discl.email ? CORBA_TRUE : CORBA_FALSE);
	}
	/* postal info */
	c_contact->Name = wrap_str(create_contact->pi.name);
	if (c_contact->Name == NULL) {
		CORBA_free(c_contact);
		CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}
	c_contact->Organization = wrap_str(create_contact->pi.org);
	if (c_contact->Organization == NULL) {
		CORBA_free(c_contact);
		CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}
	c_contact->Street1 = wrap_str(create_contact->pi.street[0]);
	if (c_contact->Street1 == NULL) {
		CORBA_free(c_contact);
		CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}
	c_contact->Street2 = wrap_str(create_contact->pi.street[1]);
	if (c_contact->Street2 == NULL) {
		CORBA_free(c_contact);
		CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}
	c_contact->Street3 = wrap_str(create_contact->pi.street[2]);
	if (c_contact->Street3 == NULL) {
		CORBA_free(c_contact);
		CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}
	c_contact->City = wrap_str(create_contact->pi.city);
	if (c_contact->City == NULL) {
		CORBA_free(c_contact);
		CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}
	c_contact->StateOrProvince = wrap_str(create_contact->pi.sp);
	if (c_contact->StateOrProvince == NULL) {
		CORBA_free(c_contact);
		CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}
	c_contact->PostalCode = wrap_str(create_contact->pi.pc);
	if (c_contact->PostalCode == NULL) {
		CORBA_free(c_contact);
		CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}
	c_contact->CC = wrap_str(create_contact->pi.cc);
	if (c_contact->CC == NULL) {
		CORBA_free(c_contact);
		CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		/* send new contact in repository */
		response = ccReg_EPP_ContactCreate(globs->service,
				create_contact->id,
				c_contact,
				&c_crDate,
				session,
				c_clTRID,
				cdata->xml_in,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_clTRID);
	CORBA_free(c_contact);

	if (raised_exception(ev)) {
		int	ret;

		if (IS_INTSERV_ERROR(ev)) {
			ret  = CORBA_REMOTE_ERROR;
		}
		else {
			ret  = CORBA_ERROR;
		}
		CORBA_exception_free(ev);
		return ret;
	}

	CLEAR_CERRNO(cerrno);

	create_contact->crDate = unwrap_str_req(pool, c_crDate, &cerrno);
	if (cerrno != 0) {
		CORBA_free(c_crDate);
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}

	CORBA_free(c_crDate);
	if (corba_call_epilog(pool, cdata, response))
		return CORBA_INT_ERROR;

	return CORBA_OK;
}

/**
 * EPP create nsset.
 *
 * @param pool    Pool for memory allocations.
 * @param globs   Corba context.
 * @param session Session identifier.
 * @param cdata   Data from xml request.
 * @return        Status.
 */
static corba_status
epp_call_create_nsset(void *pool,
		epp_corba_globs *globs,
		int session,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	ccReg_Response *response;
	ccReg_DNSHost	*c_dnshost;
	ccReg_TechContact	*c_tech;
	CORBA_char	*c_crDate, *c_clTRID, *c_authInfo;
	int	len, i, retr, cerrno;
	epps_create_nsset	*create_nsset;

	create_nsset = cdata->data;
	/*
	 * Input parameters:
	 *    id (a)
	 *    c_authInfo (*)
	 *    c_tech (*)
	 *    c_dnshost (*)
	 *    session
	 *    c_clTRID (*)
	 *    xml_in (a)
	 * Output parameters:
	 *    c_crDate (*)
	 */
	assert(create_nsset->id != NULL);
	assert(cdata->xml_in != NULL);

	c_clTRID = wrap_str(cdata->clTRID);
	if (c_clTRID == NULL)
		return CORBA_INT_ERROR;
	c_authInfo = wrap_str(create_nsset->authInfo);
	if (c_authInfo == NULL) {
		CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}

	/* alloc & init sequence of nameservers */
	c_dnshost = ccReg_DNSHost__alloc();
	if (c_dnshost == NULL) {
		CORBA_free(c_authInfo);
		CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}
	len = q_length(create_nsset->ns);
	c_dnshost->_buffer = ccReg_DNSHost_allocbuf(len);
	if (c_dnshost->_buffer == NULL) {
		CORBA_free(c_dnshost);
		CORBA_free(c_authInfo);
		CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}
	c_dnshost->_maximum = c_dnshost->_length = len;
	c_dnshost->_release = CORBA_TRUE;
	i = 0;
	q_foreach(&create_nsset->ns) {
		epp_ns	*ns;
		int	 j;

		ns = q_content(&create_nsset->ns);
		c_dnshost->_buffer[i].fqdn = wrap_str(ns->name);
		if (c_dnshost->_buffer[i].fqdn == NULL) {
			CORBA_free(c_dnshost);
			CORBA_free(c_authInfo);
			CORBA_free(c_clTRID);
			return CORBA_INT_ERROR;
		}
		/* initialize sequence of addresses */
		len = q_length(ns->addr);
		c_dnshost->_buffer[i].inet._buffer =
			ccReg_InetAddress_allocbuf(len);
		if (c_dnshost->_buffer[i].inet._buffer == NULL) {
			CORBA_free(c_dnshost);
			CORBA_free(c_authInfo);
			CORBA_free(c_clTRID);
			return CORBA_INT_ERROR;
		}
		c_dnshost->_buffer[i].inet._maximum =
			c_dnshost->_buffer[i].inet._length = len;
		c_dnshost->_buffer[i].inet._release = CORBA_TRUE;
		j = 0;
		q_foreach(&ns->addr) {
			c_dnshost->_buffer[i].inet._buffer[j] =
					wrap_str(q_content(&ns->addr));
			if (c_dnshost->_buffer[i].inet._buffer[j++] == NULL) {
				CORBA_free(c_dnshost);
				CORBA_free(c_authInfo);
				CORBA_free(c_clTRID);
				return CORBA_INT_ERROR;
			}
		}
		i++;
	}
	/* alloc & init sequence of tech contacts */
	c_tech = ccReg_TechContact__alloc();
	if (c_tech == NULL) {
		CORBA_free(c_dnshost);
		CORBA_free(c_authInfo);
		CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}
	len = q_length(create_nsset->tech);
	c_tech->_buffer = ccReg_TechContact_allocbuf(len);
	if (c_tech->_buffer == NULL) {
		CORBA_free(c_tech);
		CORBA_free(c_dnshost);
		CORBA_free(c_authInfo);
		CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}
	c_tech->_release = CORBA_TRUE;
	c_tech->_maximum = c_tech->_length = len;
	i = 0;
	q_foreach(&create_nsset->tech) {
		c_tech->_buffer[i] = wrap_str(q_content(&create_nsset->tech));
		if (c_tech->_buffer[i++] == NULL) {
			CORBA_free(c_tech);
			CORBA_free(c_dnshost);
			CORBA_free(c_authInfo);
			CORBA_free(c_clTRID);
			return CORBA_INT_ERROR;
		}
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		/* send new nsset to repository */
		response = ccReg_EPP_NSSetCreate(globs->service,
				create_nsset->id,
				c_authInfo,
				c_tech,
				c_dnshost,
				&c_crDate,
				session,
				c_clTRID,
				cdata->xml_in,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_tech);
	CORBA_free(c_dnshost);
	CORBA_free(c_authInfo);
	CORBA_free(c_clTRID);

	if (raised_exception(ev)) {
		int	ret;

		if (IS_INTSERV_ERROR(ev)) {
			ret  = CORBA_REMOTE_ERROR;
		}
		else {
			ret  = CORBA_ERROR;
		}
		CORBA_exception_free(ev);
		return ret;
	}

	CLEAR_CERRNO(cerrno);

	create_nsset->crDate = unwrap_str(pool, c_crDate, &cerrno);
	if (cerrno != 0) {
		CORBA_free(c_crDate);
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}

	CORBA_free(c_crDate);
	if (corba_call_epilog(pool, cdata, response))
		return CORBA_INT_ERROR;

	return CORBA_OK;
}

/**
 * EPP delete for domain, nsset and contact is so similar that it is worth of
 * having the code in one function and pass object type as parameter.
 *
 * @param pool    Pool for memory allocations.
 * @param globs   Corba context.
 * @param session Session identifier.
 * @param cdata   Data from xml request.
 * @param obj     Object type (see #epp_object_type)
 * @return        Status.
 */
static corba_status
epp_call_delete(void *pool,
		epp_corba_globs *globs,
		int session,
		epp_command_data *cdata,
		epp_object_type obj)
{
	CORBA_char	*c_clTRID;
	CORBA_Environment ev[1];
	ccReg_Response *response;
	int	retr;
	epps_delete	*delete;

	delete = cdata->data;
	/*
	 * Input parameters:
	 *    id (a)
	 *    session
	 *    c_clTRID (*)
	 *    xml_in (a)
	 * Output parameters: none
	 */
	assert(delete->id);
	assert(cdata->xml_in);
	c_clTRID = wrap_str(cdata->clTRID);
	if (c_clTRID == NULL)
		return CORBA_INT_ERROR;

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		if (obj == EPP_DOMAIN)
			response = ccReg_EPP_DomainDelete(globs->service,
					delete->id,
					session,
					c_clTRID,
					cdata->xml_in,
					ev);
		else if (obj == EPP_CONTACT)
			response = ccReg_EPP_ContactDelete(globs->service,
					delete->id,
					session,
					c_clTRID,
					cdata->xml_in,
					ev);
		else {
			assert(obj == EPP_NSSET);
			response = ccReg_EPP_NSSetDelete(globs->service,
					delete->id,
					session,
					c_clTRID,
					cdata->xml_in,
					ev);
		}

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

	if (raised_exception(ev)) {
		int	ret;

		if (IS_INTSERV_ERROR(ev)) {
			ret  = CORBA_REMOTE_ERROR;
		}
		else {
			ret  = CORBA_ERROR;
		}
		CORBA_exception_free(ev);
		return ret;
	}

	if (corba_call_epilog(pool, cdata, response))
		return CORBA_INT_ERROR;

	return CORBA_OK;
}

/**
 * EPP renew domain.
 *
 * @param pool    Pool for memory allocations.
 * @param globs   Corba context.
 * @param session Session identifier.
 * @param cdata   Data from xml request.
 * @return        Status.
 */
static corba_status
epp_call_renew_domain(void *pool,
		epp_corba_globs *globs,
		int session,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	ccReg_Response	*response;
	CORBA_char	*c_exDateIN, *c_exDateOUT, *c_clTRID;
	ccReg_ExtensionList	*c_ext_list;
	int	len, i, retr, cerrno;
	epps_renew	*renew;

	renew = cdata->data;
	/*
	 * Input parameters:
	 *    name (a)
	 *    c_exDateIN (*)
	 *    period
	 *    session
	 *    c_clTRID (*)
	 *    xml_in (a)
	 *    c_ext_list (*)
	 * Output parameters:
	 *    c_exDateOUT (*)
	 */
	assert(renew->name);
	assert(cdata->xml_in);

	c_clTRID = wrap_str(cdata->clTRID);
	if (c_clTRID == NULL)
		return CORBA_INT_ERROR;
	c_exDateIN = wrap_str(renew->curExDate);
	if (c_exDateIN == NULL) {
		CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}
	/* fill extension list */
	c_ext_list = ccReg_ExtensionList__alloc();
	if (c_ext_list == NULL) {
		CORBA_free(c_exDateIN);
		CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}
	len = q_length(renew->extensions);
	c_ext_list->_buffer = ccReg_ExtensionList_allocbuf(len);
	if (c_ext_list->_buffer == NULL) {
		CORBA_free(c_ext_list);
		CORBA_free(c_exDateIN);
		CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}
	c_ext_list->_maximum = c_ext_list->_length = len;
	c_ext_list->_release = CORBA_TRUE;
	i = 0;
	q_foreach(&renew->extensions) {
		epp_ext_item	*ext_item;

		ext_item = q_content(&renew->extensions);
		if (ext_item->extType == EPP_EXT_ENUMVAL) {
			ccReg_ENUMValidationExtension	*c_enumval;

			c_enumval = ccReg_ENUMValidationExtension__alloc();
			if (c_enumval == NULL) {
				CORBA_free(c_ext_list);
				CORBA_free(c_exDateIN);
				CORBA_free(c_clTRID);
				return CORBA_INT_ERROR;
			}
			c_enumval->valExDate =
				wrap_str(ext_item->ext.ext_enumval);
			if (c_enumval->valExDate == NULL) {
				CORBA_free(c_enumval);
				CORBA_free(c_ext_list);
				CORBA_free(c_exDateIN);
				CORBA_free(c_clTRID);
				return CORBA_INT_ERROR;
			}
			c_ext_list->_buffer[i]._type =
				TC_ccReg_ENUMValidationExtension;
			c_ext_list->_buffer[i]._value = c_enumval;
			c_ext_list->_buffer[i]._release = CORBA_TRUE;
		}
		i++;
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		/* send renew request to repository */
		response = ccReg_EPP_DomainRenew(globs->service,
				renew->name,
				c_exDateIN,
				renew->period,
				&c_exDateOUT,
				session,
				c_clTRID,
				cdata->xml_in,
				c_ext_list,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_ext_list);
	CORBA_free(c_exDateIN);
	CORBA_free(c_clTRID);

	if (raised_exception(ev)) {
		int	ret;

		if (IS_INTSERV_ERROR(ev)) {
			ret  = CORBA_REMOTE_ERROR;
		}
		else {
			ret  = CORBA_ERROR;
		}
		CORBA_exception_free(ev);
		return ret;
	}

	CLEAR_CERRNO(cerrno);

	renew->exDate = unwrap_str_req(pool, c_exDateOUT, &cerrno);
	if (cerrno != 0) {
		CORBA_free(c_exDateOUT);
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}
	CORBA_free(c_exDateOUT);

	if (corba_call_epilog(pool, cdata, response))
		return CORBA_INT_ERROR;

	return CORBA_OK;
}

/**
 * EPP update domain.
 *
 * @param pool    Pool for memory allocations.
 * @param globs   Corba context.
 * @param session Session identifier.
 * @param cdata   Data from xml request.
 * @return        status.
 */
static corba_status
epp_call_update_domain(void *pool,
		epp_corba_globs *globs,
		int session,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	CORBA_char	*c_clTRID, *c_registrant, *c_authInfo, *c_nsset;
	ccReg_Response	*response;
	ccReg_Status	*c_status_add, *c_status_rem;
	ccReg_AdminContact	*c_admin_add, *c_admin_rem;
	ccReg_ExtensionList	*c_ext_list;
	int	i, len, retr;
	epps_update_domain	*update_domain;

	update_domain = cdata->data;
	c_clTRID     = NULL;
	c_registrant = NULL;
	c_authInfo   = NULL;
	c_nsset      = NULL;
	c_status_rem = NULL;
	c_status_add = NULL;
	c_admin_rem  = NULL;
	c_admin_add  = NULL;
	c_ext_list   = NULL;
	/*
	 * Input parameters:
	 *    name         (a)
	 *    c_registrant (*)
	 *    c_authInfo   (*)
	 *    c_nsset      (*)
	 *    c_admin_add  (*)
	 *    c_admin_rem  (*)
	 *    c_status_add (*)
	 *    c_status_rem (*)
	 *    session
	 *    c_clTRID     (*)
	 *    xml_in       (a)
	 *    c_ext_list   (*)
	 * Output parameters: none
	 */
	assert(update_domain->name);
	assert(cdata->xml_in);

	c_clTRID = wrap_str(cdata->clTRID);
	if (c_clTRID == NULL)
		return CORBA_INT_ERROR;
	c_registrant = wrap_str_upd(update_domain->registrant);
	if (c_registrant == NULL) goto error_input;
	c_authInfo = wrap_str_upd(update_domain->authInfo);
	if (c_authInfo == NULL) goto error_input;
	c_nsset = wrap_str_upd(update_domain->nsset);
	if (c_nsset == NULL) goto error_input;

	/* admin add */
	c_admin_add = ccReg_AdminContact__alloc();
	if (c_admin_add == NULL) goto error_input;
	len = q_length(update_domain->add_admin);
	c_admin_add->_buffer = ccReg_AdminContact_allocbuf(len);
	if (c_admin_add->_buffer == NULL) goto error_input;
	c_admin_add->_maximum = c_admin_add->_length = len;
	c_admin_add->_release = CORBA_TRUE;
	i = 0;
	q_foreach(&update_domain->add_admin) {
		char	*admin;

		admin = wrap_str(q_content(&update_domain->add_admin));
		if (admin == NULL) goto error_input;
		c_admin_add->_buffer[i++] = admin;
	}
	/* admin rem */
	c_admin_rem = ccReg_AdminContact__alloc();
	if (c_admin_rem == NULL) goto error_input;
	len = q_length(update_domain->rem_admin);
	c_admin_rem->_buffer = ccReg_AdminContact_allocbuf(len);
	if (c_admin_rem->_buffer == NULL) goto error_input;
	c_admin_rem->_maximum = c_admin_rem->_length = len;
	c_admin_rem->_release = CORBA_TRUE;
	i = 0;
	q_foreach(&update_domain->rem_admin) {
		char	*admin;

		admin = wrap_str(q_content(&update_domain->rem_admin));
		if (admin == NULL) goto error_input;
		c_admin_rem->_buffer[i++] = admin;
	}

	/* status add */
	c_status_add = ccReg_Status__alloc();
	if (c_status_add == NULL) goto error_input;
	len = q_length(update_domain->add_status);
	c_status_add->_buffer = ccReg_Status_allocbuf(len);
	if (c_status_add->_buffer == NULL) goto error_input;
	c_status_add->_maximum = c_status_add->_length = len;
	c_status_add->_release = CORBA_TRUE;
	i = 0;
	q_foreach(&update_domain->add_status) {
		char	*status;

		status = wrap_str(q_content(&update_domain->add_status));
		if (status == NULL) goto error_input;
		c_status_add->_buffer[i++] = status;
	}
	/* status rem */
	c_status_rem = ccReg_Status__alloc();
	if (c_status_rem == NULL) goto error_input;
	len = q_length(update_domain->rem_status);
	c_status_rem->_buffer = ccReg_Status_allocbuf(len);
	if (c_status_rem->_buffer == NULL) goto error_input;
	c_status_rem->_maximum = c_status_rem->_length = len;
	c_status_rem->_release = CORBA_TRUE;
	i = 0;
	q_foreach(&update_domain->rem_status) {
		char	*status;

		status = wrap_str(q_content(&update_domain->rem_status));
		if (status == NULL) goto error_input;
		c_status_rem->_buffer[i++] = status;
	}

	c_ext_list = ccReg_ExtensionList__alloc();
	if (c_ext_list == NULL) goto error_input;
	len = q_length(update_domain->extensions);
	c_ext_list->_buffer = ccReg_ExtensionList_allocbuf(len);
	if (c_ext_list->_buffer == NULL) goto error_input;
	c_ext_list->_maximum = c_ext_list->_length = len;
	c_ext_list->_release = CORBA_TRUE;
	/* fill extension list if needed */
	i = 0;
	q_foreach(&update_domain->extensions) {
		epp_ext_item	*ext_item;

		ext_item = q_content(&update_domain->extensions);
		if (ext_item->extType == EPP_EXT_ENUMVAL) {
			ccReg_ENUMValidationExtension	*c_enumval;

			c_enumval = ccReg_ENUMValidationExtension__alloc();
			if (c_enumval == NULL) goto error_input;
			c_enumval->valExDate =
				wrap_str(ext_item->ext.ext_enumval);
			if (c_enumval->valExDate == NULL) goto error_input;
			c_ext_list->_buffer[i]._type =
				TC_ccReg_ENUMValidationExtension;
			c_ext_list->_buffer[i]._value = c_enumval;
			c_ext_list->_buffer[i]._release = CORBA_TRUE;
		}
		i++;
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		/* send the updates to repository */
		response = ccReg_EPP_DomainUpdate(globs->service,
				update_domain->name,
				c_registrant,
				c_authInfo,
				c_nsset,
				c_admin_add,
				c_admin_rem,
				c_status_add,
				c_status_rem,
				session,
				c_clTRID,
				cdata->xml_in,
				c_ext_list,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_clTRID);
	CORBA_free(c_registrant);
	CORBA_free(c_authInfo);
	CORBA_free(c_nsset);
	CORBA_free(c_status_rem);
	CORBA_free(c_status_add);
	CORBA_free(c_admin_rem);
	CORBA_free(c_admin_add);
	CORBA_free(c_ext_list);

	if (raised_exception(ev)) {
		int	ret;

		if (IS_INTSERV_ERROR(ev)) {
			ret  = CORBA_REMOTE_ERROR;
		}
		else {
			ret  = CORBA_ERROR;
		}
		CORBA_exception_free(ev);
		return ret;
	}

	if (corba_call_epilog(pool, cdata, response))
		return CORBA_INT_ERROR;

	CORBA_free(response);
	return CORBA_OK;

error_input:
	CORBA_free(c_clTRID);
	CORBA_free(c_registrant);
	CORBA_free(c_authInfo);
	CORBA_free(c_nsset);
	CORBA_free(c_status_rem);
	CORBA_free(c_status_add);
	CORBA_free(c_admin_rem);
	CORBA_free(c_admin_add);
	CORBA_free(c_ext_list);
	return CORBA_INT_ERROR;
}

/**
 * EPP update contact.
 *
 * @param pool    Pool for memory allocations.
 * @param globs   Corba context.
 * @param session Session identifier.
 * @param cdata   Data from xml request.
 * @return        Status.
 */
static corba_status
epp_call_update_contact(void *pool,
		epp_corba_globs *globs,
		int session,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	CORBA_char	*c_clTRID;
	ccReg_Response	*response;
	ccReg_Status	*c_status_add;
	ccReg_Status	*c_status_rem;
	ccReg_ContactChange	*c_contact;
	int	i, len, retr;
	epps_update_contact	*update_contact;

	update_contact = cdata->data;
	c_contact    = NULL;
	c_status_rem = NULL;
	c_status_add = NULL;
	c_clTRID     = NULL;
	/*
	 * Input parameters:
	 *    id (a)
	 *    c_contact (*)
	 *    c_status_add (*)
	 *    c_status_rem (*)
	 *    session
	 *    c_clTRID (*)
	 *    xml_in (a)
	 * Output parameters: none
	 */
	assert(update_contact->id);
	assert(cdata->xml_in);

	c_clTRID = wrap_str(cdata->clTRID);
	if (c_clTRID == NULL)
		return CORBA_INT_ERROR;

	/* status add */
	c_status_add = ccReg_Status__alloc();
	if (c_status_add == NULL) goto error_input;
	len = q_length(update_contact->add_status);
	c_status_add->_buffer = ccReg_Status_allocbuf(len);
	if (c_status_add->_buffer == NULL) goto error_input;
	c_status_add->_maximum = c_status_add->_length = len;
	c_status_add->_release = CORBA_TRUE;
	i = 0;
	q_foreach(&update_contact->add_status) {
		char	*status;

		status = wrap_str(q_content(&update_contact->add_status));
		if (status == NULL) goto error_input;
		c_status_add->_buffer[i++] = status;
	}
	/* status rem */
	c_status_rem = ccReg_Status__alloc();
	if (c_status_rem == NULL) goto error_input;
	len = q_length(update_contact->rem_status);
	c_status_rem->_buffer = ccReg_Status_allocbuf(len);
	if (c_status_rem->_buffer == NULL) goto error_input;
	c_status_rem->_maximum = c_status_rem->_length = len;
	c_status_rem->_release = CORBA_TRUE;
	i = 0;
	q_foreach(&update_contact->rem_status) {
		char	*status;

		status = wrap_str(q_content(&update_contact->rem_status));
		if (status == NULL) goto error_input;
		c_status_rem->_buffer[i++] = status;
	}

	/* c_contact */
	c_contact = ccReg_ContactChange__alloc();
	if (c_contact == NULL) goto error_input;
	/*
	 * Here we will change allocation schema: first do all allocs and then
	 * check success.
	 */
	if (update_contact->pi != NULL) {
		c_contact->Name    = wrap_str(update_contact->pi->name);
		c_contact->Organization = wrap_str_upd(update_contact->pi->org);
		c_contact->Street1 = wrap_str_upd(update_contact->pi->street[0]);
		c_contact->Street2 = wrap_str_upd(update_contact->pi->street[1]);
		c_contact->Street3 = wrap_str_upd(update_contact->pi->street[2]);
		c_contact->City    = wrap_str_upd(update_contact->pi->city);
		c_contact->StateOrProvince =wrap_str_upd(update_contact->pi->sp);
		c_contact->PostalCode = wrap_str_upd(update_contact->pi->pc);
		c_contact->CC      = wrap_str_upd(update_contact->pi->cc);
	}
	else {
		c_contact->Name = wrap_str(NULL);
		c_contact->Organization = wrap_str(NULL);
		c_contact->Street1 = wrap_str(NULL);
		c_contact->Street2 = wrap_str(NULL);
		c_contact->Street3 = wrap_str(NULL);
		c_contact->City = wrap_str(NULL);
		c_contact->StateOrProvince = wrap_str(NULL);
		c_contact->PostalCode = wrap_str(NULL);
		c_contact->CC = wrap_str(NULL);
	}
	if (c_contact->Name == NULL ||
	    c_contact->Organization == NULL ||
	    c_contact->Street1 == NULL ||
	    c_contact->Street2 == NULL ||
	    c_contact->Street3 == NULL ||
	    c_contact->City == NULL ||
	    c_contact->StateOrProvince == NULL ||
	    c_contact->PostalCode == NULL ||
	    c_contact->CC == NULL)
		goto error_input;

	c_contact->AuthInfoPw = wrap_str_upd(update_contact->authInfo);
	if (c_contact->AuthInfoPw == NULL) goto error_input;
	c_contact->Telephone = wrap_str_upd(update_contact->voice);
	if (c_contact->Telephone == NULL) goto error_input;
	c_contact->Fax = wrap_str_upd(update_contact->fax);
	if (c_contact->Fax == NULL) goto error_input;
	c_contact->Email = wrap_str_upd(update_contact->email);
	if (c_contact->Email == NULL) goto error_input;
	c_contact->NotifyEmail = wrap_str_upd(update_contact->notify_email);
	if (c_contact->NotifyEmail == NULL) goto error_input;
	c_contact->VAT = wrap_str_upd(update_contact->vat);
	if (c_contact->VAT == NULL) goto error_input;
	c_contact->SSN = wrap_str_upd(update_contact->ssn);
	if (c_contact->SSN == NULL) goto error_input;
	c_contact->SSNtype = convSSNType(update_contact->ssntype);
	/* disclose */
	c_contact->DiscloseFlag = convDiscl(update_contact->discl.flag);
	if (c_contact->DiscloseFlag != ccReg_DISCL_EMPTY) {
		c_contact->DiscloseName =
			(update_contact->discl.name ? CORBA_TRUE : CORBA_FALSE);
		c_contact->DiscloseOrganization =
			(update_contact->discl.org ? CORBA_TRUE :CORBA_FALSE);
		c_contact->DiscloseAddress =
			(update_contact->discl.addr ? CORBA_TRUE : CORBA_FALSE);
		c_contact->DiscloseTelephone =
			(update_contact->discl.voice ? CORBA_TRUE : CORBA_FALSE);
		c_contact->DiscloseFax =
			(update_contact->discl.fax ? CORBA_TRUE : CORBA_FALSE);
		c_contact->DiscloseEmail =
			(update_contact->discl.email ? CORBA_TRUE : CORBA_FALSE);
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		/* send the updates to repository */
		response = ccReg_EPP_ContactUpdate(globs->service,
				update_contact->id,
				c_contact,
				c_status_add,
				c_status_rem,
				session,
				c_clTRID,
				cdata->xml_in,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_contact);
	CORBA_free(c_status_rem);
	CORBA_free(c_status_add);
	CORBA_free(c_clTRID);

	if (raised_exception(ev)) {
		int	ret;

		if (IS_INTSERV_ERROR(ev)) {
			ret  = CORBA_REMOTE_ERROR;
		}
		else {
			ret  = CORBA_ERROR;
		}
		CORBA_exception_free(ev);
		return ret;
	}

	if (corba_call_epilog(pool, cdata, response))
		return CORBA_INT_ERROR;

	return CORBA_OK;

error_input:
	CORBA_free(c_contact);
	CORBA_free(c_status_rem);
	CORBA_free(c_status_add);
	CORBA_free(c_clTRID);
	return CORBA_INT_ERROR;
}

/**
 * EPP update nsset.
 *
 * @param pool    Pool for memory allocations.
 * @param globs   Corba context.
 * @param session Session identifier.
 * @param cdata   Data from xml request.
 * @return        Status.
 */
static corba_status
epp_call_update_nsset(void *pool,
		epp_corba_globs *globs,
		int session,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	CORBA_char	*c_clTRID, *c_authInfo;
	ccReg_Response	*response;
	ccReg_DNSHost	*c_dnshost_add;
	ccReg_DNSHost	*c_dnshost_rem;
	ccReg_TechContact	*c_tech_add;
	ccReg_TechContact	*c_tech_rem;
	ccReg_Status	*c_status_add;
	ccReg_Status	*c_status_rem;
	int	i, len, retr;
	epps_update_nsset	*update_nsset;

	update_nsset = cdata->data;
	c_dnshost_rem = NULL;
	c_dnshost_add = NULL;
	c_status_rem = NULL;
	c_status_add = NULL;
	c_tech_rem = NULL;
	c_tech_add = NULL;
	c_authInfo = NULL;
	c_clTRID = NULL;
	/*
	 * Input parameters:
	 *    id            (a)
	 *    c_authInfo    (*)
	 *    c_dnshost_add (*)
	 *    c_dnshost_rem (*)
	 *    c_tech_add    (*)
	 *    c_tech_rem    (*)
	 *    c_status_add  (*)
	 *    c_status_rem  (*)
	 *    session
	 *    c_clTRID      (*)
	 *    xml_in        (a)
	 * Output parameters: none
	 */
	assert(update_nsset->id);
	assert(cdata->xml_in);

	c_clTRID = wrap_str(cdata->clTRID);
	if (c_clTRID == NULL)
		return CORBA_INT_ERROR;
	c_authInfo = wrap_str_upd(update_nsset->authInfo);
	if (c_authInfo == NULL) goto error_input;

	/* tech add */
	c_tech_add = ccReg_TechContact__alloc();
	if (c_tech_add == NULL) goto error_input;
	len = q_length(update_nsset->add_tech);
	c_tech_add->_buffer = ccReg_TechContact_allocbuf(len);
	if (c_tech_add->_buffer == NULL) goto error_input;
	c_tech_add->_maximum = c_tech_add->_length = len;
	c_tech_add->_release = CORBA_TRUE;
	i = 0;
	q_foreach(&update_nsset->add_tech) {
		char	*tech;

		tech = wrap_str(q_content(&update_nsset->add_tech));
		if (tech == NULL) goto error_input;
		c_tech_add->_buffer[i++] = tech;
	}
	/* tech rem */
	c_tech_rem = ccReg_TechContact__alloc();
	if (c_tech_rem == NULL) goto error_input;
	len = q_length(update_nsset->rem_tech);
	c_tech_rem->_buffer = ccReg_TechContact_allocbuf(len);
	if (c_tech_rem->_buffer == NULL) goto error_input;
	c_tech_rem->_maximum = c_tech_rem->_length = len;
	c_tech_rem->_release = CORBA_TRUE;
	i = 0;
	q_foreach(&update_nsset->rem_tech) {
		char	*tech;

		tech = wrap_str(q_content(&update_nsset->rem_tech));
		if (tech == NULL) goto error_input;
		c_tech_rem->_buffer[i++] = tech;
	}

	/* status add */
	c_status_add = ccReg_Status__alloc();
	if (c_status_add == NULL) goto error_input;
	len = q_length(update_nsset->add_status);
	c_status_add->_buffer = ccReg_Status_allocbuf(len);
	if (c_status_add->_buffer == NULL) goto error_input;
	c_status_add->_maximum = c_status_add->_length = len;
	c_status_add->_release = CORBA_TRUE;
	i = 0;
	q_foreach(&update_nsset->add_status) {
		char	*status;

		status = wrap_str(q_content(&update_nsset->add_status));
		if (status == NULL) goto error_input;
		c_status_add->_buffer[i++] = status;
	}
	/* status rem */
	c_status_rem = ccReg_Status__alloc();
	if (c_status_rem == NULL) goto error_input;
	c_status_rem->_buffer = ccReg_Status_allocbuf(len);
	if (c_status_rem->_buffer == NULL) goto error_input;
	len = q_length(update_nsset->rem_status);
	c_status_rem->_maximum = c_status_rem->_length = len;
	c_status_rem->_release = CORBA_TRUE;
	i = 0;
	q_foreach(&update_nsset->rem_status) {
		char	*status;

		status = wrap_str(q_content(&update_nsset->rem_status));
		if (status == NULL) goto error_input;
		c_status_rem->_buffer[i++] = status;
	}

	/* name servers add */
	c_dnshost_add = ccReg_DNSHost__alloc();
	if (c_dnshost_add == NULL) goto error_input;
	len = q_length(update_nsset->add_ns);
	c_dnshost_add->_buffer = ccReg_DNSHost_allocbuf(len);
	if (c_dnshost_add->_buffer == NULL) goto error_input;
	c_dnshost_add->_maximum = c_dnshost_add->_length = len;
	c_dnshost_add->_release = CORBA_TRUE;
	i = 0;
	q_foreach(&update_nsset->add_ns) {
		epp_ns	*ns;
		int	 j;

		ns = q_content(&update_nsset->add_ns);
		c_dnshost_add->_buffer[i].fqdn = wrap_str(ns->name);
		if (c_dnshost_add->_buffer[i].fqdn == NULL) goto error_input;
		/* alloc & init sequence of ns's addresses */
		len = q_length(ns->addr);
		c_dnshost_add->_buffer[i].inet._buffer =
			ccReg_InetAddress_allocbuf(len);
		if (c_dnshost_add->_buffer[i].inet._buffer == NULL)
			goto error_input;
		c_dnshost_add->_buffer[i].inet._maximum =
			c_dnshost_add->_buffer[i].inet._length = len;
		c_dnshost_add->_buffer[i].inet._release = CORBA_TRUE;
		j = 0;
		q_foreach(&ns->addr) {
			char	*addr;

			addr = wrap_str(q_content(&ns->addr));
			if (addr == NULL) goto error_input;
			c_dnshost_add->_buffer[i].inet._buffer[j++] = addr;
		}
		i++;
	}

	/* name servers rem */
	c_dnshost_rem = ccReg_DNSHost__alloc();
	if (c_dnshost_rem == NULL) goto error_input;
	len = q_length(update_nsset->rem_ns);
	c_dnshost_rem->_buffer = ccReg_DNSHost_allocbuf(len);
	if (c_dnshost_rem->_buffer == NULL) goto error_input;
	c_dnshost_rem->_maximum = c_dnshost_rem->_length = len;
	c_dnshost_rem->_release = CORBA_TRUE;
	i = 0;
	q_foreach(&update_nsset->rem_ns) {
		char	*fqdn;

		fqdn = wrap_str(q_content(&update_nsset->rem_ns));
		if (fqdn == NULL) goto error_input;
		c_dnshost_rem->_buffer[i].fqdn = fqdn;
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		/* send the updates to repository */
		response = ccReg_EPP_NSSetUpdate(globs->service,
				update_nsset->id,
				c_authInfo,
				c_dnshost_add,
				c_dnshost_rem,
				c_tech_add,
				c_tech_rem,
				c_status_add,
				c_status_rem,
				session,
				c_clTRID,
				cdata->xml_in,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_dnshost_rem);
	CORBA_free(c_dnshost_add);
	CORBA_free(c_status_rem);
	CORBA_free(c_status_add);
	CORBA_free(c_tech_rem);
	CORBA_free(c_tech_add);
	CORBA_free(c_authInfo);
	CORBA_free(c_clTRID);

	if (raised_exception(ev)) {
		int	ret;

		if (IS_INTSERV_ERROR(ev)) {
			ret  = CORBA_REMOTE_ERROR;
		}
		else {
			ret  = CORBA_ERROR;
		}
		CORBA_exception_free(ev);
		return ret;
	}

	if (corba_call_epilog(pool, cdata, response))
		return CORBA_INT_ERROR;

	return CORBA_OK;

error_input:
	CORBA_free(c_dnshost_rem);
	CORBA_free(c_dnshost_add);
	CORBA_free(c_status_rem);
	CORBA_free(c_status_add);
	CORBA_free(c_tech_rem);
	CORBA_free(c_tech_add);
	CORBA_free(c_authInfo);
	CORBA_free(c_clTRID);
	return CORBA_INT_ERROR;
}

/**
 * EPP transfer for domain, contact and nsset is so similar that it is worth of
 * having the code in one function and pass object type as parameter.
 *
 * @param pool    Pool for memory allocations.
 * @param globs   Corba context.
 * @param session Session identifier.
 * @param cdata   Data from xml request.
 * @param obj     Object type (see #epp_object_type).
 * @return        Status.
 */
static corba_status
epp_call_transfer(void *pool,
		epp_corba_globs *globs,
		int session,
		epp_command_data *cdata,
		epp_object_type obj)
{
	CORBA_Environment ev[1];
	CORBA_char	*c_clTRID, *c_authInfo;
	ccReg_Response	*response;
	int	retr;
	epps_transfer	*transfer;

	transfer = cdata->data;
	/*
	 * Input parameters:
	 *    id (a)
	 *    c_authInfo (*)
	 *    session
	 *    c_clTRID (*)
	 *    xml_in (a)
	 * Output parameters: none
	 */
	assert(transfer->id);
	assert(cdata->xml_in);

	c_clTRID = wrap_str(cdata->clTRID);
	if (c_clTRID == NULL)
		return CORBA_INT_ERROR;
	c_authInfo = wrap_str(transfer->authInfo);
	if (c_authInfo == NULL) {
		CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		if (obj == EPP_DOMAIN) {
			response = ccReg_EPP_DomainTransfer(globs->service,
					transfer->id,
					c_authInfo,
					session,
					c_clTRID,
					cdata->xml_in,
					ev);
		}
		else if (obj == EPP_CONTACT) {
			response = ccReg_EPP_ContactTransfer(globs->service,
					transfer->id,
					c_authInfo,
					session,
					c_clTRID,
					cdata->xml_in,
					ev);
		}
		else {
			assert(obj == EPP_NSSET);
			response = ccReg_EPP_NSSetTransfer(globs->service,
					transfer->id,
					c_authInfo,
					session,
					c_clTRID,
					cdata->xml_in,
					ev);
		}

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_authInfo);
	CORBA_free(c_clTRID);

	if (raised_exception(ev)) {
		int	ret;

		if (IS_INTSERV_ERROR(ev)) {
			ret  = CORBA_REMOTE_ERROR;
		}
		else {
			ret  = CORBA_ERROR;
		}
		CORBA_exception_free(ev);
		return ret;
	}

	if (corba_call_epilog(pool, cdata, response))
		return CORBA_INT_ERROR;

	return CORBA_OK;
}

/**
 * List command for domain, contact and nsset is so similar that it is worth of
 * having the code in one function and pass object type as parameter.
 *
 * @param pool    Pool for memory allocations.
 * @param globs   Corba context.
 * @param session Session identifier.
 * @param cdata   Data from xml request.
 * @param obj     Object type (see #epp_object_type).
 * @return        Status.
 */
static corba_status
epp_call_list(void *pool,
		epp_corba_globs *globs,
		int session,
		epp_command_data *cdata,
		epp_object_type obj)
{
	CORBA_Environment	 ev[1];
	CORBA_char	*c_clTRID;
	ccReg_Response	*response;
	ccReg_Lists	*c_handles;
	int	 i, retr;
	epps_list	*list;

	list = cdata->data;
	/*
	 * Input parameters:
	 *    session
	 *    c_clTRID (*)
	 *    xml_in (a)
	 * Output parameters:
	 *    c_handles (*)
	 */
	assert(cdata->xml_in);
	c_clTRID = wrap_str(cdata->clTRID);
	if (c_clTRID == NULL)
		return CORBA_INT_ERROR;

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		if (obj == EPP_DOMAIN) {
			response = ccReg_EPP_DomainList(globs->service,
					&c_handles,
					session,
					c_clTRID,
					cdata->xml_in,
					ev);
		}
		else if (obj == EPP_CONTACT) {
			response = ccReg_EPP_ContactList(globs->service,
					&c_handles,
					session,
					c_clTRID,
					cdata->xml_in,
					ev);
		}
		else {
			assert(obj == EPP_NSSET);
			response = ccReg_EPP_NSSetList(globs->service,
					&c_handles,
					session,
					c_clTRID,
					cdata->xml_in,
					ev);
		}

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_clTRID);

	if (raised_exception(ev)) {
		int	ret;

		if (IS_INTSERV_ERROR(ev)) {
			ret  = CORBA_REMOTE_ERROR;
		}
		else {
			ret  = CORBA_ERROR;
		}
		CORBA_exception_free(ev);
		return ret;
	}

	for (i = 0; i < c_handles->_length; i++) {
		char	*handle;
		int	cerrno;

		CLEAR_CERRNO(cerrno);

		handle = unwrap_str(pool, c_handles->_buffer[i], &cerrno);
		if (cerrno != 0) {
			CORBA_free(response);
			return CORBA_INT_ERROR;
		}
		if (q_add(pool, &list->handles, handle)) {
			CORBA_free(response);
			return CORBA_INT_ERROR;
		}
	}

	CORBA_free(c_handles);
	if (corba_call_epilog(pool, cdata, response))
		return CORBA_INT_ERROR;

	return CORBA_OK;
}

corba_status
epp_call_cmd(void *pool,
		epp_corba_globs *globs,
		int session,
		epp_command_data *cdata)
{
	corba_status	cstat;

	switch (cdata->type) {
		case EPP_DUMMY:
			cstat = epp_call_dummy(pool, globs, session, cdata);
			break;
		case EPP_CHECK_CONTACT:
			cstat = epp_call_check(pool, globs, session, cdata,
					EPP_CONTACT);
			break;
		case EPP_CHECK_DOMAIN:
			cstat = epp_call_check(pool, globs, session, cdata,
					EPP_DOMAIN);
			break;
		case EPP_CHECK_NSSET:
			cstat = epp_call_check(pool, globs, session, cdata,
					EPP_NSSET);
			break;
		case EPP_INFO_CONTACT:
			cstat = epp_call_info_contact(pool, globs, session,
					cdata);
			break;
		case EPP_INFO_DOMAIN:
			cstat = epp_call_info_domain(pool, globs, session,
					cdata);
			break;
		case EPP_INFO_NSSET:
			cstat = epp_call_info_nsset(pool, globs, session, cdata);
			break;
		case EPP_LIST_CONTACT:
			cstat = epp_call_list(pool, globs, session, cdata,
					EPP_CONTACT);
			break;
		case EPP_LIST_DOMAIN:
			cstat = epp_call_list(pool, globs, session, cdata,
					EPP_DOMAIN);
			break;
		case EPP_LIST_NSSET:
			cstat = epp_call_list(pool, globs, session, cdata,
					EPP_NSSET);
			break;
		case EPP_POLL_REQ:
			cstat = epp_call_poll_req(pool, globs, session, cdata);
			break;
		case EPP_POLL_ACK:
			cstat = epp_call_poll_ack(pool, globs, session, cdata);
			break;
		case EPP_CREATE_CONTACT:
			cstat = epp_call_create_contact(pool, globs, session,
					cdata);
			break;
		case EPP_CREATE_DOMAIN:
			cstat = epp_call_create_domain(pool, globs, session,
					cdata);
			break;
		case EPP_CREATE_NSSET:
			cstat = epp_call_create_nsset(pool, globs, session,
					cdata);
			break;
		case EPP_DELETE_CONTACT:
			cstat = epp_call_delete(pool, globs, session, cdata,
					EPP_CONTACT);
			break;
		case EPP_DELETE_DOMAIN:
			cstat = epp_call_delete(pool, globs, session, cdata,
					EPP_DOMAIN);
			break;
		case EPP_DELETE_NSSET:
			cstat = epp_call_delete(pool, globs, session, cdata,
					EPP_NSSET);
			break;
		case EPP_RENEW_DOMAIN:
			cstat = epp_call_renew_domain(pool, globs, session,
					cdata);
			break;
		case EPP_UPDATE_DOMAIN:
			cstat = epp_call_update_domain(pool, globs, session,
					cdata);
			break;
		case EPP_UPDATE_CONTACT:
			cstat = epp_call_update_contact(pool, globs, session,
					cdata);
			break;
		case EPP_UPDATE_NSSET:
			cstat = epp_call_update_nsset(pool, globs, session,
					cdata);
			break;
		case EPP_TRANSFER_CONTACT:
			cstat = epp_call_transfer(pool, globs, session, cdata,
					EPP_CONTACT);
			break;
		case EPP_TRANSFER_DOMAIN:
			cstat = epp_call_transfer(pool, globs, session, cdata,
					EPP_DOMAIN);
			break;
		case EPP_TRANSFER_NSSET:
			cstat = epp_call_transfer(pool, globs, session, cdata,
					EPP_NSSET);
			break;
		default:
			cstat = CORBA_INT_ERROR;
			break;
	}

	return cstat;
}
