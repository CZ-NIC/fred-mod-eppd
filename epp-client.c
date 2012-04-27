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



/** Clear errno variable to non-error state. */
#define CLEAR_CERRNO(_cerrno)	(_cerrno = 0)

/**
 * Error code translation table.
 */
static int error_translator[][2] =
{
  {ccReg_poll_msgID,            errspec_poll_msgID},
  {ccReg_contact_handle,        errspec_contact_handle},
  {ccReg_contact_cc,            errspec_contact_cc},
  {ccReg_nsset_handle,          errspec_nsset_handle},
  {ccReg_nsset_tech,            errspec_nsset_tech},
  {ccReg_nsset_dns_name,        errspec_nsset_dns_name},
  {ccReg_nsset_dns_addr,        errspec_nsset_dns_addr},
  {ccReg_nsset_dns_name_add,    errspec_nsset_dns_name_add},
  {ccReg_nsset_dns_name_rem,    errspec_nsset_dns_name_rem},
  {ccReg_nsset_tech_add,        errspec_nsset_tech_add},
  {ccReg_nsset_tech_rem,        errspec_nsset_tech_rem},
  {ccReg_keyset_handle,		errspec_keyset_handle},
  {ccReg_keyset_tech,		errspec_keyset_tech},
  {ccReg_keyset_dnskey,		errspec_keyset_dnskey},
  {ccReg_keyset_dnskey_add,	errspec_keyset_dnskey_add},
  {ccReg_keyset_dnskey_rem,	errspec_keyset_dnskey_rem},
  {ccReg_keyset_tech_add,	errspec_keyset_tech_add},
  {ccReg_keyset_tech_rem,	errspec_keyset_tech_rem},
  {ccReg_registrar_autor,	errspec_registrar_author},
  {ccReg_domain_fqdn,           errspec_domain_fqdn},
  {ccReg_domain_registrant,     errspec_domain_registrant},
  {ccReg_domain_nsset,          errspec_domain_nsset},
  {ccReg_domain_keyset,         errspec_domain_keyset},
  {ccReg_domain_period,         errspec_domain_period},
  {ccReg_domain_admin,          errspec_domain_admin},
  {ccReg_domain_tmpcontact,     errspec_domain_tmpcontact},
  {ccReg_domain_ext_valDate,    errspec_domain_ext_valDate},
  {ccReg_domain_ext_valDate_missing, errspec_domain_ext_valDate_missing},
  {ccReg_domain_curExpDate,     errspec_domain_curExpDate},
  {ccReg_domain_admin_add,      errspec_domain_admin_add},
  {ccReg_domain_admin_rem,      errspec_domain_admin_rem},
  /* input errors */
  {ccReg_xml_not_valid,         errspec_not_valid},
  {ccReg_poll_msgID_missing,    errspec_poll_msgID_missing},
  {ccReg_contact_identtype_missing, errspec_contact_identtype_missing},
  {ccReg_transfer_op,           errspec_transfer_op},
  {-1, -1}
};


static ccReg_Disclose convDiscl(char flag);
static char convDisclBack(ccReg_Disclose discl);

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

	while ((var = error_translator[i][0]) != -1) {
		if (var == idlcode)
			return error_translator[i][1];
		i++;
	}

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

	while ((var = error_translator[i][1]) != -1) {
		if (var == eppcode)
			return error_translator[i][0];
		i++;
	}

	return -1;
}


char *
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
 * @param pool    Memory pool to allocate memory from.
 * @param str	  Input string.
 * @param cerrno  Set to 1 if malloc failed.
 * @return        Output string.
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
 * required not to be empty. If it is empty, an error message is logged.
 *
 * @param epp_ctx Epp context used for logging and memory allocation.
 * @param str	  Input string.
 * @param cerrno  Set to 1 if malloc failed.
 * @param id	  Identifier of string used in error message.
 * @return        Output string.
 */
static char *
unwrap_str_req(epp_context *epp_ctx, const char *str, int *cerrno,
		const char *id)
{
	char	*res;

	assert(str != NULL);

	if (*str == '\0')
		epplog(epp_ctx, EPP_ERROR, "Output parameter \"%s\" is empty "
				"and it shouldn't!", id);

	res = epp_strdup(epp_ctx->pool, str);
	if (res == NULL)
		*cerrno = 1;

	return res;
}


ccReg_EppParams *init_epp_params(
		const ccReg_TID login_id,
		const ccReg_TID request_id,
		const char *xml_in,
		const char *clTRID)
{
	ccReg_EppParams *c_params;

	c_params = ccReg_EppParams__alloc();
	if (c_params == NULL) {
		return NULL;
	}

	c_params->loginID = login_id;
	c_params->requestID = request_id;
	c_params->XML = NULL;
	c_params->clTRID = NULL;

	c_params->XML = wrap_str(xml_in);
	if (c_params->XML == NULL) {
		CORBA_free(c_params);
		return NULL;
	}

	c_params->clTRID = wrap_str(clTRID);
	if (c_params->clTRID == NULL) {
		CORBA_free(c_params);
		return NULL;
	}

	return c_params;
}

int
epp_call_hello(epp_context *epp_ctx, service_EPP service, char **version,
		char **curdate)
{
	CORBA_Environment ev[1];
	CORBA_char	*c_version;
	CORBA_char	*c_curdate;
	int	retr, cerrno;

  epplog(epp_ctx, EPP_DEBUG, "Corba call (epp-cmd hello)");

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		c_version = ccReg_EPP_version((ccReg_EPP) service,
				&c_curdate, ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

	if (raised_exception(ev)) {
		epplog(epp_ctx, EPP_ERROR, "CORBA exception: %s", ev->_id);
		CORBA_exception_free(ev);
		return CORBA_ERROR;
	}

	CLEAR_CERRNO(cerrno);

	*version = unwrap_str(epp_ctx->pool, c_version, &cerrno);
	if (cerrno != 0) {
		CORBA_free(c_version);
		CORBA_free(c_curdate);
		return CORBA_INT_ERROR;
	}
	CORBA_free(c_version);
	*curdate = unwrap_str(epp_ctx->pool, c_curdate, &cerrno);
	if (cerrno != 0) {
		CORBA_free(c_curdate);
		return CORBA_INT_ERROR;
	}
	CORBA_free(c_curdate);

  epplog(epp_ctx, EPP_DEBUG, "Corba call ok");
	return CORBA_OK;
}

/**
 * This function creates answer even though it has not enough data for that
 * from CORBA server.
 *
 * This behaviour is in conflict with EPP standard, but it was enforced
 * by users and administrators.
 *
 * @param epp_ctx   Epp context.
 * @param cdata     Epp data.
 * @return          Corba status.
 */
static corba_status
create_dummy_answer(epp_context *epp_ctx, epp_command_data *cdata)
{
	cdata->svTRID = epp_strdup(epp_ctx->pool, "DUMMY-SVTRID");
	if (cdata->svTRID == NULL)
		return CORBA_INT_ERROR;

	cdata->msg = epp_strdup(epp_ctx->pool, "Command failed; "
            "server closing connection");
	if (cdata->msg == NULL)
		return CORBA_INT_ERROR;

	/* this flag is needed for XML generator */
	cdata->noresdata = 1;

	cdata->rc = 2500;
	cdata->type = EPP_DUMMY;
	/* reset errors */
	cdata->errors.count = 0;
	cdata->errors.body = NULL;
	cdata->errors.cur  = NULL;
	return CORBA_ERROR;
}

/**
 * This is common routine for all corba function calls (except hello call)
 * executed at the end of command.
 *
 * Structure response is freed in any case (success or failure).
 *
 * @param epp_ctx  Epp context.
 * @param cdata    Command input and output data.
 * @param response Response returned from CORBA call.
 * @return         CORBA status.
 */
static corba_status
epilog_success(epp_context *epp_ctx, epp_command_data *cdata,
		ccReg_Response *response)
{
	int	cerrno;

	CLEAR_CERRNO(cerrno);

	cdata->rc = response->code;
	cdata->msg = unwrap_str_req(epp_ctx, response->msg, &cerrno, "msg");
	cdata->svTRID = unwrap_str_req(epp_ctx, response->svTRID, &cerrno,
			"svTRID");
	CORBA_free(response);

	if (cerrno != 0)
		return CORBA_INT_ERROR;

	return CORBA_OK;
}

/**
 * This function is called in case of invalid parameter which is signalled
 * to module by throwing InvalidParam exception.
 *
 * @param epp_ctx   Epp context.
 * @param cdata     EPP data.
 * @param exc       Data of thrown exception.
 * @return          0 if successful, 1 if required parameter is missing, 2 if
 *                  malloc failed.
 */
static int
epilog_failure(epp_context *epp_ctx, epp_command_data *cdata,
		ccReg_EPP_EppError *exc)
{
	ccReg_Error	*c_error;
	int	 i, cerrno;

	CLEAR_CERRNO(cerrno);
	cdata->svTRID = unwrap_str_req(epp_ctx, exc->svTRID, &cerrno, "svTRID");
	if (cerrno != 0) return cerrno;
	cdata->msg = unwrap_str_req(epp_ctx, exc->errMsg, &cerrno, "msg");
	if (cerrno != 0) return cerrno;
	cdata->rc = exc->errCode;

	/* process all errors one by one */
	for (i = 0; i < exc->errorList._length; i++) {
		epp_error	*err_item;

		c_error = &exc->errorList._buffer[i];

		err_item = epp_malloc(epp_ctx->pool, sizeof *err_item);
		if (err_item == NULL) return 1;
		err_item->reason = unwrap_str_req(epp_ctx, c_error->reason,
				&cerrno, "reason");
		if (cerrno != 0) return cerrno;
		/* copy position spec */
		err_item->position = c_error->position;
		/* convert error code */
		err_item->spec = err_idl2epp(c_error->code);

		if (q_add(epp_ctx->pool, &cdata->errors, err_item))
			return 2;
	}
	/* this flag is needed for XML generator */
	cdata->noresdata = 1;

	return 0;
}

/**
 * Common code for handling exceptions from corba calls.
 *
 * @param epp_ctx   Epp context.
 * @param cdata     Epp data.
 * @param ev        Exception.
 * @return          Corba status.
 */
static corba_status
handle_exception(epp_context *epp_ctx, epp_command_data *cdata,
		CORBA_Environment *ev)
{
	int	ret;

	if (IS_EPP_ERROR(ev)) {
		ccReg_EPP_EppError	*err_data;

		err_data = (ccReg_EPP_EppError *) ev->_any._value;
		ret = epilog_failure(epp_ctx, cdata, err_data);
		if (ret == 0)
			ret = CORBA_OK;
		else if (ret == 1)
			ret = create_dummy_answer(epp_ctx, cdata);
		else
			ret = CORBA_INT_ERROR;
	}
	else if (IS_NO_MESSAGES(ev)) {
		ccReg_EPP_NoMessages	*exc;
		int	cerrno;

		CLEAR_CERRNO(cerrno);
		exc = (ccReg_EPP_NoMessages *) ev->_any._value;

		cdata->rc = exc->code;
		cdata->msg = unwrap_str_req(epp_ctx, exc->msg, &cerrno, "msg");
		cdata->svTRID = unwrap_str_req(epp_ctx, exc->svTRID, &cerrno,
				"svTRID");
		/* this checks both previous allocations */
		if (cerrno != 0)
			ret = CORBA_INT_ERROR;
		else
			ret = CORBA_OK;
	}
	else {
		epplog(epp_ctx, EPP_ERROR, "CORBA exception: %s", ev->_id);
		/* we'll return 'something' in case of communication failure */
		ret = create_dummy_answer(epp_ctx, cdata);
	}

	CORBA_exception_free(ev);
	return ret;
}

/**
 * "dummy" call is dummy because it only retrieves unique svTRID and
 * error message from central repository and by this way informs repository
 * about the error. This call is used for failures detected already on side
 * of mod_eppd.
 *
 * @param epp_ctx Epp context.
 * @param service EPP service.
 * @param loginid Session identifier.
 * @param request_id  fred-logd request ID
 * @param cdata   Data from xml request.
 * @return        Status.
 */
static corba_status
epp_call_dummy(epp_context *epp_ctx,
		service_EPP service,
		unsigned long long loginid,
		const ccReg_TID request_id,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	CORBA_char	*c_clTRID;
	ccReg_Response	*response;
	ccReg_XmlErrors	*c_errorCodes;
	ccReg_ErrorStrings	*c_errStrings;
	int	len, i, retr;
	int	cerrno;

	/*
	 * Input parameters:
	 *    cdata->rc
	 *    c_errorCodes (*)
	 *    loginid
	 *    c_clTRID (*)
	 * Output parameters:
	 *    c_errStrings (*)
	 */
	c_clTRID = wrap_str(cdata->clTRID);
	if (c_clTRID == NULL)
        return CORBA_INT_ERROR;


	c_errorCodes = ccReg_XmlErrors__alloc();
	if (c_errorCodes == NULL) {
        CORBA_free(c_clTRID);
		return CORBA_INT_ERROR;
	}
	/* get number of errors */
	len = q_length(cdata->errors);
	c_errorCodes->_buffer = ccReg_XmlErrors_allocbuf(len);
	if (len != 0 && c_errorCodes->_buffer == NULL) {
        CORBA_free(c_clTRID);
		CORBA_free(c_errorCodes);
		return CORBA_INT_ERROR;
	}
	c_errorCodes->_maximum = c_errorCodes->_length = len;
	c_errorCodes->_release = CORBA_TRUE;

	/* copy each error in corba buffer */
	i = 0;
	q_foreach(&cdata->errors) {
		epp_error	*err_item;

		err_item = q_content(&cdata->errors);
		c_errorCodes->_buffer[i++] = err_epp2idl(err_item->spec);
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		response = ccReg_EPP_GetTransaction((ccReg_EPP) service,
				cdata->rc,
				loginid,
				request_id,
				c_clTRID,
				c_errorCodes,
				&c_errStrings,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_clTRID);
	CORBA_free(c_errorCodes);

	/* if it is exception then return */
	if (raised_exception(ev))
		return handle_exception(epp_ctx, cdata, ev);

	if (c_errStrings->_length != len) {
		epplog(epp_ctx,EPP_ERROR,"Bad length of translated error list");
		CORBA_free(c_errStrings);
		CORBA_free(response);
		return create_dummy_answer(epp_ctx, cdata);
	}
	CLEAR_CERRNO(cerrno);
	/* now try to pair reported errors with translated strings */
	i = 0;
	q_foreach(&cdata->errors) {
		epp_error	*err_item;

		err_item = q_content(&cdata->errors);
		if (*c_errStrings->_buffer[i] == '\0') {
			epplog(epp_ctx, EPP_ERROR, "Reuired parameter "
					"'translated error' is missing");
			CORBA_free(c_errStrings);
			CORBA_free(response);
			return create_dummy_answer(epp_ctx, cdata);
		}
		/* prefix validation errors by a translated prefix */
		if (err_item->spec == errspec_not_valid)
			err_item->reason = epp_strcat(epp_ctx->pool,
					c_errStrings->_buffer[i++],
					err_item->reason);
		else
			err_item->reason = unwrap_str(epp_ctx->pool,
					c_errStrings->_buffer[i++], &cerrno);
		if (err_item->reason == NULL) {
			CORBA_free(c_errStrings);
			CORBA_free(response);
			return CORBA_INT_ERROR;
		}
	}
	CORBA_free(c_errStrings);

	/* This is always true for this request, but we must set it here */
	cdata->noresdata = 1;

	return epilog_success(epp_ctx, cdata, response);
}

corba_status
epp_call_login(epp_context *epp_ctx,
		service_EPP service,
		unsigned long long *loginid,
		const ccReg_TID request_id,
		epp_lang *lang,
		const char *certID,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	CORBA_unsigned_long_long	c_session;
	CORBA_char	*c_clID, *c_pw, *c_newPW, *c_clTRID;
	ccReg_Languages	c_lang;
	ccReg_Response *response;
	int	retr;
	epps_login	*login;

  epplog(epp_ctx, EPP_DEBUG, "Corba call (epp-cmd login)");
	cdata->noresdata = 1;
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

		response = ccReg_EPP_ClientLogin((ccReg_EPP) service,
				c_clID,
				c_pw,
				c_newPW,
				c_clTRID,
				cdata->xml_in,
				&c_session,
				request_id,
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
	if (raised_exception(ev))
		return handle_exception(epp_ctx, cdata, ev);

	/* update session data ( XXX premature update of session data) */
	*loginid = c_session;
	*lang = login->lang;

	return epilog_success(epp_ctx, cdata, response);
}

corba_status
epp_call_logout(epp_context *epp_ctx,
		service_EPP service,
		unsigned long long *loginid,
		const ccReg_TID request_id,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	ccReg_EppParams *c_params = NULL;
	ccReg_Response	*response;
	int	retr;

    epplog(epp_ctx, EPP_DEBUG, "Corba call (epp-cmd logout)");
	cdata->noresdata = 1;
	/*
	 * Input parameters:
	 *    loginid
	 *    c_clTRID (*)
	 *    xml_in (a)
	 * Output parameters: none
	 */
	assert(cdata->xml_in != NULL);

	c_params = init_epp_params(*loginid, request_id, cdata->xml_in, cdata->clTRID);
	if(c_params == NULL) {
	    return CORBA_INT_ERROR;
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		response = ccReg_EPP_ClientLogout((ccReg_EPP) service,
				c_params,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_params);

	/* if it is exception then return */
	if (raised_exception(ev))
		return handle_exception(epp_ctx, cdata, ev);

	/* propagate information about logout upwards */
	*loginid = 0;

	return epilog_success(epp_ctx, cdata, response);
}

/**
 * EPP check for domain, nsset and contact is so similar that it is worth of
 * having the code in one function and pass object type as parameter.
 *
 * @param epp_ctx Epp context.
 * @param service EPP service.
 * @param loginid Session identifier.
 * @param request_id  fred-logd request_id
 * @param cdata   Data from xml request.
 * @param obj     Object type (see #epp_object_type)
 * @return        Status.
 */
static corba_status
epp_call_check(epp_context *epp_ctx,
		service_EPP service,
		unsigned long long loginid,
		const ccReg_TID request_id,
		epp_command_data *cdata,
		epp_object_type obj)
{
	CORBA_Environment ev[1];
	ccReg_EppParams *c_params = NULL;
	ccReg_CheckResp	*c_avails;
	ccReg_Check	*c_ids;
	ccReg_Response *response;
	int	len, i, retr;
	epps_check	*check;

	check = cdata->data;
	/*
	 * Input parameters:
	 *    c_ids (*)
	 *    loginid
	 *    c_clTRID (*)
	 *    xml_in (a)
	 * Output parameters:
	 *    c_avails (f)
	 */
	assert(cdata->xml_in != NULL);
	c_params = init_epp_params(loginid, request_id, cdata->xml_in, cdata->clTRID);
	if (c_params == NULL) {
	    return CORBA_INT_ERROR;
	}

	/* get number of contacts */
	len = q_length(check->ids);
	c_ids = ccReg_Check__alloc();
	if (c_ids == NULL) {
		CORBA_free(c_params);
		return CORBA_INT_ERROR;
	}
	c_ids->_buffer = ccReg_Check_allocbuf(len);
	if (len != 0 && c_ids->_buffer == NULL) {
		CORBA_free(c_ids);
		CORBA_free(c_params);
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
			CORBA_free(c_params);
			return CORBA_INT_ERROR;
		}
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		if (obj == EPP_CONTACT)
			response = ccReg_EPP_ContactCheck((ccReg_EPP) service,
					c_ids,
					&c_avails,
					c_params,
					ev);
		else if (obj == EPP_DOMAIN)
			response = ccReg_EPP_DomainCheck((ccReg_EPP) service,
					c_ids,
					&c_avails,
					c_params,
					ev);
		else if (obj == EPP_NSSET) {
			response = ccReg_EPP_NSSetCheck((ccReg_EPP) service,
					c_ids,
					&c_avails,
					c_params,
					ev);
		} else {
			assert(obj == EPP_KEYSET);
			response = ccReg_EPP_KeySetCheck((ccReg_EPP) service,
					c_ids,
					&c_avails,
					c_params,
					ev);

		}

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_params);
	CORBA_free(c_ids);

	/* if it is exception then return */
	if (raised_exception(ev))
		return handle_exception(epp_ctx, cdata, ev);

	/*
	 * Length of results returned should be same as lenght of input objects.
	 */
	if (len != c_avails->_length) {
		epplog(epp_ctx, EPP_ERROR, "Bad length of check list");
		CORBA_free(c_avails);
		CORBA_free(response);
		return create_dummy_answer(epp_ctx, cdata);
	}

	for (i = 0; i < c_avails->_length; i++) {
		epp_avail	*avail;
		int	cerrno;

		CLEAR_CERRNO(cerrno);

		avail = epp_malloc(epp_ctx->pool, sizeof *avail);
		if (avail == NULL) break;

		avail->avail =
			(c_avails->_buffer[i].avail == ccReg_NotExist) ? 1 : 0;
		avail->reason = unwrap_str(epp_ctx->pool,
				c_avails->_buffer[i].reason, &cerrno);
		if (cerrno != 0) break;

		if (!avail->avail && avail->reason == NULL) {
			epplog(epp_ctx, EPP_ERROR, "Reason is empty and object "
					"is not available");
			CORBA_free(c_avails);
			CORBA_free(response);
			return create_dummy_answer(epp_ctx, cdata);
		}
		if (q_add(epp_ctx->pool, &check->avails, avail)) break;
	}
	/* handle situation when allocation in for-cycle above failed */
	if (i < c_avails->_length) {
		CORBA_free(c_avails);
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}
	CORBA_free(c_avails);

	return epilog_success(epp_ctx, cdata, response);
}

/**
 * EPP info contact.
 *
 * @param epp_ctx Epp context.
 * @param service EPP service.
 * @param loginid Session identifier.
 * @param request_id  fred-logd request ID
 * @param cdata   Data from xml request.
 * @return        Status.
 */
static corba_status
epp_call_info_contact(epp_context *epp_ctx,
		service_EPP service,
		unsigned long long loginid,
		const ccReg_TID request_id,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	ccReg_EppParams *c_params = NULL;
	ccReg_Contact	*c_contact;
	ccReg_Response	*response;
	int	i, retr, cerrno;
	epps_info_contact	*info_contact;

	info_contact = cdata->data;
	/*
	 * Input parameters:
	 *    id (a)
	 *    loginid
	 *    c_clTRID (*)
	 *    xml_in (a)
	 * Output parameters:
	 *    c_contact (*)
	 */
	assert(cdata->xml_in);
	assert(info_contact->id);

	c_params = init_epp_params(loginid, request_id, cdata->xml_in, cdata->clTRID);
	if (c_params == NULL) {
	    return CORBA_INT_ERROR;
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		/* get information about contact from central repository */
		response = ccReg_EPP_ContactInfo((ccReg_EPP) service,
				info_contact->id,
				&c_contact,
				c_params,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_params);

	/* if it is exception then return */
	if (raised_exception(ev))
		return handle_exception(epp_ctx, cdata, ev);

	CLEAR_CERRNO(cerrno);

	/* copy output values */
	info_contact->roid = unwrap_str_req(epp_ctx, c_contact->ROID, &cerrno,
			"ROID");
	if (cerrno != 0) goto error;
	info_contact->handle = unwrap_str_req(epp_ctx, c_contact->handle,
			&cerrno, "handle");
	if (cerrno != 0) goto error;
	info_contact->authInfo = unwrap_str(epp_ctx->pool,
			c_contact->AuthInfoPw, &cerrno);
	if (cerrno != 0) goto error;
	info_contact->clID = unwrap_str_req(epp_ctx, c_contact->ClID, &cerrno,
			"clID");
	if (cerrno != 0) goto error;
	info_contact->crID = unwrap_str_req(epp_ctx, c_contact->CrID, &cerrno,
			"crID");
	if (cerrno != 0) goto error;
	info_contact->upID = unwrap_str(epp_ctx->pool, c_contact->UpID,
			&cerrno);
	if (cerrno != 0) goto error;
	info_contact->crDate = unwrap_str_req(epp_ctx, c_contact->CrDate,
			&cerrno, "crDate");
	if (cerrno != 0) goto error;
	info_contact->upDate = unwrap_str(epp_ctx->pool, c_contact->UpDate,
			&cerrno);
	if (cerrno != 0) goto error;
	info_contact->trDate = unwrap_str(epp_ctx->pool, c_contact->TrDate,
			&cerrno);
	if (cerrno != 0) goto error;
	/* contact status */
	for (i = 0; i < c_contact->stat._length; i++) {
		epp_status	*status;

		status = epp_malloc(epp_ctx->pool, sizeof *status);
		if (status == NULL)
			goto error;
		status->value = unwrap_str_req(epp_ctx,
				c_contact->stat._buffer[i].value, &cerrno,
				"status flag");
		if (cerrno != 0) goto error;
		status->text = unwrap_str_req(epp_ctx,
				c_contact->stat._buffer[i].text, &cerrno,
				"status text");
		if (cerrno != 0) goto error;
		if (q_add(epp_ctx->pool, &info_contact->status, status))
			goto error;
	}
	/* postal info */
	info_contact->pi.name = unwrap_str_req(epp_ctx, c_contact->Name,
			&cerrno, "name");
	if (cerrno != 0) goto error;
	info_contact->pi.org = unwrap_str(epp_ctx->pool,
			c_contact->Organization, &cerrno);
	if (cerrno != 0) goto error;
	for (i = 0; i < c_contact->Streets._length; i++) {
		char	*street;

		street = unwrap_str(epp_ctx->pool,c_contact->Streets._buffer[i],
				&cerrno);
		if (cerrno != 0) goto error;
		if (q_add(epp_ctx->pool, &info_contact->pi.streets, street))
			goto error;
	}
	info_contact->pi.city = unwrap_str_req(epp_ctx, c_contact->City,
			&cerrno, "city");
	if (cerrno != 0) goto error;
	info_contact->pi.sp = unwrap_str(epp_ctx->pool,
			c_contact->StateOrProvince, &cerrno);
	if (cerrno != 0) goto error;
	info_contact->pi.pc = unwrap_str_req(epp_ctx, c_contact->PostalCode,
			&cerrno, "pc");
	if (cerrno != 0) goto error;
	info_contact->pi.cc = unwrap_str_req(epp_ctx, c_contact->CountryCode,
			&cerrno, "cc");
	if (cerrno != 0) goto error;
	/* other attributes */
	info_contact->voice = unwrap_str(epp_ctx->pool, c_contact->Telephone,
			&cerrno);
	if (cerrno != 0) goto error;
	info_contact->fax = unwrap_str(epp_ctx->pool, c_contact->Fax, &cerrno);
	if (cerrno != 0) goto error;
	info_contact->email = unwrap_str_req(epp_ctx, c_contact->Email, &cerrno,
			"email");
	if (cerrno != 0) goto error;
	info_contact->notify_email = unwrap_str(epp_ctx->pool,
			c_contact->NotifyEmail, &cerrno);
	if (cerrno != 0) goto error;
	info_contact->vat = unwrap_str(epp_ctx->pool, c_contact->VAT, &cerrno);
	if (cerrno != 0) goto error;
	info_contact->ident = unwrap_str(epp_ctx->pool, c_contact->ident,
			&cerrno);
	if (cerrno != 0) goto error;
	/* convert identtype from idl's enum to our enum */
	switch (c_contact->identtype) {
		case ccReg_OP:
			info_contact->identtype = ident_OP;
			break;
		case ccReg_PASS:
			info_contact->identtype = ident_PASSPORT;
			break;
		case ccReg_MPSV:
			info_contact->identtype = ident_MPSV;
			break;
		case ccReg_ICO:
			info_contact->identtype = ident_ICO;
			break;
		case ccReg_BIRTHDAY:
			info_contact->identtype = ident_BIRTHDAY;
			break;
		default:
			info_contact->identtype = ident_UNKNOWN;
			break;
	}
	/* disclose info */
	
	c_contact->DiscloseFlag = convDisclBack(info_contact->discl.flag);
	
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
		info_contact->discl.vat =
			(c_contact->DiscloseVAT == CORBA_TRUE) ? 1 : 0;
		info_contact->discl.ident =
			(c_contact->DiscloseIdent == CORBA_TRUE) ? 1 : 0;
		info_contact->discl.notifyEmail =
			(c_contact->DiscloseNotifyEmail == CORBA_TRUE) ? 1 : 0;
	}

	CORBA_free(c_contact);
	return epilog_success(epp_ctx, cdata, response);

error:
	CORBA_free(c_contact);
	CORBA_free(response);
	return CORBA_INT_ERROR;
}

/**
 * EPP info domain.
 *
 * @param epp_ctx Epp context.
 * @param service EPP service.
 * @param loginid Session identifier.
 * @param request_id  fred-logd request ID
 * @param cdata   Data from xml request.
 * @return        Status.
 */
static corba_status
epp_call_info_domain(epp_context *epp_ctx,
		service_EPP service,
		unsigned long long loginid,
		const ccReg_TID request_id,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	ccReg_EppParams *c_params = NULL;
	ccReg_Response	*response;
	ccReg_Domain	*c_domain;
	int	i, retr, cerrno;
	epps_info_domain	*info_domain;

	info_domain = cdata->data;
	/*
	 * Input parameters:
	 *    name (a)
	 *    loginid
	 *    c_clTRID (*)
	 *    xml_in (a)
	 * Output parameters:
	 *    c_domain (*)
	 */
	assert(info_domain->name);
	assert(cdata->xml_in);

	c_params = init_epp_params(loginid, request_id, cdata->xml_in, cdata->clTRID);
	if(c_params == NULL) {
        return CORBA_INT_ERROR;
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		/* get information about domain */
		response = ccReg_EPP_DomainInfo((ccReg_EPP) service,
				info_domain->name,
				&c_domain,
				c_params,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_params);

	/* if it is exception then return */
	if (raised_exception(ev))
		return handle_exception(epp_ctx, cdata, ev);

	CLEAR_CERRNO(cerrno);

	/* copy output values */
	info_domain->roid   = unwrap_str_req(epp_ctx, c_domain->ROID, &cerrno,
			"ROID");
	if (cerrno != 0) goto error;
	info_domain->handle = unwrap_str_req(epp_ctx, c_domain->name, &cerrno,
			"handle");
	if (cerrno != 0) goto error;
	info_domain->clID   = unwrap_str_req(epp_ctx, c_domain->ClID, &cerrno,
			"clID");
	if (cerrno != 0) goto error;
	info_domain->crID   = unwrap_str_req(epp_ctx, c_domain->CrID, &cerrno,
			"crID");
	if (cerrno != 0) goto error;
	info_domain->upID   = unwrap_str(epp_ctx->pool, c_domain->UpID,
			&cerrno);
	if (cerrno != 0) goto error;
	info_domain->crDate = unwrap_str_req(epp_ctx, c_domain->CrDate,
			&cerrno, "crDate");
	if (cerrno != 0) goto error;
	info_domain->upDate = unwrap_str(epp_ctx->pool, c_domain->UpDate,
			&cerrno);
	if (cerrno != 0) goto error;
	info_domain->trDate = unwrap_str(epp_ctx->pool, c_domain->TrDate,
			&cerrno);
	if (cerrno != 0) goto error;
	info_domain->exDate = unwrap_str(epp_ctx->pool, c_domain->ExDate,
			&cerrno);
	if (cerrno != 0) goto error;
	info_domain->registrant = unwrap_str(epp_ctx->pool,
			c_domain->Registrant, &cerrno);
	if (cerrno != 0) goto error;
	info_domain->nsset  = unwrap_str(epp_ctx->pool, c_domain->nsset,
			&cerrno);
	if (cerrno != 0) goto error;
	info_domain->keyset  = unwrap_str(epp_ctx->pool, c_domain->keyset,
	                                &cerrno);
	if (cerrno != 0) goto error;
	info_domain->authInfo = unwrap_str(epp_ctx->pool, c_domain->AuthInfoPw,
			&cerrno);
	if (cerrno != 0) goto error;

	/* allocate and initialize status, admin lists */
	for (i = 0; i < c_domain->stat._length; i++) {
		epp_status	*status;

		status = epp_malloc(epp_ctx->pool, sizeof *status);
		if (status == NULL)
			goto error;

		status->value = unwrap_str_req(epp_ctx,
				c_domain->stat._buffer[i].value, &cerrno,
				"status flag");
		if (cerrno != 0) goto error;
		status->text = unwrap_str_req(epp_ctx,
				c_domain->stat._buffer[i].text, &cerrno,
				"status text");
		if (cerrno != 0) goto error;
		if (q_add(epp_ctx->pool, &info_domain->status, status))
			goto error;
	}
	for (i = 0; i < c_domain->admin._length; i++) {
		char	*admin;

		admin = unwrap_str_req(epp_ctx, c_domain->admin._buffer[i],
				&cerrno, "admin");
		if (cerrno != 0) goto error;
		if (q_add(epp_ctx->pool, &info_domain->admin, admin))
			goto error;
	}
	for (i = 0; i < c_domain->tmpcontact._length; i++) {
		char	*tmpcontact;

		tmpcontact = unwrap_str_req(epp_ctx,
				c_domain->tmpcontact._buffer[i], &cerrno,
				"tmpcontact");
		if (cerrno != 0) goto error;
		if (q_add(epp_ctx->pool, &info_domain->tmpcontact, tmpcontact))
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

			ext_item = epp_malloc(epp_ctx->pool, sizeof *ext_item);
			if (ext_item == NULL) goto error;
			ext_item->extType = EPP_EXT_ENUMVAL;
			ext_item->ext.ext_enum.ext_enumval = unwrap_str_req(epp_ctx,
					c_enumval->valExDate, &cerrno,
					"valExDate");

			ext_item->ext.ext_enum.publish = convDisclBack(c_enumval->publish);

			if (cerrno != 0) goto error;
			if (q_add(epp_ctx->pool, &info_domain->extensions,
						ext_item))
				goto error;
		}
	}

	CORBA_free(c_domain);
	return epilog_success(epp_ctx, cdata, response);

error:
	CORBA_free(c_domain);
	CORBA_free(response);
	return CORBA_INT_ERROR;
}

/**
 * EPP info nsset.
 *
 * @param epp_ctx Epp context.
 * @param service EPP service.
 * @param loginid Session identifier.
 * @param request_id  fred-logd request ID
 * @param cdata   Data from xml request.
 * @return        Status.
 */
static corba_status
epp_call_info_nsset(epp_context *epp_ctx,
		service_EPP service,
		unsigned long long loginid,
		const ccReg_TID request_id,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	ccReg_EppParams *c_params = NULL;
	ccReg_NSSet	*c_nsset;
	ccReg_Response	*response;
	epps_info_nsset	*info_nsset;
	int	i, retr, cerrno;

	info_nsset = cdata->data;
	/*
	 * Input parameters:
	 *    id (a)
	 *    loginid
	 *    c_clTRID (*)
	 *    xml_in (a)
	 * Output parameters:
	 *    c_contact (*)
	 */
	assert(info_nsset->id);
	assert(cdata->xml_in);
	c_params = init_epp_params(loginid, request_id, cdata->xml_in, cdata->clTRID);
	if(c_params == NULL) {
	    return CORBA_INT_ERROR;
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		/* get information about nsset */
		response = ccReg_EPP_NSSetInfo((ccReg_EPP) service,
				info_nsset->id,
				&c_nsset,
				c_params,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_params);

	/* if it is exception then return */
	if (raised_exception(ev))
		return handle_exception(epp_ctx, cdata, ev);

	CLEAR_CERRNO(cerrno);

	/* copy output values */
	info_nsset->roid   = unwrap_str_req(epp_ctx, c_nsset->ROID, &cerrno,
			"ROID");
	if (cerrno != 0) goto error;
	info_nsset->handle = unwrap_str_req(epp_ctx, c_nsset->handle, &cerrno,
			"handle");
	if (cerrno != 0) goto error;
	info_nsset->clID   = unwrap_str_req(epp_ctx, c_nsset->ClID, &cerrno,
			"clID");
	if (cerrno != 0) goto error;
	info_nsset->crID   = unwrap_str_req(epp_ctx, c_nsset->CrID, &cerrno,
			"crID");
	if (cerrno != 0) goto error;
	info_nsset->upID   = unwrap_str(epp_ctx->pool, c_nsset->UpID, &cerrno);
	if (cerrno != 0) goto error;
	info_nsset->crDate = unwrap_str_req(epp_ctx, c_nsset->CrDate, &cerrno,
			"crDate");
	if (cerrno != 0) goto error;
	info_nsset->upDate = unwrap_str(epp_ctx->pool, c_nsset->UpDate, &cerrno);
	if (cerrno != 0) goto error;
	info_nsset->trDate = unwrap_str(epp_ctx->pool, c_nsset->TrDate, &cerrno);
	if (cerrno != 0) goto error;
	info_nsset->authInfo = unwrap_str(epp_ctx->pool, c_nsset->AuthInfoPw,
			&cerrno);
	if (cerrno != 0) goto error;
	info_nsset->level = c_nsset->level;

	/* initialize status list */
	for (i = 0; i < c_nsset->stat._length; i++) {
		epp_status	*status;

		status = epp_malloc(epp_ctx->pool, sizeof *status);
		if (status == NULL)
			goto error;

		status->value = unwrap_str_req(epp_ctx,
				c_nsset->stat._buffer[i].value, &cerrno,
				"status flag");
		if (cerrno != 0) goto error;
		status->text = unwrap_str_req(epp_ctx,
				c_nsset->stat._buffer[i].text, &cerrno,
				"status text");
		if (cerrno != 0) goto error;
		if (q_add(epp_ctx->pool, &info_nsset->status, status))
			goto error;
	}
	/* initialize tech list */
	for (i = 0; i < c_nsset->tech._length; i++) {
		char	*tech;

		tech = unwrap_str_req(epp_ctx, c_nsset->tech._buffer[i], &cerrno,
				"tech");
		if (cerrno != 0) goto error;
		if (q_add(epp_ctx->pool, &info_nsset->tech, tech))
			goto error;
	}
	/* initialize required number of ns items */
	for (i = 0; i < c_nsset->dns._length; i++) {
		epp_ns	*ns_item;
		int	j;

		ns_item = epp_calloc(epp_ctx->pool, sizeof *ns_item);
		if (ns_item == NULL) goto error;

		/* process of ns item */
		ns_item->name = unwrap_str_req(epp_ctx,
				c_nsset->dns._buffer[i].fqdn, &cerrno, "fqdn");
		if (cerrno != 0) goto error;
		for (j = 0; j < c_nsset->dns._buffer[i].inet._length; j++) {
			char	*addr;

			addr = unwrap_str_req(epp_ctx,
					c_nsset->dns._buffer[i].inet._buffer[j],
					&cerrno, "addr");
			if (cerrno != 0) goto error;
			if (q_add(epp_ctx->pool, &ns_item->addr, addr))
				goto error;
		}
		/* enqueue ns item */
		if (q_add(epp_ctx->pool, &info_nsset->ns, ns_item))
			goto error;
	}

	CORBA_free(c_nsset);
	return epilog_success(epp_ctx, cdata, response);

error:
	CORBA_free(c_nsset);
	CORBA_free(response);
	return CORBA_INT_ERROR;
}

/**
 * EPP info keyset.
 *
 * @param epp_ctx Epp context.
 * @param service EPP service.
 * @param loginid Session identifier.
 * @param request_id  fred-logd request ID
 * @param cdata   Data from xml request.
 * @return        Status.
 */
static corba_status
epp_call_info_keyset(epp_context *epp_ctx,
		service_EPP service,
		unsigned long long loginid,
		const ccReg_TID request_id,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	ccReg_EppParams *c_params = NULL;
	ccReg_KeySet	*c_keyset;
	ccReg_Response	*response;
	epps_info_keyset *info_keyset;
	int	i, retr, cerrno;

	info_keyset = cdata->data;
	/*
	 * Input parameters:
	 *    id (a)
	 *    loginid
	 *    c_clTRID (*)
	 *    xml_in (a)
	 * Output parameters:
	 *    c_contact (*)
	 */
	assert(info_keyset->id);
	assert(cdata->xml_in);
	c_params = init_epp_params(loginid, request_id, cdata->xml_in, cdata->clTRID);
	if(c_params == NULL) {
	    return CORBA_INT_ERROR;
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		/* get information about nsset */
		response = ccReg_EPP_KeySetInfo((ccReg_EPP) service,
				info_keyset->id,
				&c_keyset,
				c_params,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_params);

	/* if it is exception then return */
	if (raised_exception(ev))
		return handle_exception(epp_ctx, cdata, ev);

	CLEAR_CERRNO(cerrno);

	/* copy output values */
	info_keyset->roid   = unwrap_str_req(epp_ctx, c_keyset->ROID, &cerrno,
			"ROID");
	if (cerrno != 0) goto error;
	info_keyset->handle = unwrap_str_req(epp_ctx, c_keyset->handle, &cerrno,
			"handle");
	if (cerrno != 0) goto error;
	info_keyset->clID   = unwrap_str_req(epp_ctx, c_keyset->ClID, &cerrno,
			"clID");
	if (cerrno != 0) goto error;
	info_keyset->crID   = unwrap_str_req(epp_ctx, c_keyset->CrID, &cerrno,
			"crID");
	if (cerrno != 0) goto error;
	info_keyset->upID   = unwrap_str(epp_ctx->pool, c_keyset->UpID, &cerrno);
	if (cerrno != 0) goto error;
	info_keyset->crDate = unwrap_str_req(epp_ctx, c_keyset->CrDate, &cerrno,
			"crDate");
	if (cerrno != 0) goto error;
	info_keyset->upDate = unwrap_str(epp_ctx->pool, c_keyset->UpDate, &cerrno);
	if (cerrno != 0) goto error;
	info_keyset->trDate = unwrap_str(epp_ctx->pool, c_keyset->TrDate, &cerrno);
	if (cerrno != 0) goto error;
	info_keyset->authInfo = unwrap_str(epp_ctx->pool, c_keyset->AuthInfoPw,
			&cerrno);
	if (cerrno != 0) goto error;

	/* initialize status list */
	for (i = 0; i < c_keyset->stat._length; i++) {
		epp_status	*status;

		status = epp_malloc(epp_ctx->pool, sizeof *status);
		if (status == NULL)
			goto error;

		status->value = unwrap_str_req(epp_ctx,
				c_keyset->stat._buffer[i].value, &cerrno,
				"status flag");
		if (cerrno != 0) goto error;
		status->text = unwrap_str_req(epp_ctx,
				c_keyset->stat._buffer[i].text, &cerrno,
				"status text");
		if (cerrno != 0) goto error;
		if (q_add(epp_ctx->pool, &info_keyset->status, status))
			goto error;
	}
	/* initialize tech list */
	for (i = 0; i < c_keyset->tech._length; i++) {
		char	*tech;

		tech = unwrap_str_req(epp_ctx, c_keyset->tech._buffer[i], &cerrno,
				"tech");
		if (cerrno != 0) goto error;
		if (q_add(epp_ctx->pool, &info_keyset->tech, tech))
			goto error;
	}
	/* initialize dnskey items */
	for (i = 0; i < c_keyset->dnsk._length; i++) {
		epp_dnskey *dnskey_item;

		dnskey_item = epp_calloc(epp_ctx->pool, sizeof *dnskey_item);
		if (dnskey_item == NULL) goto error;

		/* process of dnskey item */
		dnskey_item->flags = c_keyset->dnsk._buffer[i].flags;
		dnskey_item->alg = c_keyset->dnsk._buffer[i].alg;
		dnskey_item->protocol = c_keyset->dnsk._buffer[i].protocol;
		dnskey_item->public_key = unwrap_str_req(epp_ctx, c_keyset->dnsk._buffer[i].key, &cerrno, "public_key");
		if (cerrno != 0) goto error;

		/* enqueue dnskey item */
		if (q_add(epp_ctx->pool, &info_keyset->keys, dnskey_item))
			goto error;
	}

	CORBA_free(c_keyset);
	return epilog_success(epp_ctx, cdata, response);

error:
	CORBA_free(c_keyset);
	CORBA_free(response);
	return CORBA_INT_ERROR;
}



/**
 * EPP poll request.
 *
 * @param epp_ctx Epp context.
 * @param service EPP service.
 * @param loginid Session identifier.
 * @param request_id  fred-logd request ID
 * @param cdata   Data from xml request.
 * @return        Status.
 */
static corba_status
epp_call_poll_req(epp_context *epp_ctx,
		service_EPP service,
		unsigned long long loginid,
		const ccReg_TID request_id,
		epp_command_data *cdata)
{
	ccReg_Response	*response;
	ccReg_PollType	 c_polltype;
	CORBA_any	*c_mesg;
	CORBA_Environment	ev[1];
	CORBA_short	 c_count;
	CORBA_char	*c_qdate, *c_msgID;
	ccReg_EppParams *c_params = NULL;
	epps_poll_req	*poll_req;
	int	retr, cerrno;

	poll_req = cdata->data;
	/*
	 * Input parameters:
	 *    loginid
	 *    c_clTRID (*)
	 *    xml_in (a)
	 * Output parameters:
	 *    c_msgID (*)
	 *    c_count
	 *    c_qdate (*)
	 *    c_polltype
	 *    c_mesg (*)
	 */
	assert(cdata->xml_in);

	c_params = init_epp_params(loginid, request_id, cdata->xml_in, cdata->clTRID);
	if(c_params == NULL) {
	    return CORBA_INT_ERROR;
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		/* get message from repository */
		response = ccReg_EPP_PollRequest((ccReg_EPP) service,
				&c_msgID,
				&c_count,
				&c_qdate,
				&c_polltype,
				&c_mesg,
                c_params,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_params);

	/* if it is exception then return */
	if (raised_exception(ev))
		return handle_exception(epp_ctx, cdata, ev);

	CLEAR_CERRNO(cerrno);

	poll_req->count = c_count;
	poll_req->msgid = unwrap_str(epp_ctx->pool, c_msgID, &cerrno);
	if (cerrno != 0) goto error;
	poll_req->qdate = unwrap_str(epp_ctx->pool, c_qdate, &cerrno);
	if (cerrno != 0) goto error;
	/* copy message data */
	switch (c_polltype) {
		case ccReg_polltype_transfer_domain:
			{
			ccReg_PollMsg_HandleDateReg *hdr =
				(ccReg_PollMsg_HandleDateReg *) c_mesg->_value;
			poll_req->type = pt_transfer_domain;
			poll_req->msg.hdt.handle = unwrap_str(epp_ctx->pool,
					hdr->handle, &cerrno);
			if (cerrno != 0) goto error;
			poll_req->msg.hdt.date = unwrap_str(epp_ctx->pool,
					hdr->date, &cerrno);
			if (cerrno != 0) goto error;
			poll_req->msg.hdt.clID = unwrap_str(epp_ctx->pool,
					hdr->clID, &cerrno);
			if (cerrno != 0) goto error;
			break;
			}
		case ccReg_polltype_transfer_contact:
			{
			ccReg_PollMsg_HandleDateReg *hdr =
				(ccReg_PollMsg_HandleDateReg *) c_mesg->_value;
			poll_req->type = pt_transfer_contact;
			poll_req->msg.hdt.handle = unwrap_str(epp_ctx->pool,
					hdr->handle, &cerrno);
			if (cerrno != 0) goto error;
			poll_req->msg.hdt.date = unwrap_str(epp_ctx->pool,
					hdr->date, &cerrno);
			if (cerrno != 0) goto error;
			poll_req->msg.hdt.clID = unwrap_str(epp_ctx->pool,
					hdr->clID, &cerrno);
			if (cerrno != 0) goto error;
			break;
			}
		case ccReg_polltype_transfer_nsset:
			{
			ccReg_PollMsg_HandleDateReg *hdr =
				(ccReg_PollMsg_HandleDateReg *) c_mesg->_value;
			poll_req->type = pt_transfer_nsset;
			poll_req->msg.hdt.handle = unwrap_str(epp_ctx->pool,
					hdr->handle, &cerrno);
			if (cerrno != 0) goto error;
			poll_req->msg.hdt.date = unwrap_str(epp_ctx->pool,
					hdr->date, &cerrno);
			if (cerrno != 0) goto error;
			poll_req->msg.hdt.clID = unwrap_str(epp_ctx->pool,
					hdr->clID, &cerrno);
			if (cerrno != 0) goto error;
			break;
			}
		case ccReg_polltype_transfer_keyset:
			{
			ccReg_PollMsg_HandleDateReg *hdr =
				(ccReg_PollMsg_HandleDateReg *) c_mesg->_value;
			poll_req->type = pt_transfer_keyset;
			poll_req->msg.hdt.handle = unwrap_str(epp_ctx->pool,
					hdr->handle, &cerrno);
			if (cerrno != 0) goto error;
			poll_req->msg.hdt.date = unwrap_str(epp_ctx->pool,
					hdr->date, &cerrno);
			if (cerrno != 0) goto error;
			poll_req->msg.hdt.clID = unwrap_str(epp_ctx->pool,
					hdr->clID, &cerrno);
			if (cerrno != 0) goto error;
			break;
			}
		case ccReg_polltype_delete_contact:
			poll_req->type = pt_delete_contact;
			poll_req->msg.handle = unwrap_str(epp_ctx->pool,
					*((char **) c_mesg->_value), &cerrno);
			if (cerrno != 0) goto error;
			break;
		case ccReg_polltype_delete_nsset:
			poll_req->type = pt_delete_nsset;
			poll_req->msg.handle = unwrap_str(epp_ctx->pool,
					*((char **) c_mesg->_value), &cerrno);
			if (cerrno != 0) goto error;
			break;
		case ccReg_polltype_delete_keyset:
			poll_req->type = pt_delete_keyset;
			poll_req->msg.handle = unwrap_str(epp_ctx->pool,
					*((char **) c_mesg->_value), &cerrno);
			if (cerrno != 0) goto error;
			break;
		case ccReg_polltype_delete_domain:
			{
			ccReg_PollMsg_HandleDate *hd =
				(ccReg_PollMsg_HandleDate *) c_mesg->_value;
			poll_req->type = pt_delete_domain;
			poll_req->msg.hd.handle = unwrap_str(epp_ctx->pool,
					hd->handle, &cerrno);
			if (cerrno != 0) goto error;
			poll_req->msg.hd.date = unwrap_str(epp_ctx->pool,
					hd->date, &cerrno);
			if (cerrno != 0) goto error;
			break;
			}
		case ccReg_polltype_impexpiration:
			{
			ccReg_PollMsg_HandleDate *hd =
				(ccReg_PollMsg_HandleDate *) c_mesg->_value;
			poll_req->type = pt_impexpiration;
			poll_req->msg.hd.handle = unwrap_str(epp_ctx->pool,
					hd->handle, &cerrno);
			if (cerrno != 0) goto error;
			poll_req->msg.hd.date = unwrap_str(epp_ctx->pool,
					hd->date, &cerrno);
			if (cerrno != 0) goto error;
			break;
			}
		case ccReg_polltype_expiration:
			{
			ccReg_PollMsg_HandleDate *hd =
				(ccReg_PollMsg_HandleDate *) c_mesg->_value;
			poll_req->type = pt_expiration;
			poll_req->msg.hd.handle = unwrap_str(epp_ctx->pool,
					hd->handle, &cerrno);
			if (cerrno != 0) goto error;
			poll_req->msg.hd.date = unwrap_str(epp_ctx->pool,
					hd->date, &cerrno);
			if (cerrno != 0) goto error;
			break;
			}
		case ccReg_polltype_impvalidation:
			{
			ccReg_PollMsg_HandleDate *hd =
				(ccReg_PollMsg_HandleDate *) c_mesg->_value;
			poll_req->type = pt_impvalidation;
			poll_req->msg.hd.handle = unwrap_str(epp_ctx->pool,
					hd->handle, &cerrno);
			if (cerrno != 0) goto error;
			poll_req->msg.hd.date = unwrap_str(epp_ctx->pool,
					hd->date, &cerrno);
			if (cerrno != 0) goto error;
			break;
			}
		case ccReg_polltype_validation:
			{
			ccReg_PollMsg_HandleDate *hd =
				(ccReg_PollMsg_HandleDate *) c_mesg->_value;
			poll_req->type = pt_validation;
			poll_req->msg.hd.handle = unwrap_str(epp_ctx->pool,
					hd->handle, &cerrno);
			if (cerrno != 0) goto error;
			poll_req->msg.hd.date = unwrap_str(epp_ctx->pool,
					hd->date, &cerrno);
			if (cerrno != 0) goto error;
			break;
			}
		case ccReg_polltype_outzone:
			{
			ccReg_PollMsg_HandleDate *hd =
				(ccReg_PollMsg_HandleDate *) c_mesg->_value;
			poll_req->type = pt_outzone;
			poll_req->msg.hd.handle = unwrap_str(epp_ctx->pool,
					hd->handle, &cerrno);
			if (cerrno != 0) goto error;
			poll_req->msg.hd.date = unwrap_str(epp_ctx->pool,
					hd->date, &cerrno);
			if (cerrno != 0) goto error;
			break;
			}
		case ccReg_polltype_techcheck:
			{
			ccReg_PollMsg_Techcheck *tc =
				(ccReg_PollMsg_Techcheck *) c_mesg->_value;
			int	i;

			poll_req->type = pt_techcheck;
			poll_req->msg.tc.handle = unwrap_str(epp_ctx->pool,
					tc->handle, &cerrno);
			if (cerrno != 0) goto error;
			/* copy list of extra fqdns */
			for (i = 0; i < tc->fqdns._length; i++) {
				char *fqdn = unwrap_str(epp_ctx->pool,
						tc->fqdns._buffer[i], &cerrno);
				if (cerrno != 0) goto error;
				if (q_add(epp_ctx->pool,
						&poll_req->msg.tc.fqdns, fqdn))
					goto error;
			}
			for (i = 0; i < tc->tests._length; i++) {
				ccReg_TechcheckItem *tci= &tc->tests._buffer[i];
				epp_testResult	*tr = epp_malloc(epp_ctx->pool,
						sizeof *tr);
				tr->status = (tci->status ? 1 : 0);
				tr->testname = unwrap_str(epp_ctx->pool,
						tci->testname, &cerrno);
				if (cerrno != 0) goto error;
				tr->note = unwrap_str(epp_ctx->pool,
						tci->note, &cerrno);
				if (cerrno != 0) goto error;
				if (q_add(epp_ctx->pool,
						&poll_req->msg.tc.tests, tr))
					goto error;
			}
			break;
			}
		case ccReg_polltype_lowcredit:
			{
			ccReg_PollMsg_LowCredit *lc =
				(ccReg_PollMsg_LowCredit *) c_mesg->_value;
			poll_req->type = pt_lowcredit;
			poll_req->msg.lc.zone = unwrap_str(epp_ctx->pool,
					lc->zone, &cerrno);
			if (cerrno != 0) goto error;
			poll_req->msg.lc.limit = lc->limit;
			poll_req->msg.lc.credit = lc->credit;
			break;
			}
        case ccReg_polltype_request_fee_info:
            {
            ccReg_PollMsg_RequestFeeInfo *rfi =
                (ccReg_PollMsg_RequestFeeInfo *) c_mesg->_value;
            poll_req->type = pt_request_fee_info;
            poll_req->msg.rfi.period_from = unwrap_str(epp_ctx->pool,
                    rfi->periodFrom, &cerrno);
            if (cerrno != 0) goto error;
            poll_req->msg.rfi.period_to = unwrap_str(epp_ctx->pool,
                    rfi->periodTo, &cerrno);
            if (cerrno != 0) goto error;
            poll_req->msg.rfi.total_free_count = rfi->totalFreeCount;
            poll_req->msg.rfi.used_count = rfi->usedCount;
            poll_req->msg.rfi.price = unwrap_str(epp_ctx->pool,
                    rfi->price, &cerrno);
            if (cerrno != 0) goto error;
            break;
            }
		default:
			epplog(epp_ctx, EPP_ERROR, "Unexpected type of poll "
					"message.");
			goto error;
	}

	CORBA_free(c_msgID);
	CORBA_free(c_mesg);
	CORBA_free(c_qdate);
	return epilog_success(epp_ctx, cdata, response);

error:
	CORBA_free(c_msgID);
	CORBA_free(c_qdate);
	CORBA_free(c_mesg);
	CORBA_free(response);
	return CORBA_INT_ERROR;
}

/**
 * EPP poll acknowledge.
 *
 * @param epp_ctx Epp context.
 * @param service EPP service.
 * @param loginid Session identifier.
 * @param request_id  fred-logd request ID
 * @param cdata   Data from xml request.
 * @return        Status.
 */
static corba_status
epp_call_poll_ack(epp_context *epp_ctx,
		service_EPP service,
		unsigned long long loginid,
		const ccReg_TID request_id,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	CORBA_char	*c_msgID;
	CORBA_short	 c_count;
	ccReg_EppParams *c_params = NULL;
	ccReg_Response	*response;
	int	retr, cerrno;
	epps_poll_ack	*poll_ack;

	poll_ack = cdata->data;
	/*
	 * Input parameters:
	 *    msgid (a)
	 *    loginid
	 *    c_clTRID (*)
	 *    xml_in (a)
	 * Output parameters:
	 *    c_count
	 *    c_msgID (*)
	 */
	assert(poll_ack->msgid);
	assert(cdata->xml_in);

	c_params = init_epp_params(loginid, request_id, cdata->xml_in, cdata->clTRID);
	if(c_params == NULL) {
	    return CORBA_INT_ERROR;
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		/* send acknoledgement */
		response = ccReg_EPP_PollAcknowledgement((ccReg_EPP) service,
				poll_ack->msgid,
				&c_count,
				&c_msgID,
				c_params,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_params);

	/* if it is exception then return */
	if (raised_exception(ev))
		return handle_exception(epp_ctx, cdata, ev);

	CLEAR_CERRNO(cerrno);

	poll_ack->count = c_count;
	poll_ack->newmsgid = unwrap_str(epp_ctx->pool, c_msgID, &cerrno);
	if (cerrno != 0) goto error;

	CORBA_free(c_msgID);
	return epilog_success(epp_ctx, cdata, response);

error:
	CORBA_free(c_msgID);
	CORBA_free(response);
	return CORBA_INT_ERROR;
}

/**
 * EPP create domain.
 *
 * @param epp_ctx Epp context.
 * @param service EPP service.
 * @param loginid Session identifier.
 * @param request_id  fred-logd request ID
 * @param cdata   Data from xml request.
 * @return        Status.
 */
static corba_status
epp_call_create_domain(epp_context *epp_ctx,
		service_EPP service,
		unsigned long long loginid,
                const ccReg_TID request_id,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	CORBA_char	*c_crDate, *c_exDate;
	CORBA_char	*c_registrant, *c_nsset, *c_keyset, *c_authInfo;
	ccReg_Response	*response = NULL;
	ccReg_AdminContact	*c_admin = NULL;
	ccReg_ExtensionList	*c_ext_list = NULL;
	ccReg_Period_str	*c_period = NULL;
    ccReg_EppParams     *c_params = NULL;
	int	len, i, retr, cerrno, input_ok;
	epps_create_domain	*create_domain;

	create_domain = cdata->data;
	input_ok = 0;
	/* init corba input parameters to NULL, because CORBA_free(NULL) is ok */
	c_authInfo = NULL;
	c_period = NULL;
	c_nsset = NULL;
	c_keyset = NULL;
	c_registrant = NULL;
    c_params = NULL;
	/*
	 * Input parameters:
	 *    name (a)
	 *    c_registrant (*)
	 *    c_nsset    (*)
	 *    c_authInfo (*)
	 *    c_period   (*)
	 *    c_admin  (*)
	 *    loginid
	 *    c_clTRID (*)
	 *    xml_in (a)
	 *    c_ext_list (*)
	 * Output parameters:
	 *    c_crDate (*)
	 *    c_exDate (*)
	 */
	assert(create_domain->name);
	assert(cdata->xml_in);

	c_params = init_epp_params(loginid, request_id, cdata->xml_in, cdata->clTRID);
    if (c_params == NULL) goto error_input;

	c_registrant = wrap_str(create_domain->registrant);
	if (c_registrant == NULL) goto error_input;
	c_nsset = wrap_str(create_domain->nsset);
	if (c_nsset == NULL) goto error_input;
	c_keyset = wrap_str(create_domain->keyset);
	if (c_keyset == NULL) goto error_input;
	c_authInfo = wrap_str(create_domain->authInfo);
	if (c_authInfo == NULL) goto error_input;
	c_period = ccReg_Period_str__alloc();
	if (c_period == NULL) goto error_input;
	c_period->count = create_domain->period;
	c_period->unit  = (create_domain->unit == TIMEUNIT_MONTH) ?
		ccReg_unit_month : ccReg_unit_year;
	c_admin = ccReg_AdminContact__alloc();
	if (c_admin == NULL) goto error_input;
	len = q_length(create_domain->admin);
	c_admin->_buffer = ccReg_AdminContact_allocbuf(len);
	if (len != 0 && c_admin->_buffer == NULL) goto error_input;
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
	if (len != 0 && c_ext_list->_buffer == NULL) goto error_input;
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
				wrap_str(ext_item->ext.ext_enum.ext_enumval);
			if (c_enumval->valExDate == NULL) {
				CORBA_free(c_enumval);
				goto error_input;
			}

			c_enumval->publish = convDiscl(ext_item->ext.ext_enum.publish);

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
		response = ccReg_EPP_DomainCreate((ccReg_EPP) service,
				create_domain->name,
				c_registrant,
				c_nsset,
				c_keyset,
				c_authInfo,
				c_period,
				c_admin,
				&c_crDate,
				&c_exDate,
                                c_params,
				c_ext_list,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	input_ok = 1;

error_input:
	CORBA_free(c_ext_list);
	CORBA_free(c_admin);
	CORBA_free(c_authInfo);
	CORBA_free(c_period);
	CORBA_free(c_nsset);
	CORBA_free(c_keyset);
	CORBA_free(c_registrant);
        CORBA_free(c_params);
	if (!input_ok)
		return CORBA_INT_ERROR;

	/* if it is exception then return */
	if (raised_exception(ev))
		return handle_exception(epp_ctx, cdata, ev);

	CLEAR_CERRNO(cerrno);

	create_domain->crDate = unwrap_str_req(epp_ctx, c_crDate, &cerrno,
			"crDate");
	if (cerrno != 0) goto error;
	create_domain->exDate = unwrap_str_req(epp_ctx, c_exDate, &cerrno,
			"exDate");
	if (cerrno != 0) goto error;

	CORBA_free(c_crDate);
	CORBA_free(c_exDate);
	return epilog_success(epp_ctx, cdata, response);

error:
	CORBA_free(c_crDate);
	CORBA_free(c_exDate);
	CORBA_free(response);
	return CORBA_INT_ERROR;
}

/**
 * Convert our SSN enum to IDL's SSNtyp enum.
 *
 * @param our_ident Our ssn's type.
 * @return        SSN type as defined in IDL.
 */
static ccReg_identtyp
convIdentType(epp_identType our_ident)
{
	switch (our_ident) {
		case ident_OP: return ccReg_OP; break;
		case ident_PASSPORT: return ccReg_PASS; break;
		case ident_MPSV: return ccReg_MPSV; break;
		case ident_ICO: return ccReg_ICO; break;
		case ident_BIRTHDAY: return ccReg_BIRTHDAY; break;
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



static char convDisclBack(ccReg_Disclose discl)
{
	if (discl == ccReg_DISCL_HIDE)
		return 0;
	else if (discl == ccReg_DISCL_DISPLAY)
		return 1;
	else
		return -1;
}

/**
 * EPP create contact.
 *
 * @param epp_ctx Epp context.
 * @param service EPP service.
 * @param loginid Session identifier.
 * @param request_id  fred-logd request ID
 * @param cdata   Data from xml request.
 * @return        Status.
 */
static corba_status
epp_call_create_contact(epp_context *epp_ctx,
		service_EPP service,
		unsigned long long loginid,
                const ccReg_TID request_id,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	CORBA_char	*c_crDate;
	ccReg_ContactChange	*c_contact;
	ccReg_Response *response;
        ccReg_EppParams *c_params = NULL;
	int	retr, cerrno, len, i;
	epps_create_contact	*create_contact;

	create_contact = cdata->data;
	/*
	 * Input parameters:
	 *    id        (a)
	 *    c_contact (*)
	 *    loginid
	 *    xml_in    (a)
	 * Output parameters:
	 *    c_crDate  (*)
	 */
	assert(create_contact->id);
	assert(cdata->xml_in);

	/* fill in corba input values */
	c_contact = ccReg_ContactChange__alloc();
	if (c_contact == NULL) {
		
		return CORBA_INT_ERROR;
	}
	c_contact->AuthInfoPw = wrap_str(create_contact->authInfo);
	if (c_contact->AuthInfoPw == NULL) {
		CORBA_free(c_contact);
		return CORBA_INT_ERROR;
	}
	c_contact->Telephone = wrap_str(create_contact->voice);
	if (c_contact->AuthInfoPw == NULL) {
		CORBA_free(c_contact);
		return CORBA_INT_ERROR;
	}
	c_contact->Fax = wrap_str(create_contact->fax);
	if (c_contact->Fax == NULL) {
		CORBA_free(c_contact);
		return CORBA_INT_ERROR;
	}
	c_contact->Email = wrap_str(create_contact->email);
	if (c_contact->Email == NULL) {
		CORBA_free(c_contact);
		return CORBA_INT_ERROR;
	}
	c_contact->NotifyEmail =
			wrap_str(create_contact->notify_email);
	if (c_contact->NotifyEmail == NULL) {
		CORBA_free(c_contact);
		return CORBA_INT_ERROR;
	}
	c_contact->VAT = wrap_str(create_contact->vat);
	if (c_contact->VAT == NULL) {
		CORBA_free(c_contact);
		return CORBA_INT_ERROR;
	}
	c_contact->ident = wrap_str(create_contact->ident);
	if (c_contact->ident == NULL) {
		CORBA_free(c_contact);
		return CORBA_INT_ERROR;
	}
	c_contact->identtype = convIdentType(create_contact->identtype);
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
		c_contact->DiscloseVAT =
			(create_contact->discl.vat ? CORBA_TRUE : CORBA_FALSE);
		c_contact->DiscloseIdent =
			(create_contact->discl.ident ? CORBA_TRUE : CORBA_FALSE);
		c_contact->DiscloseNotifyEmail =
			(create_contact->discl.notifyEmail ? CORBA_TRUE : CORBA_FALSE);
	}
	/* postal info */
	c_contact->Name = wrap_str(create_contact->pi.name);
	if (c_contact->Name == NULL) {
		CORBA_free(c_contact);
		return CORBA_INT_ERROR;
	}
	c_contact->Organization = wrap_str(create_contact->pi.org);
	if (c_contact->Organization == NULL) {
		CORBA_free(c_contact);
		return CORBA_INT_ERROR;
	}
	len = q_length(create_contact->pi.streets);
	c_contact->Streets._buffer = ccReg_Lists_allocbuf(len);
	if (len != 0 && c_contact->Streets._buffer == NULL) {
		CORBA_free(c_contact);
		return CORBA_INT_ERROR;
	}
	c_contact->Streets._maximum = c_contact->Streets._length = len;
	c_contact->Streets._release = CORBA_TRUE;
	i = 0;
	q_foreach(&create_contact->pi.streets) {
		c_contact->Streets._buffer[i] =
			wrap_str(q_content(&create_contact->pi.streets));
		if (c_contact->Streets._buffer[i++] == NULL) {
			CORBA_free(c_contact);
			return CORBA_INT_ERROR;
		}
	}
	c_contact->City = wrap_str(create_contact->pi.city);
	if (c_contact->City == NULL) {
		CORBA_free(c_contact);
		return CORBA_INT_ERROR;
	}
	c_contact->StateOrProvince = wrap_str(create_contact->pi.sp);
	if (c_contact->StateOrProvince == NULL) {
		CORBA_free(c_contact);
		return CORBA_INT_ERROR;
	}
	c_contact->PostalCode = wrap_str(create_contact->pi.pc);
	if (c_contact->PostalCode == NULL) {
		CORBA_free(c_contact);
		return CORBA_INT_ERROR;
	}
	c_contact->CC = wrap_str(create_contact->pi.cc);
	if (c_contact->CC == NULL) {
		CORBA_free(c_contact);
		return CORBA_INT_ERROR;
	}

	c_params = init_epp_params(loginid, request_id, cdata->xml_in, cdata->clTRID);
	if(c_params == NULL) {
		CORBA_free(c_contact);
		return CORBA_INT_ERROR;
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		/* send new contact in repository */
		response = ccReg_EPP_ContactCreate((ccReg_EPP) service,
				create_contact->id,
				c_contact,
				&c_crDate,
                                c_params,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_contact);
        CORBA_free(c_params);

	/* if it is exception then return */
	if (raised_exception(ev))
		return handle_exception(epp_ctx, cdata, ev);

	CLEAR_CERRNO(cerrno);

	create_contact->crDate = unwrap_str_req(epp_ctx, c_crDate, &cerrno,
			"crDate");
	if (cerrno != 0) {
		CORBA_free(c_crDate);
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}

	CORBA_free(c_crDate);
	return epilog_success(epp_ctx, cdata, response);
}

/**
 * EPP create nsset.
 *
 * @param epp_ctx Epp context.
 * @param service EPP service.
 * @param loginid Session identifier.
 * @param request_id  fred-logd request ID
 * @param cdata   Data from xml request.
 * @return        Status.
 */
static corba_status
epp_call_create_nsset(epp_context *epp_ctx,
		service_EPP service,
		unsigned long long loginid,
                const ccReg_TID request_id,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	ccReg_Response *response;
	ccReg_DNSHost	*c_dnshost;
	ccReg_TechContact	*c_tech;
        ccReg_EppParams *c_params = NULL;
	CORBA_char	*c_crDate, *c_authInfo;
	int	len, i, retr, cerrno;
	epps_create_nsset	*create_nsset;

	create_nsset = cdata->data;
	/*
	 * Input parameters:
	 *    id (a)
	 *    c_authInfo (*)
	 *    c_tech (*)
	 *    c_dnshost (*)
	 *    level
	 *    loginid
	 *    c_clTRID (*)
	 *    xml_in (a)
	 * Output parameters:
	 *    c_crDate (*)
	 */
	assert(create_nsset->id != NULL);
	assert(cdata->xml_in != NULL);

	c_authInfo = wrap_str(create_nsset->authInfo);
	if (c_authInfo == NULL) {
		return CORBA_INT_ERROR;
	}

	/* alloc & init sequence of nameservers */
	c_dnshost = ccReg_DNSHost__alloc();
	if (c_dnshost == NULL) {
		CORBA_free(c_authInfo);
		return CORBA_INT_ERROR;
	}
	len = q_length(create_nsset->ns);
	c_dnshost->_buffer = ccReg_DNSHost_allocbuf(len);
	if (len != 0 && c_dnshost->_buffer == NULL) {
		CORBA_free(c_dnshost);
		CORBA_free(c_authInfo);
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
			return CORBA_INT_ERROR;
		}
		/* initialize sequence of addresses */
		len = q_length(ns->addr);
		c_dnshost->_buffer[i].inet._buffer =
			ccReg_InetAddress_allocbuf(len);
		if (len != 0 && c_dnshost->_buffer[i].inet._buffer == NULL) {
			CORBA_free(c_dnshost);
			CORBA_free(c_authInfo);
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
		return CORBA_INT_ERROR;
	}
	len = q_length(create_nsset->tech);
	c_tech->_buffer = ccReg_TechContact_allocbuf(len);
	if (len != 0 && c_tech->_buffer == NULL) {
		CORBA_free(c_tech);
		CORBA_free(c_dnshost);
		CORBA_free(c_authInfo);
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
			return CORBA_INT_ERROR;
		}
	}

	c_params = init_epp_params(loginid, request_id, cdata->xml_in, cdata->clTRID);

	if(c_params == NULL) {
        CORBA_free(c_tech);
		CORBA_free(c_dnshost);
		CORBA_free(c_authInfo);
		return CORBA_INT_ERROR;
	}
        
	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		/* send new nsset to repository */
		response = ccReg_EPP_NSSetCreate((ccReg_EPP) service,
				create_nsset->id,
				c_authInfo,
				c_tech,
				c_dnshost,
				create_nsset->level,
				&c_crDate,
                                c_params,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_tech);
	CORBA_free(c_dnshost);
	CORBA_free(c_authInfo);
        CORBA_free(c_params);

	/* if it is exception then return */
	if (raised_exception(ev))
		return handle_exception(epp_ctx, cdata, ev);

	CLEAR_CERRNO(cerrno);

	create_nsset->crDate = unwrap_str(epp_ctx->pool, c_crDate, &cerrno);
	if (cerrno != 0) {
		CORBA_free(c_crDate);
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}

	CORBA_free(c_crDate);
	return epilog_success(epp_ctx, cdata, response);
}

/**
 * EPP create keyset.
 *
 * @param epp_ctx Epp context.
 * @param service EPP service.
 * @param loginid Session identifier.
 * @param request_id  fred-logd request ID
 * @param cdata   Data from xml request.
 * @return        Status.
 */
static corba_status
epp_call_create_keyset(epp_context *epp_ctx,
		service_EPP service,
		unsigned long long loginid,
                const ccReg_TID request_id,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	ccReg_Response *response;
	ccReg_DSRecord	*c_dsrecord;
	ccReg_DNSKey *c_dnskey;
	ccReg_TechContact	*c_tech;
        ccReg_EppParams         *c_params;
	CORBA_char	*c_crDate, *c_authInfo;
	int	len, i, retr, cerrno;
	epps_create_keyset	*create_keyset;

	create_keyset = cdata->data;
	/*
	 * Input parameters:
	 *    id (a)
	 *    c_authInfo (*)
	 *    c_tech (*)
	 *    c_dsrecord (*)
	 *    level
	 *    loginid
	 *    c_clTRID (*)
	 *    xml_in (a)
	 * Output parameters:
	 *    c_crDate (*)
	 */
	assert(create_keyset->id != NULL);
	assert(cdata->xml_in != NULL);

	c_authInfo = wrap_str(create_keyset->authInfo);
	if (c_authInfo == NULL) {
		return CORBA_INT_ERROR;
	}

	/* alloc & init sequence of delegation signer records 
     * note: dsrecords are obsolete but we didn't changed
     * interface so we use only empty sequence */
	c_dsrecord = ccReg_DSRecord__alloc();
	if (c_dsrecord == NULL) {
		CORBA_free(c_authInfo);
		return CORBA_INT_ERROR;
	}
	/* alloc & init sequence of DNSKEY records */
	c_dnskey = ccReg_DNSKey__alloc();
	if (c_dnskey == NULL) {
		CORBA_free(c_dsrecord);
		CORBA_free(c_authInfo);
		return CORBA_INT_ERROR;
	}
	len = q_length(create_keyset->keys);
	c_dnskey->_buffer = ccReg_DNSKey_allocbuf(len);
	if (len != 0 && c_dnskey->_buffer == NULL) {
		CORBA_free(c_dsrecord);
		CORBA_free(c_authInfo);
		return CORBA_INT_ERROR;
	}

	c_dnskey->_maximum = c_dnskey->_length = len;
	c_dnskey->_release = CORBA_TRUE;
	i = 0;
	q_foreach(&create_keyset->keys) {
		epp_dnskey *dnskey;

		dnskey = q_content(&create_keyset->keys);

		c_dnskey->_buffer[i].flags = dnskey->flags;
		c_dnskey->_buffer[i].protocol = dnskey->protocol;
		c_dnskey->_buffer[i].alg = dnskey->alg;

		c_dnskey->_buffer[i].key = wrap_str(dnskey->public_key);
		if(c_dnskey->_buffer[i].key == NULL) {
			CORBA_free(c_dnskey);
			CORBA_free(c_dsrecord);
			CORBA_free(c_authInfo);
			return CORBA_INT_ERROR;
		}

		i++;
	}

	/* alloc & init sequence of tech contacts */
	c_tech = ccReg_TechContact__alloc();
	if (c_tech == NULL) {
		CORBA_free(c_dnskey);
		CORBA_free(c_dsrecord);
		CORBA_free(c_authInfo);
		return CORBA_INT_ERROR;
	}
	len = q_length(create_keyset->tech);
	c_tech->_buffer = ccReg_TechContact_allocbuf(len);
	if (len != 0 && c_tech->_buffer == NULL) {
		CORBA_free(c_tech);
		CORBA_free(c_dnskey);
		CORBA_free(c_dsrecord);
		CORBA_free(c_authInfo);
		return CORBA_INT_ERROR;
	}
	c_tech->_release = CORBA_TRUE;
	c_tech->_maximum = c_tech->_length = len;
	i = 0;
	q_foreach(&create_keyset->tech) {
		c_tech->_buffer[i] = wrap_str(q_content(&create_keyset->tech));
		if (c_tech->_buffer[i++] == NULL) {
			CORBA_free(c_tech);
			CORBA_free(c_dnskey);
			CORBA_free(c_dsrecord);
			CORBA_free(c_authInfo);
			return CORBA_INT_ERROR;
		}
	}

	c_params = init_epp_params(loginid, request_id, cdata->xml_in, cdata->clTRID);
	if (c_params == NULL) {
		CORBA_free(c_tech);
		CORBA_free(c_dnskey);
		CORBA_free(c_dsrecord);
		CORBA_free(c_authInfo);
		return CORBA_INT_ERROR;
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		/* send new keyset to repository */
		response = ccReg_EPP_KeySetCreate((ccReg_EPP) service,
				create_keyset->id,
				c_authInfo,
				c_tech,
				c_dsrecord,
				c_dnskey,
				&c_crDate,
                                c_params,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_tech);
	CORBA_free(c_dnskey);
	CORBA_free(c_dsrecord);
	CORBA_free(c_authInfo);
        CORBA_free(c_params);

	/* if it is exception then return */
	if (raised_exception(ev))
		return handle_exception(epp_ctx, cdata, ev);

	CLEAR_CERRNO(cerrno);

	create_keyset->crDate = unwrap_str(epp_ctx->pool, c_crDate, &cerrno);
	if (cerrno != 0) {
		CORBA_free(c_crDate);
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}

	CORBA_free(c_crDate);
	return epilog_success(epp_ctx, cdata, response);
}


/**
 * EPP delete for domain, nsset and contact is so similar that it is worth of
 * having the code in one function and pass object type as parameter.
 *
 * @param epp_ctx Epp context.
 * @param service EPP service.
 * @param loginid Session identifier.
 * @param request_id  fred-logd request ID
 * @param cdata   Data from xml request.
 * @param obj     Object type (see #epp_object_type)
 * @return        Status.
 */
static corba_status
epp_call_delete(epp_context *epp_ctx,
		service_EPP service,
		unsigned long long loginid,
                const ccReg_TID request_id,
		epp_command_data *cdata,
		epp_object_type obj)
{
	CORBA_Environment ev[1];
	ccReg_Response *response;
        ccReg_EppParams *c_params;
	int	retr;
	epps_delete	*delete;

	delete = cdata->data;
	/*
	 * Input parameters:
	 *    id (a)
	 *    loginid
	 *    c_clTRID (*)
	 *    xml_in (a)
	 * Output parameters: none
	 */
	assert(delete->id);
	assert(cdata->xml_in);

	c_params = init_epp_params(loginid, request_id, cdata->xml_in, cdata->clTRID);
	if (c_params == NULL) {
		return CORBA_INT_ERROR;
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		if (obj == EPP_DOMAIN)
			response = ccReg_EPP_DomainDelete((ccReg_EPP) service,
					delete->id, c_params, ev);
		else if (obj == EPP_CONTACT)
			response = ccReg_EPP_ContactDelete((ccReg_EPP) service,
					delete->id, c_params, ev);
		else if (obj == EPP_KEYSET)
			response = ccReg_EPP_KeySetDelete((ccReg_EPP) service,
					delete->id, c_params, ev);
		else {
			assert(obj == EPP_NSSET);
			response = ccReg_EPP_NSSetDelete((ccReg_EPP) service,
					delete->id, c_params, ev);
		}

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

	CORBA_free(c_params);

	/* if it is exception then return */
	if (raised_exception(ev))
		return handle_exception(epp_ctx, cdata, ev);

	return epilog_success(epp_ctx, cdata, response);
}

/**
 * EPP renew domain.
 *
 * @param epp_ctx Epp context.
 * @param service EPP service.
 * @param loginid Session identifier.
 * @param request_id  fred-logd request ID
 * @param cdata   Data from xml request.
 * @return        Status.
 */
static corba_status
epp_call_renew_domain(epp_context *epp_ctx,
		service_EPP service,
		unsigned long long loginid,
        const ccReg_TID request_id,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	ccReg_Response	*response;
	CORBA_char	*c_exDateIN, *c_exDateOUT;
	ccReg_Period_str	*c_period;
	ccReg_ExtensionList	*c_ext_list;
        ccReg_EppParams         *c_params;
	int	len, i, retr, cerrno, input_ok;
	epps_renew	*renew;

	renew = cdata->data;
	input_ok = 0;
	c_period = NULL;
	c_exDateIN = NULL;
	c_ext_list = NULL;
        c_params = NULL;
	/*
	 * Input parameters:
	 *    name (a)
	 *    c_exDateIN (*)
	 *    c_period (*)
	 *    loginid
	 *    c_clTRID (*)
	 *    xml_in (a)
	 *    c_ext_list (*)
	 * Output parameters:
	 *    c_exDateOUT (*)
	 */
	assert(renew->name);
	assert(cdata->xml_in);

	c_exDateIN = wrap_str(renew->curExDate);
	if (c_exDateIN == NULL) goto error_input;
	c_period = ccReg_Period_str__alloc();
	if (c_period == NULL) goto error_input;
	c_period->count = renew->period;
	c_period->unit  = (renew->unit == TIMEUNIT_MONTH) ?
		ccReg_unit_month : ccReg_unit_year;
	/* fill extension list */
	c_ext_list = ccReg_ExtensionList__alloc();
	if (c_ext_list == NULL) goto error_input;
	len = q_length(renew->extensions);
	c_ext_list->_buffer = ccReg_ExtensionList_allocbuf(len);
	if (len != 0 && c_ext_list->_buffer == NULL) goto error_input;
	c_ext_list->_maximum = c_ext_list->_length = len;
	c_ext_list->_release = CORBA_TRUE;
	i = 0;


	q_foreach(&renew->extensions) {
		epp_ext_item	*ext_item;

		ext_item = q_content(&renew->extensions);
		if (ext_item->extType == EPP_EXT_ENUMVAL) {
			ccReg_ENUMValidationExtension	*c_enumval;

			c_enumval = ccReg_ENUMValidationExtension__alloc();
			if (c_enumval == NULL) goto error_input;
			c_enumval->valExDate =
				wrap_str(ext_item->ext.ext_enum.ext_enumval);
			if (c_enumval->valExDate == NULL) {
				CORBA_free(c_enumval);
				goto error_input;
			}
			c_enumval->publish = convDiscl(ext_item->ext.ext_enum.publish);

			c_ext_list->_buffer[i]._type =
				TC_ccReg_ENUMValidationExtension;
			c_ext_list->_buffer[i]._value = c_enumval;
			c_ext_list->_buffer[i]._release = CORBA_TRUE;
		}
		i++;
	}

	c_params = init_epp_params(loginid, request_id, cdata->xml_in, cdata->clTRID);
	if (c_params == NULL) {
			goto error_input;
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		/* send renew request to repository */
		response = ccReg_EPP_DomainRenew((ccReg_EPP) service,
				renew->name,
				c_exDateIN,
				c_period,
				&c_exDateOUT,
                                c_params,
				c_ext_list,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	input_ok = 1;

error_input:
	CORBA_free(c_ext_list);
	CORBA_free(c_exDateIN);
	CORBA_free(c_period);
	CORBA_free(c_params);
	if (!input_ok)
		return CORBA_INT_ERROR;

	/* if it is exception then return */
	if (raised_exception(ev))
		return handle_exception(epp_ctx, cdata, ev);

	CLEAR_CERRNO(cerrno);

	renew->exDate = unwrap_str_req(epp_ctx, c_exDateOUT, &cerrno, "exDate");
	if (cerrno != 0) {
		CORBA_free(c_exDateOUT);
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}
	CORBA_free(c_exDateOUT);

	return epilog_success(epp_ctx, cdata, response);
}

/**
 * EPP update domain.
 *
 * @param epp_ctx Epp context.
 * @param service EPP service.
 * @param loginid Session identifier.
 * @param request_id  fred-logd request ID
 * @param cdata   Data from xml request.
 * @return        status.
 */
static corba_status
epp_call_update_domain(epp_context *epp_ctx,
		service_EPP service,
		unsigned long long loginid,
                const ccReg_TID request_id,
		epp_command_data *cdata)
{
	CORBA_Environment	 ev[1];
	ccReg_AdminContact	*c_admin_add, *c_admin_rem, *c_tmpcontact_rem;
	ccReg_ExtensionList	*c_ext_list;
	epps_update_domain	*update_domain;
	CORBA_char	*c_registrant, *c_authInfo, *c_nsset, *c_keyset;
	ccReg_Response	*response = NULL;
        ccReg_EppParams *c_params;
	int	i, len, retr, input_ok;

	input_ok = 0;
	update_domain = cdata->data;
	c_registrant = NULL;
	c_authInfo   = NULL;
	c_nsset      = NULL;
	c_keyset     = NULL;
	c_admin_rem  = NULL;
	c_admin_add  = NULL;
	c_ext_list   = NULL;
	c_tmpcontact_rem  = NULL;
        c_params     = NULL;
	/*
	 * Input parameters:
	 *    name         (a)
	 *    c_registrant (*)
	 *    c_authInfo   (*)
	 *    c_nsset      (*)
	 *    c_admin_add  (*)
	 *    c_admin_rem  (*)
	 *    c_tmpcontact_rem  (*)
	 *    loginid
	 *    c_clTRID     (*)
	 *    xml_in       (a)
	 *    c_ext_list   (*)
	 * Output parameters: none
	 */
	assert(update_domain->name);
	assert(cdata->xml_in);

	c_registrant = wrap_str_upd(update_domain->registrant);
	if (c_registrant == NULL) goto error_input;
	c_authInfo = wrap_str_upd(update_domain->authInfo);
	if (c_authInfo == NULL) goto error_input;
	c_nsset = wrap_str_upd(update_domain->nsset);
	if (c_nsset == NULL) goto error_input;
	c_keyset = wrap_str_upd(update_domain->keyset);
	if (c_keyset == NULL) goto error_input;

	/* admin add */
	c_admin_add = ccReg_AdminContact__alloc();
	if (c_admin_add == NULL) goto error_input;
	len = q_length(update_domain->add_admin);
	c_admin_add->_buffer = ccReg_AdminContact_allocbuf(len);
	if (len != 0 && c_admin_add->_buffer == NULL) goto error_input;
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
	if (len != 0 && c_admin_rem->_buffer == NULL) goto error_input;
	c_admin_rem->_maximum = c_admin_rem->_length = len;
	c_admin_rem->_release = CORBA_TRUE;
	i = 0;
	q_foreach(&update_domain->rem_admin) {
		char	*admin;

		admin = wrap_str(q_content(&update_domain->rem_admin));
		if (admin == NULL) goto error_input;
		c_admin_rem->_buffer[i++] = admin;
	}
	/* tempcontact rem */
	c_tmpcontact_rem = ccReg_AdminContact__alloc();
	if (c_tmpcontact_rem == NULL) goto error_input;
	len = q_length(update_domain->rem_tmpcontact);
	c_tmpcontact_rem->_buffer = ccReg_AdminContact_allocbuf(len);
	if (len != 0 && c_tmpcontact_rem->_buffer == NULL) goto error_input;
	c_tmpcontact_rem->_maximum = c_tmpcontact_rem->_length = len;
	c_tmpcontact_rem->_release = CORBA_TRUE;
	i = 0;
	q_foreach(&update_domain->rem_tmpcontact) {
		char	*tmpcontact;

		tmpcontact = wrap_str(q_content(&update_domain->rem_tmpcontact));
		if (tmpcontact == NULL) goto error_input;
		c_tmpcontact_rem->_buffer[i++] = tmpcontact;
	}

	c_ext_list = ccReg_ExtensionList__alloc();
	if (c_ext_list == NULL) goto error_input;
	len = q_length(update_domain->extensions);
	c_ext_list->_buffer = ccReg_ExtensionList_allocbuf(len);
	if (len != 0 && c_ext_list->_buffer == NULL) goto error_input;
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
				wrap_str(ext_item->ext.ext_enum.ext_enumval);
			if (c_enumval->valExDate == NULL) goto error_input;

			c_enumval->publish = convDiscl(ext_item->ext.ext_enum.publish);

			c_ext_list->_buffer[i]._type =
				TC_ccReg_ENUMValidationExtension;
			c_ext_list->_buffer[i]._value = c_enumval;
			c_ext_list->_buffer[i]._release = CORBA_TRUE;
		}
		i++;
	}

	c_params = init_epp_params(loginid, request_id, cdata->xml_in, cdata->clTRID);
	if (c_params == NULL) {
		goto error_input;
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		/* send the updates to repository */
		response = ccReg_EPP_DomainUpdate((ccReg_EPP) service,
				update_domain->name,
				c_registrant,
				c_authInfo,
				c_nsset,
				c_keyset,
				c_admin_add,
				c_admin_rem,
				c_tmpcontact_rem,
                c_params,
				c_ext_list,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	input_ok = 1;

error_input:
	CORBA_free(c_registrant);
	CORBA_free(c_authInfo);
	CORBA_free(c_nsset);
	CORBA_free(c_keyset);
	CORBA_free(c_admin_rem);
	CORBA_free(c_admin_add);
	CORBA_free(c_ext_list);
	CORBA_free(c_tmpcontact_rem);
        CORBA_free(c_params);
	if (!input_ok)
		return CORBA_INT_ERROR;

	/* if it is exception then return */
	if (raised_exception(ev))
		return handle_exception(epp_ctx, cdata, ev);

	return epilog_success(epp_ctx, cdata, response);
}

/**
 * EPP update contact.
 *
 * @param epp_ctx Epp context.
 * @param service EPP service.
 * @param loginid Session identifier.
 * @param request_id  fred-logd request ID
 * @param cdata   Data from xml request.
 * @return        Status.
 */
static corba_status
epp_call_update_contact(epp_context *epp_ctx,
		service_EPP service,
		unsigned long long loginid,
                const ccReg_TID request_id,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	ccReg_Response	*response;
	ccReg_ContactChange	*c_contact;
        ccReg_EppParams         *c_params;
	int	retr, len, i, input_ok;
	epps_update_contact	*update_contact;

	input_ok = 0;
	update_contact = cdata->data;
	c_contact    = NULL;
	c_params     = NULL;
	/*
	 * Input parameters:
	 *    id (a)
	 *    c_contact (*)
	 *    loginid
	 *    c_clTRID (*)
	 *    xml_in (a)
	 * Output parameters: none
	 */
	assert(update_contact->id);
	assert(cdata->xml_in);

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

		len = q_length(update_contact->pi->streets);
		c_contact->Streets._buffer = ccReg_Lists_allocbuf(len);
		if (len != 0 && c_contact->Streets._buffer == NULL)
			goto error_input;
		c_contact->Streets._maximum = c_contact->Streets._length = len;
		c_contact->Streets._release = CORBA_TRUE;
		i = 0;
		q_foreach(&update_contact->pi->streets) {
			c_contact->Streets._buffer[i] = wrap_str(
					q_content(&update_contact->pi->streets));
			if (c_contact->Streets._buffer[i++] == NULL)
				goto error_input;
		}

		c_contact->City    = wrap_str_upd(update_contact->pi->city);
		c_contact->StateOrProvince =wrap_str_upd(update_contact->pi->sp);
		c_contact->PostalCode = wrap_str_upd(update_contact->pi->pc);
		c_contact->CC      = wrap_str_upd(update_contact->pi->cc);
	}
	else {
		c_contact->Name = wrap_str(NULL);
		c_contact->Organization = wrap_str(NULL);
		c_contact->Streets._maximum = c_contact->Streets._length = 0;
		c_contact->City = wrap_str(NULL);
		c_contact->StateOrProvince = wrap_str(NULL);
		c_contact->PostalCode = wrap_str(NULL);
		c_contact->CC = wrap_str(NULL);
	}
	if (c_contact->Name == NULL ||
	    c_contact->Organization == NULL ||
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
	c_contact->ident = wrap_str_upd(update_contact->ident);
	if (c_contact->ident == NULL) goto error_input;
	c_contact->identtype = convIdentType(update_contact->identtype);
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
		c_contact->DiscloseVAT =
			(update_contact->discl.vat ? CORBA_TRUE : CORBA_FALSE);
		c_contact->DiscloseIdent =
			(update_contact->discl.ident ? CORBA_TRUE : CORBA_FALSE);
		c_contact->DiscloseNotifyEmail =
			(update_contact->discl.notifyEmail ? CORBA_TRUE : CORBA_FALSE);
	}

	c_params = init_epp_params(loginid, request_id, cdata->xml_in, cdata->clTRID);
	if (c_params == NULL) {
			goto error_input;
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		/* send the updates to repository */
		response = ccReg_EPP_ContactUpdate((ccReg_EPP) service,
				update_contact->id,
				c_contact,
                                c_params,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	input_ok = 1;

error_input:
	CORBA_free(c_contact);
	CORBA_free(c_params);
	if (!input_ok)
		return CORBA_INT_ERROR;

	/* if it is exception then return */
	if (raised_exception(ev))
		return handle_exception(epp_ctx, cdata, ev);

	return epilog_success(epp_ctx, cdata, response);
}

/**
 * EPP update nsset.
 *
 * @param epp_ctx Epp context.
 * @param service EPP service.
 * @param loginid Session identifier.
 * @param request_id  fred-logd request ID
 * @param cdata   Data from xml request.
 * @return        Status.
 */
static corba_status
epp_call_update_nsset(epp_context *epp_ctx,
		service_EPP service,
		unsigned long long loginid,
                const ccReg_TID request_id,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	CORBA_char	*c_authInfo;
	ccReg_Response	*response;
	ccReg_DNSHost	*c_dnshost_add;
	ccReg_DNSHost	*c_dnshost_rem;
	ccReg_TechContact	*c_tech_add;
	ccReg_TechContact	*c_tech_rem;
        ccReg_EppParams *c_params;
	int	i, len, retr, input_ok;
	epps_update_nsset	*update_nsset;

	input_ok = 0;
	update_nsset = cdata->data;
	c_dnshost_rem = NULL;
	c_dnshost_add = NULL;
	c_tech_rem = NULL;
	c_tech_add = NULL;
	c_authInfo = NULL;
	c_params = NULL;
	/*
	 * Input parameters:
	 *    id            (a)
	 *    c_authInfo    (*)
	 *    c_dnshost_add (*)
	 *    c_dnshost_rem (*)
	 *    c_tech_add    (*)
	 *    c_tech_rem    (*)
	 *    level
	 *    loginid
	 *    c_clTRID      (*)
	 *    xml_in        (a)
	 * Output parameters: none
	 */
	assert(update_nsset->id);
	assert(cdata->xml_in);

	c_authInfo = wrap_str_upd(update_nsset->authInfo);
	if (c_authInfo == NULL) goto error_input;

	/* tech add */
	c_tech_add = ccReg_TechContact__alloc();
	if (c_tech_add == NULL) goto error_input;
	len = q_length(update_nsset->add_tech);
	c_tech_add->_buffer = ccReg_TechContact_allocbuf(len);
	if (len != 0 && c_tech_add->_buffer == NULL) goto error_input;
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
	if (len != 0 && c_tech_rem->_buffer == NULL) goto error_input;
	c_tech_rem->_maximum = c_tech_rem->_length = len;
	c_tech_rem->_release = CORBA_TRUE;
	i = 0;
	q_foreach(&update_nsset->rem_tech) {
		char	*tech;

		tech = wrap_str(q_content(&update_nsset->rem_tech));
		if (tech == NULL) goto error_input;
		c_tech_rem->_buffer[i++] = tech;
	}

	/* name servers add */
	c_dnshost_add = ccReg_DNSHost__alloc();
	if (c_dnshost_add == NULL) goto error_input;
	len = q_length(update_nsset->add_ns);
	c_dnshost_add->_buffer = ccReg_DNSHost_allocbuf(len);
	if (len != 0 && c_dnshost_add->_buffer == NULL) goto error_input;
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
		if (len != 0 && c_dnshost_add->_buffer[i].inet._buffer == NULL)
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
	if (len != 0 && c_dnshost_rem->_buffer == NULL) goto error_input;
	c_dnshost_rem->_maximum = c_dnshost_rem->_length = len;
	c_dnshost_rem->_release = CORBA_TRUE;
	i = 0;
	q_foreach(&update_nsset->rem_ns) {
		char	*fqdn;

		fqdn = wrap_str(q_content(&update_nsset->rem_ns));
		if (fqdn == NULL) goto error_input;
		c_dnshost_rem->_buffer[i++].fqdn = fqdn;
	}

	c_params = init_epp_params(loginid, request_id, cdata->xml_in, cdata->clTRID);
	if (c_params == NULL) {
		goto error_input;
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		/* send the updates to repository */
		response = ccReg_EPP_NSSetUpdate((ccReg_EPP) service,
				update_nsset->id,
				c_authInfo,
				c_dnshost_add,
				c_dnshost_rem,
				c_tech_add,
				c_tech_rem,
				update_nsset->level,
				c_params,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	input_ok = 1;

error_input:
	CORBA_free(c_dnshost_rem);
	CORBA_free(c_dnshost_add);
	CORBA_free(c_tech_rem);
	CORBA_free(c_tech_add);
	CORBA_free(c_authInfo);
	CORBA_free(c_params);
	if (!input_ok)
		return CORBA_INT_ERROR;

	/* if it is exception then return */
	if (raised_exception(ev))
		return handle_exception(epp_ctx, cdata, ev);

	return epilog_success(epp_ctx, cdata, response);
}

/**
 * EPP update keyset.
 *
 * @param epp_ctx Epp context.
 * @param service EPP service.
 * @param loginid Session identifier.
 * @param request_id  fred-logd request ID
 * @param cdata   Data from xml request.
 * @return        Status.
 */
static corba_status
epp_call_update_keyset(epp_context *epp_ctx,
		service_EPP service,
		unsigned long long loginid,
                const ccReg_TID request_id,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	CORBA_char	*c_authInfo;
	ccReg_Response	*response;
	ccReg_DSRecord	*c_ds_add;
	ccReg_DSRecord	*c_ds_rem;
	ccReg_DNSKey	*c_dnskey_add;
	ccReg_DNSKey	*c_dnskey_rem;
	ccReg_TechContact	*c_tech_add;
	ccReg_TechContact	*c_tech_rem;
        ccReg_EppParams *c_params;
	int	i, len, retr, input_ok;
	epps_update_keyset *update_keyset;

	input_ok = 0;
	update_keyset = cdata->data;
	response = NULL;
	c_ds_rem = NULL;
	c_ds_add = NULL;
	c_dnskey_add = NULL;
	c_dnskey_rem = NULL;
	c_tech_rem = NULL;
	c_tech_add = NULL;
	c_authInfo = NULL;
        c_params = NULL;
	/*
	 * Input parameters:
	 *    id            (a)
	 *    c_authInfo    (*)
	 *    c_ds_add (*)
	 *    c_ds_rem (*)
	 *    c_tech_add    (*)
	 *    c_tech_rem    (*)
	 *    level
	 *    loginid
	 *    c_clTRID      (*)
	 *    xml_in        (a)
	 * Output parameters: none
	 */
	assert(update_keyset->id);
	assert(cdata->xml_in);

	c_authInfo = wrap_str_upd(update_keyset->authInfo);
	if (c_authInfo == NULL) goto error_input;

	/* tech add */
	c_tech_add = ccReg_TechContact__alloc();
	if (c_tech_add == NULL) goto error_input;
	len = q_length(update_keyset->add_tech);
	c_tech_add->_buffer = ccReg_TechContact_allocbuf(len);
	if (len != 0 && c_tech_add->_buffer == NULL) goto error_input;
	c_tech_add->_maximum = c_tech_add->_length = len;
	c_tech_add->_release = CORBA_TRUE;
	i = 0;
	q_foreach(&update_keyset->add_tech) {
		char	*tech;

		tech = wrap_str(q_content(&update_keyset->add_tech));
		if (tech == NULL) goto error_input;
		c_tech_add->_buffer[i++] = tech;
	}
	/* tech rem */
	c_tech_rem = ccReg_TechContact__alloc();
	if (c_tech_rem == NULL) goto error_input;
	len = q_length(update_keyset->rem_tech);
	c_tech_rem->_buffer = ccReg_TechContact_allocbuf(len);
	if (len != 0 && c_tech_rem->_buffer == NULL) goto error_input;
	c_tech_rem->_maximum = c_tech_rem->_length = len;
	c_tech_rem->_release = CORBA_TRUE;
	i = 0;
	q_foreach(&update_keyset->rem_tech) {
		char	*tech;

		tech = wrap_str(q_content(&update_keyset->rem_tech));
		if (tech == NULL) goto error_input;
		c_tech_rem->_buffer[i++] = tech;
	}

	/* delegation signers add */
	c_ds_add = ccReg_DSRecord__alloc();
	if (c_ds_add == NULL) goto error_input;
	/* delegation signers rem */
	c_ds_rem = ccReg_DSRecord__alloc();
	if (c_ds_rem == NULL) goto error_input;

	/* DNSKEY records add */
	c_dnskey_add = ccReg_DNSKey__alloc();
	if (c_dnskey_add == NULL) goto error_input;
	len = q_length(update_keyset->add_dnskey);
	c_dnskey_add->_buffer = ccReg_DNSKey_allocbuf(len);
	if (len != 0 && c_dnskey_add->_buffer == NULL) goto error_input;
	c_dnskey_add->_maximum = c_dnskey_add->_length = len;
	c_dnskey_add->_release = CORBA_TRUE;
	i = 0;
	q_foreach(&update_keyset->add_dnskey) {
		epp_dnskey *key;

		key = q_content(&update_keyset->add_dnskey);

		c_dnskey_add->_buffer[i].flags = key->flags;
		c_dnskey_add->_buffer[i].protocol = key->protocol;
		c_dnskey_add->_buffer[i].alg = key->alg;
		c_dnskey_add->_buffer[i].key = wrap_str(key->public_key);

		i++;
	}

	/* DNSKEY records rem */
	c_dnskey_rem = ccReg_DNSKey__alloc();
	if (c_dnskey_rem == NULL) goto error_input;
	len = q_length(update_keyset->rem_dnskey);
	c_dnskey_rem->_buffer = ccReg_DNSKey_allocbuf(len);
	if (len != 0 && c_dnskey_rem->_buffer == NULL) goto error_input;
	c_dnskey_rem->_maximum = c_dnskey_rem->_length = len;
	c_dnskey_rem->_release = CORBA_TRUE;
	i = 0;
	q_foreach(&update_keyset->rem_dnskey) {
		epp_dnskey *key;

		key = q_content(&update_keyset->rem_dnskey);

		c_dnskey_rem->_buffer[i].flags = key->flags;
		c_dnskey_rem->_buffer[i].protocol = key->protocol;
		c_dnskey_rem->_buffer[i].alg = key->alg;
		c_dnskey_rem->_buffer[i].key = wrap_str(key->public_key);

		i++;
	}

	c_params = init_epp_params(loginid, request_id, cdata->xml_in, cdata->clTRID);
	if (c_params == NULL) {
			goto error_input;
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		/* send the updates to repository */
		response = ccReg_EPP_KeySetUpdate((ccReg_EPP) service,
				update_keyset->id,
				c_authInfo,
				c_tech_add,
				c_tech_rem,
				c_ds_add,
				c_ds_rem,
				c_dnskey_add,
				c_dnskey_rem,
                                c_params,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	input_ok = 1;

error_input:
	CORBA_free(c_ds_rem);
	CORBA_free(c_ds_add);
	CORBA_free(c_dnskey_rem);
	CORBA_free(c_dnskey_add);
	CORBA_free(c_tech_rem);
	CORBA_free(c_tech_add);
	CORBA_free(c_authInfo);
	CORBA_free(c_params);
	if (!input_ok)
		return CORBA_INT_ERROR;

	/* if it is exception then return */
	if (raised_exception(ev))
		return handle_exception(epp_ctx, cdata, ev);

	return epilog_success(epp_ctx, cdata, response);
}



/**
 * EPP transfer for domain, contact, nsset and keyset is so similar that it is worth of
 * having the code in one function and pass object type as parameter.
 *
 * @param epp_ctx Epp context.
 * @param service EPP service.
 * @param loginid Session identifier.
 * @param request_id  fred-logd request ID
 * @param cdata   Data from xml request.
 * @param obj     Object type (see #epp_object_type).
 * @return        Status.
 */
static corba_status
epp_call_transfer(epp_context *epp_ctx,
		service_EPP service,
		unsigned long long loginid,
                const ccReg_TID request_id,
		epp_command_data *cdata,
		epp_object_type obj)
{
	CORBA_Environment ev[1];
	CORBA_char	*c_authInfo;
	ccReg_Response	*response;
	ccReg_EppParams *c_params = NULL;
	int	retr;
	epps_transfer	*transfer;

	transfer = cdata->data;
	/*
	 * Input parameters:
	 *    id (a)
	 *    c_authInfo (*)
	 *    loginid
	 *    c_clTRID (*)
	 *    xml_in (a)
	 * Output parameters: none
	 */
	assert(transfer->id);
	assert(cdata->xml_in);

	c_authInfo = wrap_str(transfer->authInfo);
	if (c_authInfo == NULL) {
		return CORBA_INT_ERROR;
	}

	c_params = init_epp_params(loginid, request_id, cdata->xml_in, cdata->clTRID);
	if (c_params == NULL) {
		CORBA_free(c_authInfo);
		return CORBA_INT_ERROR;
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		if (obj == EPP_DOMAIN) {
			response = ccReg_EPP_DomainTransfer((ccReg_EPP) service,
					transfer->id,
					c_authInfo,
                                        c_params,
					ev);
		}
		else if (obj == EPP_CONTACT) {
			response = ccReg_EPP_ContactTransfer((ccReg_EPP) service,
					transfer->id,
					c_authInfo,
                                        c_params,
					ev);
		}
		else if (obj == EPP_KEYSET) {
			response = ccReg_EPP_KeySetTransfer((ccReg_EPP) service,
					transfer->id,
					c_authInfo,
                                        c_params,
					ev);
		}
		else {
			assert(obj == EPP_NSSET);
			response = ccReg_EPP_NSSetTransfer((ccReg_EPP) service,
					transfer->id,
					c_authInfo,
                                        c_params,
					ev);
		}

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_authInfo);
	CORBA_free(c_params);

	/* if it is exception then return */
	if (raised_exception(ev))
		return handle_exception(epp_ctx, cdata, ev);

	return epilog_success(epp_ctx, cdata, response);
}

/**
 * List command for domain, contact and nsset is so similar that it is worth of
 * having the code in one function and pass object type as parameter.
 *
 * @param epp_ctx Epp context.
 * @param service EPP service.
 * @param loginid Session identifier.
 * @param request_id  fred-logd request ID
 * @param cdata   Data from xml request.
 * @param obj     Object type (see #epp_object_type).
 * @return        Status.
 */
static corba_status
epp_call_list(epp_context *epp_ctx,
		service_EPP service,
		unsigned long long loginid,
		const ccReg_TID request_id,
		epp_command_data *cdata,
		epp_object_type obj)
{
	CORBA_Environment	 ev[1];
	ccReg_EppParams *c_params = NULL;
	ccReg_Response	*response;
	ccReg_Lists	*c_handles;
	int	 i, retr;
	epps_list	*list;

	list = cdata->data;
	/*
	 * Input parameters:
	 *    loginid
	 *    c_clTRID (*)
	 *    xml_in (a)
	 * Output parameters:
	 *    c_handles (*)
	 */
	assert(cdata->xml_in);

	c_params = init_epp_params(loginid, request_id, cdata->xml_in, cdata->clTRID);
	if(c_params == NULL) {
	    return CORBA_INT_ERROR;
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		if (obj == EPP_DOMAIN) {
			response = ccReg_EPP_DomainList((ccReg_EPP) service,
					&c_handles,
					c_params,
					ev);
		}
		else if (obj == EPP_CONTACT) {
			response = ccReg_EPP_ContactList((ccReg_EPP) service,
					&c_handles,
					c_params,
					ev);
		}
		else if(obj == EPP_KEYSET) {
			response = ccReg_EPP_KeySetList((ccReg_EPP) service,
					&c_handles,
					c_params,
					ev);
		}
		else {
			assert(obj == EPP_NSSET);
			response = ccReg_EPP_NSSetList((ccReg_EPP) service,
					&c_handles,
					c_params,
					ev);
		}

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_params);

	/* if it is exception then return */
	if (raised_exception(ev))
		return handle_exception(epp_ctx, cdata, ev);

	for (i = 0; i < c_handles->_length; i++) {
		char	*handle;
		int	cerrno;

		CLEAR_CERRNO(cerrno);

		handle = unwrap_str(epp_ctx->pool, c_handles->_buffer[i],
				&cerrno);
		if (cerrno != 0) {
			CORBA_free(response);
			return CORBA_INT_ERROR;
		}
		if (q_add(epp_ctx->pool, &list->handles, handle)) {
			CORBA_free(response);
			return CORBA_INT_ERROR;
		}
	}

	CORBA_free(c_handles);
	return epilog_success(epp_ctx, cdata, response);
}

/**
 * SendAuthInfo command.
 *
 * @param epp_ctx Epp context.
 * @param service EPP service.
 * @param loginid Session identifier.
 * @param request_id  fred-logd request ID
 * @param cdata   Data from xml request.
 * @param obj     Object type (see #epp_object_type).
 * @return        Status.
 */
static corba_status
epp_call_sendauthinfo(epp_context *epp_ctx,
		service_EPP service,
		unsigned long long loginid,
                const ccReg_TID request_id,
		epp_command_data *cdata,
		epp_object_type obj)
{
	CORBA_Environment	 ev[1];
	CORBA_char	*c_handle;
	ccReg_Response	*response;
	epps_sendAuthInfo	*sendAuthInfo;
	ccReg_EppParams *c_params = NULL;
	int	 retr;

	sendAuthInfo = cdata->data;
	/*
	 * Input parameters:
	 *    loginid
	 *    c_clTRID (*)
	 *    c_handle (*)
	 *    xml_in (a)
	 * Output parameters: none
	 */
	assert(cdata->xml_in);

	c_params = init_epp_params(loginid, request_id, cdata->xml_in, cdata->clTRID);
	if(c_params == NULL) {
		return CORBA_INT_ERROR;
	}

	c_handle = wrap_str(sendAuthInfo->id);
	if (c_handle == NULL) {
		CORBA_free(c_params);
                return CORBA_INT_ERROR;
	}
        // TODO create a separate function for c_params allocation

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		if (obj == EPP_DOMAIN) {
			response = ccReg_EPP_domainSendAuthInfo(
					(ccReg_EPP) service,
					c_handle,
                                        c_params,
					ev);
		}
		else if (obj == EPP_CONTACT) {
			response = ccReg_EPP_contactSendAuthInfo(
					(ccReg_EPP) service,
					c_handle,
                                        c_params,
					ev);
		}
		else if (obj == EPP_KEYSET) {
			response = ccReg_EPP_keysetSendAuthInfo(
					(ccReg_EPP) service,
					c_handle,
                                        c_params,
					ev);
		}
		else {
			assert(obj == EPP_NSSET);
			response = ccReg_EPP_nssetSendAuthInfo(
					(ccReg_EPP) service,
					c_handle,
                                        c_params,
					ev);
		}

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_handle);
	CORBA_free(c_params);

	/* if it is exception then return */
	if (raised_exception(ev))
		return handle_exception(epp_ctx, cdata, ev);

	return epilog_success(epp_ctx, cdata, response);
}

/**
 * Retrieve information about available credit of registrar.
 *
 * @param epp_ctx Epp context.
 * @param service EPP service.
 * @param loginid Session identifier.
 * @param request_id  fred-logd request ID
 * @param cdata   Data from xml request.
 * @return        Status.
 */
static corba_status
epp_call_creditinfo(epp_context *epp_ctx,
		service_EPP service,
		unsigned long long loginid,
		const ccReg_TID request_id,
		epp_command_data *cdata)
{
	CORBA_Environment	 ev[1];
	ccReg_EppParams *c_params = NULL;
	ccReg_ZoneCredit	*c_zoneCredit;
	ccReg_Response	*response;
	epps_creditInfo	*creditInfo;
	int	 retr, i;

	creditInfo = cdata->data;
	/*
	 * Input parameters:
	 *    loginid
	 *    c_clTRID (*)
	 *    xml_in (a)
	 * Output parameters:
	 *    c_zoneCredit (*)
	 */
	assert(cdata->xml_in);

    c_params = init_epp_params(loginid, request_id, cdata->xml_in, cdata->clTRID);
    if(c_params == NULL) {
        return CORBA_INT_ERROR;
    }

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		response = ccReg_EPP_ClientCredit((ccReg_EPP) service,
				&c_zoneCredit,
				c_params,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_params);

	/* if it is exception then return */
	if (raised_exception(ev))
		return handle_exception(epp_ctx, cdata, ev);

	for (i = 0; i < c_zoneCredit->_length; i++) {
		epp_zonecredit	*zonecredit;
		int	cerrno;

		zonecredit = epp_malloc(epp_ctx->pool, sizeof *zonecredit);
		if (zonecredit == NULL)
			break;
		CLEAR_CERRNO(cerrno);
		zonecredit->zone = unwrap_str(epp_ctx->pool,
				c_zoneCredit->_buffer[i].zone_fqdn, &cerrno);
		if (cerrno != 0)
			break;
		zonecredit->credit = unwrap_str(epp_ctx->pool,
                c_zoneCredit->_buffer[i].price, &cerrno);
        if (cerrno != 0)
            break;

		if (q_add(epp_ctx->pool, &creditInfo->zonecredits, zonecredit))
			break;
	}

	/* error occured ? */
	if (i < c_zoneCredit->_length) {
		CORBA_free(response);
		CORBA_free(c_zoneCredit);
		return CORBA_INT_ERROR;
	}
	CORBA_free(c_zoneCredit);

	return epilog_success(epp_ctx, cdata, response);
}

/**
 * Issue technical test on nsset.
 *
 * @param epp_ctx Epp context.
 * @param service EPP service.
 * @param loginid Session identifier.
 * @param request_id  fred-logd request ID
 * @param cdata   Data from xml request.
 * @return        Status.
 */
static corba_status
epp_call_test_nsset(epp_context *epp_ctx,
		service_EPP service,
		unsigned long long loginid,
		const ccReg_TID request_id,
		epp_command_data *cdata)
{
	CORBA_Environment	 ev[1];
	CORBA_char	*c_handle;
	ccReg_EppParams *c_params = NULL;
	ccReg_Lists	*c_names;
	ccReg_Response	*response;
	epps_test	*test;
	int	 retr, len, i, input_ok;

	test = cdata->data;
	input_ok = 0;
	c_handle = NULL;
	c_names  = NULL;
	/*
	 * Input parameters:
	 *    loginid
	 *    c_clTRID (*)
	 *    c_handle (*)
	 *    level
	 *    c_names (*)
	 *    xml_in (a)
	 * Output parameters: none
	 */
	assert(cdata->xml_in);

    c_params = init_epp_params(loginid, request_id, cdata->xml_in, cdata->clTRID);
    if(c_params == NULL) {
        goto error_input;
    }

	c_handle = wrap_str(test->id);
	if (c_handle == NULL)
		goto error_input;

	/* create list of test fqdns */
	c_names = ccReg_Lists__alloc();
	if (c_names == NULL)
		goto error_input;
	len = q_length(test->names);
	c_names->_buffer = ccReg_Lists_allocbuf(len);
	if (len != 0 && c_names->_buffer == NULL)
		goto error_input;
	c_names->_maximum = c_names->_length = len;
	c_names->_release = CORBA_TRUE;
	i = 0;
	q_foreach(&test->names) {
		char *name = q_content(&test->names);

		c_names->_buffer[i] = CORBA_string_dup(name);
		if (c_names->_buffer[i++] == NULL)
			goto error_input;
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		response = ccReg_EPP_nssetTest((ccReg_EPP) service,
				c_handle,
				test->level,
				c_names,
				c_params,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	input_ok = 1;

error_input:
	CORBA_free(c_handle);
	CORBA_free(c_names);
	CORBA_free(c_params);
	if (!input_ok)
		return CORBA_INT_ERROR;

	/* if it is exception then return */
	if (raised_exception(ev))
		return handle_exception(epp_ctx, cdata, ev);

	return epilog_success(epp_ctx, cdata, response);
}

/**
 * Info functions handler.
 *
 * @param epp_ctx  Epp context.
 * @param service  EPP service.
 * @param loginid  Session identifier.
 * @param request_id   fred-logd request ID
 * @param cdata    Data from xml request.
 * @param c_infotype Type of info query.
 * @return         Status.
 */
static corba_status
epp_call_info(epp_context *epp_ctx,
		service_EPP service,
		unsigned long long loginid,
		const ccReg_TID request_id,
		epp_command_data *cdata,
		ccReg_InfoType c_infotype)
{
	CORBA_Environment	 ev[1];
	CORBA_char	*c_handle;
	ccReg_EppParams *c_params = NULL;
	CORBA_long	 c_count;
	ccReg_Response	*response;
	epps_info	*info;
	int	 retr, input_ok;

	info = cdata->data;
	input_ok = 0;
	c_handle = NULL;
	/*
	 * Input parameters:
	 *    loginid
	 *    c_clTRID (*)
	 *    c_infotype
	 *    c_handle (*)
	 *    xml_in (a)
	 * Output parameters:
	 *    c_count
	 */
	assert(cdata->xml_in);
    c_params = init_epp_params(loginid, request_id, cdata->xml_in, cdata->clTRID);
    if(c_params == NULL) {
        goto error_input;
    }

	c_handle = wrap_str(info->handle);
	if (c_handle == NULL)
		goto error_input;

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		response = ccReg_EPP_info((ccReg_EPP) service,
				c_infotype,
				c_handle,
				&c_count,
				c_params,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	input_ok = 1;

error_input:
	CORBA_free(c_handle);
	CORBA_free(c_params);
	if (!input_ok)
		return CORBA_INT_ERROR;

	/* if it is exception then return */
	if (raised_exception(ev))
		return handle_exception(epp_ctx, cdata, ev);

	info->count = (unsigned int) c_count;

	return epilog_success(epp_ctx, cdata, response);
}

/**
 * Get results of info search.
 *
 * @param epp_ctx Epp context.
 * @param service EPP service.
 * @param loginid Session identifier.
 * @param request_id  fred-logd request ID
 * @param cdata   Data from xml request.
 * @return        Status.
 */
static corba_status
epp_call_getInfoResults(epp_context *epp_ctx,
		service_EPP service,
		unsigned long long loginid,
		const ccReg_TID request_id,
		epp_command_data *cdata)
{
	CORBA_Environment	 ev[1];
	ccReg_EppParams *c_params = NULL;
	ccReg_Response	*response;
	ccReg_Lists	*c_handles;
	int	 i, retr;
	epps_list	*list;

	list = cdata->data;
	/*
	 * Input parameters:
	 *    loginid
	 *    c_clTRID (*)
	 *    xml_in (a)
	 * Output parameters:
	 *    c_handles (*)
	 */
	assert(cdata->xml_in);
    c_params = init_epp_params(loginid, request_id, cdata->xml_in, cdata->clTRID);
    if(c_params == NULL) {
        return CORBA_INT_ERROR;
    }

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		response = ccReg_EPP_getInfoResults((ccReg_EPP) service,
				&c_handles,
				c_params,
				ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	CORBA_free(c_params);

	/* if it is exception then return */
	if (raised_exception(ev))
		return handle_exception(epp_ctx, cdata, ev);

	for (i = 0; i < c_handles->_length; i++) {
		char	*handle;
		int	cerrno;

		CLEAR_CERRNO(cerrno);

		handle = unwrap_str(epp_ctx->pool, c_handles->_buffer[i],
				&cerrno);
		if (cerrno != 0) {
			CORBA_free(response);
			return CORBA_INT_ERROR;
		}
		if (q_add(epp_ctx->pool, &list->handles, handle)) {
			CORBA_free(response);
			return CORBA_INT_ERROR;
		}
	}

	CORBA_free(c_handles);
	return epilog_success(epp_ctx, cdata, response);
}

corba_status
epp_call_cmd(epp_context *epp_ctx,
		service_EPP service,
		unsigned long long loginid,
                const ccReg_TID request_id,
		epp_command_data *cdata)
{
	corba_status	cstat;
  
        epplog(epp_ctx, EPP_DEBUG, "Corba call (epp-cmd %d)", cdata->type);
	switch (cdata->type) {
		case EPP_DUMMY:
			cdata->noresdata = 1;
			cstat = epp_call_dummy(epp_ctx, service, loginid, request_id, cdata);
			break;
		case EPP_CHECK_CONTACT:
			cstat = epp_call_check(epp_ctx, service, loginid, request_id, cdata,
					EPP_CONTACT);
			break;
		case EPP_CHECK_DOMAIN:
			cstat = epp_call_check(epp_ctx, service, loginid, request_id, cdata,
					EPP_DOMAIN);
			break;
		case EPP_CHECK_NSSET:
			cstat = epp_call_check(epp_ctx, service, loginid, request_id, cdata,
					EPP_NSSET);
			break;
		case EPP_CHECK_KEYSET:
			cstat = epp_call_check(epp_ctx, service, loginid, request_id, cdata,
					EPP_KEYSET);
			break;
		case EPP_INFO_CONTACT:
			cstat = epp_call_info_contact(epp_ctx, service, loginid, request_id,
					cdata);
			break;
		case EPP_INFO_DOMAIN:
			cstat = epp_call_info_domain(epp_ctx, service, loginid, request_id,
					cdata);
			break;
		case EPP_INFO_NSSET:
			cstat = epp_call_info_nsset(epp_ctx, service, loginid, request_id,
					cdata);
			break;
		case EPP_INFO_KEYSET:
			cstat = epp_call_info_keyset(epp_ctx, service, loginid, request_id,
					cdata);
			break;
		case EPP_LIST_CONTACT:
			cstat = epp_call_list(epp_ctx, service, loginid, request_id, cdata,
					EPP_CONTACT);
			break;
		case EPP_LIST_DOMAIN:
			cstat = epp_call_list(epp_ctx, service, loginid, request_id, cdata,
					EPP_DOMAIN);
			break;
		case EPP_LIST_NSSET:
			cstat = epp_call_list(epp_ctx, service, loginid, request_id, cdata,
					EPP_NSSET);
			break;
		case EPP_LIST_KEYSET:
			cstat = epp_call_list(epp_ctx, service, loginid, request_id, cdata,
					EPP_KEYSET);
			break;
		case EPP_POLL_REQ:
			cdata->noresdata = 1;
			cstat = epp_call_poll_req(epp_ctx, service, loginid, request_id,
					cdata);
			break;
		case EPP_POLL_ACK:
			cdata->noresdata = 1;
			cstat = epp_call_poll_ack(epp_ctx, service, loginid, request_id,
					cdata);
			break;
		case EPP_CREATE_CONTACT:
			cstat = epp_call_create_contact(epp_ctx, service,loginid, request_id,
					cdata);
			break;
		case EPP_CREATE_DOMAIN:
			cstat = epp_call_create_domain(epp_ctx, service, loginid, request_id,
					cdata);
			break;
		case EPP_CREATE_NSSET:
			cstat = epp_call_create_nsset(epp_ctx, service, loginid, request_id,
					cdata);
			break;
		case EPP_CREATE_KEYSET:
			cstat = epp_call_create_keyset(epp_ctx, service, loginid, request_id,
					cdata);
			break;
		case EPP_DELETE_CONTACT:
			cdata->noresdata = 1;
			cstat = epp_call_delete(epp_ctx, service, loginid, request_id, cdata,
					EPP_CONTACT);
			break;
		case EPP_DELETE_DOMAIN:
			cdata->noresdata = 1;
			cstat = epp_call_delete(epp_ctx, service, loginid, request_id, cdata,
					EPP_DOMAIN);
			break;
		case EPP_DELETE_NSSET:
			cdata->noresdata = 1;
			cstat = epp_call_delete(epp_ctx, service, loginid, request_id, cdata,
					EPP_NSSET);
			break;
		case EPP_DELETE_KEYSET:
			cdata->noresdata = 1;
			cstat = epp_call_delete(epp_ctx, service, loginid, request_id, cdata,
					EPP_KEYSET);
			break;
		case EPP_RENEW_DOMAIN:
			cstat = epp_call_renew_domain(epp_ctx, service, loginid, request_id,
					cdata);
			break;
		case EPP_UPDATE_DOMAIN:
			cdata->noresdata = 1;
			cstat = epp_call_update_domain(epp_ctx, service, loginid, request_id,
					cdata);
			break;
		case EPP_UPDATE_CONTACT:
			cdata->noresdata = 1;
			cstat = epp_call_update_contact(epp_ctx, service,loginid, request_id,
					cdata);
			break;
		case EPP_UPDATE_NSSET:
			cdata->noresdata = 1;
			cstat = epp_call_update_nsset(epp_ctx, service, loginid, request_id,
					cdata);
			break;
		case EPP_UPDATE_KEYSET:
			cdata->noresdata = 1;
			cstat = epp_call_update_keyset(epp_ctx, service, loginid, request_id,
					cdata);
			break;

		case EPP_TRANSFER_CONTACT:
			cdata->noresdata = 1;
			cstat = epp_call_transfer(epp_ctx, service, loginid, request_id,
					cdata, EPP_CONTACT);
			break;
		case EPP_TRANSFER_DOMAIN:
			cdata->noresdata = 1;
			cstat = epp_call_transfer(epp_ctx, service, loginid, request_id,
					cdata, EPP_DOMAIN);
			break;
		case EPP_TRANSFER_NSSET:
			cdata->noresdata = 1;
			cstat = epp_call_transfer(epp_ctx, service, loginid, request_id,
					cdata, EPP_NSSET);
			break;
		case EPP_TRANSFER_KEYSET:
			cdata->noresdata = 1;
			cstat = epp_call_transfer(epp_ctx, service, loginid, request_id,
					cdata, EPP_KEYSET);
			break;
		case EPP_SENDAUTHINFO_DOMAIN:
			cdata->noresdata = 1;
			cstat = epp_call_sendauthinfo(epp_ctx, service, loginid, request_id,
					cdata, EPP_DOMAIN);
			break;
		case EPP_SENDAUTHINFO_CONTACT:
			cdata->noresdata = 1;
			cstat = epp_call_sendauthinfo(epp_ctx, service, loginid, request_id,
					cdata, EPP_CONTACT);
			break;
		case EPP_SENDAUTHINFO_NSSET:
			cdata->noresdata = 1;
			cstat = epp_call_sendauthinfo(epp_ctx, service, loginid, request_id,
					cdata, EPP_NSSET);
			break;
		case EPP_SENDAUTHINFO_KEYSET:
			cdata->noresdata = 1;
			cstat = epp_call_sendauthinfo(epp_ctx, service, loginid, request_id,
					cdata, EPP_KEYSET);
			break;

		case EPP_CREDITINFO:
			cstat = epp_call_creditinfo(epp_ctx, service, loginid, request_id,
					cdata);
			break;
		case EPP_TEST_NSSET:
			cdata->noresdata = 1;
			cstat = epp_call_test_nsset(epp_ctx, service, loginid, request_id,
					cdata);
			break;
		case EPP_INFO_LIST_CONTACTS:
			cstat = epp_call_info(epp_ctx, service, loginid, request_id,
					cdata, ccReg_IT_LIST_CONTACTS);
			break;
		case EPP_INFO_LIST_DOMAINS:
			cstat = epp_call_info(epp_ctx, service, loginid, request_id,
					cdata, ccReg_IT_LIST_DOMAINS);
			break;
		case EPP_INFO_LIST_NSSETS:
			cstat = epp_call_info(epp_ctx, service, loginid, request_id,
					cdata, ccReg_IT_LIST_NSSETS);
			break;
		case EPP_INFO_LIST_KEYSETS:
			cstat = epp_call_info(epp_ctx, service, loginid, request_id,
					cdata, ccReg_IT_LIST_KEYSETS);
			break;
		case EPP_INFO_DOMAINS_BY_NSSET:
			cstat = epp_call_info(epp_ctx, service, loginid, request_id,
					cdata, ccReg_IT_DOMAINS_BY_NSSET);
			break;
		case EPP_INFO_DOMAINS_BY_KEYSET:
			cstat = epp_call_info(epp_ctx, service, loginid, request_id,
					cdata, ccReg_IT_DOMAINS_BY_KEYSET);
			break;
		case EPP_INFO_DOMAINS_BY_CONTACT:
			cstat = epp_call_info(epp_ctx, service, loginid, request_id,
					cdata, ccReg_IT_DOMAINS_BY_CONTACT);
			break;
		case EPP_INFO_NSSETS_BY_CONTACT:
			cstat = epp_call_info(epp_ctx, service, loginid, request_id,
					cdata, ccReg_IT_NSSETS_BY_CONTACT);
			break;
		case EPP_INFO_KEYSETS_BY_CONTACT:
			cstat = epp_call_info(epp_ctx, service, loginid, request_id,
					cdata, ccReg_IT_KEYSETS_BY_CONTACT);
			break;
		case EPP_INFO_NSSETS_BY_NS:
			cstat = epp_call_info(epp_ctx, service, loginid, request_id,
					cdata, ccReg_IT_NSSETS_BY_NS);
			break;
		case EPP_INFO_GET_RESULTS:
			cstat = epp_call_getInfoResults(epp_ctx, service,
					loginid, request_id, cdata);
			break;
		default:
			cstat = CORBA_INT_ERROR;
			break;
	}

	return cstat;
}

void
epp_call_CloseSession(epp_context *epp_ctx, service_EPP service,
		unsigned long long loginid)
{
	CORBA_Environment	 ev[1];
	int	 retr;

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		ccReg_EPP_sessionClosed((ccReg_EPP) service, loginid, ev);

		/* if COMM_FAILURE exception is not raised quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

	if (raised_exception(ev)) {
		epplog(epp_ctx, EPP_ERROR, "CORBA exception in sessionClosed: "
				"%s", ev->_id);
		CORBA_exception_free(ev);
		/* ignore error */
		return;
	}
}

