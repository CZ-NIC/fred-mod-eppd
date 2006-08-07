/**
 * @file epp-client.c
 * Corba component is used for communication between apache module and
 * central repository. Input are self-descriptive data stored in structure
 * ussually called cdata. Output data are returned via the same structure.
 * Purpose of this module is to hide the complexity of communication behind
 * simple API defined in epp-client.h. The function names are analogical
 * to names defined in EPP protocol standard.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <orbit/orbit.h>

#include "epp_common.h"
#include "epp-client.h"
#include "ccReg.h"

/** Quick test if corba exception was raised. */
#define raised_exception(ev)	((ev)->_major != CORBA_NO_EXCEPTION)

/**
 * Persistent structure initialized at startup, needed for corba function calls.
 */
struct epp_corba_globs_t {
	CORBA_ORB	corba;	/**< corba is global corba object. */
	ccReg_EPP	service;	/**< service is ccReg object stub */
};

epp_corba_globs *
epp_corba_init(const char *ior)
{
	CORBA_ORB  global_orb = CORBA_OBJECT_NIL;	/* global orb */
	ccReg_EPP e_service = CORBA_OBJECT_NIL;	/* object's stub */
	epp_corba_globs	*globs;	/* structure used to store global_orb and service */
	CORBA_Environment ev[1];
	CORBA_exception_init(ev);
 
	/* create orb object */
	global_orb = CORBA_ORB_init(0, NULL, "orbit-local-orb", ev);
	if (raised_exception(ev)) {
		CORBA_exception_free(ev);
		if (global_orb != CORBA_OBJECT_NIL) CORBA_ORB_destroy(global_orb, ev);
		CORBA_exception_free(ev);
		return NULL;
	}

	/* create object's stub */
	e_service = (ccReg_EPP) CORBA_ORB_string_to_object(global_orb, ior, ev);
	if (raised_exception(ev)) {
		CORBA_exception_free(ev);
		/* releasing managed object */
		CORBA_Object_release(e_service, ev);
		CORBA_exception_free(ev);
		/* tear down the ORB */
		if (global_orb != CORBA_OBJECT_NIL) {
			CORBA_ORB_destroy(global_orb, ev);
			CORBA_exception_free(ev);
		}
		return NULL;
	}
	CORBA_exception_free(ev);

	if ((globs = malloc(sizeof *globs)) == NULL) {
		/* releasing managed object */
		CORBA_Object_release(e_service, ev);
		CORBA_exception_free(ev);
		/* tear down the ORB */
		if (global_orb != CORBA_OBJECT_NIL) {
			CORBA_ORB_destroy(global_orb, ev);
			CORBA_exception_free(ev);
		}
		return NULL;
	}

	globs->corba = global_orb;
	globs->service = e_service;
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
 * @param cerrors Buffer of errors used as input.
 * @param errors List of errors
 * converted errors (output).
 */
static void get_errors(struct circ_list *errors, ccReg_Error *c_errors) {
	struct circ_list	*item; epp_error	*err_item; int	i; ccReg_Error_seq
		*c_error; CORBA_Environment ev[1];

	CORBA_exception_init(ev);

	/* process all errors one by one */
	for (i = 0; i < c_errors->_length; i++) {
		if ((item = malloc(sizeof *item)) == NULL) break;
		if ((err_item = malloc(sizeof *err_item)) == NULL) {
			free(item);
			break;
		}
		c_error = &c_errors->_buffer[i];
		err_item->reason = strdup(c_error->reason);
		err_item->standalone = 0; /* the surrounding tags are missing */

		/* convert "any" type (timestamp, long, string) to string */
		if (CORBA_TypeCode_equal(c_error->value._type, TC_CORBA_string, ev))
			err_item->value = strdup(* ((char **) c_error->value._value));
		else if (CORBA_TypeCode_equal(c_error->value._type, TC_CORBA_long, ev))
		{
			err_item->value = malloc(10); /* should be enough for any number */
			snprintf(err_item->value, 10, "%ld",
					*((long *) c_error->value._value));
		}
		else if (CORBA_TypeCode_equal(c_error->value._type,
					TC_ccReg_timestamp, ev))
		{
			err_item->value = malloc(30);
			get_rfc3339_date( *((unsigned long long *) c_error->value._value),
					err_item->value);
		}
		else
			err_item->value = strdup("Unknown value type");

		/* convert error code */
		switch (c_error->code) {
			case ccReg_pollAck_msgID:
				err_item->spec = errspec_pollAck_msgID;
				break;
			case ccReg_contactUpdate_cc:
				err_item->spec = errspec_contactUpdate_cc;
				break;
			case ccReg_contactCreate_cc:
				err_item->spec = errspec_contactCreate_cc;
				break;
			case ccReg_contactCreate_handle:
				err_item->spec = errspec_contactCreate_handle;
				break;
			case ccReg_nssetCreate_handle:
				err_item->spec = errspec_nssetCreate_handle;
				break;
			case ccReg_domainCreate_fqdn:
				err_item->spec = errspec_domainCreate_fqdn;
				break;
			case ccReg_contactUpdate_status_add:
				err_item->spec = errspec_contactUpdate_status_add;
				break;
			case ccReg_contactUpdate_status_rem:
				err_item->spec = errspec_contactUpdate_status_rem;
				break;
			case ccReg_nssetUpdate_status_add:
				err_item->spec = errspec_nssetUpdate_status_add;
				break;
			case ccReg_nssetUpdate_status_rem:
				err_item->spec = errspec_nssetUpdate_status_rem;
				break;
			case ccReg_domainUpdate_status_add:
				err_item->spec = errspec_domainUpdate_status_add;
				break;
			case ccReg_domainUpdate_status_rem:
				err_item->spec = errspec_domainUpdate_status_rem;
				break;
			case ccReg_nssetCreate_tech:
				err_item->spec = errspec_nssetCreate_tech;
				break;
			case ccReg_nssetUpdate_tech_add:
				err_item->spec = errspec_nssetUpdate_tech_add;
				break;
			case ccReg_nssetUpdate_tech_rem:
				err_item->spec = errspec_nssetUpdate_tech_rem;
				break;
			case ccReg_nssetCreate_ns_name:
				err_item->spec = errspec_nssetCreate_ns_name;
				break;
			case ccReg_nssetUpdate_ns_name_add:
				err_item->spec = errspec_nssetUpdate_ns_name_add;
				break;
			case ccReg_nssetUpdate_ns_name_rem:
				err_item->spec = errspec_nssetUpdate_ns_name_rem;
				break;
			case ccReg_nssetCreate_ns_addr:
				err_item->spec = errspec_nssetCreate_ns_addr;
				break;
			case ccReg_nssetUpdate_ns_addr_add:
				err_item->spec = errspec_nssetUpdate_ns_addr_add;
				break;
			case ccReg_nssetUpdate_ns_addr_rem:
				err_item->spec = errspec_nssetUpdate_ns_addr_rem;
				break;
			case ccReg_domainCreate_registrant:
				err_item->spec = errspec_domainCreate_registrant;
				break;
			case ccReg_domainUpdate_registrant:
				err_item->spec = errspec_domainUpdate_registrant;
				break;
			case ccReg_domainCreate_nsset:
				err_item->spec = errspec_domainCreate_nsset;
				break;
			case ccReg_domainUpdate_nsset:
				err_item->spec = errspec_domainUpdate_nsset;
				break;
			case ccReg_domainCreate_period:
				err_item->spec = errspec_domainCreate_period;
				break;
			case ccReg_domainRenew_period:
				err_item->spec = errspec_domainRenew_period;
				break;
			case ccReg_domainCreate_admin:
				err_item->spec = errspec_domainCreate_admin;
				break;
			case ccReg_domainUpdate_admin_add:
				err_item->spec = errspec_domainUpdate_admin_add;
				break;
			case ccReg_domainUpdate_admin_rem:
				err_item->spec = errspec_domainUpdate_admin_rem;
				break;
			case ccReg_domainCreate_ext_valDate:
				err_item->spec = errspec_domainCreate_ext_valdate;
				break;
			case ccReg_domainUpdate_ext_valDate:
				err_item->spec = errspec_domainUpdate_ext_valdate;
				break;
			case ccReg_domainRenew_ext_valDate:
				err_item->spec = errspec_domainRenew_ext_valDate;
				break;
			case ccReg_domainRenew_curExpDate:
				err_item->spec = errspec_domainRenew_curExpDate;
				break;
			default:
				err_item->spec = errspec_unknow;
				break;
		}
		CL_CONTENT(item) = (void *) err_item;
		CL_ADD(errors, item);
	}

	if (i < c_errors->_length) {
		/* XXX what should we do? */
	}
}

int
epp_call_hello(epp_corba_globs *globs, char *buf, unsigned len)
{
	CORBA_Environment ev[1];
	CORBA_string version;

	CORBA_exception_init(ev);

	version = ccReg_EPP_version(globs->service, ev);

	if (raised_exception(ev)) {
		/* do NOT try to free version even if not NULL -> segfault */
		CORBA_exception_free(ev);
		return 0;
	}
	CORBA_exception_free(ev);

	strncpy(buf, version, len - 1);
	/* just want to be sure the string is NULL terminated in any case */
	buf[len] = '\0';
	CORBA_free(version);
	return 1;
}

/**
 * "dummy" call is dummy because it only retrieves unique svTRID and
 * error message from central repository and by this way informs repository
 * about the error. This call is used for failures detected already on side
 * of mod_eppd.
 *
 * @param globs Corba context.
 * @param session Session identifier.
 * @param cdata Data from xml request.
 * @return status (see #corba_status).
 */
static corba_status
epp_call_dummy(epp_corba_globs *globs, int session, epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	ccReg_Response *response;

	CORBA_exception_init(ev);

	response = ccReg_EPP_GetTransaction(globs->service,
			session,
			cdata->clTRID,
			cdata->rc,
			ev);

	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		CORBA_exception_free(ev);
		return CORBA_ERROR;
	}
	CORBA_exception_free(ev);

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		CORBA_free(response);
		return CORBA_REMOTE_ERROR;
	}

	get_errors(cdata->errors, &response->errors);
	cdata->svTRID = strdup(response->svTRID);
	cdata->msg = strdup(response->errMsg);
	/* rc is known */

	CORBA_free(response);
	return CORBA_OK;
}

corba_status
epp_call_login(
		epp_corba_globs *globs,
		int *session,
		epp_lang *lang,
		char *certID,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	CORBA_long	c_session;
	ccReg_Languages	c_lang;
	ccReg_Response *response;

	CORBA_exception_init(ev);
	c_lang = (cdata->in->login.lang == LANG_EN) ? ccReg_EN : ccReg_CS;

	response = ccReg_EPP_ClientLogin(globs->service,
			cdata->in->login.clID,
			cdata->in->login.pw,
			cdata->in->login.newPW,
			cdata->clTRID,
			cdata->xml_in,
			&c_session,
			certID,
			c_lang,
			ev);

	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		CORBA_exception_free(ev);
		return CORBA_ERROR;
	}

	CORBA_exception_free(ev);
	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		CORBA_free(response);
		return CORBA_REMOTE_ERROR;
	}

	get_errors(cdata->errors, &response->errors);
	cdata->svTRID = strdup(response->svTRID);
	cdata->msg = strdup(response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);

	if (cdata->rc == 1000) {
		*session = c_session;
		*lang = cdata->in->login.lang;
	}

	return CORBA_OK;
}

corba_status
epp_call_logout(
		epp_corba_globs *globs,
		int session,
		epp_command_data *cdata,
		int *logout)
{
	CORBA_Environment ev[1];
	ccReg_Response *response;

	CORBA_exception_init(ev);
	*logout = 0;

	response = ccReg_EPP_ClientLogout(globs->service,
			session,
			cdata->clTRID,
			cdata->xml_in,
			ev);
	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		CORBA_exception_free(ev);
		return CORBA_ERROR;
	}
	CORBA_exception_free(ev);

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		CORBA_free(response);
		return CORBA_REMOTE_ERROR;
	}

	get_errors(cdata->errors, &response->errors);
	cdata->svTRID = strdup(response->svTRID);
	cdata->msg = strdup(response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);

	/* propagate information about logout upwards */
	if (cdata->rc == 1500) *logout = 1;

	return CORBA_OK;
}

/**
 * EPP check for domain, nsset and contact is so similar that it is worth of
 * having the code in one function and pass object type as parameter.
 *
 * @param globs Corba context.
 * @param session Session identifier.
 * @param cdata Data from xml request.
 * @param obj Object type (see #epp_object_type)
 * @return status (see #corba_status).
 */
static corba_status
epp_call_check(epp_corba_globs *globs, int session, epp_command_data *cdata,
		epp_object_type obj)
{
	CORBA_Environment ev[1];
	ccReg_Avail	*c_bools;
	ccReg_Check	*c_ids;
	ccReg_Response *response;
	struct circ_list	*item;
	int	len, i;

	CORBA_exception_init(ev);

	/* get number of contacts */
	len = cl_length(cdata->in->check.ids);
	c_ids = ccReg_Check__alloc();
	c_ids->_buffer = ccReg_Check_allocbuf(len);
	c_ids->_maximum = c_ids->_length = len;
	c_ids->_release = CORBA_TRUE;

	/* copy each requested object in corba buffer */
	i = 0;
	CL_FOREACH(cdata->in->check.ids)
		c_ids->_buffer[i++] = CORBA_string_dup(CL_CONTENT(cdata->in->check.ids));

	if (obj == EPP_CONTACT)
		response = ccReg_EPP_ContactCheck(globs->service,
				c_ids,
				&c_bools,
				session,
				cdata->clTRID,
				cdata->xml_in,
				ev);
	else if (obj == EPP_DOMAIN)
		response = ccReg_EPP_DomainCheck(globs->service,
				c_ids,
				&c_bools,
				session,
				cdata->clTRID,
				cdata->xml_in,
				ev);
	else {
		assert(obj == EPP_NSSET);
		response = ccReg_EPP_NSSetCheck(globs->service,
				c_ids,
				&c_bools,
				session,
				cdata->clTRID,
				cdata->xml_in,
				ev);
	}

	CORBA_free(c_ids);

	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		CORBA_exception_free(ev);
		return CORBA_ERROR;
	}
	CORBA_exception_free(ev);

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		CORBA_free(c_bools);
		CORBA_free(response);
		return CORBA_REMOTE_ERROR;
	}

	/* alloc necessary structures */
	if ((cdata->out = calloc(1, sizeof (*cdata->out))) == NULL) {
		CORBA_free(c_bools);
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}
	if ((cdata->out->check.bools = malloc(sizeof *item)) == NULL) {
		free(cdata->out);
		cdata->out = NULL;
		CORBA_free(c_bools);
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}
	CL_NEW(cdata->out->check.bools);

	/* length of results returned should be same as lenght of input objects */
	assert(len == c_bools->_length);
	/*
	 * circular list stores items in reversed order.
	 * Therefore we have reverse processing order of items in
	 * c_bools->_buffer array
	 */
	for (i = c_bools->_length - 1; i >= 0; i--) {
		if ((item = malloc(sizeof *item)) == NULL) break;
		/*
		 * note that we cannot use zero value for false value
		 * since value zero of content pointer denotes that
		 * the item in list is a sentinel (first and last).
		 * Therefore we will use value 2 for false (1 remains true).
		 */
		CL_CONTENT(item) = (void *) (c_bools->_buffer[i] ? 1 : 2);
		CL_ADD(cdata->out->check.bools, item);
	}
	CORBA_free(c_bools);

	/* handle situation when item allocation above failed */
	if (i > 0) {
		cl_purge(cdata->out->check.bools);
		free(cdata->out);
		cdata->out = NULL;
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}

	get_errors(cdata->errors, &response->errors);
	cdata->svTRID = strdup(response->svTRID);
	cdata->msg = strdup(response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);
	return CORBA_OK;
}

/**
 * EPP info contact.
 *
 * @param globs Corba context.
 * @param session Session identifier.
 * @param cdata Data from xml request.
 * @return status (see #corba_status).
 */
static corba_status
epp_call_info_contact(epp_corba_globs *globs, int session,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	ccReg_Contact	*c_contact;
	ccReg_Response	*response;
	epp_postalInfo	*pi;
	epp_discl	*discl;
	struct circ_list	*item;
	int	i;

	CORBA_exception_init(ev);

	/* get information about contact from central repository */
	response = ccReg_EPP_ContactInfo(globs->service,
			cdata->in->info.id,
			&c_contact,
			session,
			cdata->clTRID,
			cdata->xml_in,
			ev);

	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		CORBA_exception_free(ev);
		return CORBA_ERROR;
	}
	CORBA_exception_free(ev);

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		CORBA_free(c_contact);
		CORBA_free(response);
		return CORBA_REMOTE_ERROR;
	}

	/* first allocate all necessary structures */
	if ((cdata->out = calloc(1, sizeof (*cdata->out))) == NULL) {
		CORBA_free(c_contact);
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}
	if ((cdata->out->info_contact.postalInfo = calloc(1, sizeof *pi)) == NULL) {
		free(cdata->out);
		cdata->out = NULL;
		CORBA_free(c_contact);
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}
	if ((cdata->out->info_contact.discl = calloc(1, sizeof *discl)) == NULL) {
		free(cdata->out->info_contact.postalInfo);
		free(cdata->out);
		cdata->out = NULL;
		CORBA_free(c_contact);
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}
	if ((cdata->out->info_contact.status = malloc(sizeof *item)) == NULL) {
		free(cdata->out->info_contact.discl);
		free(cdata->out->info_contact.postalInfo);
		free(cdata->out);
		cdata->out = NULL;
		CORBA_free(c_contact);
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}

	/* ok, now everything was successfully allocated */
	cdata->out->info_contact.roid = strdup(c_contact->ROID);
	cdata->out->info_contact.crID = strdup(c_contact->CrID);
	cdata->out->info_contact.upID = strdup(c_contact->UpID);
	cdata->out->info_contact.crDate = c_contact->CrDate;
	cdata->out->info_contact.upDate = c_contact->UpDate;
	/* contact status */
	CL_NEW(cdata->out->info_contact.status);
	for (i = 0; i < c_contact->stat._length; i++) {
		item = malloc(sizeof *item);
		CL_CONTENT(item) =(void *) strdup(c_contact->stat._buffer[i]);
		CL_ADD(cdata->out->info_contact.status, item);
	}
	/* postal info */
	pi = cdata->out->info_contact.postalInfo;
	pi->name = strdup(c_contact->Name);
	pi->org = strdup(c_contact->Organization);
	pi->street[0] = strdup(c_contact->Street1);
	pi->street[1] = strdup(c_contact->Street2);
	pi->street[2] = strdup(c_contact->Street3);
	pi->city = strdup(c_contact->City);
	pi->sp = strdup(c_contact->StateOrProvince);
	pi->pc = strdup(c_contact->PostalCode);
	pi->cc = strdup(c_contact->CountryCode);
	/* other attributes */
	cdata->out->info_contact.voice = strdup(c_contact->Telephone);
	cdata->out->info_contact.fax = strdup(c_contact->Fax);
	cdata->out->info_contact.email = strdup(c_contact->Email);
	cdata->out->info_contact.notify_email =
		strdup(c_contact->NotifyEmail);
	cdata->out->info_contact.vat = strdup(c_contact->VAT);
	cdata->out->info_contact.ssn = strdup(c_contact->SSN);
	/* disclose info */
	discl = cdata->out->info_contact.discl;
	discl->name = c_contact->DiscloseName;
	discl->org = c_contact->DiscloseOrganization;
	discl->addr = c_contact->DiscloseAddress;
	discl->voice = c_contact->DiscloseTelephone;
	discl->fax = c_contact->DiscloseFax;
	discl->email = c_contact->DiscloseEmail;

	CORBA_free(c_contact);

	get_errors(cdata->errors, &response->errors);
	cdata->svTRID = strdup(response->svTRID);
	cdata->msg = strdup(response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);
	return CORBA_OK;
}

/**
 * EPP info domain.
 *
 * @param globs Corba context.
 * @param session Session identifier.
 * @param cdata Data from xml request.
 * @return status (see #corba_status).
 */
static corba_status
epp_call_info_domain(epp_corba_globs *globs, int session,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	ccReg_Response	*response;
	ccReg_Domain	*c_domain;
	struct circ_list	*item;
	int i;

	CORBA_exception_init(ev);

	/* get information about domain */
	response = ccReg_EPP_DomainInfo(globs->service,
			cdata->in->info.id,
			&c_domain,
			session,
			cdata->clTRID,
			cdata->xml_in,
			ev);

	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		CORBA_exception_free(ev);
		return CORBA_ERROR;
	}
	CORBA_exception_free(ev);

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		CORBA_free(c_domain);
		CORBA_free(response);
		return CORBA_REMOTE_ERROR;
	}

	/* allocate necessary structures */
	if ((cdata->out = calloc(1, sizeof (*cdata->out))) == NULL) {
		CORBA_free(c_domain);
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}
	if ((cdata->out->info_domain.status = malloc(sizeof *item)) == NULL) {
		free(cdata->out);
		cdata->out = NULL;
		CORBA_free(c_domain);
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}
	if ((cdata->out->info_domain.admin = malloc(sizeof *item)) == NULL) {
		free(cdata->out->info_domain.status);
		free(cdata->out);
		cdata->out = NULL;
		CORBA_free(c_domain);
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}
	if ((cdata->out->info_domain.ds = malloc(sizeof *item)) == NULL) {
		free(cdata->out->info_domain.admin);
		free(cdata->out->info_domain.status);
		free(cdata->out);
		cdata->out = NULL;
		CORBA_free(c_domain);
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}

	/* ok, now everything was successfully allocated */
	cdata->out->info_domain.roid = strdup(c_domain->ROID);
	cdata->out->info_domain.clID = strdup(c_domain->ClID);
	cdata->out->info_domain.crID = strdup(c_domain->CrID);
	cdata->out->info_domain.upID = strdup(c_domain->UpID);
	cdata->out->info_domain.crDate = c_domain->CrDate;
	cdata->out->info_domain.upDate = c_domain->UpDate;
	cdata->out->info_domain.trDate = c_domain->TrDate;
	cdata->out->info_domain.exDate = c_domain->ExDate;

	cdata->out->info_domain.registrant = strdup(c_domain->Registrant);
	cdata->out->info_domain.nsset = strdup(c_domain->nsset);
	cdata->out->info_domain.authInfo = strdup(c_domain->AuthInfoPw);

	/* allocate and initialize status, admin lists */
	CL_NEW(cdata->out->info_domain.status);
	for (i = 0; i < c_domain->stat._length; i++) {
		item = malloc(sizeof *item);
		CL_CONTENT(item) = (void *) strdup(c_domain->stat._buffer[i]);
		CL_ADD(cdata->out->info_domain.status, item);
	}
	CL_NEW(cdata->out->info_domain.admin);
	for (i = 0; i < c_domain->admin._length; i++) {
		item = malloc(sizeof *item);
		CL_CONTENT(item) = (void *) strdup(c_domain->admin._buffer[i]);
		CL_ADD(cdata->out->info_domain.admin, item);
	}
	/* temporary stub until dnssec will be implemented */
	CL_NEW(cdata->out->info_domain.ds);

	/* look for extensions */
	for (i = 0; i < c_domain->ext._length; i++) {
		/* is it enumval extension? */
		if (CORBA_TypeCode_equal(c_domain->ext._buffer[i]._type,
				TC_ccReg_ENUMValidationExtension, ev))
		{
			ccReg_ENUMValidationExtension	*c_enumval =
				c_domain->ext._buffer[i]._value;
			cdata->out->info_domain.valExDate = c_enumval->valExDate;
		}
	}

	CORBA_free(c_domain);

	get_errors(cdata->errors, &response->errors);
	cdata->svTRID = strdup(response->svTRID);
	cdata->msg = strdup(response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);
	return CORBA_OK;
}

/**
 * EPP info nsset.
 *
 * @param globs Corba context.
 * @param session Session identifier.
 * @param cdata Data from xml request.
 * @return status (see #corba_status).
 */
static corba_status
epp_call_info_nsset(epp_corba_globs *globs, int session, epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	ccReg_NSSet	*c_nsset;
	ccReg_Response	*response;
	struct circ_list	*item;
	int i, j;

	CORBA_exception_init(ev);

	/* get information about nsset */
	response = ccReg_EPP_NSSetInfo(globs->service,
			cdata->in->info.id,
			&c_nsset,
			session,
			cdata->clTRID,
			cdata->xml_in,
			ev);

	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		CORBA_exception_free(ev);
		return CORBA_ERROR;
	}
	CORBA_exception_free(ev);

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		CORBA_free(c_nsset);
		CORBA_free(response);
		return CORBA_REMOTE_ERROR;
	}

	/* allocate needed structures */
	if ((cdata->out = calloc(1, sizeof (*cdata->out))) == NULL) {
		CORBA_free(c_nsset);
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}
	if ((cdata->out->info_nsset.status = malloc(sizeof *item)) == NULL) {
		free(cdata->out);
		cdata->out = NULL;
		CORBA_free(c_nsset);
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}
	if ((cdata->out->info_nsset.ns = malloc(sizeof *item)) == NULL) {
		free(cdata->out->info_nsset.status);
		free(cdata->out);
		cdata->out = NULL;
		CORBA_free(c_nsset);
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}
	if ((cdata->out->info_nsset.tech = malloc(sizeof *item)) == NULL) {
		free(cdata->out->info_nsset.ns);
		free(cdata->out->info_nsset.status);
		free(cdata->out);
		cdata->out = NULL;
		CORBA_free(c_nsset);
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}

	/* ok, now alomost everything was successfully allocated */
	cdata->out->info_nsset.roid = strdup(c_nsset->ROID);
	cdata->out->info_nsset.clID = strdup(c_nsset->ClID);
	cdata->out->info_nsset.crID = strdup(c_nsset->CrID);
	cdata->out->info_nsset.upID = strdup(c_nsset->UpID);
	cdata->out->info_nsset.crDate = c_nsset->CrDate;
	cdata->out->info_nsset.upDate = c_nsset->UpDate;
	cdata->out->info_nsset.trDate = c_nsset->TrDate;
	cdata->out->info_nsset.authInfo = strdup(c_nsset->AuthInfoPw);

	/* allocate and initialize status list */
	CL_NEW(cdata->out->info_nsset.status);
	for (i = 0; i < c_nsset->stat._length; i++) {
		item = malloc(sizeof *item);
		CL_CONTENT(item) = (void *) strdup(c_nsset->stat._buffer[i]);
		CL_ADD(cdata->out->info_nsset.status, item);
	}
	/* allocate and initialize tech list */
	CL_NEW(cdata->out->info_nsset.tech);
	for (i = 0; i < c_nsset->tech._length; i++) {
		item = malloc(sizeof *item);
		CL_CONTENT(item) = (void *) strdup(c_nsset->tech._buffer[i]);
		CL_ADD(cdata->out->info_nsset.tech, item);
	}
	/*
	 * allocate and initialize required number of ns items
	 */
	CL_NEW(cdata->out->info_nsset.ns);
	for (i = 0; i < c_nsset->dns._length; i++) {
		epp_ns	*item_ns;

		/* ns item */
		item = malloc(sizeof *item);
		item_ns = malloc(sizeof *item_ns);
		CL_CONTENT(item) = (void *) item_ns;
		CL_ADD(cdata->out->info_nsset.ns, item);
		/* content of ns item */
		item_ns->name = strdup(c_nsset->dns._buffer[i].fqdn);
		item_ns->addr = malloc(sizeof (struct circ_list));
		CL_NEW(item_ns->addr);
		for (j = 0; j < c_nsset->dns._buffer[i].inet._length; j++) {
			item = malloc(sizeof *item);
			CL_CONTENT(item) = (void *)
				strdup(c_nsset->dns._buffer[i].inet._buffer[j]);
			CL_ADD(item_ns->addr, item);
		}
	}

	CORBA_free(c_nsset);

	get_errors(cdata->errors, &response->errors);
	cdata->svTRID = strdup(response->svTRID);
	cdata->msg = strdup(response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);
	return CORBA_OK;
}

/**
 * EPP poll request.
 *
 * @param globs Corba context.
 * @param session Session identifier.
 * @param cdata Data from xml request.
 * @return status (see #corba_status).
 */
static corba_status
epp_call_poll_req(epp_corba_globs *globs, int session, epp_command_data *cdata)
{
	ccReg_Response	*response;
	CORBA_Environment	ev[1];
	CORBA_short	c_count;
	CORBA_long	c_msgID;
	ccReg_timestamp	c_qdate;
	CORBA_char	*c_msg;

	CORBA_exception_init(ev);

	/* get message from repository */
	response = ccReg_EPP_PollRequest(globs->service,
			&c_msgID,
			&c_count,
			&c_qdate,
			&c_msg,
			session,
			cdata->clTRID,
			cdata->xml_in,
			ev);

	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		CORBA_exception_free(ev);
		return CORBA_ERROR;
	}
	CORBA_exception_free(ev);

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		CORBA_free(c_msg);
		CORBA_free(response);
		return CORBA_REMOTE_ERROR;
	}

	if ((cdata->out = calloc(1, sizeof (*cdata->out))) == NULL) {
		CORBA_free(c_msg);
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}

	cdata->out->poll_req.count = c_count;
	cdata->out->poll_req.msgid = c_msgID;
	cdata->out->poll_req.qdate = c_qdate;
	cdata->out->poll_req.msg = strdup(c_msg);

	CORBA_free(c_msg);

	get_errors(cdata->errors, &response->errors);
	cdata->svTRID = strdup(response->svTRID);
	cdata->msg = strdup(response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);
	return CORBA_OK;
}

/**
 * EPP poll acknoledge.
 *
 * @param globs Corba context.
 * @param session Session identifier.
 * @param cdata Data from xml request.
 * @return status (see #corba_status).
 */
static corba_status
epp_call_poll_ack(epp_corba_globs *globs, int session, epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	CORBA_long	c_msgID;
	CORBA_short	c_count;
	ccReg_Response *response;

	assert(cdata->in != NULL);
	CORBA_exception_init(ev);

	/* send acknoledgement */
	response = ccReg_EPP_PollAcknowledgement(globs->service,
			cdata->in->poll_ack.msgid,
			&c_count,
			&c_msgID,
			session,
			cdata->clTRID,
			cdata->xml_in,
			ev);

	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		CORBA_exception_free(ev);
		return CORBA_ERROR;
	}
	CORBA_exception_free(ev);

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		CORBA_free(response);
		return CORBA_REMOTE_ERROR;
	}

	if ((cdata->out = calloc(1, sizeof (*cdata->out))) == NULL) {
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}

	cdata->out->poll_ack.count = c_count;
	cdata->out->poll_ack.msgid = c_msgID;

	get_errors(cdata->errors, &response->errors);
	cdata->svTRID = strdup(response->svTRID);
	cdata->msg = strdup(response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);
	return CORBA_OK;
}

/**
 * EPP create domain.
 *
 * @param globs Corba context.
 * @param session Session identifier.
 * @param cdata Data from xml request.
 * @return status (see #corba_status).
 */
static corba_status
epp_call_create_domain(epp_corba_globs *globs, int session,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	ccReg_timestamp	c_crDate;
	ccReg_timestamp	c_exDate;
	ccReg_Response *response;
	ccReg_AdminContact	*c_admin;
	ccReg_ExtensionList	*c_ext_list;
	int	len, i;

	assert(cdata->in != NULL);
	CORBA_exception_init(ev);

	/* fill in corba input parameters */
	c_admin = ccReg_AdminContact__alloc();
	len = cl_length(cdata->in->create_domain.admin);
	c_admin->_buffer = ccReg_AdminContact_allocbuf(len);
	c_admin->_maximum = c_admin->_length = len;
	c_admin->_release = CORBA_TRUE;
	i = 0;
	CL_FOREACH(cdata->in->create_domain.admin)
		c_admin->_buffer[i++] = CORBA_string_dup(
				CL_CONTENT(cdata->in->create_domain.admin));
	c_ext_list = ccReg_ExtensionList__alloc();
	/* fill extension list if needed */
	if (cdata->in->create_domain.valExDate != 0) {
		ccReg_ENUMValidationExtension	*c_enumval;

		c_enumval = ccReg_ENUMValidationExtension__alloc();
		c_enumval->valExDate = cdata->in->create_domain.valExDate;
		c_ext_list->_buffer = ccReg_ExtensionList_allocbuf(1);
		c_ext_list->_maximum = c_ext_list->_length = 1;
		c_ext_list->_release = CORBA_TRUE;
		c_ext_list->_buffer[0]._type = TC_ccReg_ENUMValidationExtension;
		c_ext_list->_buffer[0]._value = c_enumval;
		c_ext_list->_buffer[0]._release = CORBA_TRUE;
	}

	/* send new domain in central repository */
	response = ccReg_EPP_DomainCreate(globs->service,
			cdata->in->create_domain.name,
			cdata->in->create_domain.registrant,
			cdata->in->create_domain.nsset,
			cdata->in->create_domain.authInfo,
			cdata->in->create_domain.period,
			c_admin,
			&c_crDate,
			&c_exDate,
			session,
			cdata->clTRID,
			cdata->xml_in,
			c_ext_list,
			ev);

	CORBA_free(c_admin);
	CORBA_free(c_ext_list);

	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		CORBA_exception_free(ev);
		return CORBA_ERROR;
	}
	CORBA_exception_free(ev);

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		CORBA_free(response);
		return CORBA_REMOTE_ERROR;
	}

	if ((cdata->out = calloc(1, sizeof (*cdata->out))) == NULL) {
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}

	cdata->out->create.crDate = c_crDate;
	cdata->out->create.exDate = c_exDate;

	get_errors(cdata->errors, &response->errors);
	cdata->svTRID = strdup(response->svTRID);
	cdata->msg = strdup(response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);
	return CORBA_OK;
}

/**
 * EPP create contact.
 *
 * @param globs Corba context.
 * @param session Session identifier.
 * @param cdata Data from xml request.
 * @return status (see #corba_status).
 */
static corba_status
epp_call_create_contact(epp_corba_globs *globs, int session,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	ccReg_timestamp	c_crDate;
	ccReg_ContactChange	*c_contact;
	ccReg_Response *response;

	assert(cdata->in != NULL);
	CORBA_exception_init(ev);

	/* fill in corba input values */
	c_contact = ccReg_ContactChange__alloc();
	c_contact->Telephone = CORBA_string_dup(cdata->in->create_contact.voice);
	c_contact->Fax = CORBA_string_dup(cdata->in->create_contact.fax);
	c_contact->Email = CORBA_string_dup(cdata->in->create_contact.email);
	c_contact->NotifyEmail =
		CORBA_string_dup(cdata->in->create_contact.notify_email);
	c_contact->VAT = CORBA_string_dup(cdata->in->create_contact.vat);
	c_contact->SSN = CORBA_string_dup(cdata->in->create_contact.ssn);
	/* disclose */
	c_contact->DiscloseName = cdata->in->create_contact.discl->name;
	c_contact->DiscloseOrganization = cdata->in->create_contact.discl->org;
	c_contact->DiscloseAddress = cdata->in->create_contact.discl->addr;
	c_contact->DiscloseTelephone = cdata->in->create_contact.discl->voice;
	c_contact->DiscloseFax = cdata->in->create_contact.discl->fax;
	c_contact->DiscloseEmail = cdata->in->create_contact.discl->email;
	/* postal info */
	c_contact->Name =
		CORBA_string_dup(cdata->in->create_contact.postalInfo->name);
	c_contact->Organization =
		CORBA_string_dup(cdata->in->create_contact.postalInfo->org);
	c_contact->Street1 =
		CORBA_string_dup(cdata->in->create_contact.postalInfo->street[0]);
	c_contact->Street2 =
		CORBA_string_dup(cdata->in->create_contact.postalInfo->street[1]);
	c_contact->Street3 =
		CORBA_string_dup(cdata->in->create_contact.postalInfo->street[2]);
	c_contact->City =
		CORBA_string_dup(cdata->in->create_contact.postalInfo->city);
	c_contact->StateOrProvince =
		CORBA_string_dup(cdata->in->create_contact.postalInfo->sp);
	c_contact->PostalCode =
		CORBA_string_dup(cdata->in->create_contact.postalInfo->pc);
	c_contact->CC =
		CORBA_string_dup(cdata->in->create_contact.postalInfo->cc);

	/* send new contact in repository */
	response = ccReg_EPP_ContactCreate(globs->service,
			cdata->in->create_contact.id,
			c_contact,
			&c_crDate,
			session,
			cdata->clTRID,
			cdata->xml_in,
			ev);

	CORBA_free(c_contact);

	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		CORBA_exception_free(ev);
		return CORBA_ERROR;
	}
	CORBA_exception_free(ev);

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		CORBA_free(response);
		return CORBA_REMOTE_ERROR;
	}

	if ((cdata->out = calloc(1, sizeof (*cdata->out))) == NULL) {
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}

	cdata->out->create.crDate = c_crDate;

	get_errors(cdata->errors, &response->errors);
	cdata->svTRID = strdup(response->svTRID);
	cdata->msg = strdup(response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);
	return CORBA_OK;
}

/**
 * EPP create nsset.
 *
 * @param globs Corba context.
 * @param session Session identifier.
 * @param cdata Data from xml request.
 * @return status (see #corba_status).
 */
static corba_status
epp_call_create_nsset(epp_corba_globs *globs, int session,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	ccReg_Response *response;
	ccReg_DNSHost	*c_dnshost;
	ccReg_TechContact	*c_tech;
	ccReg_timestamp	c_crDate;
	int	len, i, j;

	assert(cdata->in != NULL);
	CORBA_exception_init(ev);

	/* alloc & init sequence of nameservers */
	c_dnshost = ccReg_DNSHost__alloc();
	len = cl_length(cdata->in->create_nsset.ns);
	c_dnshost->_buffer = ccReg_DNSHost_allocbuf(len);
	c_dnshost->_maximum = c_dnshost->_length = len;
	c_dnshost->_release = CORBA_TRUE;
	i = 0;
	CL_FOREACH(cdata->in->create_nsset.ns) {
		/* alloc & init sequence of ns's addresses */
		epp_ns *ns = (epp_ns *) CL_CONTENT(cdata->in->create_nsset.ns);
		len = cl_length(ns->addr);
		c_dnshost->_buffer[i].inet._buffer = ccReg_InetAddress_allocbuf(len);
		c_dnshost->_buffer[i].inet._maximum =
			c_dnshost->_buffer[i].inet._length = len;
		c_dnshost->_buffer[i].inet._release = CORBA_TRUE;
		j = 0;
		CL_FOREACH(ns->addr)
			c_dnshost->_buffer[i].inet._buffer[j++] =
					CORBA_string_dup(CL_CONTENT(ns->addr));
		c_dnshost->_buffer[i++].fqdn = CORBA_string_dup(ns->name);
	}
	/* alloc & init sequence of tech contacts */
	c_tech = ccReg_TechContact__alloc();
	len = cl_length(cdata->in->create_nsset.tech);
	c_tech->_buffer = ccReg_TechContact_allocbuf(len);
	c_tech->_maximum = c_tech->_length = len;
	c_tech->_release = CORBA_TRUE;
	i = 0;
	CL_FOREACH(cdata->in->create_nsset.tech)
		c_tech->_buffer[i++] = CORBA_string_dup(
				CL_CONTENT(cdata->in->create_nsset.tech));

	/* send new nsset to repository */
	response = ccReg_EPP_NSSetCreate(globs->service,
			cdata->in->create_nsset.id,
			cdata->in->create_nsset.authInfo,
			c_tech,
			c_dnshost,
			&c_crDate,
			session,
			cdata->clTRID,
			cdata->xml_in,
			ev);

	CORBA_free(c_tech);
	CORBA_free(c_dnshost);

	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		CORBA_exception_free(ev);
		return CORBA_ERROR;
	}
	CORBA_exception_free(ev);

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		CORBA_free(response);
		return CORBA_REMOTE_ERROR;
	}

	if ((cdata->out = calloc(1, sizeof (*cdata->out))) == NULL) {
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}

	cdata->out->create.crDate = c_crDate;

	get_errors(cdata->errors, &response->errors);
	cdata->svTRID = strdup(response->svTRID);
	cdata->msg = strdup(response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);
	return CORBA_OK;
}

/**
 * EPP delete for domain, nsset and contact is so similar that it is worth of
 * having the code in one function and pass object type as parameter.
 *
 * @param globs Corba context.
 * @param session Session identifier.
 * @param cdata Data from xml request.
 * @param obj Object type (see #epp_object_type)
 * @return status (see #corba_status).
 */
static corba_status
epp_call_delete(epp_corba_globs *globs, int session,
		epp_command_data *cdata, epp_object_type obj)
{
	ccReg_Response *response;
	CORBA_Environment ev[1];

	assert(cdata->in != NULL);

	CORBA_exception_init(ev);

	if (obj == EPP_DOMAIN)
		response = ccReg_EPP_DomainDelete(globs->service,
				cdata->in->delete.id,
				session,
				cdata->clTRID,
				cdata->xml_in,
				ev);
	else if (obj == EPP_CONTACT)
		response = ccReg_EPP_ContactDelete(globs->service,
				cdata->in->delete.id,
				session,
				cdata->clTRID,
				cdata->xml_in,
				ev);
	else {
		assert(obj == EPP_NSSET);
		response = ccReg_EPP_NSSetDelete(globs->service,
				cdata->in->delete.id,
				session,
				cdata->clTRID,
				cdata->xml_in,
				ev);
	}

	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		CORBA_exception_free(ev);
		return CORBA_ERROR;
	}
	CORBA_exception_free(ev);

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		CORBA_free(response);
		return CORBA_REMOTE_ERROR;
	}

	get_errors(cdata->errors, &response->errors);
	cdata->svTRID = strdup(response->svTRID);
	cdata->msg = strdup(response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);
	return CORBA_OK;
}

/**
 * EPP renew domain.
 *
 * @param globs Corba context.
 * @param session Session identifier.
 * @param cdata Data from xml request.
 * @return status (see #corba_status).
 */
static corba_status
epp_call_renew_domain(epp_corba_globs *globs, int session,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	ccReg_Response *response;
	ccReg_timestamp	c_exDate;
	ccReg_ExtensionList	*c_ext_list;

	assert(cdata->in != NULL);
	CORBA_exception_init(ev);
	c_ext_list = ccReg_ExtensionList__alloc();
	/* fill extension list if needed */
	if (cdata->in->renew.valExDate != 0) {
		ccReg_ENUMValidationExtension	*c_enumval;

		c_enumval = ccReg_ENUMValidationExtension__alloc();
		c_enumval->valExDate = cdata->in->renew.valExDate;
		c_ext_list->_buffer = ccReg_ExtensionList_allocbuf(1);
		c_ext_list->_maximum = c_ext_list->_length = 1;
		c_ext_list->_release = CORBA_TRUE;
		c_ext_list->_buffer[0]._type = TC_ccReg_ENUMValidationExtension;
		c_ext_list->_buffer[0]._value = c_enumval;
		c_ext_list->_buffer[0]._release = CORBA_TRUE;
	}

	/* send renew request to repository */
	response = ccReg_EPP_DomainRenew(globs->service,
			cdata->in->renew.name,
			cdata->in->renew.exDate,
			cdata->in->renew.period,
			&c_exDate,
			session,
			cdata->clTRID,
			cdata->xml_in,
			c_ext_list,
			ev);

	CORBA_free(c_ext_list);

	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		CORBA_exception_free(ev);
		return CORBA_ERROR;
	}
	CORBA_exception_free(ev);

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		CORBA_free(response);
		return CORBA_REMOTE_ERROR;
	}

	if ((cdata->out = calloc(1, sizeof (*cdata->out))) == NULL) {
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}
	cdata->out->renew.exDate = c_exDate;

	get_errors(cdata->errors, &response->errors);
	cdata->svTRID = strdup(response->svTRID);
	cdata->msg = strdup(response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);
	return CORBA_OK;
}

/**
 * EPP update domain.
 *
 * @param globs Corba context.
 * @param session Session identifier.
 * @param cdata Data from xml request.
 * @return status (see #corba_status).
 */
static corba_status
epp_call_update_domain(epp_corba_globs *globs, int session,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	ccReg_Response *response;
	ccReg_AdminContact	*c_admin_add;
	ccReg_AdminContact	*c_admin_rem;
	ccReg_Status	*c_status_add;
	ccReg_Status	*c_status_rem;
	ccReg_ExtensionList	*c_ext_list;
	int	i, len;

	assert(cdata->in != NULL);
	CORBA_exception_init(ev);

	/* admin add */
	c_admin_add = ccReg_AdminContact__alloc();
	len = cl_length(cdata->in->update_domain.add_admin);
	c_admin_add->_buffer = ccReg_AdminContact_allocbuf(len);
	c_admin_add->_maximum = c_admin_add->_length = len;
	c_admin_add->_release = CORBA_TRUE;
	i = 0;
	CL_FOREACH(cdata->in->update_domain.add_admin)
		c_admin_add->_buffer[i++] = CORBA_string_dup(
				CL_CONTENT(cdata->in->update_domain.add_admin));
	/* admin rem */
	c_admin_rem = ccReg_AdminContact__alloc();
	len = cl_length(cdata->in->update_domain.rem_admin);
	c_admin_rem->_buffer = ccReg_AdminContact_allocbuf(len);
	c_admin_rem->_maximum = c_admin_rem->_length = len;
	c_admin_rem->_release = CORBA_TRUE;
	i = 0;
	CL_FOREACH(cdata->in->update_domain.rem_admin)
		c_admin_rem->_buffer[i++] = CORBA_string_dup(
				CL_CONTENT(cdata->in->update_domain.rem_admin));
	/* status add */
	c_status_add = ccReg_Status__alloc();
	len = cl_length(cdata->in->update_domain.add_status);
	c_status_add->_buffer = ccReg_Status_allocbuf(len);
	c_status_add->_maximum = c_status_add->_length = len;
	c_status_add->_release = CORBA_TRUE;
	i = 0;
	CL_FOREACH(cdata->in->update_domain.add_status)
		c_status_add->_buffer[i++] = CORBA_string_dup(
				CL_CONTENT(cdata->in->update_domain.add_status));
	/* status rem */
	c_status_rem = ccReg_Status__alloc();
	len = cl_length(cdata->in->update_domain.rem_status);
	c_status_rem->_buffer = ccReg_Status_allocbuf(len);
	c_status_rem->_maximum = c_status_rem->_length = len;
	c_status_rem->_release = CORBA_TRUE;
	i = 0;
	CL_FOREACH(cdata->in->update_domain.rem_status)
		c_status_rem->_buffer[i++] = CORBA_string_dup(
				CL_CONTENT(cdata->in->update_domain.rem_status));
	c_ext_list = ccReg_ExtensionList__alloc();
	/* fill extension list if needed */
	if (cdata->in->create_domain.valExDate != 0) {
		ccReg_ENUMValidationExtension	*c_enumval;

		c_enumval = ccReg_ENUMValidationExtension__alloc();
		c_enumval->valExDate = cdata->in->update_domain.valExDate;
		c_ext_list->_buffer = ccReg_ExtensionList_allocbuf(1);
		c_ext_list->_maximum = c_ext_list->_length = 1;
		c_ext_list->_release = CORBA_TRUE;
		c_ext_list->_buffer[0]._type = TC_ccReg_ENUMValidationExtension;
		c_ext_list->_buffer[0]._value = c_enumval;
		c_ext_list->_buffer[0]._release = CORBA_TRUE;
	}

	/* send the updates to repository */
	response = ccReg_EPP_DomainUpdate(globs->service,
			cdata->in->update_domain.name,
			cdata->in->update_domain.registrant,
			cdata->in->update_domain.authInfo,
			cdata->in->update_domain.nsset,
			c_admin_add,
			c_admin_rem,
			c_status_add,
			c_status_rem,
			session,
			cdata->clTRID,
			cdata->xml_in,
			c_ext_list,
			ev);

	CORBA_free(c_status_rem);
	CORBA_free(c_status_add);
	CORBA_free(c_admin_rem);
	CORBA_free(c_admin_add);
	CORBA_free(c_ext_list);

	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		CORBA_exception_free(ev);
		return CORBA_ERROR;
	}
	CORBA_exception_free(ev);

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		CORBA_free(response);
		return CORBA_REMOTE_ERROR;
	}

	get_errors(cdata->errors, &response->errors);
	cdata->svTRID = strdup(response->svTRID);
	cdata->msg = strdup(response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);
	return CORBA_OK;
}

/**
 * EPP update contact.
 *
 * @param globs Corba context.
 * @param session Session identifier.
 * @param cdata Data from xml request.
 * @return status (see #corba_status).
 */
static corba_status
epp_call_update_contact(epp_corba_globs *globs, int session,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	ccReg_Response *response;
	ccReg_Status	*c_status_add;
	ccReg_Status	*c_status_rem;
	ccReg_ContactChange	*c_contact;
	int	i, len;

	assert(cdata->in != NULL);
	CORBA_exception_init(ev);

	/* status add */
	c_status_add = ccReg_Status__alloc();
	len = cl_length(cdata->in->update_contact.add_status);
	c_status_add->_buffer = ccReg_Status_allocbuf(len);
	c_status_add->_maximum = c_status_add->_length = len;
	c_status_add->_release = CORBA_TRUE;
	i = 0;
	CL_FOREACH(cdata->in->update_contact.add_status)
		c_status_add->_buffer[i++] = CORBA_string_dup(
				CL_CONTENT(cdata->in->update_contact.add_status));
	/* status rem */
	c_status_rem = ccReg_Status__alloc();
	len = cl_length(cdata->in->update_contact.rem_status);
	c_status_rem->_buffer = ccReg_Status_allocbuf(len);
	c_status_rem->_maximum = c_status_rem->_length = len;
	c_status_rem->_release = CORBA_TRUE;
	i = 0;
	CL_FOREACH(cdata->in->update_contact.rem_status)
		c_status_rem->_buffer[i++] = CORBA_string_dup(
				CL_CONTENT(cdata->in->update_contact.rem_status));
	/* c_contact */
	c_contact = ccReg_ContactChange__alloc();
	c_contact->Name =
		CORBA_string_dup(cdata->in->update_contact.postalInfo->name);
	c_contact->Organization =
		CORBA_string_dup(cdata->in->update_contact.postalInfo->org);
	c_contact->Street1 =
		CORBA_string_dup(cdata->in->update_contact.postalInfo->street[0]);
	c_contact->Street2 =
		CORBA_string_dup(cdata->in->update_contact.postalInfo->street[1]);
	c_contact->Street3 =
		CORBA_string_dup(cdata->in->update_contact.postalInfo->street[2]);
	c_contact->City =
		CORBA_string_dup(cdata->in->update_contact.postalInfo->city);
	c_contact->StateOrProvince =
		CORBA_string_dup(cdata->in->update_contact.postalInfo->sp);
	c_contact->PostalCode =
		CORBA_string_dup(cdata->in->update_contact.postalInfo->pc);
	c_contact->CC =
		CORBA_string_dup(cdata->in->update_contact.postalInfo->cc);
	c_contact->Telephone = CORBA_string_dup(cdata->in->update_contact.voice);
	c_contact->Fax = CORBA_string_dup(cdata->in->update_contact.fax);
	c_contact->Email = CORBA_string_dup(cdata->in->update_contact.email);
	c_contact->NotifyEmail =
		CORBA_string_dup(cdata->in->update_contact.notify_email);
	c_contact->VAT = CORBA_string_dup(cdata->in->update_contact.vat);
	c_contact->SSN = CORBA_string_dup(cdata->in->update_contact.ssn);
	c_contact->DiscloseName = cdata->in->update_contact.discl->name;
	c_contact->DiscloseOrganization = cdata->in->update_contact.discl->org;
	c_contact->DiscloseAddress = cdata->in->update_contact.discl->addr;
	c_contact->DiscloseTelephone = cdata->in->update_contact.discl->voice;
	c_contact->DiscloseFax = cdata->in->update_contact.discl->fax;
	c_contact->DiscloseEmail = cdata->in->update_contact.discl->email;

	/* send the updates to repository */
	response = ccReg_EPP_ContactUpdate(globs->service,
			cdata->in->update_contact.id,
			c_contact,
			c_status_add,
			c_status_rem,
			session,
			cdata->clTRID,
			cdata->xml_in,
			ev);

	CORBA_free(c_status_rem);
	CORBA_free(c_status_add);
	CORBA_free(c_contact);

	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		CORBA_exception_free(ev);
		return CORBA_ERROR;
	}
	CORBA_exception_free(ev);

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		CORBA_free(response);
		return CORBA_REMOTE_ERROR;
	}

	get_errors(cdata->errors, &response->errors);
	cdata->svTRID = strdup(response->svTRID);
	cdata->msg = strdup(response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);
	return CORBA_OK;
}

/**
 * EPP update nsset.
 *
 * @param globs Corba context.
 * @param session Session identifier.
 * @param cdata Data from xml request.
 * @return status (see #corba_status).
 */
static corba_status
epp_call_update_nsset(epp_corba_globs *globs, int session,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	ccReg_Response *response;
	ccReg_DNSHost	*c_dnshost_add;
	ccReg_DNSHost	*c_dnshost_rem;
	ccReg_TechContact	*c_tech_add;
	ccReg_TechContact	*c_tech_rem;
	ccReg_Status	*c_status_add;
	ccReg_Status	*c_status_rem;
	epp_ns	*ns;
	int	i, j, len;

	assert(cdata->in != NULL);
	CORBA_exception_init(ev);

	/* tech add */
	c_tech_add = ccReg_TechContact__alloc();
	len = cl_length(cdata->in->update_nsset.add_tech);
	c_tech_add->_buffer = ccReg_TechContact_allocbuf(len);
	c_tech_add->_maximum = c_tech_add->_length = len;
	c_tech_add->_release = CORBA_TRUE;
	i = 0;
	CL_FOREACH(cdata->in->update_nsset.add_tech)
		c_tech_add->_buffer[i++] = CORBA_string_dup(
				CL_CONTENT(cdata->in->update_nsset.add_tech));
	/* Tech rem */
	c_tech_rem = ccReg_TechContact__alloc();
	len = cl_length(cdata->in->update_nsset.rem_tech);
	c_tech_rem->_buffer = ccReg_TechContact_allocbuf(len);
	c_tech_rem->_maximum = c_tech_rem->_length = len;
	c_tech_rem->_release = CORBA_TRUE;
	i = 0;
	CL_FOREACH(cdata->in->update_nsset.rem_tech)
		c_tech_rem->_buffer[i++] = CORBA_string_dup(
				CL_CONTENT(cdata->in->update_nsset.rem_tech));
	/* status add */
	c_status_add = ccReg_Status__alloc();
	len = cl_length(cdata->in->update_nsset.add_status);
	c_status_add->_buffer = ccReg_Status_allocbuf(len);
	c_status_add->_maximum = c_status_add->_length = len;
	c_status_add->_release = CORBA_TRUE;
	i = 0;
	CL_FOREACH(cdata->in->update_nsset.add_status)
		c_status_add->_buffer[i++] = CORBA_string_dup(
				CL_CONTENT(cdata->in->update_nsset.add_status));
	/* status rem */
	c_status_rem = ccReg_Status__alloc();
	len = cl_length(cdata->in->update_nsset.rem_status);
	c_status_rem->_buffer = ccReg_Status_allocbuf(len);
	c_status_rem->_maximum = c_status_rem->_length = len;
	c_status_rem->_release = CORBA_TRUE;
	i = 0;
	CL_FOREACH(cdata->in->update_nsset.rem_status)
		c_status_rem->_buffer[i++] = CORBA_string_dup(
				CL_CONTENT(cdata->in->update_nsset.rem_status));
	/* name servers add */
	c_dnshost_add = ccReg_DNSHost__alloc();
	len = cl_length(cdata->in->update_nsset.add_ns);
	c_dnshost_add->_buffer = ccReg_DNSHost_allocbuf(len);
	c_dnshost_add->_maximum = c_dnshost_add->_length = len;
	c_dnshost_add->_release = CORBA_TRUE;
	i = 0;
	CL_FOREACH(cdata->in->update_nsset.add_ns) {
		/* alloc & init sequence of ns's addresses */
		ns = (epp_ns *) CL_CONTENT(cdata->in->update_nsset.add_ns);
		len = cl_length(ns->addr);
		c_dnshost_add->_buffer[i].inet._buffer = ccReg_InetAddress_allocbuf(len);
		c_dnshost_add->_buffer[i].inet._maximum =
			c_dnshost_add->_buffer[i].inet._length = len;
		c_dnshost_add->_buffer[i].inet._release = CORBA_TRUE;
		j = 0;
		CL_FOREACH(ns->addr)
			c_dnshost_add->_buffer[i].inet._buffer[j++] =
					CORBA_string_dup(CL_CONTENT(ns->addr));
		c_dnshost_add->_buffer[i++].fqdn = CORBA_string_dup(ns->name);
	}
	/* name servers rem */
	c_dnshost_rem = ccReg_DNSHost__alloc();
	len = cl_length(cdata->in->update_nsset.rem_ns);
	c_dnshost_rem->_buffer = ccReg_DNSHost_allocbuf(len);
	c_dnshost_rem->_maximum = c_dnshost_rem->_length = len;
	c_dnshost_rem->_release = CORBA_TRUE;
	i = 0;
	CL_FOREACH(cdata->in->update_nsset.rem_ns) {
		/* alloc & init sequence of ns's addresses */
		c_dnshost_rem->_buffer[i++].fqdn =
			CORBA_string_dup(CL_CONTENT(cdata->in->update_nsset.rem_ns));
	}

	/* send the updates to repository */
	response = ccReg_EPP_NSSetUpdate(globs->service,
			cdata->in->update_nsset.id,
			cdata->in->update_nsset.authInfo,
			c_dnshost_add,
			c_dnshost_rem,
			c_tech_add,
			c_tech_rem,
			c_status_add,
			c_status_rem,
			session,
			cdata->clTRID,
			cdata->xml_in,
			ev);

	CORBA_free(c_status_rem);
	CORBA_free(c_status_add);
	CORBA_free(c_tech_rem);
	CORBA_free(c_tech_add);
	CORBA_free(c_dnshost_rem);
	CORBA_free(c_dnshost_add);

	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		CORBA_exception_free(ev);
		return CORBA_ERROR;
	}
	CORBA_exception_free(ev);

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		CORBA_free(response);
		return CORBA_REMOTE_ERROR;
	}

	get_errors(cdata->errors, &response->errors);
	cdata->svTRID = strdup(response->svTRID);
	cdata->msg = strdup(response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);
	return CORBA_OK;
}

/**
 * EPP transfer for domain and nsset is so similar that it is worth of
 * having the code in one function and pass object type as parameter.
 *
 * @param globs Corba context.
 * @param session Session identifier.
 * @param cdata Data from xml request.
 * @param obj Object type (see #epp_object_type)
 * @return status (see #corba_status).
 */
static corba_status
epp_call_transfer(epp_corba_globs *globs, int session,
		epp_command_data *cdata, epp_object_type obj)
{
	CORBA_Environment ev[1];
	ccReg_Response *response;

	CORBA_exception_init(ev);

	if (obj == EPP_DOMAIN) {
		response = ccReg_EPP_DomainTransfer(globs->service,
				cdata->in->transfer.id,
				cdata->in->transfer.authInfo,
				session,
				cdata->clTRID,
				cdata->xml_in,
				ev);
	}
	else {
		assert(obj == EPP_NSSET);
		response = ccReg_EPP_NSSetTransfer(globs->service,
				cdata->in->transfer.id,
				cdata->in->transfer.authInfo,
				session,
				cdata->clTRID,
				cdata->xml_in,
				ev);
	}

	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		CORBA_exception_free(ev);
		return CORBA_ERROR;
	}
	CORBA_exception_free(ev);

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		CORBA_free(response);
		return CORBA_REMOTE_ERROR;
	}

	get_errors(cdata->errors, &response->errors);
	cdata->svTRID = strdup(response->svTRID);
	cdata->msg = strdup(response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);
	return CORBA_OK;
}

corba_status
epp_call_cmd(epp_corba_globs *globs, int session, epp_command_data *cdata)
{
	corba_status	cstat;

	switch (cdata->type) {
		case EPP_DUMMY:
			cstat = epp_call_dummy(globs, session, cdata);
			break;
		case EPP_CHECK_CONTACT:
			cstat = epp_call_check(globs, session, cdata, EPP_CONTACT);
			break;
		case EPP_CHECK_DOMAIN:
			cstat = epp_call_check(globs, session, cdata, EPP_DOMAIN);
			break;
		case EPP_CHECK_NSSET:
			cstat = epp_call_check(globs, session, cdata, EPP_NSSET);
			break;
		case EPP_INFO_CONTACT:
			cstat = epp_call_info_contact(globs, session, cdata);
			break;
		case EPP_INFO_DOMAIN:
			cstat = epp_call_info_domain(globs, session, cdata);
			break;
		case EPP_INFO_NSSET:
			cstat = epp_call_info_nsset(globs, session, cdata);
			break;
		case EPP_POLL_REQ:
			cstat = epp_call_poll_req(globs, session, cdata);
			break;
		case EPP_POLL_ACK:
			cstat = epp_call_poll_ack(globs, session, cdata);
			break;
		case EPP_CREATE_CONTACT:
			cstat = epp_call_create_contact(globs, session, cdata);
			break;
		case EPP_CREATE_DOMAIN:
			cstat = epp_call_create_domain(globs, session, cdata);
			break;
		case EPP_CREATE_NSSET:
			cstat = epp_call_create_nsset(globs, session, cdata);
			break;
		case EPP_DELETE_CONTACT:
			cstat = epp_call_delete(globs, session, cdata, EPP_CONTACT);
			break;
		case EPP_DELETE_DOMAIN:
			cstat = epp_call_delete(globs, session, cdata, EPP_DOMAIN);
			break;
		case EPP_DELETE_NSSET:
			cstat = epp_call_delete(globs, session, cdata, EPP_NSSET);
			break;
		case EPP_RENEW_DOMAIN:
			cstat = epp_call_renew_domain(globs, session, cdata);
			break;
		case EPP_UPDATE_DOMAIN:
			cstat = epp_call_update_domain(globs, session, cdata);
			break;
		case EPP_UPDATE_CONTACT:
			cstat = epp_call_update_contact(globs, session, cdata);
			break;
		case EPP_UPDATE_NSSET:
			cstat = epp_call_update_nsset(globs, session, cdata);
			break;
		case EPP_TRANSFER_DOMAIN:
			cstat = epp_call_transfer(globs, session, cdata, EPP_DOMAIN);
			break;
		case EPP_TRANSFER_NSSET:
			cstat = epp_call_transfer(globs, session, cdata, EPP_NSSET);
			break;
		default:
			cstat = CORBA_INT_ERROR;
			break;
	}

	return cstat;
}
