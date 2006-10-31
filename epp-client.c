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

/**
 * Persistent structure initialized at startup, needed for corba function calls.
 */
struct epp_corba_globs_t {
	CORBA_ORB	corba;	/**< corba is global corba object. */
	ccReg_EPP	service;/**< service is ccReg object stub */
};

epp_corba_globs *
epp_corba_init(const char *ns_loc, const char *obj_name)
{
	CORBA_ORB  global_orb = CORBA_OBJECT_NIL;	/* global orb */
	ccReg_EPP service = CORBA_OBJECT_NIL;	/* object's stub */
	epp_corba_globs	*globs;	/* used to store global_orb and service */
	CORBA_Environment ev[1];
	CosNaming_NamingContext ns; /* used for nameservice */
	CosNaming_NameComponent *name_component; /* EPP's name */
	CosNaming_Name *cos_name; /* Cos name used in service lookup */
	char ns_string[150];
 
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
 */
static void get_errors(void *pool,
		struct circ_list *errors,
		ccReg_Error *c_errors)
{
	struct circ_list	*item;
	epp_error	*err_item;
	int	i;
	ccReg_Error_seq *c_error;
	CORBA_Environment ev[1];

	CORBA_exception_init(ev);

	/* process all errors one by one */
	for (i = 0; i < c_errors->_length; i++) {
		if ((item = epp_malloc(pool, sizeof *item)) == NULL ||
			(err_item = epp_malloc(pool, sizeof *err_item)) == NULL)
		{
			break;
		}
		c_error = &c_errors->_buffer[i];
		err_item->reason = epp_strdup(pool, c_error->reason);
		err_item->standalone = 0; /* the surrounding tags are missing */

		/* convert "any" type (short, long, string) to string */
		if (CORBA_TypeCode_equal(c_error->value._type, TC_CORBA_string, ev))
			err_item->value = epp_strdup(pool,
					* ((char **) c_error->value._value));
		else if (CORBA_TypeCode_equal(c_error->value._type, TC_CORBA_long, ev))
		{
			err_item->value = epp_malloc(pool, 10); /* should be enough for any number */
			snprintf(err_item->value, 10, "%ld",
					*((long *) c_error->value._value));
		}
		else if (CORBA_TypeCode_equal(c_error->value._type, TC_CORBA_short, ev))
		{
			err_item->value = epp_malloc(pool, 10); /* should be enough for any number */
			snprintf(err_item->value, 10, "%d",
					*((short *) c_error->value._value));
		}
		else
			err_item->value = epp_strdup(pool, "Unknown value type");

		/* convert error code */
		switch (c_error->code) {
			case ccReg_pollAck_msgID:
				err_item->spec = errspec_pollAck_msgID;
				break;
			case ccReg_contactInfo_handle:
				err_item->spec = errspec_contactInfo_handle;
				break;
			case ccReg_contactCreate_cc:
				err_item->spec = errspec_contactCreate_cc;
				break;
			case ccReg_contactCreate_handle:
				err_item->spec = errspec_contactCreate_handle;
				break;
			case ccReg_contactUpdate_cc:
				err_item->spec = errspec_contactUpdate_cc;
				break;
			case ccReg_contactUpdate_status_add:
				err_item->spec = errspec_contactUpdate_status_add;
				break;
			case ccReg_contactUpdate_status_rem:
				err_item->spec = errspec_contactUpdate_status_rem;
				break;
			case ccReg_nssetInfo_handle:
				err_item->spec = errspec_nssetInfo_handle;
				break;
			case ccReg_nssetCreate_handle:
				err_item->spec = errspec_nssetCreate_handle;
				break;
			case ccReg_nssetCreate_ns_name:
				err_item->spec = errspec_nssetCreate_ns_name;
				break;
			case ccReg_nssetCreate_ns_addr:
				err_item->spec = errspec_nssetCreate_ns_addr;
				break;
			case ccReg_nssetCreate_tech:
				err_item->spec = errspec_nssetCreate_tech;
				break;
			case ccReg_nssetUpdate_status_add:
				err_item->spec = errspec_nssetUpdate_status_add;
				break;
			case ccReg_nssetUpdate_status_rem:
				err_item->spec = errspec_nssetUpdate_status_rem;
				break;
			case ccReg_nssetUpdate_tech_add:
				err_item->spec = errspec_nssetUpdate_tech_add;
				break;
			case ccReg_nssetUpdate_tech_rem:
				err_item->spec = errspec_nssetUpdate_tech_rem;
				break;
			case ccReg_nssetUpdate_ns_name_add:
				err_item->spec = errspec_nssetUpdate_ns_name_add;
				break;
			case ccReg_nssetUpdate_ns_name_rem:
				err_item->spec = errspec_nssetUpdate_ns_name_rem;
				break;
			case ccReg_nssetUpdate_ns_addr_add:
				err_item->spec = errspec_nssetUpdate_ns_addr_add;
				break;
			case ccReg_nssetUpdate_ns_addr_rem:
				err_item->spec = errspec_nssetUpdate_ns_addr_rem;
				break;
			case ccReg_domainInfo_fqdn:
				err_item->spec = errspec_domainInfo_fqdn;
				break;
			case ccReg_domainCreate_fqdn:
				err_item->spec = errspec_domainCreate_fqdn;
				break;
			case ccReg_domainCreate_registrant:
				err_item->spec = errspec_domainCreate_registrant;
				break;
			case ccReg_domainCreate_nsset:
				err_item->spec = errspec_domainCreate_nsset;
				break;
			case ccReg_domainCreate_period:
				err_item->spec = errspec_domainCreate_period;
				break;
			case ccReg_domainCreate_admin:
				err_item->spec = errspec_domainCreate_admin;
				break;
			case ccReg_domainCreate_ext_valDate:
				err_item->spec = errspec_domainCreate_ext_valdate;
				break;
			case ccReg_domainUpdate_registrant:
				err_item->spec = errspec_domainUpdate_registrant;
				break;
			case ccReg_domainUpdate_nsset:
				err_item->spec = errspec_domainUpdate_nsset;
				break;
			case ccReg_domainUpdate_admin_add:
				err_item->spec = errspec_domainUpdate_admin_add;
				break;
			case ccReg_domainUpdate_admin_rem:
				err_item->spec = errspec_domainUpdate_admin_rem;
				break;
			case ccReg_domainUpdate_status_add:
				err_item->spec = errspec_domainUpdate_status_add;
				break;
			case ccReg_domainUpdate_status_rem:
				err_item->spec = errspec_domainUpdate_status_rem;
				break;
			case ccReg_domainUpdate_ext_valDate:
				err_item->spec = errspec_domainUpdate_ext_valdate;
				break;
			case ccReg_domainRenew_curExpDate:
				err_item->spec = errspec_domainRenew_curExpDate;
				break;
			case ccReg_domainRenew_period:
				err_item->spec = errspec_domainRenew_period;
				break;
			case ccReg_domainRenew_ext_valDate:
				err_item->spec = errspec_domainRenew_ext_valDate;
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
epp_call_hello(void *pool,
		epp_corba_globs *globs,
		char **version,
		char **curdate)
{
	CORBA_Environment ev[1];
	CORBA_char	*c_version;
	CORBA_char	*c_curdate;
	int	retr;

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		c_version = ccReg_EPP_version(globs->service, &c_curdate, ev);

		/* if COMM_FAILURE exception is not raised then quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

	if (raised_exception(ev)) {
		CORBA_exception_free(ev);
		return 0;
	}
	CORBA_exception_free(ev);

	*version = epp_strdup(pool, c_version);
	*curdate = epp_strdup(pool, c_curdate);

	CORBA_free(c_version);
	CORBA_free(c_curdate);
	return 1;
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
	ccReg_Response	*response;
	int	retr;

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		response = ccReg_EPP_GetTransaction(globs->service,
				session,
				cdata->clTRID,
				cdata->rc,
				ev);

		/* if COMM_FAILURE exception is not raised then quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
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

	get_errors(pool, cdata->errors, &response->errors);
	cdata->svTRID = epp_strdup(pool, response->svTRID);
	cdata->msg = epp_strdup(pool, response->errMsg);
	/* rc is known */

	CORBA_free(response);
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
	ccReg_Languages	c_lang;
	ccReg_Response *response;
	int	retr;

	c_lang = (cdata->in->login.lang == LANG_EN) ? ccReg_EN : ccReg_CS;

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

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

		/* if COMM_FAILURE exception is not raised then quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

	/* if it is exception then return */
	if (raised_exception(ev)) {
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

	get_errors(pool, cdata->errors, &response->errors);
	cdata->svTRID = epp_strdup(pool, response->svTRID);
	cdata->msg = epp_strdup(pool, response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);

	if (cdata->rc == 1000) {
		*session = c_session;
		*lang = cdata->in->login.lang;
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
	ccReg_Response *response;
	int	retr;

	*logout = 0;
	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		response = ccReg_EPP_ClientLogout(globs->service,
				session,
				cdata->clTRID,
				cdata->xml_in,
				ev);

		/* if COMM_FAILURE exception is not raised then quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

	if (raised_exception(ev)) {
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

	get_errors(pool, cdata->errors, &response->errors);
	cdata->svTRID = epp_strdup(pool, response->svTRID);
	cdata->msg = epp_strdup(pool, response->errMsg);
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
	ccReg_CheckResp	*c_avails;
	ccReg_Check	*c_ids;
	ccReg_Response *response;
	struct circ_list	*item;
	int	len, i;
	int	retr;

	/* get number of contacts */
	len = cl_length(cdata->in->check.ids);
	c_ids = ccReg_Check__alloc();
	c_ids->_buffer = ccReg_Check_allocbuf(len);
	c_ids->_maximum = c_ids->_length = len;
	c_ids->_release = CORBA_TRUE;

	/* copy each requested object in corba buffer */
	i = 0;
	CL_FOREACH(cdata->in->check.ids)
		c_ids->_buffer[i++] = CORBA_string_dup(
				CL_CONTENT(cdata->in->check.ids));

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		if (obj == EPP_CONTACT)
			response = ccReg_EPP_ContactCheck(globs->service,
					c_ids,
					&c_avails,
					session,
					cdata->clTRID,
					cdata->xml_in,
					ev);
		else if (obj == EPP_DOMAIN)
			response = ccReg_EPP_DomainCheck(globs->service,
					c_ids,
					&c_avails,
					session,
					cdata->clTRID,
					cdata->xml_in,
					ev);
		else {
			assert(obj == EPP_NSSET);
			response = ccReg_EPP_NSSetCheck(globs->service,
					c_ids,
					&c_avails,
					session,
					cdata->clTRID,
					cdata->xml_in,
					ev);
		}

		/* if COMM_FAILURE exception is not raised then quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

	CORBA_free(c_ids);

	if (raised_exception(ev)) {
		CORBA_exception_free(ev);
		return CORBA_ERROR;
	}
	CORBA_exception_free(ev);

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		CORBA_free(c_avails);
		CORBA_free(response);
		return CORBA_REMOTE_ERROR;
	}

	/* alloc necessary structures */
	if (!(cdata->out = epp_calloc(pool, sizeof (*cdata->out)))
		|| !(cdata->out->check.avails = epp_malloc(pool, sizeof *item)))
	{
		CORBA_free(c_avails);
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}
	CL_NEW(cdata->out->check.avails);

	/*
	 * length of results returned should be same as lenght of input
	 * objects
	 */
	assert(len == c_avails->_length); /* XXX change this in production release */
	/*
	 * circular list stores items in reversed order.
	 * Therefore we have reverse processing order of items in
	 * c_avails->_buffer array
	 */
	for (i = c_avails->_length - 1; i >= 0; i--) {
		epp_avail	*avail;

		if ((item = epp_malloc(pool, sizeof *item)) == NULL ||
			(avail = epp_malloc(pool, sizeof *avail)) == NULL)
		{
			break;
		}
		avail->avail =
			(c_avails->_buffer[i].avail == ccReg_NotExist) ? 1 : 0;
		avail->reason = epp_strdup(pool, c_avails->_buffer[i].reason);
		if (avail->avail) assert(*avail->reason == '\0');
		CL_CONTENT(item) = (void *) avail;
		CL_ADD(cdata->out->check.avails, item);
	}
	CORBA_free(c_avails);

	/* handle situation when item allocation above failed */
	if (i > 0) {
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}

	get_errors(pool, cdata->errors, &response->errors);
	cdata->svTRID = epp_strdup(pool, response->svTRID);
	cdata->msg = epp_strdup(pool, response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);
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
	ccReg_Contact	*c_contact;
	ccReg_Response	*response;
	epp_postalInfo	*pi;
	epp_discl	*discl;
	struct circ_list	*item;
	int	i, retr;

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		/* get information about contact from central repository */
		response = ccReg_EPP_ContactInfo(globs->service,
				cdata->in->info.id,
				&c_contact,
				session,
				cdata->clTRID,
				cdata->xml_in,
				ev);


		/* if COMM_FAILURE exception is not raised then quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

	if (raised_exception(ev)) {
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
	if (!(cdata->out = epp_calloc(pool, sizeof (*cdata->out)))
		|| !(cdata->out->info_contact.postalInfo =
			epp_calloc(pool, sizeof *pi))
		|| !(cdata->out->info_contact.discl =
			epp_calloc(pool, sizeof *discl))
		|| !(cdata->out->info_contact.status =
			epp_malloc(pool, sizeof *item)))
	{
		CORBA_free(c_contact);
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}

	/* ok, now everything was successfully allocated */
	cdata->out->info_contact.roid = epp_strdup(pool, c_contact->ROID);
	cdata->out->info_contact.handle = epp_strdup(pool, c_contact->handle);
	cdata->out->info_contact.authInfo = epp_strdup(pool, c_contact->AuthInfoPw);
	cdata->out->info_contact.clID = epp_strdup(pool, c_contact->ClID);
	cdata->out->info_contact.crID = epp_strdup(pool, c_contact->CrID);
	cdata->out->info_contact.upID = epp_strdup(pool, c_contact->UpID);
	cdata->out->info_contact.crDate = epp_strdup(pool, c_contact->CrDate);
	cdata->out->info_contact.upDate = epp_strdup(pool, c_contact->UpDate);
	cdata->out->info_contact.trDate = epp_strdup(pool, c_contact->TrDate);
	/* contact status */
	CL_NEW(cdata->out->info_contact.status);
	for (i = 0; i < c_contact->stat._length; i++) {
		item = epp_malloc(pool, sizeof *item);
		CL_CONTENT(item) =
			(void *) epp_strdup(pool, c_contact->stat._buffer[i]);
		CL_ADD(cdata->out->info_contact.status, item);
	}
	/* postal info */
	pi = cdata->out->info_contact.postalInfo;
	pi->name = epp_strdup(pool, c_contact->Name);
	pi->org = epp_strdup(pool, c_contact->Organization);
	pi->street[0] = epp_strdup(pool, c_contact->Street1);
	pi->street[1] = epp_strdup(pool, c_contact->Street2);
	pi->street[2] = epp_strdup(pool, c_contact->Street3);
	pi->city = epp_strdup(pool, c_contact->City);
	pi->sp = epp_strdup(pool, c_contact->StateOrProvince);
	pi->pc = epp_strdup(pool, c_contact->PostalCode);
	pi->cc = epp_strdup(pool, c_contact->CountryCode);
	/* other attributes */
	cdata->out->info_contact.voice = epp_strdup(pool, c_contact->Telephone);
	cdata->out->info_contact.fax = epp_strdup(pool, c_contact->Fax);
	cdata->out->info_contact.email = epp_strdup(pool, c_contact->Email);
	cdata->out->info_contact.notify_email =
		epp_strdup(pool, c_contact->NotifyEmail);
	cdata->out->info_contact.vat = epp_strdup(pool, c_contact->VAT);
	cdata->out->info_contact.ssn = epp_strdup(pool, c_contact->SSN);
	/* convert ssntype from idl's enum to our enum */
	switch (c_contact->SSNtype) {
		case ccReg_RC:
			cdata->out->info_contact.ssntype = SSN_RC;
			break;
		case ccReg_OP:
			cdata->out->info_contact.ssntype = SSN_OP;
			break;
		case ccReg_PASS:
			cdata->out->info_contact.ssntype = SSN_PASSPORT;
			break;
		case ccReg_MPSV:
			cdata->out->info_contact.ssntype = SSN_MPSV;
			break;
		case ccReg_ICO:
			cdata->out->info_contact.ssntype = SSN_ICO;
			break;
		default:
			cdata->out->info_contact.ssntype = SSN_UNKNOWN;
			break;
	}
	/* disclose info */
	discl = cdata->out->info_contact.discl;
	if (c_contact->DiscloseFlag == ccReg_DISCL_HIDE)
		discl->flag = 0;
	else if (c_contact->DiscloseFlag == ccReg_DISCL_DISPLAY)
		discl->flag = 1;
	else discl->flag = -1;
	/* init discl values only if there is exceptional behaviour */
	if (discl->flag != -1) {
		discl->name = (c_contact->DiscloseName == CORBA_TRUE) ? 1 : 0;
		discl->org = (c_contact->DiscloseOrganization == CORBA_TRUE) ? 1 : 0;
		discl->addr = (c_contact->DiscloseAddress == CORBA_TRUE) ? 1 : 0;
		discl->voice = (c_contact->DiscloseTelephone == CORBA_TRUE) ? 1 : 0;
		discl->fax = (c_contact->DiscloseFax == CORBA_TRUE) ? 1 : 0;
		discl->email = (c_contact->DiscloseEmail == CORBA_TRUE) ? 1 : 0;
	}

	CORBA_free(c_contact);

	get_errors(pool, cdata->errors, &response->errors);
	cdata->svTRID = epp_strdup(pool, response->svTRID);
	cdata->msg = epp_strdup(pool, response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);
	return CORBA_OK;
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
	ccReg_Response	*response;
	ccReg_Domain	*c_domain;
	struct circ_list	*item;
	int	i, retr;

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		/* get information about domain */
		response = ccReg_EPP_DomainInfo(globs->service,
				cdata->in->info.id,
				&c_domain,
				session,
				cdata->clTRID,
				cdata->xml_in,
				ev);

		/* if COMM_FAILURE exception is not raised then quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

	if (raised_exception(ev)) {
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
	if (!(cdata->out = epp_calloc(pool, sizeof (*cdata->out)))
		|| !(cdata->out->info_domain.status =
			epp_malloc(pool, sizeof *item))
		|| !(cdata->out->info_domain.admin =
			epp_malloc(pool, sizeof *item))
		|| !(cdata->out->info_domain.ds =
			epp_malloc(pool, sizeof *item)))
	{
		CORBA_free(c_domain);
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}

	/* ok, now everything was successfully allocated */
	cdata->out->info_domain.roid   = epp_strdup(pool, c_domain->ROID);
	cdata->out->info_domain.handle = epp_strdup(pool, c_domain->name);
	cdata->out->info_domain.clID   = epp_strdup(pool, c_domain->ClID);
	cdata->out->info_domain.crID   = epp_strdup(pool, c_domain->CrID);
	cdata->out->info_domain.upID   = epp_strdup(pool, c_domain->UpID);
	cdata->out->info_domain.crDate = epp_strdup(pool, c_domain->CrDate);
	cdata->out->info_domain.upDate = epp_strdup(pool, c_domain->UpDate);
	cdata->out->info_domain.trDate = epp_strdup(pool, c_domain->TrDate);
	cdata->out->info_domain.exDate = epp_strdup(pool, c_domain->ExDate);
	cdata->out->info_domain.registrant = epp_strdup(pool,
			c_domain->Registrant);
	cdata->out->info_domain.nsset  = epp_strdup(pool, c_domain->nsset);
	cdata->out->info_domain.authInfo = epp_strdup(pool,
			c_domain->AuthInfoPw);

	/* allocate and initialize status, admin lists */
	CL_NEW(cdata->out->info_domain.status);
	for (i = 0; i < c_domain->stat._length; i++) {
		item = epp_malloc(pool, sizeof *item);
		CL_CONTENT(item) =
			(void *) epp_strdup(pool, c_domain->stat._buffer[i]);
		CL_ADD(cdata->out->info_domain.status, item);
	}
	CL_NEW(cdata->out->info_domain.admin);
	for (i = 0; i < c_domain->admin._length; i++) {
		item = epp_malloc(pool, sizeof *item);
		CL_CONTENT(item) =
			(void *) epp_strdup(pool, c_domain->admin._buffer[i]);
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

			cdata->out->info_domain.valExDate =
				epp_strdup(pool, c_enumval->valExDate);
		}
	}
	/* if valExDate was not given, then fill it with empty value */
	if (cdata->out->info_domain.valExDate == NULL)
		cdata->out->info_domain.valExDate = epp_strdup(pool, "");

	CORBA_free(c_domain);

	get_errors(pool, cdata->errors, &response->errors);
	cdata->svTRID = epp_strdup(pool, response->svTRID);
	cdata->msg = epp_strdup(pool, response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);
	return CORBA_OK;
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
	ccReg_NSSet	*c_nsset;
	ccReg_Response	*response;
	struct circ_list	*item;
	int i, j, retr;

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		/* get information about nsset */
		response = ccReg_EPP_NSSetInfo(globs->service,
				cdata->in->info.id,
				&c_nsset,
				session,
				cdata->clTRID,
				cdata->xml_in,
				ev);

		/* if COMM_FAILURE exception is not raised then quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

	if (raised_exception(ev)) {
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
	if (!(cdata->out = epp_calloc(pool, sizeof (*cdata->out)))
		|| !(cdata->out->info_nsset.status =
				epp_malloc(pool, sizeof *item))
		|| !(cdata->out->info_nsset.ns =
				epp_malloc(pool, sizeof *item))
		|| !(cdata->out->info_nsset.tech =
				epp_malloc(pool, sizeof *item)))
	{
		CORBA_free(c_nsset);
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}

	/* ok, now alomost everything was successfully allocated */
	cdata->out->info_nsset.roid   = epp_strdup(pool, c_nsset->ROID);
	cdata->out->info_nsset.handle = epp_strdup(pool, c_nsset->handle);
	cdata->out->info_nsset.clID   = epp_strdup(pool, c_nsset->ClID);
	cdata->out->info_nsset.crID   = epp_strdup(pool, c_nsset->CrID);
	cdata->out->info_nsset.upID   = epp_strdup(pool, c_nsset->UpID);
	cdata->out->info_nsset.crDate = epp_strdup(pool, c_nsset->CrDate);
	cdata->out->info_nsset.upDate = epp_strdup(pool, c_nsset->UpDate);
	cdata->out->info_nsset.trDate = epp_strdup(pool, c_nsset->TrDate);
	cdata->out->info_nsset.authInfo = epp_strdup(pool, c_nsset->AuthInfoPw);

	/* allocate and initialize status list */
	CL_NEW(cdata->out->info_nsset.status);
	for (i = 0; i < c_nsset->stat._length; i++) {
		item = epp_malloc(pool, sizeof *item);
		CL_CONTENT(item) =
			(void *) epp_strdup(pool, c_nsset->stat._buffer[i]);
		CL_ADD(cdata->out->info_nsset.status, item);
	}
	/* allocate and initialize tech list */
	CL_NEW(cdata->out->info_nsset.tech);
	for (i = 0; i < c_nsset->tech._length; i++) {
		item = epp_malloc(pool, sizeof *item);
		CL_CONTENT(item) =
			(void *) epp_strdup(pool, c_nsset->tech._buffer[i]);
		CL_ADD(cdata->out->info_nsset.tech, item);
	}
	/*
	 * allocate and initialize required number of ns items
	 */
	CL_NEW(cdata->out->info_nsset.ns);
	for (i = 0; i < c_nsset->dns._length; i++) {
		epp_ns	*item_ns;

		/* ns item */
		item = epp_malloc(pool, sizeof *item);
		item_ns = epp_malloc(pool, sizeof *item_ns);
		CL_CONTENT(item) = (void *) item_ns;
		CL_ADD(cdata->out->info_nsset.ns, item);
		/* content of ns item */
		item_ns->name = epp_strdup(pool, c_nsset->dns._buffer[i].fqdn);
		item_ns->addr = epp_malloc(pool, sizeof (struct circ_list));
		CL_NEW(item_ns->addr);
		for (j = 0; j < c_nsset->dns._buffer[i].inet._length; j++) {
			item = epp_malloc(pool, sizeof *item);
			CL_CONTENT(item) = (void *)
				epp_strdup(pool, c_nsset->dns._buffer[i].inet._buffer[j]);
			CL_ADD(item_ns->addr, item);
		}
	}

	CORBA_free(c_nsset);

	get_errors(pool, cdata->errors, &response->errors);
	cdata->svTRID = epp_strdup(pool, response->svTRID);
	cdata->msg = epp_strdup(pool, response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);
	return CORBA_OK;
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
	CORBA_long	c_msgID;
	CORBA_char	*c_qdate;
	CORBA_char	*c_msg;
	int	retr;

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
				cdata->clTRID,
				cdata->xml_in,
				ev);

		/* if COMM_FAILURE exception is not raised then quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

	if (raised_exception(ev)) {
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
		CORBA_free(c_qdate);
		CORBA_free(response);
		return CORBA_REMOTE_ERROR;
	}

	if ((cdata->out = epp_calloc(pool, sizeof (*cdata->out))) == NULL) {
		CORBA_free(c_msg);
		CORBA_free(c_qdate);
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}

	cdata->out->poll_req.count = c_count;
	cdata->out->poll_req.msgid = c_msgID;
	cdata->out->poll_req.qdate = epp_strdup(pool, c_qdate);
	cdata->out->poll_req.msg = epp_strdup(pool, c_msg);

	CORBA_free(c_msg);
	CORBA_free(c_qdate);

	get_errors(pool, cdata->errors, &response->errors);
	cdata->svTRID = epp_strdup(pool, response->svTRID);
	cdata->msg = epp_strdup(pool, response->errMsg);
	cdata->rc = response->errCode;

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
	CORBA_long	c_msgID;
	CORBA_short	c_count;
	ccReg_Response *response;
	int	retr;

	assert(cdata->in != NULL);

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
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

		/* if COMM_FAILURE exception is not raised then quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

	if (raised_exception(ev)) {
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

	if ((cdata->out = epp_calloc(pool, sizeof (*cdata->out))) == NULL) {
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}

	cdata->out->poll_ack.count = c_count;
	cdata->out->poll_ack.msgid = c_msgID;

	get_errors(pool, cdata->errors, &response->errors);
	cdata->svTRID = epp_strdup(pool, response->svTRID);
	cdata->msg = epp_strdup(pool, response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);
	return CORBA_OK;
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
	CORBA_char	*c_crDate;
	CORBA_char	*c_exDate;
	ccReg_Response *response;
	ccReg_AdminContact	*c_admin;
	ccReg_ExtensionList	*c_ext_list;
	int	len, i, retr;

	assert(cdata->in != NULL);

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
	if (*cdata->in->create_domain.valExDate != '\0') {
		ccReg_ENUMValidationExtension	*c_enumval;

		c_enumval = ccReg_ENUMValidationExtension__alloc();
		c_enumval->valExDate =
			CORBA_string_dup(cdata->in->create_domain.valExDate);
		c_ext_list->_buffer = ccReg_ExtensionList_allocbuf(1);
		c_ext_list->_maximum = c_ext_list->_length = 1;
		c_ext_list->_release = CORBA_TRUE;
		c_ext_list->_buffer[0]._type = TC_ccReg_ENUMValidationExtension;
		c_ext_list->_buffer[0]._value = c_enumval;
		c_ext_list->_buffer[0]._release = CORBA_TRUE;
	}
	else {
		c_ext_list->_maximum = c_ext_list->_length = 0;
		c_ext_list->_release = CORBA_TRUE;
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

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

		/* if COMM_FAILURE exception is not raised then quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

	CORBA_free(c_admin);
	CORBA_free(c_ext_list);

	if (raised_exception(ev)) {
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
		CORBA_free(c_crDate);
		CORBA_free(c_exDate);
		return CORBA_REMOTE_ERROR;
	}

	if ((cdata->out = epp_calloc(pool, sizeof (*cdata->out))) == NULL) {
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}

	cdata->out->create.crDate = epp_strdup(pool, c_crDate);
	cdata->out->create.exDate = epp_strdup(pool, c_exDate);

	CORBA_free(c_crDate);
	CORBA_free(c_exDate);

	get_errors(pool, cdata->errors, &response->errors);
	cdata->svTRID = epp_strdup(pool, response->svTRID);
	cdata->msg = epp_strdup(pool, response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);
	return CORBA_OK;
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
	CORBA_char	*c_crDate;
	ccReg_ContactChange	*c_contact;
	ccReg_Response *response;
	int	retr;

	assert(cdata->in != NULL);

	/* fill in corba input values */
	c_contact = ccReg_ContactChange__alloc();
	c_contact->AuthInfoPw = CORBA_string_dup(cdata->in->create_contact.authInfo);
	c_contact->Telephone = CORBA_string_dup(cdata->in->create_contact.voice);
	c_contact->Fax = CORBA_string_dup(cdata->in->create_contact.fax);
	c_contact->Email = CORBA_string_dup(cdata->in->create_contact.email);
	c_contact->NotifyEmail =
			CORBA_string_dup(cdata->in->create_contact.notify_email);
	c_contact->VAT = CORBA_string_dup(cdata->in->create_contact.vat);
	c_contact->SSN = CORBA_string_dup(cdata->in->create_contact.ssn);
	c_contact->SSNtype = convSSNType(cdata->in->create_contact.ssntype);
	/* disclose */
	c_contact->DiscloseFlag = convDiscl(cdata->in->create_contact.discl->flag);
	if (c_contact->DiscloseFlag != ccReg_DISCL_EMPTY) {
		epp_discl	*discl = cdata->in->create_contact.discl;

		c_contact->DiscloseName = (discl->name ? CORBA_TRUE : CORBA_FALSE);
		c_contact->DiscloseOrganization = (discl->org ? CORBA_TRUE :CORBA_FALSE);
		c_contact->DiscloseAddress = (discl->addr ? CORBA_TRUE : CORBA_FALSE);
		c_contact->DiscloseTelephone = (discl->voice ? CORBA_TRUE : CORBA_FALSE);
		c_contact->DiscloseFax = (discl->fax ? CORBA_TRUE : CORBA_FALSE);
		c_contact->DiscloseEmail = (discl->email ? CORBA_TRUE : CORBA_FALSE);
	}
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

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		/* send new contact in repository */
		response = ccReg_EPP_ContactCreate(globs->service,
				cdata->in->create_contact.id,
				c_contact,
				&c_crDate,
				session,
				cdata->clTRID,
				cdata->xml_in,
				ev);

		/* if COMM_FAILURE exception is not raised then quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

	CORBA_free(c_contact);

	if (raised_exception(ev)) {
		CORBA_exception_free(ev);
		return CORBA_ERROR;
	}
	CORBA_exception_free(ev);

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		CORBA_free(c_crDate);
		CORBA_free(response);
		return CORBA_REMOTE_ERROR;
	}

	if ((cdata->out = epp_calloc(pool, sizeof (*cdata->out))) == NULL) {
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}

	cdata->out->create.crDate = epp_strdup(pool, c_crDate);
	CORBA_free(c_crDate);

	get_errors(pool, cdata->errors, &response->errors);
	cdata->svTRID = epp_strdup(pool, response->svTRID);
	cdata->msg = epp_strdup(pool, response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);
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
	CORBA_char	*c_crDate;
	int	len, i, j, retr;

	assert(cdata->in != NULL);

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

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

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

		/* if COMM_FAILURE exception is not raised then quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

	CORBA_free(c_tech);
	CORBA_free(c_dnshost);

	if (raised_exception(ev)) {
		CORBA_exception_free(ev);
		return CORBA_ERROR;
	}
	CORBA_exception_free(ev);

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		CORBA_free(c_crDate);
		CORBA_free(response);
		return CORBA_REMOTE_ERROR;
	}

	if ((cdata->out = epp_calloc(pool, sizeof (*cdata->out))) == NULL) {
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}

	cdata->out->create.crDate = epp_strdup(pool, c_crDate);
	CORBA_free(c_crDate);

	get_errors(pool, cdata->errors, &response->errors);
	cdata->svTRID = epp_strdup(pool, response->svTRID);
	cdata->msg = epp_strdup(pool, response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);
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
	ccReg_Response *response;
	CORBA_Environment ev[1];
	int	retr;

	assert(cdata->in != NULL);

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
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

		/* if COMM_FAILURE exception is not raised then quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

	if (raised_exception(ev)) {
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

	get_errors(pool, cdata->errors, &response->errors);
	cdata->svTRID = epp_strdup(pool, response->svTRID);
	cdata->msg = epp_strdup(pool, response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);
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
	CORBA_char	*c_exDate;
	ccReg_ExtensionList	*c_ext_list;
	int	retr;

	assert(cdata->in != NULL);
	c_ext_list = ccReg_ExtensionList__alloc();
	/* fill extension list if needed */
	if (*cdata->in->renew.valExDate != '\0') {
		ccReg_ENUMValidationExtension	*c_enumval;

		c_enumval = ccReg_ENUMValidationExtension__alloc();
		c_enumval->valExDate =
			CORBA_string_dup(cdata->in->renew.valExDate);
		c_ext_list->_buffer = ccReg_ExtensionList_allocbuf(1);
		c_ext_list->_maximum = c_ext_list->_length = 1;
		c_ext_list->_release = CORBA_TRUE;
		c_ext_list->_buffer[0]._type = TC_ccReg_ENUMValidationExtension;
		c_ext_list->_buffer[0]._value = c_enumval;
		c_ext_list->_buffer[0]._release = CORBA_TRUE;
	}
	else {
		c_ext_list->_maximum = c_ext_list->_length = 0;
		c_ext_list->_release = CORBA_FALSE;
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

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

		/* if COMM_FAILURE exception is not raised then quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

	CORBA_free(c_ext_list);

	if (raised_exception(ev)) {
		CORBA_exception_free(ev);
		return CORBA_ERROR;
	}
	CORBA_exception_free(ev);

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		CORBA_free(c_exDate);
		CORBA_free(response);
		return CORBA_REMOTE_ERROR;
	}

	if ((cdata->out = epp_calloc(pool, sizeof (*cdata->out))) == NULL) {
		CORBA_free(c_exDate);
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}
	cdata->out->renew.exDate = epp_strdup(pool, c_exDate);
	CORBA_free(c_exDate);

	get_errors(pool, cdata->errors, &response->errors);
	cdata->svTRID = epp_strdup(pool, response->svTRID);
	cdata->msg = epp_strdup(pool, response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);
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
	ccReg_Response	*response;
	ccReg_AdminContact	*c_admin_add;
	ccReg_AdminContact	*c_admin_rem;
	ccReg_Status	*c_status_add;
	ccReg_Status	*c_status_rem;
	ccReg_ExtensionList	*c_ext_list;
	int	i, len, retr;

	assert(cdata->in != NULL);

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
	if (*cdata->in->create_domain.valExDate != '\0') {
		ccReg_ENUMValidationExtension	*c_enumval;

		c_enumval = ccReg_ENUMValidationExtension__alloc();
		c_enumval->valExDate =
			CORBA_string_dup(cdata->in->update_domain.valExDate);
		c_ext_list->_buffer = ccReg_ExtensionList_allocbuf(1);
		c_ext_list->_maximum = c_ext_list->_length = 1;
		c_ext_list->_release = CORBA_TRUE;
		c_ext_list->_buffer[0]._type = TC_ccReg_ENUMValidationExtension;
		c_ext_list->_buffer[0]._value = c_enumval;
		c_ext_list->_buffer[0]._release = CORBA_TRUE;
	}
	else {
		c_ext_list->_maximum = c_ext_list->_length = 0;
		c_ext_list->_release = CORBA_FALSE;
	}


	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

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

		/* if COMM_FAILURE exception is not raised then quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

	CORBA_free(c_status_rem);
	CORBA_free(c_status_add);
	CORBA_free(c_admin_rem);
	CORBA_free(c_admin_add);
	CORBA_free(c_ext_list);

	if (raised_exception(ev)) {
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

	get_errors(pool, cdata->errors, &response->errors);
	cdata->svTRID = epp_strdup(pool, response->svTRID);
	cdata->msg = epp_strdup(pool, response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);
	return CORBA_OK;
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
	ccReg_Response	*response;
	ccReg_Status	*c_status_add;
	ccReg_Status	*c_status_rem;
	ccReg_ContactChange	*c_contact;
	int	i, len, retr;

	assert(cdata->in != NULL);

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
	c_contact->AuthInfoPw = CORBA_string_dup(cdata->in->update_contact.authInfo);
	c_contact->Telephone = CORBA_string_dup(cdata->in->update_contact.voice);
	c_contact->Fax = CORBA_string_dup(cdata->in->update_contact.fax);
	c_contact->Email = CORBA_string_dup(cdata->in->update_contact.email);
	c_contact->NotifyEmail =
		CORBA_string_dup(cdata->in->update_contact.notify_email);
	c_contact->VAT = CORBA_string_dup(cdata->in->update_contact.vat);
	c_contact->SSN = CORBA_string_dup(cdata->in->update_contact.ssn);
	c_contact->SSNtype = convSSNType(cdata->in->update_contact.ssntype);
	/* disclose */
	c_contact->DiscloseFlag = convDiscl(cdata->in->update_contact.discl->flag);
	if (c_contact->DiscloseFlag != ccReg_DISCL_EMPTY) {
		epp_discl	*discl = cdata->in->update_contact.discl;
		c_contact->DiscloseName = (discl->name ? CORBA_TRUE : CORBA_FALSE);
		c_contact->DiscloseOrganization = (discl->org ? CORBA_TRUE :CORBA_FALSE);
		c_contact->DiscloseAddress = (discl->addr ? CORBA_TRUE : CORBA_FALSE);
		c_contact->DiscloseTelephone = (discl->voice ? CORBA_TRUE : CORBA_FALSE);
		c_contact->DiscloseFax = (discl->fax ? CORBA_TRUE : CORBA_FALSE);
		c_contact->DiscloseEmail = (discl->email ? CORBA_TRUE : CORBA_FALSE);
	}

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

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

		/* if COMM_FAILURE exception is not raised then quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

	CORBA_free(c_status_rem);
	CORBA_free(c_status_add);
	CORBA_free(c_contact);

	if (raised_exception(ev)) {
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

	get_errors(pool, cdata->errors, &response->errors);
	cdata->svTRID = epp_strdup(pool, response->svTRID);
	cdata->msg = epp_strdup(pool, response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);
	return CORBA_OK;
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
	ccReg_Response *response;
	ccReg_DNSHost	*c_dnshost_add;
	ccReg_DNSHost	*c_dnshost_rem;
	ccReg_TechContact	*c_tech_add;
	ccReg_TechContact	*c_tech_rem;
	ccReg_Status	*c_status_add;
	ccReg_Status	*c_status_rem;
	epp_ns	*ns;
	int	i, j, len, retr;

	assert(cdata->in != NULL);

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

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

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

		/* if COMM_FAILURE exception is not raised then quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

	CORBA_free(c_status_rem);
	CORBA_free(c_status_add);
	CORBA_free(c_tech_rem);
	CORBA_free(c_tech_add);
	CORBA_free(c_dnshost_rem);
	CORBA_free(c_dnshost_add);

	if (raised_exception(ev)) {
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

	get_errors(pool, cdata->errors, &response->errors);
	cdata->svTRID = epp_strdup(pool, response->svTRID);
	cdata->msg = epp_strdup(pool, response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);
	return CORBA_OK;
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
	ccReg_Response *response;
	int	retr;

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
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
		else if (obj == EPP_CONTACT) {
			response = ccReg_EPP_ContactTransfer(globs->service,
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

		/* if COMM_FAILURE exception is not raised then quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

	if (raised_exception(ev)) {
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

	get_errors(pool, cdata->errors, &response->errors);
	cdata->svTRID = epp_strdup(pool, response->svTRID);
	cdata->msg = epp_strdup(pool, response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);
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
	ccReg_Response	*response;
	ccReg_Lists	*c_handles;
	struct circ_list	*item;
	int	 i, retr;

	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		if (obj == EPP_DOMAIN) {
			response = ccReg_EPP_DomainList(globs->service,
					&c_handles,
					session,
					cdata->clTRID,
					cdata->xml_in,
					ev);
		}
		else if (obj == EPP_CONTACT) {
			response = ccReg_EPP_ContactList(globs->service,
					&c_handles,
					session,
					cdata->clTRID,
					cdata->xml_in,
					ev);
		}
		else {
			assert(obj == EPP_NSSET);
			response = ccReg_EPP_NSSetList(globs->service,
					&c_handles,
					session,
					cdata->clTRID,
					cdata->xml_in,
					ev);
		}

		/* if COMM_FAILURE exception is not raised then quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
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
		CORBA_free(c_handles);
		return CORBA_REMOTE_ERROR;
	}

	if (!(cdata->out = epp_calloc(pool, sizeof (*cdata->out)))
		|| !(cdata->out->list.handles = epp_malloc(pool, sizeof *item)))
	{
		CORBA_free(response);
		CORBA_free(c_handles);
		return CORBA_INT_ERROR;
	}
	CL_NEW(cdata->out->list.handles);

	for (i = 0; i < c_handles->_length; i++) {
		/* if malloc fails we will silently ignore the rest of handles */
		if ((item = epp_malloc(pool, sizeof *item)) == NULL) break;
		CL_CONTENT(item) = epp_strdup(pool, c_handles->_buffer[i]);
		CL_ADD(cdata->out->list.handles, item);
	}
	CORBA_free(c_handles);

	get_errors(pool, cdata->errors, &response->errors);
	cdata->svTRID = epp_strdup(pool, response->svTRID);
	cdata->msg = epp_strdup(pool, response->errMsg);
	cdata->rc = response->errCode;

	CORBA_free(response);
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
			cstat = epp_call_check(pool, globs, session, cdata, EPP_CONTACT);
			break;
		case EPP_CHECK_DOMAIN:
			cstat = epp_call_check(pool, globs, session, cdata, EPP_DOMAIN);
			break;
		case EPP_CHECK_NSSET:
			cstat = epp_call_check(pool, globs, session, cdata, EPP_NSSET);
			break;
		case EPP_INFO_CONTACT:
			cstat = epp_call_info_contact(pool, globs, session, cdata);
			break;
		case EPP_INFO_DOMAIN:
			cstat = epp_call_info_domain(pool, globs, session, cdata);
			break;
		case EPP_INFO_NSSET:
			cstat = epp_call_info_nsset(pool, globs, session, cdata);
			break;
		case EPP_LIST_CONTACT:
			cstat = epp_call_list(pool, globs, session, cdata, EPP_CONTACT);
			break;
		case EPP_LIST_DOMAIN:
			cstat = epp_call_list(pool, globs, session, cdata, EPP_DOMAIN);
			break;
		case EPP_LIST_NSSET:
			cstat = epp_call_list(pool, globs, session, cdata, EPP_NSSET);
			break;
		case EPP_POLL_REQ:
			cstat = epp_call_poll_req(pool, globs, session, cdata);
			break;
		case EPP_POLL_ACK:
			cstat = epp_call_poll_ack(pool, globs, session, cdata);
			break;
		case EPP_CREATE_CONTACT:
			cstat = epp_call_create_contact(pool, globs, session, cdata);
			break;
		case EPP_CREATE_DOMAIN:
			cstat = epp_call_create_domain(pool, globs, session, cdata);
			break;
		case EPP_CREATE_NSSET:
			cstat = epp_call_create_nsset(pool, globs, session, cdata);
			break;
		case EPP_DELETE_CONTACT:
			cstat = epp_call_delete(pool, globs, session, cdata, EPP_CONTACT);
			break;
		case EPP_DELETE_DOMAIN:
			cstat = epp_call_delete(pool, globs, session, cdata, EPP_DOMAIN);
			break;
		case EPP_DELETE_NSSET:
			cstat = epp_call_delete(pool, globs, session, cdata, EPP_NSSET);
			break;
		case EPP_RENEW_DOMAIN:
			cstat = epp_call_renew_domain(pool, globs, session, cdata);
			break;
		case EPP_UPDATE_DOMAIN:
			cstat = epp_call_update_domain(pool, globs, session, cdata);
			break;
		case EPP_UPDATE_CONTACT:
			cstat = epp_call_update_contact(pool, globs, session, cdata);
			break;
		case EPP_UPDATE_NSSET:
			cstat = epp_call_update_nsset(pool, globs, session, cdata);
			break;
		case EPP_TRANSFER_CONTACT:
			cstat = epp_call_transfer(pool, globs, session, cdata, EPP_CONTACT);
			break;
		case EPP_TRANSFER_DOMAIN:
			cstat = epp_call_transfer(pool, globs, session, cdata, EPP_DOMAIN);
			break;
		case EPP_TRANSFER_NSSET:
			cstat = epp_call_transfer(pool, globs, session, cdata, EPP_NSSET);
			break;
		default:
			cstat = CORBA_INT_ERROR;
			break;
	}

	return cstat;
}
