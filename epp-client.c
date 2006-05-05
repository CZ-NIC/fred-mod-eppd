/**
 * Copyright statement ;)
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <orbit/orbit.h>

#include "epp_common.h"
#include "epp-client.h"
#include "ccReg.h"

#define raised_exception(ev)	((ev)->_major != CORBA_NO_EXCEPTION)


typedef struct {
	CORBA_ORB	corba;
	ccReg_EPP	service;
}epp_corba_globs;

/**
 * Read string from stream.
 */
static gchar*
read_string_from_stream(FILE *stream)
{
	gulong length;
	gchar *objref;
	int c;
	int i = 0;

	length = 4 * 1024; /* should suffice ordinary IOR string */
	objref = g_malloc0(length * sizeof (gchar));
	if (objref == NULL) return NULL;

	/* skip leading white space */
	while ((c = fgetc(stream)) !=EOF && g_ascii_isspace(c));
	/* POST: c==EOF or c=first character */

	if (c != EOF) {
		/* append c to string while more c exist and c not white space */
		do {
			/* check size */
			if (i >= length - 1) {
				length *= 2;
				objref = g_realloc(objref, length);
			}
			objref[i++] = c;
		}while ((c = fgetc(stream)) != EOF && !g_ascii_isspace(c));
	}
	/* terminate string with \0 */
	objref[i] = '\0';

	return objref;
}


void *
epp_corba_init(const char *ior)
{
	CORBA_ORB  global_orb = CORBA_OBJECT_NIL; /* global orb */
	ccReg_EPP e_service = CORBA_OBJECT_NIL;
	epp_corba_globs	*globs;
	CORBA_Environment ev[1];
	CORBA_exception_init(ev);
 
	global_orb = CORBA_ORB_init(0, NULL, "orbit-local-orb", ev);
	if (raised_exception(ev)) {
		if (global_orb != CORBA_OBJECT_NIL) CORBA_ORB_destroy(global_orb, ev);
		return NULL;
	}

	e_service = (ccReg_EPP) CORBA_ORB_string_to_object(global_orb, ior, ev);
	if (raised_exception(ev)) {
		/* releasing managed object */
		CORBA_Object_release(e_service, ev);
		/* tear down the ORB */
		if (global_orb != CORBA_OBJECT_NIL) CORBA_ORB_destroy(global_orb, ev);
		return NULL;
	}

	if ((globs = malloc(sizeof *globs)) == NULL) {
		/* releasing managed object */
		CORBA_Object_release(e_service, ev);
		/* tear down the ORB */
		if (global_orb != CORBA_OBJECT_NIL)
			CORBA_ORB_destroy(global_orb, ev);
		return NULL;
	}

	globs->corba = global_orb;
	globs->service = e_service;
	return (void *) globs;
}

void
epp_corba_init_cleanup(void *corba_globs)
{
	CORBA_Environment ev[1];
	epp_corba_globs	*globs = (epp_corba_globs *) corba_globs;
	CORBA_exception_init(ev);

	/* releasing managed object */
	CORBA_Object_release(globs->service, ev);
	/* tear down the ORB */
	CORBA_ORB_destroy(globs->corba, ev);

	free(globs);
}

corba_status
epp_call_dummy(void *globs, int session, epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	ccReg_Response *response;
	CORBA_exception_init(ev);

	response = ccReg_EPP_GetTransaction(((epp_corba_globs *) globs)->service,
			session,
			cdata->clTRID,
			cdata->rc,
			ev);
	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		return CORBA_ERROR;
	}

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		CORBA_free(response);
		return CORBA_REMOTE_ERROR;
	}

	cdata->svTRID = strdup(response->svTRID);

	CORBA_free(response);
	return CORBA_OK;
}

corba_status
epp_call_login(void *globs, int *session, epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	CORBA_exception_init(ev);
	CORBA_long	c_session;
	ccReg_Response *response;

	response = ccReg_EPP_ClientLogin(((epp_corba_globs *) globs)->service,
			cdata->un.login.clID,
			cdata->un.login.pw,
			cdata->un.login.newPW,
			cdata->clTRID,
			&c_session,
			ev);
	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		return CORBA_ERROR;
	}

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		CORBA_free(response);
		return CORBA_REMOTE_ERROR;
	}

	cdata->svTRID = strdup(response->svTRID);
	cdata->rc = response->errCode;
	if (cdata->rc == 1000) *session = c_session;

	CORBA_free(response);
	return CORBA_OK;
}

corba_status
epp_call_logout(void *globs, int session, epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	ccReg_Response *response;
	CORBA_exception_init(ev);

	response = ccReg_EPP_ClientLogout(((epp_corba_globs *) globs)->service,
			session,
			cdata->clTRID,
			ev);
	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		return CORBA_ERROR;
	}

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		CORBA_free(response);
		return CORBA_REMOTE_ERROR;
	}

	cdata->svTRID = strdup(response->svTRID);
	cdata->rc = response->errCode;

	CORBA_free(response);
	return CORBA_OK;
}

/**
 * <check> for different objects is so much similar that it is worth of
 * having the code in one function and create just wrappers for different
 * kinds of objects.
 */
static corba_status
epp_call_check(void *globs, int session, epp_command_data *cdata,
		epp_object_type obj)
{
	CORBA_Environment ev[1];
	corba_status	ret;
	int	len, i;
	ccReg_Response *response;
	ccReg_Avail	*bools;
	ccReg_Check	*ids = ccReg_Check__alloc();

	CORBA_exception_init(ev);
	/* get number of contacts */
	CL_LENGTH(cdata->in->check.ids, len);
	ids->_buffer = ccReg_Check_allocbuf(len);
	ids->_length = len;

	i = 0;
	CL_FOREACH(cdata->in->check.ids)
		ids->_buffer[i++] = CORBA_string_dup(
				CL_CONTENT(cdata->un.check.idbools));

	if (obj == EPP_CONTACT)
		response = ccReg_EPP_ContactCheck(( (epp_corba_globs *) globs)->service,
				ids,
				&bools,
				session,
				cdata->clTRID,
				ev);
	else
		response = ccReg_EPP_DomainCheck(( (epp_corba_globs *) globs)->service,
				ids,
				&bools,
				session,
				cdata->clTRID,
				ev);

	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		CORBA_free(ids);
		return CORBA_ERROR;
	}

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		ret = CORBA_REMOTE_ERROR;
	}
	else {
		if ((cdata->out = calloc(1, sizeof (*cdata->out))) == NULL)
			ret = CORBA_INT_ERROR;
		else {
			struct circ_list	*item;

			if ((cdata->out->check.bools = malloc(sizeof *item)) == NULL) {
				free(cdata->out);
				cdata->out = NULL;
				ret = CORBA_INT_ERROR;
			}
			else {
				CL_NEW(cdata->out->check.bools);
				for (i = 0; i < bools->_length; i++) {
					item = malloc(sizeof *item);
					CL_CONTENT(cdata->out->check.bools) = (void *)
						bools->_buffer[i];
				}
				if (i == bools->_length) ret = CORBA_OK;
				cdata->svTRID = strdup(response->svTRID);
				cdata->rc = response->errCode;
			}
		}
	}

	CORBA_free(response);
	CORBA_free(ids);
	CORBA_free(bools);

	return ret;
}

corba_status
epp_call_check_contact(void *globs, int session, epp_command_data *cdata)
{
	return epp_call_check(globs, session, cdata, EPP_CONTACT);
}

corba_status
epp_call_check_domain(void *globs, int session, epp_command_data *cdata)
{
	return epp_call_check(globs, session, cdata, EPP_DOMAIN);
}

corba_status
epp_call_info_contact(void *globs, int session, epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	corba_status	ret;
	ccReg_Response	*response;
	ccReg_Contact	*c_contact;

	CORBA_exception_init(ev);

	response = ccReg_EPP_ContactInfo(( (epp_corba_globs *) globs)->service,
			cdata->in->info_contact.id,
			c_contact,
			session,
			cdata->clTRID,
			ev);

	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		return CORBA_ERROR;
	}

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		ret = CORBA_REMOTE_ERROR;
	}
	else {
		epp_postalInfo	*pi;
		epp_discl	*discl;

		if ((cdata->out = calloc(1, sizeof (*cdata->out))) == NULL)
			ret = CORBA_INT_ERROR;
		else if ((cdata->out->info_contact.addr_int = calloc(1, sizeof *pi))
					== NULL)
		{
			free(cdata->out);
			cdata->out = NULL;
			ret = CORBA_INT_ERROR;
		}
		else if ((cdata->out->info_contact.addr_loc = calloc(1, sizeof *pi))
					== NULL)
		{
			free(cdata->out->info_contact.addr_int);
			free(cdata->out);
			cdata->out = NULL;
			ret = CORBA_INT_ERROR;
		}
		else if ((cdata->out->info_contact.discl = calloc(1, sizeof *discl))
					== NULL)
		{
			free(cdata->out->info_contact.addr_int);
			free(cdata->out->info_contact.addr_loc);
			free(cdata->out);
			cdata->out = NULL;
			ret = CORBA_INT_ERROR;
		}
		else if ((cdata->out->info_contact.status=malloc(sizeof *item)) == NULL)
		{
			free(cdata->out->info_contact.addr_int);
			free(cdata->out->info_contact.addr_loc);
			free(cdata->out);
			cdata->out = NULL;
			ret = CORBA_INT_ERROR;
		}
		/* ok, now everything was successfully allocated */
		else {
			cdata->out->info_contact.roid = strdup(c_contact->ROID);
			cdata->out->info_contact.clID = strdup(c_contact->ClID);
			cdata->out->info_contact.crID = strdup(c_contact->CrID);
			cdata->out->info_contact.upID = strdup(c_contact->UpID);
			cdata->out->info_contact.crDate = c_contact->CrDate;
			cdata->out->info_contact.upDate = c_contact->UpDate;
			cdata->out->info_contact.trDate = c_contact->TrDate;
			/* contact status */
			CL_NEW(cdata->out->info_contact.status);
			for (i = 0; i < c_contact->status->_length; i++) {
				item = malloc(sizeof *item);
				CL_CONTENT(cdata->out->info_contact.status) = (void *)
					strdup(c_contact->status->_buffer[i]);
			}
			/* local address */
			pi = cdata->out->info_contact.addr_loc;
			pi->name = strdup(c_contact->addr_loc->Name);
			pi->org = strdup(c_contact->addr_loc->Organization);
			pi->street1 = strdup(c_contact->addr_loc->Street1);
			pi->street2 = strdup(c_contact->addr_loc->Street2);
			pi->street3 = strdup(c_contact->addr_loc->Street3);
			pi->city = strdup(c_contact->addr_loc->City);
			pi->sp = strdup(c_contact->addr_loc->StateOrProvince);
			pi->pc = strdup(c_contact->addr_loc->PostalCode);
			pi->cc = strdup(c_contact->addr_loc->Country);
			/* international address */
			pi = cdata->out->info_contact.addr_int;
			pi->name = strdup(c_contact->addr_int->Name);
			pi->org = strdup(c_contact->addr_int->Organization);
			pi->street1 = strdup(c_contact->addr_int->Street1);
			pi->street2 = strdup(c_contact->addr_int->Street2);
			pi->street3 = strdup(c_contact->addr_int->Street3);
			pi->city = strdup(c_contact->addr_int->City);
			pi->sp = strdup(c_contact->addr_int->StateOrProvince);
			pi->pc = strdup(c_contact->addr_int->PostalCode);
			pi->cc = strdup(c_contact->addr_int->Country);
			/* others */
			cdata->out->info_contact.voice = strdup(c_contact->Telephone);
			cdata->out->info_contact.fax = strdup(c_contact->Fax);
			cdata->out->info_contact.email = strdup(c_contact->Email);
			cdata->out->info_contact.notify_email =
				strdup(c_contact->NotifyEmail);
			cdata->out->info_contact.vat = strdup(c_contact->VAT);
			cdata->out->info_contact.ssn = strdup(c_contact->SSN);
			cdata->out->info_contact.authInfo = strdup(c_contact->AuthInfoPw);
			/* disclose info */
			discl = cdata->out->info_contact.discl;
			discl->name_int = c_contact->DiscloseNameInt;
			discl->name_loc = c_contact->DiscloseNameLoc;
			discl->org_int = c_contact->DiscloseOrganizationInt;
			discl->org_loc = c_contact->DiscloseOrganizationLoc;
			discl->addr_int = c_contact->DiscloseAddressInt;
			discl->addr_loc = c_contact->DiscloseAddressLoc;
			discl->voice = c_contact->DiscloseTelephone;
			discl->fax = c_contact->DiscloseFax;
			discl->email = c_contact->DiscloseEmail;

			cdata->svTRID = strdup(response->svTRID);
			cdata->rc = response->errCode;
			ret = CORBA_OK;
	}

	CORBA_free(response);
	CORBA_free(c_contact);

	return ret;
}

corba_status
epp_call_info_domain(void *globs, int session, epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	corba_status	ret;
	ccReg_Response	*response;
	ccReg_Domain	*c_domain;

	CORBA_exception_init(ev);

	response = ccReg_EPP_DomainInfo(( (epp_corba_globs *) globs)->service,
			cdata->in->info_domain.name,
			c_domain,
			session,
			cdata->clTRID,
			ev);

	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		return CORBA_ERROR;
	}

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		ret = CORBA_REMOTE_ERROR;
	}
	else {
		struct circ_list	*item;

		if ((cdata->out = calloc(1, sizeof (*cdata->out))) == NULL)
			ret = CORBA_INT_ERROR;
		else if ((cdata->out->info_domain.status =malloc(sizeof *item)) == NULL)
		{
			free(cdata->out);
			cdata->out = NULL;
			ret = CORBA_INT_ERROR;
		}
		else if ((cdata->out->info_domain.admin = malloc(sizeof *item)) == NULL)
		{
			free(cdata->out->info_domain.status);
			free(cdata->out);
			cdata->out = NULL;
			ret = CORBA_INT_ERROR;
		}
		else if ((cdata->out->info_domain.tech = malloc(sizeof *item)) == NULL)
		{
			free(cdata->out->info_domain.admin);
			free(cdata->out->info_domain.status);
			free(cdata->out);
			cdata->out = NULL;
			ret = CORBA_INT_ERROR;
		}
		/* ok, now everything was successfully allocated */
		else {
			int i;

			cdata->out->info_domain.roid = strdup(c_domain->ROID);
			cdata->out->info_domain.clID = strdup(c_domain->ClID);
			cdata->out->info_domain.crID = strdup(c_domain->CrID);
			cdata->out->info_domain.upID = strdup(c_domain->UpID);
			cdata->out->info_domain.crDate = c_domain->CrDate;
			cdata->out->info_domain.upDate = c_domain->UpDate;
			cdata->out->info_domain.trDate = c_domain->TrDate;
			cdata->out->info_domain.trDate = c_domain->ExDate;

			cdata->out->info_domain.registrant = strdup(c_domain->Registrant);
			cdata->out->info_domain.nsset = strdup(c_domain->nsset);
			cdata->out->info_domain.authInfo = strdup(c_domain->AuthInfoPw);

			/* allocate and initialize status, admin and tech lists */
			CL_NEW(cdata->out->info_domain.status);
			CL_NEW(cdata->out->info_domain.admin);
			CL_NEW(cdata->out->info_domain.tech);
			for (i = 0; i < c_domain->status->_length; i++) {
				item = malloc(sizeof *item);
				CL_CONTENT(cdata->out->info_domain.status) = (void *)
					strdup(c_domain->status->_buffer[i]);
			}
			for (i = 0; i < c_domain->admin->_length; i++) {
				item = malloc(sizeof *item);
				CL_CONTENT(cdata->out->info_domain.admin) = (void *)
					strdup(c_domain->admin->_buffer[i]);
			}
			for (i = 0; i < c_domain->tech->_length; i++) {
				item = malloc(sizeof *item);
				CL_CONTENT(cdata->out->info_domain.tech) = (void *)
					strdup(c_domain->tech->_buffer[i]);
			}

			cdata->svTRID = strdup(response->svTRID);
			cdata->rc = response->errCode;
			ret = CORBA_OK;
	}

	CORBA_free(response);
	CORBA_free(c_contact);

	return ret;
}

corba_status
epp_call_poll_req(void *globs, int session, epp_command_data *cdata)
{
	ccReg_Response	*response;
	corba_status	ret;
	CORBA_Environment	ev[1];
	CORBA_long	c_count;
	CORBA_long	c_msgID;
	CORBA_unsigned_long_long	qdate;
	CORBA_char	*c_msg;

	CORBA_exception_init(ev);

	response = ccReg_EPP_PollRequest(( (epp_corba_globs *) globs)->service,
			&c_count,
			&c_msgID,
			&c_qdate,
			&c_msg,
			session,
			cdata->clTRID,
			ev);

	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		return CORBA_ERROR;
	}

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		CORBA_free(response);
		return CORBA_REMOTE_ERROR;
	}

	if ((cdata->out = calloc(1, sizeof (*cdata->out))) == NULL)
		ret = CORBA_INT_ERROR;
	else {
		cdata->out->poll_req.count = c_count;
		cdata->out->poll_req.msgid = c_msgid;
		cdata->out->poll_req.qdate = c_qdate;
		cdata->out->poll_req.msg = strdup(c_msg);

		cdata->svTRID = strdup(response->svTRID);
		cdata->rc = response->errCode;
	}

	CORBA_free(msg);
	CORBA_free(response);
	return CORBA_OK;
}

corba_status
epp_call_poll_ack(void *globs, int session, epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	CORBA_long	c_msgID;
	CORBA_short	c_count;
	ccReg_Response *response;
	corba_status	ret;

	assert(cdata->in != NULL);
	CORBA_exception_init(ev);

	response = ccReg_EPP_PollAck(( (epp_corba_globs *) globs)->service,
			cdata->in->poll_ack.msgid,
			&c_count,
			&c_msgID,
			session,
			cdata->clTRID,
			ev);

	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		return CORBA_ERROR;
	}

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		CORBA_free(response);
		return CORBA_REMOTE_ERROR;
	}

	if ((cdata->out = calloc(1, sizeof (*cdata->out))) == NULL)
		ret = CORBA_INT_ERROR;
	else {
		cdata->out->poll_ack.count = c_count;
		cdata->out->poll_ack.msgid = c_msgID;

		cdata->svTRID = strdup(response->svTRID);
		cdata->rc = response->errCode;
	}

	CORBA_free(response);
	return CORBA_OK;
}
