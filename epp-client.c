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

/**
 * Needed for corba function calls.
 *   - corba is global corba object
 *   - service is ccReg object handle
 */
struct epp_corba_globs_t {
	CORBA_ORB	corba;
	ccReg_EPP	service;
};

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


epp_corba_globs *
epp_corba_init(const char *ior)
{
	CORBA_ORB  global_orb = CORBA_OBJECT_NIL; /* global orb */
	ccReg_EPP e_service = CORBA_OBJECT_NIL;
	epp_corba_globs	*globs;
	CORBA_Environment ev[1];
	CORBA_exception_init(ev);
 
	global_orb = CORBA_ORB_init(0, NULL, "orbit-local-orb", ev);
	if (raised_exception(ev)) {
		CORBA_exception_free(ev);
		if (global_orb != CORBA_OBJECT_NIL) CORBA_ORB_destroy(global_orb, ev);
		CORBA_exception_free(ev);
		return NULL;
	}

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

	if ((globs = malloc(sizeof *globs)) == NULL) {
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

	globs->corba = global_orb;
	globs->service = e_service;
	CORBA_exception_free(ev);
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

corba_status
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

	cdata->svTRID = strdup(response->svTRID);

	CORBA_free(response);
	return CORBA_OK;
}

corba_status
epp_call_login(epp_corba_globs *globs, int *session, epp_command_data *cdata)
{
	CORBA_long	c_session;
	CORBA_Environment ev[1];
	ccReg_Response *response;
	CORBA_exception_init(ev);

	response = ccReg_EPP_ClientLogin(globs->service,
			cdata->in->login.clID,
			cdata->in->login.pw,
			cdata->in->login.newPW,
			cdata->clTRID,
			&c_session,
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

	cdata->svTRID = strdup(response->svTRID);
	cdata->rc = response->errCode;
	if (cdata->rc == 1000) *session = c_session;

	CORBA_free(response);
	return CORBA_OK;
}

corba_status
epp_call_logout(epp_corba_globs *globs, int session, epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	ccReg_Response *response;
	CORBA_exception_init(ev);

	response = ccReg_EPP_ClientLogout(globs->service,
			session,
			cdata->clTRID,
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
epp_call_check(epp_corba_globs *globs, int session, epp_command_data *cdata,
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
				CL_CONTENT(cdata->in->check.ids));

	if (obj == EPP_CONTACT)
		response = ccReg_EPP_ContactCheck(globs->service,
				ids,
				&bools,
				session,
				cdata->clTRID,
				ev);
	else if (obj == EPP_DOMAIN)
		response = ccReg_EPP_DomainCheck(globs->service,
				ids,
				&bools,
				session,
				cdata->clTRID,
				ev);
	else
		response = ccReg_EPP_NSSetCheck(globs->service,
				ids,
				&bools,
				session,
				cdata->clTRID,
				ev);

	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		CORBA_exception_free(ev);
		CORBA_free(ids);
		return CORBA_ERROR;
	}
	CORBA_exception_free(ev);

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		ret = CORBA_REMOTE_ERROR;
	}
	else {
		ret = CORBA_OK;
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
				assert(len == bools->_length);
				for (i = 0; i < bools->_length; i++) {
					item = malloc(sizeof *item);
					/*
					 * note that we cannot use zero value for false value
					 * since value zero of content pointer denotes that
					 * the item in list is a sentinel (first or last).
					 * Therefore we will use value 2 as false value.
					 */
					CL_CONTENT(item) = (void *) (bools->_buffer[i] ? 1 : 2);
					CL_ADD(cdata->out->check.bools, item);
				}
				if (i != bools->_length) ret = CORBA_INT_ERROR;
				else {
					cdata->svTRID = strdup(response->svTRID);
					cdata->rc = response->errCode;
				}
			}
		}
	}

	CORBA_free(response);
	CORBA_free(ids);
	CORBA_free(bools);

	return ret;
}

corba_status
epp_call_check_contact(epp_corba_globs *globs, int session, epp_command_data *cdata)
{
	return epp_call_check(globs, session, cdata, EPP_CONTACT);
}

corba_status
epp_call_check_domain(epp_corba_globs *globs, int session, epp_command_data *cdata)
{
	return epp_call_check(globs, session, cdata, EPP_DOMAIN);
}

corba_status
epp_call_check_nsset(epp_corba_globs *globs, int session, epp_command_data *cdata)
{
	return epp_call_check(globs, session, cdata, EPP_NSSET);
}

corba_status
epp_call_info_contact(epp_corba_globs *globs, int session, epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	corba_status	ret;
	ccReg_Response	*response;
	ccReg_Contact	*c_contact;

	CORBA_exception_init(ev);

	response = ccReg_EPP_ContactInfo(globs->service,
			cdata->in->info.id,
			&c_contact,
			session,
			cdata->clTRID,
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
		ret = CORBA_REMOTE_ERROR;
	}
	else {
		epp_postalInfo	*pi;
		epp_discl	*discl;
		struct circ_list	*item;

		if ((cdata->out = calloc(1, sizeof (*cdata->out))) == NULL)
			ret = CORBA_INT_ERROR;
		else if ((cdata->out->info_contact.postalInfo = calloc(1, sizeof *pi))
				== NULL)
		{
			free(cdata->out);
			cdata->out = NULL;
			ret = CORBA_INT_ERROR;
		}
		else if ((cdata->out->info_contact.discl = calloc(1, sizeof *discl))
				== NULL)
		{
			free(cdata->out->info_contact.postalInfo);
			free(cdata->out);
			cdata->out = NULL;
			ret = CORBA_INT_ERROR;
		}
		else if ((cdata->out->info_contact.status = malloc(sizeof *item))
				== NULL)
		{
			free(cdata->out->info_contact.postalInfo);
			free(cdata->out);
			cdata->out = NULL;
			ret = CORBA_INT_ERROR;
		}
		/* ok, now everything was successfully allocated */
		else {
			int	i;

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
			pi = cdata->out->info_contact.postalInfo;
			pi->name = strdup(c_contact->Name);
			pi->org = strdup(c_contact->Organization);
			pi->street[0] = strdup(c_contact->Street1);
			pi->street[1] = strdup(c_contact->Street2);
			pi->street[2] = strdup(c_contact->Street3);
			pi->city = strdup(c_contact->City);
			pi->sp = strdup(c_contact->StateOrProvince);
			pi->pc = strdup(c_contact->PostalCode);
			pi->cc = strdup(c_contact->Country);
			/* others */
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

			cdata->svTRID = strdup(response->svTRID);
			cdata->rc = response->errCode;
			ret = CORBA_OK;
		}
	}

	CORBA_free(response);
	CORBA_free(c_contact);

	return ret;
}

corba_status
epp_call_info_domain(epp_corba_globs *globs, int session, epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	corba_status	ret;
	ccReg_Response	*response;
	ccReg_Domain	*c_domain;

	CORBA_exception_init(ev);

	response = ccReg_EPP_DomainInfo(globs->service,
			cdata->in->info.id,
			&c_domain,
			session,
			cdata->clTRID,
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
		ret = CORBA_REMOTE_ERROR;
	}
	else {
		struct circ_list	*item;

		if ((cdata->out = calloc(1, sizeof (*cdata->out))) == NULL)
			ret = CORBA_INT_ERROR;
		else if ((cdata->out->info_domain.status = malloc(sizeof *item)) == NULL)
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
			cdata->out->info_domain.exDate = c_domain->ExDate;

			cdata->out->info_domain.registrant = strdup(c_domain->Registrant);
			cdata->out->info_domain.nsset = strdup(c_domain->nsset);
			cdata->out->info_domain.authInfo = strdup(c_domain->AuthInfoPw);

			/* allocate and initialize status, admin lists */
			CL_NEW(cdata->out->info_domain.status);
			CL_NEW(cdata->out->info_domain.admin);
			for (i = 0; i < c_domain->stat._length; i++) {
				item = malloc(sizeof *item);
				CL_CONTENT(item) = (void *) strdup(c_domain->stat._buffer[i]);
				CL_ADD(cdata->out->info_domain.status, item);
			}
			for (i = 0; i < c_domain->admin._length; i++) {
				item = malloc(sizeof *item);
				CL_CONTENT(item) = (void *) strdup(c_domain->admin._buffer[i]);
				CL_ADD(cdata->out->info_domain.admin, item);
			}

			cdata->svTRID = strdup(response->svTRID);
			cdata->rc = response->errCode;
			ret = CORBA_OK;
		}
	}

	CORBA_free(response);
	CORBA_free(c_domain);

	return ret;
}

corba_status
epp_call_info_nsset(epp_corba_globs *globs, int session, epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	corba_status	ret;
	ccReg_Response	*response;
	ccReg_NSSet	*c_nsset;

	CORBA_exception_init(ev);

	response = ccReg_EPP_NSSetInfo(globs->service,
			cdata->in->info.id,
			&c_nsset,
			session,
			cdata->clTRID,
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
		ret = CORBA_REMOTE_ERROR;
	}
	else {
		struct circ_list	*item;

		if ((cdata->out = calloc(1, sizeof (*cdata->out))) == NULL)
			ret = CORBA_INT_ERROR;
		else if ((cdata->out->info_nsset.status = malloc(sizeof *item)) == NULL)
		{
			free(cdata->out);
			cdata->out = NULL;
			ret = CORBA_INT_ERROR;
		}
		else if ((cdata->out->info_nsset.ns = malloc(sizeof *item)) == NULL)
		{
			free(cdata->out->info_nsset.status);
			free(cdata->out);
			cdata->out = NULL;
			ret = CORBA_INT_ERROR;
		}
		else if ((cdata->out->info_nsset.tech = malloc(sizeof *item)) == NULL)
		{
			free(cdata->out->info_nsset.ns);
			free(cdata->out->info_nsset.status);
			free(cdata->out);
			cdata->out = NULL;
			ret = CORBA_INT_ERROR;
		}
		/* ok, now alomost everything was successfully allocated */
		else {
			int i, j;

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

			cdata->svTRID = strdup(response->svTRID);
			cdata->rc = response->errCode;
			ret = CORBA_OK;
		}
	}

	CORBA_free(response);
	CORBA_free(c_nsset);

	return ret;
}

corba_status
epp_call_poll_req(epp_corba_globs *globs, int session, epp_command_data *cdata)
{
	ccReg_Response	*response;
	corba_status	ret;
	CORBA_Environment	ev[1];
	CORBA_short	c_count;
	CORBA_long	c_msgID;
	ccReg_timestamp	c_qdate;
	CORBA_char	*c_msg;

	CORBA_exception_init(ev);

	response = ccReg_EPP_PollRequest(globs->service,
			&c_msgID,
			&c_count,
			&c_qdate,
			&c_msg,
			session,
			cdata->clTRID,
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
		CORBA_free(c_msg);
		return CORBA_REMOTE_ERROR;
	}

	if ((cdata->out = calloc(1, sizeof (*cdata->out))) == NULL)
		ret = CORBA_INT_ERROR;
	else {
		cdata->out->poll_req.count = c_count;
		cdata->out->poll_req.msgid = c_msgID;
		cdata->out->poll_req.qdate = c_qdate;
		cdata->out->poll_req.msg = strdup(c_msg);

		cdata->svTRID = strdup(response->svTRID);
		cdata->rc = response->errCode;
	}

	CORBA_free(c_msg);
	CORBA_free(response);
	return CORBA_OK;
}

corba_status
epp_call_poll_ack(epp_corba_globs *globs, int session, epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	CORBA_long	c_msgID;
	CORBA_short	c_count;
	ccReg_Response *response;
	corba_status	ret;

	assert(cdata->in != NULL);
	CORBA_exception_init(ev);

	response = ccReg_EPP_PollAcknowledgement(globs->service,
			cdata->in->poll_ack.msgid,
			&c_count,
			&c_msgID,
			session,
			cdata->clTRID,
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

corba_status
epp_call_create_domain(epp_corba_globs *globs, int session,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	ccReg_timestamp	c_crDate;
	ccReg_timestamp	c_exDate;
	ccReg_Response *response;
	ccReg_AdminContact	*c_admin;
	int	len, i;

	assert(cdata->in != NULL);
	CORBA_exception_init(ev);

	c_admin = ccReg_AdminContact__alloc();
	CL_LENGTH(cdata->in->create_domain.admin, len);
	c_admin->_buffer = ccReg_AdminContact_allocbuf(len);
	c_admin->_length = len;
	i = 0;
	CL_FOREACH(cdata->in->create_domain.admin)
		c_admin->_buffer[i++] = CORBA_string_dup(
				CL_CONTENT(cdata->in->create_domain.admin));

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
			ev);

	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		CORBA_exception_free(ev);
		CORBA_free(c_admin);
		return CORBA_ERROR;
	}
	CORBA_exception_free(ev);

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		CORBA_free(c_admin);
		CORBA_free(response);
		return CORBA_REMOTE_ERROR;
	}

	if ((cdata->out = calloc(1, sizeof (*cdata->out))) == NULL) {
		CORBA_free(c_admin);
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}

	cdata->out->create.crDate = c_crDate;
	cdata->out->create.exDate = c_exDate;

	cdata->svTRID = strdup(response->svTRID);
	cdata->rc = response->errCode;

	CORBA_free(c_admin);
	CORBA_free(response);
	return CORBA_OK;
}

corba_status
epp_call_create_contact(epp_corba_globs *globs, int session,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	ccReg_timestamp	c_crDate;
	ccReg_Response *response;
	ccReg_ContactChange	*c_contact;

	assert(cdata->in != NULL);
	CORBA_exception_init(ev);

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
	c_contact->Name = CORBA_string_dup(cdata->in->create_contact.postalInfo->name);
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
	c_contact->Country =
		CORBA_string_dup(cdata->in->create_contact.postalInfo->cc);

	response = ccReg_EPP_ContactCreate(globs->service,
			cdata->in->create_contact.id,
			c_contact,
			&c_crDate,
			session,
			cdata->clTRID,
			ev);

	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		CORBA_exception_free(ev);
		CORBA_free(c_contact);
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

	if ((cdata->out = calloc(1, sizeof (*cdata->out))) == NULL) {
		CORBA_free(c_contact);
		CORBA_free(response);
		return CORBA_INT_ERROR;
	}

	cdata->out->create.crDate = c_crDate;
	cdata->svTRID = strdup(response->svTRID);
	cdata->rc = response->errCode;

	CORBA_free(c_contact);
	CORBA_free(response);
	return CORBA_OK;
}

corba_status
epp_call_create_nsset(epp_corba_globs *globs, int session,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	ccReg_timestamp	c_crDate;
	ccReg_Response *response;
	ccReg_DNSHost	*c_dnshost;
	ccReg_TechContact	*c_tech;
	epp_ns	*ns;
	corba_status	ret;
	int	len, i, j;

	assert(cdata->in != NULL);
	CORBA_exception_init(ev);

	/* alloc & init sequence of nameservers */
	c_dnshost = ccReg_DNSHost__alloc();
	CL_LENGTH(cdata->in->create_nsset.ns, len);
	c_dnshost->_buffer = ccReg_DNSHost_allocbuf(len);
	c_dnshost->_length = len;
	i = 0;
	CL_FOREACH(cdata->in->create_nsset.ns) {
		/* alloc & init sequence of ns's addresses */
		ns = (epp_ns *) CL_CONTENT(cdata->in->create_nsset.ns);
		CL_LENGTH(ns->addr, len);
		c_dnshost->_buffer[i].inet._buffer = ccReg_InetAddress_allocbuf(len);
		c_dnshost->_buffer[i].inet._length = len;
		j = 0;
		CL_FOREACH(ns->addr)
			c_dnshost->_buffer[i].inet._buffer[j++] =
					CORBA_string_dup(CL_CONTENT(ns->addr));
		c_dnshost->_buffer[i++].fqdn = CORBA_string_dup(ns->name);
	}
	/* alloc & init sequence of tech contacts */
	c_tech = ccReg_TechContact__alloc();
	CL_LENGTH(cdata->in->create_nsset.tech, len);
	c_tech->_buffer = ccReg_TechContact_allocbuf(len);
	c_tech->_length = len;
	i = 0;
	CL_FOREACH(cdata->in->create_nsset.tech)
		c_tech->_buffer[i++] = CORBA_string_dup(
				CL_CONTENT(cdata->in->create_nsset.tech));

	response = ccReg_EPP_NSSetCreate(globs->service,
			cdata->in->create_nsset.id,
			cdata->in->create_nsset.authInfo,
			c_tech,
			c_dnshost,
			&c_crDate,
			session,
			cdata->clTRID,
			ev);

	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		CORBA_exception_free(ev);
		CORBA_free(c_tech);
		for (i = 0; i < c_dnshost->_length; i++)
			CORBA_free(c_dnshost->_buffer[i].inet._buffer);
		CORBA_free(c_dnshost);
		return CORBA_ERROR;
	}
	CORBA_exception_free(ev);

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		ret = CORBA_REMOTE_ERROR;
	}
	else {
		if ((cdata->out = calloc(1, sizeof (*cdata->out))) == NULL) {
			ret = CORBA_INT_ERROR;
		}
		else {
			cdata->out->create.crDate = c_crDate;
			cdata->svTRID = strdup(response->svTRID);
			cdata->rc = response->errCode;
			ret = CORBA_OK;
		}
	}

	CORBA_free(c_tech);
	for (i = 0; i < c_dnshost->_length; i++)
		CORBA_free(c_dnshost->_buffer[i].inet._buffer);
	CORBA_free(c_dnshost);
	CORBA_free(response);
	return CORBA_OK;
}

static corba_status
epp_call_delete(epp_corba_globs *globs, int session,
		epp_command_data *cdata, epp_object_type obj)
{
	ccReg_Response *response;
	CORBA_Environment ev[1];

	CORBA_exception_init(ev);

	if (obj == EPP_DOMAIN)
		response = ccReg_EPP_DomainDelete(globs->service,
				cdata->in->delete.id,
				session,
				cdata->clTRID,
				ev);
	else if (obj == EPP_CONTACT)
		response = ccReg_EPP_ContactDelete(globs->service,
				cdata->in->delete.id,
				session,
				cdata->clTRID,
				ev);
	else {
		assert(obj == EPP_NSSET);
		response = ccReg_EPP_NSSetDelete(globs->service,
				cdata->in->delete.id,
				session,
				cdata->clTRID,
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

	cdata->svTRID = strdup(response->svTRID);
	cdata->rc = response->errCode;

	CORBA_free(response);
	return CORBA_OK;
}

corba_status
epp_call_delete_domain(epp_corba_globs *globs, int session,
		epp_command_data *cdata)
{
	assert(cdata->in != NULL);
	return epp_call_delete(globs, session, cdata, EPP_DOMAIN);
}

corba_status
epp_call_delete_contact(epp_corba_globs *globs, int session,
		epp_command_data *cdata)
{
	assert(cdata->in != NULL);
	return epp_call_delete(globs, session, cdata, EPP_CONTACT);
}

corba_status
epp_call_delete_nsset(epp_corba_globs *globs, int session,
		epp_command_data *cdata)
{
	assert(cdata->in != NULL);
	return epp_call_delete(globs, session, cdata, EPP_NSSET);
}

corba_status
epp_call_renew_domain(epp_corba_globs *globs, int session,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	ccReg_Response *response;

	assert(cdata->in != NULL);
	CORBA_exception_init(ev);

	response = ccReg_EPP_DomainRenew(globs->service,
			cdata->in->renew.name,
			cdata->in->renew.exDate,
			cdata->in->renew.period,
			session,
			cdata->clTRID,
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

	cdata->svTRID = strdup(response->svTRID);
	cdata->rc = response->errCode;

	CORBA_free(response);
	return CORBA_OK;
}

corba_status
epp_call_update_domain(epp_corba_globs *globs, int session,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	ccReg_Response *response;
	ccReg_AdminContact	*c_admin_add;
	ccReg_AdminContact	*c_admin_rem;
	ccReg_Status	*c_status_add;
	ccReg_Status	*c_status_rem;
	corba_status	ret;
	int	i, len;

	assert(cdata->in != NULL);
	CORBA_exception_init(ev);

	/* admin add */
	c_admin_add = ccReg_AdminContact__alloc();
	CL_LENGTH(cdata->in->update_domain.add_admin, len);
	c_admin_add->_buffer = ccReg_AdminContact_allocbuf(len);
	c_admin_add->_length = len;
	i = 0;
	CL_FOREACH(cdata->in->update_domain.add_admin)
		c_admin_add->_buffer[i++] =
				CL_CONTENT(cdata->in->update_domain.add_admin);
	/* admin rem */
	c_admin_rem = ccReg_AdminContact__alloc();
	CL_LENGTH(cdata->in->update_domain.rem_admin, len);
	c_admin_rem->_buffer = ccReg_AdminContact_allocbuf(len);
	c_admin_rem->_length = len;
	i = 0;
	CL_FOREACH(cdata->in->update_domain.rem_admin)
		c_admin_rem->_buffer[i++] =
				CL_CONTENT(cdata->in->update_domain.rem_admin);
	/* status add */
	c_status_add = ccReg_Status__alloc();
	CL_LENGTH(cdata->in->update_domain.add_status, len);
	c_status_add->_buffer = ccReg_Status_allocbuf(len);
	c_status_add->_length = len;
	i = 0;
	CL_FOREACH(cdata->in->update_domain.add_status)
		c_status_add->_buffer[i++] =
				CL_CONTENT(cdata->in->update_domain.add_status);
	/* status rem */
	c_status_rem = ccReg_Status__alloc();
	CL_LENGTH(cdata->in->update_domain.rem_status, len);
	c_status_rem->_buffer = ccReg_Status_allocbuf(len);
	c_status_rem->_length = len;
	i = 0;
	CL_FOREACH(cdata->in->update_domain.rem_status)
		c_status_rem->_buffer[i++] =
				CL_CONTENT(cdata->in->update_domain.rem_status);

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
			ev);

	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		CORBA_exception_free(ev);
		CORBA_free(c_status_rem);
		CORBA_free(c_status_add);
		CORBA_free(c_admin_rem);
		CORBA_free(c_admin_add);
		return CORBA_ERROR;
	}
	CORBA_exception_free(ev);

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		ret = CORBA_REMOTE_ERROR;
	}
	else {
		cdata->svTRID = strdup(response->svTRID);
		cdata->rc = response->errCode;
		ret = CORBA_OK;
	}

	CORBA_free(c_status_rem);
	CORBA_free(c_status_add);
	CORBA_free(c_admin_rem);
	CORBA_free(c_admin_add);
	CORBA_free(response);
	return ret;
}

corba_status
epp_call_update_contact(epp_corba_globs *globs, int session,
		epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	ccReg_Response *response;
	ccReg_Status	*c_status_add;
	ccReg_Status	*c_status_rem;
	ccReg_ContactChange	*c_contact;
	corba_status	ret;
	int	i, len;

	assert(cdata->in != NULL);
	CORBA_exception_init(ev);

	/* status add */
	c_status_add = ccReg_Status__alloc();
	CL_LENGTH(cdata->in->update_contact.add_status, len);
	c_status_add->_buffer = ccReg_Status_allocbuf(len);
	c_status_add->_length = len;
	i = 0;
	CL_FOREACH(cdata->in->update_contact.add_status)
		c_status_add->_buffer[i++] =
				CL_CONTENT(cdata->in->update_contact.add_status);
	/* status rem */
	c_status_rem = ccReg_Status__alloc();
	CL_LENGTH(cdata->in->update_contact.rem_status, len);
	c_status_rem->_buffer = ccReg_Status_allocbuf(len);
	c_status_rem->_length = len;
	i = 0;
	CL_FOREACH(cdata->in->update_contact.rem_status)
		c_status_rem->_buffer[i++] =
				CL_CONTENT(cdata->in->update_contact.rem_status);
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
	c_contact->Country =
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

	response = ccReg_EPP_ContactUpdate(globs->service,
			cdata->in->update_contact.id,
			c_contact,
			c_status_add,
			c_status_rem,
			session,
			cdata->clTRID,
			ev);

	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		CORBA_exception_free(ev);
		CORBA_free(c_status_rem);
		CORBA_free(c_status_add);
		CORBA_free(c_contact);
		return CORBA_ERROR;
	}
	CORBA_exception_free(ev);

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		ret = CORBA_REMOTE_ERROR;
	}
	else {
		cdata->svTRID = strdup(response->svTRID);
		cdata->rc = response->errCode;
		ret = CORBA_OK;
	}

	CORBA_free(c_status_rem);
	CORBA_free(c_status_add);
	CORBA_free(c_contact);
	CORBA_free(response);
	return ret;
}

corba_status
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
	corba_status	ret;
	epp_ns	*ns;
	int	i, j, len;

	assert(cdata->in != NULL);
	CORBA_exception_init(ev);

	/* tech add */
	c_tech_add = ccReg_TechContact__alloc();
	CL_LENGTH(cdata->in->update_nsset.add_tech, len);
	c_tech_add->_buffer = ccReg_TechContact_allocbuf(len);
	c_tech_add->_length = len;
	i = 0;
	CL_FOREACH(cdata->in->update_nsset.add_tech)
		c_tech_add->_buffer[i++] =
				CL_CONTENT(cdata->in->update_nsset.add_tech);
	/* Tech rem */
	c_tech_rem = ccReg_TechContact__alloc();
	CL_LENGTH(cdata->in->update_nsset.rem_tech, len);
	c_tech_rem->_buffer = ccReg_TechContact_allocbuf(len);
	c_tech_rem->_length = len;
	i = 0;
	CL_FOREACH(cdata->in->update_nsset.rem_tech)
		c_tech_rem->_buffer[i++] =
				CL_CONTENT(cdata->in->update_nsset.rem_tech);
	/* status add */
	c_status_add = ccReg_Status__alloc();
	CL_LENGTH(cdata->in->update_nsset.add_status, len);
	c_status_add->_buffer = ccReg_Status_allocbuf(len);
	c_status_add->_length = len;
	i = 0;
	CL_FOREACH(cdata->in->update_nsset.add_status)
		c_status_add->_buffer[i++] =
				CL_CONTENT(cdata->in->update_nsset.add_status);
	/* status rem */
	c_status_rem = ccReg_Status__alloc();
	CL_LENGTH(cdata->in->update_nsset.rem_status, len);
	c_status_rem->_buffer = ccReg_Status_allocbuf(len);
	c_status_rem->_length = len;
	i = 0;
	CL_FOREACH(cdata->in->update_nsset.rem_status)
		c_status_rem->_buffer[i++] =
				CL_CONTENT(cdata->in->update_nsset.rem_status);
	/* name servers add */
	c_dnshost_add = ccReg_DNSHost__alloc();
	CL_LENGTH(cdata->in->update_nsset.add_ns, len);
	c_dnshost_add->_buffer = ccReg_DNSHost_allocbuf(len);
	c_dnshost_add->_length = len;
	i = 0;
	CL_FOREACH(cdata->in->update_nsset.add_ns) {
		/* alloc & init sequence of ns's addresses */
		ns = (epp_ns *) CL_CONTENT(cdata->in->update_nsset.add_ns);
		CL_LENGTH(ns->addr, len);
		c_dnshost_add->_buffer[i].inet._buffer = ccReg_InetAddress_allocbuf(len);
		c_dnshost_add->_buffer[i].inet._length = len;
		j = 0;
		CL_FOREACH(ns->addr)
			c_dnshost_add->_buffer[i].inet._buffer[j] =
					CORBA_string_dup(CL_CONTENT(ns->addr));
		c_dnshost_add->_buffer[i++].fqdn = CORBA_string_dup(ns->name);
	}
	/* name servers rem */
	c_dnshost_rem = ccReg_DNSHost__alloc();
	CL_LENGTH(cdata->in->update_nsset.rem_ns, len);
	c_dnshost_rem->_buffer = ccReg_DNSHost_allocbuf(len);
	c_dnshost_rem->_length = len;
	i = 0;
	CL_FOREACH(cdata->in->update_nsset.rem_ns) {
		/* alloc & init sequence of ns's addresses */
		ns = (epp_ns *) CL_CONTENT(cdata->in->update_nsset.rem_ns);
		CL_LENGTH(ns->addr, len);
		c_dnshost_rem->_buffer[i].inet._buffer = ccReg_InetAddress_allocbuf(len);
		c_dnshost_rem->_buffer[i].inet._length = len;
		j = 0;
		CL_FOREACH(ns->addr)
			c_dnshost_rem->_buffer[i].inet._buffer[j] =
					CORBA_string_dup(CL_CONTENT(ns->addr));
		c_dnshost_rem->_buffer[i++].fqdn = CORBA_string_dup(ns->name);
	}

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
			ev);

	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		CORBA_exception_free(ev);
		CORBA_free(c_status_rem);
		CORBA_free(c_status_add);
		CORBA_free(c_tech_rem);
		CORBA_free(c_tech_add);
		CORBA_free(c_dnshost_rem);
		CORBA_free(c_dnshost_add);
		return CORBA_ERROR;
	}
	CORBA_exception_free(ev);

	/*
	 * in case of an error of EPP server (CR) the svTRID field is
	 * empty string
	 */
	if (*response->svTRID == '\0') {
		ret = CORBA_REMOTE_ERROR;
	}
	else {
		cdata->svTRID = strdup(response->svTRID);
		cdata->rc = response->errCode;
		ret = CORBA_OK;
	}

	CORBA_free(c_status_rem);
	CORBA_free(c_status_add);
	CORBA_free(c_tech_rem);
	CORBA_free(c_tech_add);
	CORBA_free(c_dnshost_rem);
	CORBA_free(c_dnshost_add);
	CORBA_free(response);
	return ret;
}

static corba_status
epp_call_transfer(epp_corba_globs *globs, int session,
		epp_command_data *cdata, epp_object_type obj)
{
	CORBA_Environment ev[1];
	ccReg_Response *response;

	CORBA_exception_init(ev);

	if (obj == EPP_DOMAIN)
		response = ccReg_EPP_DomainTransfer(globs->service,
				cdata->in->transfer.id,
				cdata->in->transfer.authInfo,
				session,
				cdata->clTRID,
				ev);
	else {
		assert(obj == EPP_NSSET);
		response = ccReg_EPP_NSSetTransfer(globs->service,
				cdata->in->transfer.id,
				cdata->in->transfer.authInfo,
				session,
				cdata->clTRID,
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

	cdata->svTRID = strdup(response->svTRID);
	cdata->rc = response->errCode;
	CORBA_free(response);
	return CORBA_OK;
}

corba_status
epp_call_transfer_domain(epp_corba_globs *globs, int session,
		epp_command_data *cdata)
{
	assert(cdata->in != NULL);
	return epp_call_transfer(globs, session, cdata, EPP_DOMAIN);
}

corba_status
epp_call_transfer_nsset(epp_corba_globs *globs, int session,
		epp_command_data *cdata)
{
	assert(cdata->in != NULL);
	return epp_call_transfer(globs, session, cdata, EPP_NSSET);
}
