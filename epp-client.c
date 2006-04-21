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
epp_call_login(void *globs, int *session, epp_command_data *cdata)
{
	CORBA_Environment ev[1];
	ccReg_Response *response;
	CORBA_exception_init(ev);

	response = ccReg_EPP_ClientLogin(((epp_corba_globs *) globs)->service,
			cdata->un.login.clID,
			cdata->clTRID,
			cdata->un.login.pw,
			cdata->un.login.newPW,
			session,
			ev);
	if (raised_exception(ev)) {
		/* do NOT try to free response even if not NULL -> segfault */
		return CORBA_ERROR;
	}

	assert(cdata->svTRID);

	cdata->svTRID = strdup(response->svTRID);
	cdata->rc = response->errCode;

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

	assert(cdata->svTRID);

	cdata->svTRID = strdup(response->svTRID);
	cdata->rc = response->errCode;

	CORBA_free(response);
	return CORBA_OK;
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

	assert(cdata->svTRID);

	cdata->svTRID = strdup(response->svTRID);

	CORBA_free(response);
	return CORBA_OK;
}
