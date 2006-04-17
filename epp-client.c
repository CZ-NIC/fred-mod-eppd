/**
 * Copyright statement ;)
 */

#include <string.h>
#include <orbit/orbit.h>

/* This header file was generated from the idl */
#include "ccReg.h"
#include "epp-client.h"

#define raised_exception(ev)	((ev)->_major != CORBA_NO_EXCEPTION)


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


/**
 * Import object from file.
 */
static CORBA_Object
import_object_from_file (CORBA_ORB orb, CORBA_char *filename,
			      CORBA_Environment *ev)
{
        FILE         *file;
	gchar        *objref;
        CORBA_Object  obj = CORBA_OBJECT_NIL;
  
        if ((file = fopen(filename, "r")) == NULL) {
		ev->_major = CORBA_SYSTEM_EXCEPTION;
		return CORBA_OBJECT_NIL;		
     	}
	objref = read_string_from_stream(file);

	if (!objref || strlen(objref) == 0) {
		if (objref) g_free (objref);
		ev->_major = CORBA_SYSTEM_EXCEPTION;
		fclose (file);
		return CORBA_OBJECT_NIL;		
	}

	obj = (CORBA_Object) CORBA_ORB_string_to_object(orb, objref, ev);
	free (objref);

	fclose (file);
	return obj;
}
 
orb_rc_t
corba_init(void **service, void **orb)
{
	CORBA_ORB  global_orb = CORBA_OBJECT_NIL; /* global orb */
	ccReg_EPP e_service = CORBA_OBJECT_NIL;
	CORBA_Environment ev[1];
	CORBA_exception_init(ev);
	CORBA_char filename[] = "/tmp/ccReg.ref";
 
	global_orb = CORBA_ORB_init(0, NULL, "orbit-local-orb", ev);
	if (raised_exception(ev)) {
		if (global_orb != CORBA_OBJECT_NIL) CORBA_ORB_destroy(global_orb, ev);
		return ORB_EINIT;
	}

	e_service = (ccReg_EPP)
		import_object_from_file(global_orb, filename, ev);
	if (raised_exception(ev)) {
		/* releasing managed object */
		CORBA_Object_release(e_service, ev);
		/* tear down the ORB */
		if (global_orb != CORBA_OBJECT_NIL)
			CORBA_ORB_destroy(global_orb, ev);
		return ORB_EIMPORT;
	}

	*orb = (void *) global_orb;
	*service = (void *) e_service;
	return ORB_OK;
}

void
corba_cleanup(void *service, void *orb)
{
	CORBA_Environment ev[1];
	CORBA_exception_init(ev);

	/* releasing managed object */
	CORBA_Object_release((ccReg_EPP) service, ev);
	/* tear down the ORB */
	CORBA_ORB_destroy((CORBA_ORB) global_orb, ev);
}

orb_rc_t
corba_login(void *par_service, epp_login_data *login_data)
{
	ccReg_Response *response;
	ccReg_EPP service = (ccReg_EPP) par_service;

	response = ccReg_EPP_ClientLogin(service , ...);
	if (raised_exception(ev)) {
		/* do NOT try to free dm even if not NULL -> segfault */
		return ORB_ESERVICE;
	}

	login_data->sessionID = response->clientID;
	login_data->svTRID = strdup(response->svTRID);
	login_data->rc = response->errCode;

	CORBA_free(response);
	return ORB_OK;
}

orb_rc_t
corba_logout(void *par_service, int sessionID, epp_logout_data *logout_data)
{
	ccReg_Response *response;
	ccReg_EPP service = (ccReg_EPP) par_service;

	response = ccReg_EPP_ClientLogout(service , sessionID, logout_data->clTRID);
	if (raised_exception(ev)) {
		/* do NOT try to free dm even if not NULL -> segfault */
		return ORB_ESERVICE;
	}

	logout_data->svTRID = strdup(response->svTRID);
	logout_data->rc = response->errCode;

	CORBA_free(response);
	return ORB_OK;
}

