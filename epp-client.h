/**
 * @file epp-client.h
 *
 * Interface definition of corba module.
 */
#ifndef EPP_CLIENT_H
#define EPP_CLIENT_H

#include "epp_common.h"

/** Possible return values of functions from corba module. */
typedef enum {
	CORBA_OK,   /**< No errors. */
	/**
	 * Corba function call failed (e.g. server is not available).
	 */
	CORBA_ERROR,
	CORBA_INT_ERROR, /**< This should occur unusualy (e.g. malloc failed) */
	/**
	 * Epp server is responding but cannot send qualified response
	 * because of an error on its side.
	 */
	CORBA_REMOTE_ERROR
}corba_status;

typedef void *service_EPP;

/**
 * Purpose of this function is to get version string of ccReg from
 * corba server, which is used as part of server's name in <greeting>
 * frame.
 *
 * @param pool        Pool for memory allocations.
 * @param service     EPP service.
 * @param version     Output parameter version string.
 * @param curdate     Output parameter current date.
 * @return            If successfull 1 and 0 if corba function call failed.
 */
int
epp_call_hello(void *pool,
		service_EPP  service,
		char **version,
		char **curdate);

/**
 * Call corba login function, which sets up a session variables.
 *
 * @param pool        Pool for memory allocations.
 * @param service     EPP service.
 * @param session     If successfully logged in, the session identifier assigned
 *                    by server will be stored in this parameter.
 * @param lang        If successfully logged in, the selected language will be
 *                    stored in this parameter.
 * @param fingerprint Fingerprint of client's certificate.
 * @param cdata       Data from parsed xml command.
 * @return            Status.
 */
corba_status
epp_call_login(void *pool,
		service_EPP service,
		int *session,
		epp_lang *lang,
		const char *fingerprint,
		epp_command_data *cdata);

/**
 * Call corba logout function.
 *
 * @param pool        Pool for memory allocations.
 * @param service     EPP service.
 * @param session     Session identifier.
 * @param cdata       Data from parsed xml command.
 * @param logout      Tells whether the client should be really logged out
 * @return            Status.
 */
corba_status
epp_call_logout(void *pool,
		service_EPP service,
		int session,
		epp_command_data *cdata,
		int *logout);

/**
 * Call generic command corba handler which decides what to do on the basis
 * of cdata content.
 *
 * login, logout commands are not handled by this function.
 * They are rather handled by dedicated functions epp_call_login() and
 * epp_call_logout(). For all other commands use this function.
 *
 * @param pool        Pool for memory allocations.
 * @param service     EPP service.
 * @param session     Session identifier
 * @param cdata       Data from parsed xml command.
 * @return            Status.
 */
corba_status
epp_call_cmd(void *pool,
		service_EPP service,
		int session,
		epp_command_data *cdata);

/**
 * This function calls corba function which saves generated XML in database.
 *
 * From architectural view THIS IS UGLY HACK! And until
 * serving of EPP request will become complex operation composed from
 * several function calls, it will remain so.
 *
 * @param service     EPP service.
 * @param cdata       Used to get svTRID.
 * @param xml         Output XML.
 */
void
epp_call_save_output_xml(service_EPP service,
		epp_command_data *cdata,
		const char *xml);

#endif /* EPP_CLIENT_H */
