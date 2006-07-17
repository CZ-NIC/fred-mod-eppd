/**
 * @file epp-client.h
 * Interface definition of corba module.
 */
#ifndef EPP_CLIENT_H
#define EPP_CLIENT_H

#include "epp_common.h"

/** Possible return values of functions from corba module. */
typedef enum {
	CORBA_OK,	/**< No errors. */
	CORBA_ERROR,/**< Corba function call failed (e.g. server is not available) */
	CORBA_INT_ERROR, /**< This should occur unusualy (e.g. malloc failed) */
	/**
	 * epp server is responding but cannot send qualified response
	 * because of an error on its side.
	 */
	CORBA_REMOTE_ERROR
}corba_status;

/**
 * Opaque structure which stores variables needed for corba function calls.
 */
typedef struct epp_corba_globs_t epp_corba_globs;

/**
 * Corba module initialization.
 * The most important step in corba module initialization is EPP service
 * creation, which is specified by ior. This object reference is used
 * in all subsequent corba function calls, no matter to which connection
 * they belong.
 *
 * @param iorfile A file where is stored service's reference
 * @return corba_globs or NULL in case of failure
 */
epp_corba_globs *
epp_corba_init(const char *iorfile);

/**
 * corba_init_cleanup releases resources allocated in epp_corba_init().
 *
 * @param corba_globs Corba context.
 */
void
epp_corba_init_cleanup(epp_corba_globs *corba_globs);

/**
 * Purpose of this function is to get version string of ccReg from
 * corba server, which is used as part of server's name in <greeting>
 * frame.
 *
 * @param corba_globs Corba context.
 * @param buf Allocated buffer for version string.
 * @param len Length of allocated buffer (version string is truncated
 * if longer then len - 1).
 * @return If successfull 1 and 0 if corba function call failed.
 */
int
epp_call_hello(epp_corba_globs *corba_globs, char *buf, unsigned len);

/**
 * Call corba login function, which sets up a session variables.
 *
 * @param corba_globs Corba context.
 * @param session If successfully logged in, the session identifier assigned
 * by server will be stored in this paramter.
 * stored in this parameter.
 * @param lang If successfully logged in, the selected language will be
 * stored in this parameter.
 * @param fingerprint Fingerprint of client's certificate.
 * @param cdata Data from parsed xml command.
 * @return status (see #corba_status).
 */
corba_status
epp_call_login(
		epp_corba_globs *corba_globs,
		int *session,
		epp_lang *lang,
		char *fingerprint,
		epp_command_data *cdata);

/**
 * Call corba logout function.
 *
 * @param corba_globs Corba context.
 * @param session Session identifier.
 * @param cdata Data from parsed xml command.
 * @param logout Tells whether the client should be really logged out
 * (ussually means whether the connection should be terminated).
 * @return status (see #corba_status).
 */
corba_status
epp_call_logout(
		epp_corba_globs *corba_globs,
		int session,
		epp_command_data *cdata,
		int *logout);

/**
 * Call generic command corba handler which decides what to do on the basis
 * of cdata content. login, logout commands are not handled by this function.
 * They are rather handled by dedicated functions epp_call_login() and
 * epp_call_logout(). For all other commands use this function.
 *
 * @param corba_globs Corba context.
 * @param session Session identifier
 * @param cdata Data from parsed xml command.
 * @return status (see #corba_status).
 */
corba_status
epp_call_cmd(epp_corba_globs *corba_globs, int session, epp_command_data *cdata);

#endif /* EPP_CLIENT_H */
