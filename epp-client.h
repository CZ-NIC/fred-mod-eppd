#ifndef EPP_CLIENT_H
#define EPP_CLIENT_H

#include "epp_common.h"

/* possible return values from corba wrapper functions */
typedef enum {
	CORBA_OK,
	/* corba function call failed (e.g. server is not available) */
	CORBA_ERROR,
	/* this should be really unusual (e.g. malloc failed) */
	CORBA_INT_ERROR,
	/*
	 * epp server is ok but cannot send qualified response because of an error
	 */
	CORBA_REMOTE_ERROR
}corba_status;

/**
 * Opaque structure which stores variables needed for corba calls.
 */
typedef struct epp_corba_globs_t epp_corba_globs;

/**
 * Corba global-like variables which is opaque to apache
 * and are used in subsequent corba function calls are returned by this
 * function.
 * @par iorfile File where is stored service handle
 * @ret corba_globs or NULL in case of failure
 */
epp_corba_globs *epp_corba_init(const char *iorfile);

/**
 * corba_init_cleanup releases global-like variables.
 * @par corba_globs Corba global-like variables
 */
void epp_corba_init_cleanup(epp_corba_globs *corba_globs);

/**
 * Call corba getsvTRID function. This is mostly used for generating error
 * messages.
 * @par corba_globs Corba global-like variables
 * @par session Session identifier
 * @par cdata Necessary input data
 * @ret CORBA_OK if succesful
 */
corba_status
epp_corba_call(
		epp_corba_globs *globs,
		int *session,
		epp_lang *lang,
		char *fingerprint,
		epp_command_data *cdata,
		int *logout);

#endif /* EPP_CLIENT_H */
