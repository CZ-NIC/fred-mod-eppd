#ifndef EPP_CLIENT_H
#define EPP_CLIENT_H

/* possible return values from corba wrapper functions */
typedef enum {
	CORBA_OK,
	/* corba function call failed (e.g. server is not available) */
	CORBA_ERROR,
	/*
	 * epp server is ok but cannot send qualified response because of an error
	 */
	CORBA_REMOTE_ERROR
} corba_status;

/*
 * Corba global-like variables which is opaque to apache
 * and are used in subsequent corba function calls are returned by this
 * function.
 * @par iorfile File where is stored service handle
 * @ret corba_globs or NULL in case of failure
 */
void *epp_corba_init(const char *iorfile);

/**
 * corba_init_cleanup releases global-like variables.
 * @par corba_globs Corba global-like variables
 */
void epp_corba_init_cleanup(void *corba_globs);

/**
 * Call corba login function. Note that session variable might be altered,
 * this is not possible in other corba calls.
 * @par corba_globs Corba global-like variables
 * @par session Session identifier
 * @par cdata Necessary input data
 * @ret CORBA_OK if succesful
 */
corba_status
epp_call_login(void *corba_globs, int *session, epp_command_data *cdata);

/**
 * Call corba logout function.
 * @par corba_globs Corba global-like variables
 * @par session Session identifier
 * @par cdata Necessary input data
 * @ret CORBA_OK if succesful
 */
corba_status
epp_call_logout(void *corba_globs, int session, epp_command_data *cdata);

/**
 * Call corba getsvTRID function. This is mostly used for generating error
 * messages.
 * @par corba_globs Corba global-like variables
 * @par session Session identifier
 * @par cdata Necessary input data
 * @ret CORBA_OK if succesful
 */
corba_status
epp_call_dummy(void *corba_globs, int session, epp_command_data *cdata);

/* Query Commands
typedef struct {
	int dummy;
} epp_data_check;

typedef struct {
	int dummy;
} epp_data_info;

typedef struct {
	int dummy;
} epp_data_poll;

typedef struct {
	int dummy;
} epp_data_transfer_query;
*/

/* Tranfer Commands
typedef struct {
	int dummy;
} epp_data_create;

typedef struct {
	int dummy;
} epp_data_delete;

typedef struct {
	int dummy;
} epp_data_renew;

typedef struct {
	int dummy;
} epp_data_tranfer_transform;

typedef struct {
	int dummy;
} epp_data_update;
*/

#endif /* EPP_CLIENT_H */
