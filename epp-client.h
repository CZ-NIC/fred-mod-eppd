#ifndef EPP_CLIENT_H
#define EPP_CLIENT_H

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
 * Call corba getsvTRID function. This is mostly used for generating error
 * messages.
 * @par corba_globs Corba global-like variables
 * @par session Session identifier
 * @par cdata Necessary input data
 * @ret CORBA_OK if succesful
 */
corba_status
epp_call_dummy(void *corba_globs, int session, epp_command_data *cdata);

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
 * Call corba check contact function.
 * @par corba_globs Corba global-like variables
 * @par session Session identifier
 * @par cdata Necessary input data
 * @ret CORBA_OK if succesful
 */
corba_status
epp_call_check_contact(void *corba_globs, int session, epp_command_data *cdata);

/**
 * Call corba check domain function.
 * @par corba_globs Corba global-like variables
 * @par session Session identifier
 * @par cdata Necessary input data
 * @ret CORBA_OK if succesful
 */
corba_status
epp_call_check_domain(void *corba_globs, int session, epp_command_data *cdata);

/**
 * Call corba check nsset function.
 * @par corba_globs Corba global-like variables
 * @par session Session identifier
 * @par cdata Necessary input data
 * @ret CORBA_OK if succesful
 */
corba_status
epp_call_check_nsset(void *corba_globs, int session, epp_command_data *cdata);

/**
 * Call corba info contact function.
 * @par corba_globs Corba global-like variables
 * @par session Session identifier
 * @par cdata Necessary input data
 * @ret CORBA_OK if succesful
 */
corba_status
epp_call_info_contact(void *corba_globs, int session, epp_command_data *cdata);

/**
 * Call corba info domain function.
 * @par corba_globs Corba global-like variables
 * @par session Session identifier
 * @par cdata Necessary input data
 * @ret CORBA_OK if succesful
 */
corba_status
epp_call_info_domain(void *corba_globs, int session, epp_command_data *cdata);

/**
 * Call corba info nsset function.
 * @par corba_globs Corba global-like variables
 * @par session Session identifier
 * @par cdata Necessary input data
 * @ret CORBA_OK if succesful
 */
corba_status
epp_call_info_nsset(void *corba_globs, int session, epp_command_data *cdata);

/**
 * Call corba poll request function.
 * @par corba_globs Corba global-like variables
 * @par session Session identifier
 * @par cdata Necessary input data
 * @ret CORBA_OK if succesful
 */
corba_status
epp_call_poll_req(void *corba_globs, int session, epp_command_data *cdata);

/**
 * Call corba poll acknoledge function.
 * @par corba_globs Corba global-like variables
 * @par session Session identifier
 * @par cdata Necessary input data
 * @ret CORBA_OK if succesful
 */
corba_status
epp_call_poll_ack(void *corba_globs, int session, epp_command_data *cdata);


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
