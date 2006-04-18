#ifndef EPP_CLIENT_H
#define EPP_CLIENT_H

/* possible return values from corba wrapper functions */
typedef enum { ORB_OK, ORB_EINIT, ORB_EIMPORT, ORB_ESERVICE } orb_rc_t;

/*
 * corba service is initialized as part of connection context initialization.
 * Corba service handle which is opaque to xml parser
 * is used in subsequent corba function calls.
 * @par service Pointer for storing corba service
 * @par orb Pointer for storing global orb
 * @ret ORB_OK in case of success
 */
orb_rc_t corba_init(void **service, void **orb);

/*
 * corba_cleanup releases service and global orb.
 * @par service Corba service
 * @par orb Global orb
 */
void corba_cleanup(void *service, void *orb);

/* from time to time we need to handle list of parameters */
typedef struct stringlist_t stringlist;
struct stringlist_t {
	stringlist	*next;
	char	*content;
};

/*
 * we need to obtain svTRID from central server for each reply,
 * even for error reporting replies. corba_dummy is used for it.
 */
typedef struct {
	/* input parameters */
	char *clTRID;
	int	rc;
	/* output parameters */
	char *svTRID;
} epp_data_dummy;

orb_rc_t corba_dummy(void *service, int sessionID, epp_data_dummy *dummy_data);

/* Session commands */
typedef struct {
	/* input parameters */
	char *clID;
	char *pw;
	char *newPW;
	char *clTRID;
	stringlist	*objuri; // not used
	stringlist	*exturi; // not used
	/* output parameters */
	char *svTRID;
	int	rc;
} epp_data_login;

orb_rc_t corba_login(void *service, int *sessionID, epp_data_login *login_data);

typedef struct {
	/* input parameters */
	char *clTRID;
	/* output parameters */
	char *svTRID;
	int	rc;
} epp_data_logout;

orb_rc_t
corba_logout(void *service, int sessionID, epp_data_logout *logout_data);

/* Query Commands */
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

/* Tranfer Commands */
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

#endif /* EPP_CLIENT_H */
