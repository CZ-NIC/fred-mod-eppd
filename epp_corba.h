
#ifndef EPP_DATA_H
#define EPP_DATA_H

/* Session commands */
typedef struct {
	/* input parameters */
	char *clID;
	char *pw;
	char *newPW;
	char *clTRID;
	/* output parameters */
	char *svTRID;
	int	sessionID;
	int	rc;
} epp_data_login;

int corba_login(epp_data_login *login_data);

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

#endif /* EPP_DATA_H */
