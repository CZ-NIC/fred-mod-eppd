
#ifndef EPP_CLIENT_H
#define EPP_CLIENT_H

typedef struct stringlist_t stringlist;
struct stringlist_t {
	stringlist	*next;
	char	*content;
};

/* Session commands */
typedef struct {
	/* input parameters */
	char *clID;
	char *pw;
	char *newPW;
	char *clTRID;
	stringlist	*objuri;
	stringlist	*exturi;
	/* output parameters */
	char *svTRID;
	int	sessionID;
	int	rc;
} epp_data_login;

int corba_login(epp_data_login *login_data);

typedef struct {
	/* input parameters */
	char *clTRID;
	/* output parameters */
	char *svTRID;
	int	rc;
} epp_data_logout;

int corba_logout(epp_data_logout *logout_data);

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
