#ifndef EPP_COMMON_H
#define EPP_COMMON_H

/**
 * Enumeration of all commands this software is able to handle.
 * The object specific commands are expanded (EPP_{command}_{object}.
 */
typedef enum {
	EPP_UNKNOWN_CMD,
	/*
	 * 'dummy' is not a command from point of view of epp client, but is
	 * command from central repozitory's point of view
	 */
	EPP_DUMMY,
	EPP_LOGIN,
	EPP_LOGOUT,
	EPP_CHECK_CONTACT,
	EPP_CHECK_DOMAIN,
	EPP_CHECK_NSSET,
	EPP_INFO_CONTACT,
	EPP_INFO_DOMAIN,
	EPP_INFO_NSSET,
	EPP_POLL_REQ,
	EPP_POLL_ACK
}epp_command_type;

/**
 * Enumeration of objects this server operates on.
 */
typedef enum {
	EPP_UNKNOWN_OBJ,
	EPP_CONTACT,
	EPP_DOMAIN,
	EPP_NSSET
}epp_object_type;

/**
 * circular list of void pointers
 * sentinel has content == NULL
 */
struct circ_list {
	struct circ_list	*next;
	void	*content;
};

/*
 * macros for manipulation with circ_list
 */
#define CL_NEW(cl)	\
	do {				\
		(cl)->next = (cl);	\
		(cl)->content = NULL;	\
	} while(0)

#define CL_ADD(cl, newcl)	\
	do { 				\
		(newcl)->next = (cl)->next;	\
		(cl)->next = (newcl);		\
	} while(0)

#define CL_NEXT(cl)	((cl) = (cl)->next)
#define CL_CONTENT(cl)	(cl)->content

/*
 * caller must be sure that the list pointer is at the beginning when using
 * this macro
 */
#define CL_FOREACH(cl)	\
	for ((cl) = (cl)->next; (cl)->content != NULL; (cl) = (cl)->next)

/* shift and get content of item in circular list. */
#define CL_SHIFTGET(cl)	(((cl) = (cl)->next)->content)

/* move pointer to the beginning */
#define CL_RESET(cl)	\
	do { 				\
		if ((cl)->content == NULL) break;	\
		while (((cl) = (cl)->next)->content != NULL);	\
	} while(0)

/*
 * purge circular list, note that all content must be freed upon using
 * this macro. List pointer must be at the beginning upon start.
 */
#define CL_PURGE(cl)	\
	do { 				\
		struct circ_list	*temp;			\
		(cl) = (cl)->next;					\
		while ((cl)->content != NULL) {		\
			temp = cl->next;				\
			free(cl);						\
			cl = temp;						\
		}									\
		free(cl);							\
	} while(0)

/* count the number of items in the list */
#define CL_LENGTH(cl, i)	\
	for ((cl) = (cl)->next, i = 0; (cl)->content != NULL; (cl) = (cl)->next, i++)


/**
 * Structure gathers postal info about contact. Can be used for both -
 * international and local address.
 */
typedef struct {
	char	*name;
	char	*org;
	char	*street1;
	char	*street2;
	char	*street3;
	char	*city;
	char	*sp;	/* state or province */
	char	*pc;	/* postal code */
	char	*cc;	/* country code */
}epp_postalInfo;

/**
 * Disclose information concerning contact.
 * All items inside are booleans.
 */
typedef struct {
	char	name;
	char	org;
	char	addr;
	char	voice;
	char	fax;
	char	email;
}epp_discl;

/**
 * Nameserver has a name and possibly more than one ip address
 */
typedef struct {
	char	*name;
	struct circ_list	*addr;
}epp_ns;

/**
 * This structure gathers outputs of parsing stage and serves as input
 * for corba function call stage and after that as input for response
 * generation stage. Structure fits for all kinds of commands. And is
 * self-identifing.
 */
typedef struct {
	/* this part is same for all commands */
	char	*clTRID;	/* client TRID - may be null */
	char	*svTRID;	/* server TRID, must not be null at the end */
	int	rc;	/* epp return code */

	epp_command_type type;
	/* logout and dummy have no additional parameters */
	/*
	 * input parameters
	 * are allocated and initialized during parsing stage
	 */
	union {
		/* additional login parameters */
		struct {
			char *clID;
			char *pw;
			char *newPW;
			struct circ_list	*objuri; // currently not used
			struct circ_list	*exturi; // currently not used
		}login;
		/* additional check contact, domain and nsset parameters */
		struct {
			struct circ_list	*ids; /* ids of objects */
		}check;
		/* additional info contact, domain and nsset parameters */
		struct {
			char	*id;
		}info;
		/* additional poll acknoledge parameters */
		struct {
			int	msgid;
		}poll_ack;
	}*in;
	/*
	 * output parameters
	 * are allocated and initialized after corba function call and used
	 * in response generator
	 */
	union {
		/* additional check contact and domain parameters */
		struct {
			/* booleans are answers to check */
			struct circ_list	*bools;
		}check;
		/* additional info contact parameters */
		struct {
			char	*roid;
			struct circ_list	*status;
			epp_postalInfo	*postalInfo;
			char	*voice;
			char	*fax;
			char	*email;
			char	*clID;
			char	*crID;
			long long	crDate;
			char	*upID;
			long long	upDate;
			long long	trDate;
			char	*authInfo;
			char	*notify_email;
			char	*vat;
			char	*ssn;
			epp_discl	*discl;
		}info_contact;
		/* additional info domain parameters */
		struct {
			char	*roid;
			struct circ_list	*status;
			char	*registrant;
			struct circ_list	*admin;
			char	*nsset;
			char	*clID;
			char	*crID;
			long long	crDate;
			long long	exDate;
			char	*upID;
			long long	upDate;
			long long	trDate;
			char	*authInfo;
		}info_domain;
		/* additional info nsset parameters */
		struct {
			char	*roid;
			struct circ_list	*status;
			char	*clID;
			char	*crID;
			char	*upID;
			long long	crDate;
			long long	upDate;
			long long	trDate;
			char	*authInfo;
			struct circ_list	*ns;
			struct circ_list	*tech;
		}info_nsset;
		/* additional poll request parameters */
		struct {
			int	count;
			int	msgid;
			long long	qdate;
			char	*msg;
		}poll_req;
		/* additional poll acknoledge parameters */
		struct {
			int	count;
			int	msgid;
		}poll_ack;
	}*out;
}epp_command_data;

#endif
