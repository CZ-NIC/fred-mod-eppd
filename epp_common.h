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
	 * command from central repository's point of view
	 */
	EPP_DUMMY,
	/* session commands */
	EPP_LOGIN,
	EPP_LOGOUT,
	/* query commands */
	EPP_CHECK_CONTACT,
	EPP_CHECK_DOMAIN,
	EPP_CHECK_NSSET,
	EPP_INFO_CONTACT,
	EPP_INFO_DOMAIN,
	EPP_INFO_NSSET,
	EPP_POLL_REQ,
	EPP_POLL_ACK,
	/* transform commands */
	EPP_CREATE_CONTACT,
	EPP_CREATE_DOMAIN,
	EPP_CREATE_NSSET,
	EPP_DELETE_CONTACT,
	EPP_DELETE_DOMAIN,
	EPP_DELETE_NSSET,
	EPP_UPDATE_CONTACT,
	EPP_UPDATE_DOMAIN,
	EPP_UPDATE_NSSET,
	EPP_TRANSFER_DOMAIN,
	EPP_TRANSFER_NSSET,
	EPP_RENEW_DOMAIN
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

/*
 * definition of languages (english is default)
 * it servers as an index in array of messages
 */
typedef enum {
	LANG_EN	= 0,
	LANG_CS,
}epp_lang;

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
	char	*street[3];
	char	*city;
	char	*sp;	/* state or province */
	char	*pc;	/* postal code */
	char	*cc;	/* country code */
}epp_postalInfo;

/**
 * Disclose information concerning contact.
 * All items inside are treated as booleans.
 * Value 1 means it is an exception to data collection policy.
 * Example: if server data collection policy is "public"
 * 	then value 1 in this structure means the item should be private.
 * Note: Data collection policy of our server is "public".
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
 * Delegation signer information, together with public key information.
 */
typedef struct {
	unsigned short	keytag;
	unsigned char	alg;
	unsigned char	digestType;
	char	*digest;
	int	maxSigLife;	/* zero means that the field is empty */
	/* optional dns rr (-1 in theese fields means that they are empty) */
	unsigned flags;
	unsigned protocol;
	unsigned key_alg;
	char	*pubkey;
}epp_ds;

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

	epp_command_type type;	/* identifies epp command and object */

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
			/* pseudo parameter lang - not used in corba call but only localy */
			unsigned lang;
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
		/* additional create domain parameters */
		struct {
			char	*name;
			char	*registrant;
			struct circ_list	*admin;
			char	*nsset;
			int	period;	/* in months */
			char	*authInfo;
			/* dnssec extension */
			struct circ_list	*ds;
			/* enum validation extension */
			long long	valExDate;
		}create_domain;
		/* additional create contact parameters */
		struct {
			char	*id;
			epp_postalInfo	*postalInfo;
			char	*voice;
			char	*fax;
			char	*email;
			char	*notify_email;
			char	*vat;
			char	*ssn;
			epp_discl	*discl;
		}create_contact;
		/* additional create nsset parameters */
		struct {
			char	*id;
			char	*authInfo;
			struct circ_list	*tech;
			struct circ_list	*ns;
		}create_nsset;
		/* additional delete parameters */
		struct {
			char	*id;
		}delete;
		/* additional renew domain parameters */
		struct {
			char	*name;
			long long	exDate;
			int	period;
		}renew;
		/* additional update domain parameters */
		struct {
			char	*name;
			struct circ_list	*add_admin;
			struct circ_list	*rem_admin;
			struct circ_list	*add_status;
			struct circ_list	*rem_status;
			char	*registrant;
			char	*nsset;
			char	*authInfo;
			/* dnssec extension */
			struct circ_list	*chg_ds;
			struct circ_list	*add_ds;
			struct circ_list	*rem_ds;
			/* enum validation extension */
			long long	valExDate;
		}update_domain;
		/* additional update contact parameters */
		struct {
			char	*id;
			struct circ_list	*add_status;
			struct circ_list	*rem_status;
			epp_postalInfo	*postalInfo;
			char	*voice;
			char	*fax;
			char	*email;
			char	*notify_email;
			char	*vat;
			char	*ssn;
			epp_discl	*discl;
		}update_contact;
		/* additional update nsset parameters */
		struct {
			char	*id;
			struct circ_list	*add_status;
			struct circ_list	*rem_status;
			struct circ_list	*add_ns;
			struct circ_list	*rem_ns;
			struct circ_list	*add_tech;
			struct circ_list	*rem_tech;
			char	*authInfo;
		}update_nsset;
		/* additional transfer parameters */
		struct {
			char	*id;
			char	*authInfo;
		}transfer;
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
			char	*crID;
			long long	crDate;
			char	*upID;
			long long	upDate;
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
			/* dnssec extension */
			struct circ_list	*ds;
			/* enum validation extension */
			long long	valExDate;
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
		/* additional create contact, nsset or domain parameters */
		struct {
			long long	crDate;
			long long	exDate; /* used only in domain object */
		}create;
		/* additional renew domain parameters */
		struct {
			long long	exDate;
		}renew;
	}*out;
}epp_command_data;

#endif
