/**
 * @file epp_common.h
 * The most important structures, function definitions and routine declarations
 * are found in this file. Since they are used by all components of mod_eppd,
 * they are most important and should be read first when trying to understand
 * to the module's code.
 */

#ifndef EPP_COMMON_H
#define EPP_COMMON_H

/**
 * Enumeration of all EPP commands this module is able to handle.
 * The object specific commands are expanded to (EPP_{command}_{object}.
 */
typedef enum {
	EPP_UNKNOWN_CMD = 0,
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
 * Enumeration of EPP objects which this server operates on.
 */
typedef enum {
	EPP_UNKNOWN_OBJ = 0,
	EPP_CONTACT,
	EPP_DOMAIN,
	EPP_NSSET
}epp_object_type;

/**
 * definition of languages (english is default)
 */
typedef enum {
	LANG_EN	= 0,
	LANG_CS,
}epp_lang;

/**
 * In case that central repository finds out that some parameter is bad,
 * there has to be way how to propagate this information back to client.
 * The standard requires that client provided value has to be surrounded
 * with xml tags, of which the central repository is not aware. Therefore
 * mod_eppd has to complete the tags and this error specification specifies
 * which tags.
 */
typedef enum {
	errspec_unknow, 
	errspec_pollAck_msgID,
	errspec_contactCreate_handle,
	errspec_contactCreate_cc,
	errspec_contactUpdate_cc,
	errspec_contactUpdate_status_add,
	errspec_contactUpdate_status_rem,
	errspec_nssetCreate_handle,
	errspec_nssetCreate_tech,
	errspec_nssetCreate_ns_name,
	errspec_nssetCreate_ns_addr,
	errspec_nssetUpdate_ns_name_add,
	errspec_nssetUpdate_ns_addr_add,
	errspec_nssetUpdate_ns_name_rem,
	errspec_nssetUpdate_ns_addr_rem,
	errspec_nssetUpdate_tech_add,
	errspec_nssetUpdate_tech_rem,
	errspec_nssetUpdate_status_add,
	errspec_nssetUpdate_status_rem,
	errspec_domainCreate_fqdn,
	errspec_domainCreate_registrant,
	errspec_domainCreate_nsset,
	errspec_domainCreate_period,
	errspec_domainCreate_admin,
	errspec_domainCreate_ext_valdate,
	errspec_domainUpdate_registrant,
	errspec_domainUpdate_nsset,
	errspec_domainUpdate_admin_add,
	errspec_domainUpdate_admin_rem,
	errspec_domainUpdate_status_add,
	errspec_domainUpdate_status_rem,
	errspec_domainUpdate_ext_valdate,
	errspec_domainRenew_curExpDate,
	errspec_domainRenew_period,
	errspec_domainRenew_ext_valDate
}epp_errorspec;

/**
 * The struct represents one epp error in ExtValue element. It is either
 * validation error (in that case surrounding tags are contained in value
 * and standalone is set to 1) or error reported by central repository
 * (in that case surrounding tags are missing and has to be completed
 * according to #epp_errorspec value).
 */
typedef struct {
	char	*value; /**< Client provided input which caused the error. */
	int	standalone;	/**< The surrounding tags are included (1) or not (0). */
	char	*reason;	/**< Human readable reason of error. */
	epp_errorspec	spec;	/**< Specification of surrounding XML tags */
}epp_error;

/**
 * @defgroup circgroup Circular list structure and utilities
 * @{
 */

/**
 * Circular list structure used on countless places throughout the module.
 * The understanding of how this implementation of circular list works
 * is essential for understanding the module's code. It is one way linked
 * list of items, which is never ending because the last item points to
 * the first item of the list. The way how to recognize the so called
 * sentinel, which is the first and last item of the list, is that its
 * content is NULL.
 */
struct circ_list {
	struct circ_list	*next;	/**< Link to next item in the list. */
	void	*content;	/**< Pointer to content of item. */
};

/**
 * Macro for initialization of list. The item has to be already
 * allocated. The item will become sentinel and stay so forever. You
 * don't have to call this macro for item, which is going to be only
 * added to existing list.
 */
#define CL_NEW(cl)	\
	do {				\
		(cl)->next = (cl);	\
		(cl)->content = NULL;	\
	} while(0)

/** Macro to add item to existing list. */
#define CL_ADD(cl, newcl)	\
	do { 				\
		(newcl)->next = (cl)->next;	\
		(cl)->next = (newcl);		\
	} while(0)

/** Get next item in a list. */
#define CL_NEXT(cl)	((cl) = (cl)->next)
/** Get content pointer of item. */
#define CL_CONTENT(cl)	(cl)->content

/**
 * Iterate through items in a list. cl advances each round to next item in
 * list, until the sentinel is encountered. Caller must be sure that the
 * list pointer is at the beginning when using this macro - use CL_RESET
 * for that.
 */
#define CL_FOREACH(cl)	\
	for ((cl) = (cl)->next; (cl)->content != NULL; (cl) = (cl)->next)

/** Move pointer to the beginning of a list (it will point to sentinel) */
#define CL_RESET(cl)	\
	do { 				\
		if ((cl)->content == NULL) break;	\
		while (((cl) = (cl)->next)->content != NULL);	\
	} while(0)


/** Return the number of items in the list */
inline unsigned cl_length(struct circ_list *cl);
/** If the list is empty return value is 1, otherwise 0 */
#define CL_EMPTY(cl)	((cl) == (cl)->next)

/**
 * Free circular list, note that content of all items must be freed
 * before using this function. List pointer must be at the beginning
 * upon start (use CL_RESET for that if you are not sure).
 */
inline void cl_purge(struct circ_list *cl);
/** @} */

/**
 * Structure gathers postal info about contact.
 */
typedef struct {
	char	*name;
	char	*org;	/**< organization */
	char	*street[3];
	char	*city;
	char	*sp;	/**< state or province */
	char	*pc;	/**< postal code */
	char	*cc;	/**< country code */
}epp_postalInfo;

/**
 * Disclose information of contact.
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
 * Nameserver has a name and possibly more than one ip address.
 */
typedef struct {
	char	*name;
	struct circ_list	*addr;
}epp_ns;

/**
 * Delegation signer information, together with public key information.
 * For more detailed information about the individual fields see
 * RFC 4310.
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
 * This structure is central to the concept of the whole module. The
 * communication among module's components is done through this structure.
 * It gathers outputs of parsing stage and serves as input/output
 * for corba function call stage and after that as input for response
 * generation stage. Structure fits for all kinds of possible commands and
 * their extensions. The structure is self-identifing, which means, that
 * it holds information about which command it holds.
 */
typedef struct {
	/* theese items are same for all possible epp commands */
	char	*clTRID;	/**< client's TRID */
	char	*svTRID;	/**< server's TRID */
	int	rc;	/**< EPP return code defined in standard. */
	char	*msg;	/**< Text message coresponding to return code. */
	/** List of validation errors or errors from central repository. */
	struct circ_list	*errors;

	/**
	 * Identification of epp command. This value influences selection
	 * from in and out union.
	 */
	epp_command_type type;

	/* logout and dummy commands have no additional parameters */

	/**
	 * Input parameters for all possible epp commands.
	 * This part is allocated and initialized during parsing stage.
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
			unsigned long long	valExDate;
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
			unsigned long long	exDate;
			int	period;
			/* enum validation extension */
			unsigned long long	valExDate;
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
			unsigned long long	valExDate;
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

	/**
	 * Output parameters for all possible epp commands.
	 * They are allocated and initialized after corba function call
	 * and used in response generator.
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
			unsigned long long	crDate;
			char	*upID;
			unsigned long long	upDate;
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
			unsigned long long	crDate;
			unsigned long long	exDate;
			char	*upID;
			unsigned long long	upDate;
			unsigned long long	trDate;
			char	*authInfo;
			/* dnssec extension */
			struct circ_list	*ds;
			/* enum validation extension */
			unsigned long long	valExDate;
		}info_domain;
		/* additional info nsset parameters */
		struct {
			char	*roid;
			struct circ_list	*status;
			char	*clID;
			char	*crID;
			char	*upID;
			unsigned long long	crDate;
			unsigned long long	upDate;
			unsigned long long	trDate;
			char	*authInfo;
			struct circ_list	*ns;
			struct circ_list	*tech;
		}info_nsset;
		/* additional poll request parameters */
		struct {
			int	count;
			int	msgid;
			unsigned long long	qdate;
			char	*msg;
		}poll_req;
		/* additional poll acknoledge parameters */
		struct {
			int	count;
			int	msgid;
		}poll_ack;
		/* additional create contact, nsset or domain parameters */
		struct {
			unsigned long long	crDate;
			unsigned long long	exDate; /* used only in domain object */
		}create;
		/* additional renew domain parameters */
		struct {
			unsigned long long	exDate;
		}renew;
	}*out;
}epp_command_data;

/**
 * Function for converting number of seconds since 1970 ... to string
 * formated in rfc 3339 way. This is required by EPP protocol.
 * @par date Number of seconds since epoch.
 * @par str Preallocated buffer for date (must be at least 25 bytes long).
 */
void get_rfc3339_date(long long date, char *str);

/**
 * Function for converting number of seconds since 1970 ... to string
 * formated in rfc 3339 way. The time part is stripped, so that only
 * date time remains.
 * @par date Number of seconds since epoch.
 * @par str Preallocated buffer for date (must be at least 11 bytes long).
 */
void get_stripped_date(long long date, char *str);

#endif
