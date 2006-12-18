/**
 * @file epp_common.h
 *
 * The most important structures, function definitions and routine declarations
 * are found in this file. Since they are used by all components of mod_eppd,
 * they are most important and should be read first when trying to understand
 * to the module's code.
 */

#ifndef EPP_COMMON_H
#define EPP_COMMON_H

/**
 * Enumeration of codes of all EPP commands this module is able to handle.
 * The object specific commands are written as EPP_{command}_{object}.
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
	EPP_LIST_CONTACT,
	EPP_LIST_DOMAIN,
	EPP_LIST_NSSET,
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
	EPP_TRANSFER_CONTACT,
	EPP_TRANSFER_DOMAIN,
	EPP_TRANSFER_NSSET,
	EPP_RENEW_DOMAIN,
	/* protocol extensions */
	EPP_SENDAUTHINFO_CONTACT,
	EPP_SENDAUTHINFO_DOMAIN,
	EPP_SENDAUTHINFO_NSSET,
	EPP_CREDITINFO
}epp_command_type;

/**
 * Enumeration of implemented extensions.
 */
typedef enum {
	EPP_EXT_ENUMVAL
}domain_ext_type;

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
	errspec_unknown = 0, 
	errspec_poll_msgID,
	errspec_poll_msgID_missing,
	errspec_contact_handle,
	errspec_contact_cc,
	errspec_contact_identtype_missing,
	errspec_nsset_handle,
	errspec_nsset_tech,
	errspec_nsset_dns_name,
	errspec_nsset_dns_addr,
	errspec_nsset_dns_name_add,
	errspec_nsset_dns_name_rem,
	errspec_nsset_tech_add,
	errspec_nsset_tech_rem,
	errspec_domain_fqdn,
	errspec_domain_registrant,
	errspec_domain_nsset,
	errspec_domain_period,
	errspec_domain_admin,
	errspec_domain_ext_valDate,
	errspec_domain_curExpDate,
	errspec_domain_admin_add,
	errspec_domain_admin_rem,
	errspec_transfer_op
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
	/**
	 * Specification of surrounding XML tags.
	 *
	 * For validation errors this is set to errspec_unknown.
	 */
	epp_errorspec spec;
	/**
	 * Human readable reason of error.
	 *
	 * For schema validity errors it is filled by mod_eppd (by message from
	 * libxml), which is send to server which transforms libxml message and
	 * returns the result of transformation (by transformation is ment
	 * prefixing by localized text). In all other cases it is left empty
	 * and filled wholly by CR.
	 */
	char	*reason;
}epp_error;

/**
 * @defgroup queuegroup Queue structure and utilities
 * @{
 */

/**
 * Definition of queue item type.
 */
typedef struct queue_item_t qitem;
struct queue_item_t {
	qitem   *next;	  /**< Link to next item in a queue. */
	void	*content; /**< Pointer to content of item. */
};

/**
 * Queue structure used on countless places throughout the program.
 *
 * It is one way linked list of items, consisting of two parts: head and body.
 */
typedef struct {
	int	 count;     /**< Optimization for length() function. */
	qitem	*body;      /**< Items in a queue. */
	qitem	*cur;       /**< Currently selected item. */
}qhead;

/** Get length of a queue. */
#define q_length(_qhead)	((_qhead).count)
/** Shift to next item in a queue. */
#define q_next(_qhead)	\
	((_qhead)->cur = ((_qhead)->cur) ? (_qhead)->cur->next : NULL)
/** Get content of current item. */
#define q_content(_qhead)	((_qhead)->cur->content)
/** Reset current item to the first one. */
#define q_reset(_qhead)	((_qhead)->cur = (_qhead)->body)
/**
 * Iterate through items in a list. cl advances each round to next item in
 * list, until the sentinel is encountered. Caller must be sure that the
 * list pointer is at the beginning when using this macro - use cl_reset
 * for that.
 */
#define q_foreach(_qhead)	\
	for ((_qhead)->cur = (_qhead)->body; (_qhead)->cur != NULL; (_qhead)->cur = (_qhead)->cur->next)
/**
 * Add new item to a queue (the item will be enqueued at the end of queue).
 *
 * @param pool    Pool from which the new item will be allocated.
 * @param head    The queue.
 * @param data    Pointer to data which shoud be enqueued.
 * @return        0 if successfull, otherwise 1.
 */
int q_add(void *pool, qhead *head, void *data);

/** @} */


/* ********************************************************************* */


/**
 * Structure for holding status' names and values.
 */
typedef struct {
	char	*value;
	char	*text;
}epp_status;

/**
 * Structure gathers postal info about contact.
 */
typedef struct {
	char	*name;  /**< Name. */
	char	*org;	/**< Organization. */
	qhead	 streets; /**< 3x street. */
	char	*city;  /**< City. */
	char	*sp;	/**< State or province. */
	char	*pc;	/**< Postal code. */
	char	*cc;	/**< Country code. */
}epp_postalInfo;

/**
 * Disclose information of contact.
 * All items except flag inside are treated as booleans.
 * Value 1 means it is an exception to data collection policy.
 * Flag represents the default server policy.
 * Example: if server data collection policy is "public" (flag == 0)
 * 	then value 1 in this structure means the item should be hidden.
 */
typedef struct {
	/**
	 * Value 1 means following items are exception to server policy, which
	 * is assumed to be private (hide all items).
	 * Value 0 means following items are exception to server policy, which
	 * is assumed to be public (show all items).
	 * And value -1 means there are not elements that require exceptional
	 * behaviour.
	 */
	char	flag;
	unsigned char	name; /**< Contact's name is exceptional. */
	unsigned char	org;  /**< Contact's organization is exceptional. */
	unsigned char	addr; /**< Contact's address is exceptional. */
	unsigned char	voice;/**< Contact's voice (tel. number) is exceptional. */
	unsigned char	fax;  /**< Contact's fax number is exceptional. */
	unsigned char	email;/**< Contact's email address is exceptional. */
}epp_discl;

/**
 * Nameserver has a name and possibly more than one ip address.
 */
typedef struct {
	char	*name;	 /**< fqdn of nameserver. */
	qhead	 addr; /**< List of ip addresses. */
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

/** Type of identification number used in contact object. */
typedef enum {
	ident_UNKNOWN, /**< Unknown value can also mean undefined. */
	ident_OP,      /**< Number of ID card. */
	ident_RC,      /**< Born number (rodne cislo). */
	ident_PASSPORT,/**< Number of passport. */
	ident_MPSV,    /**< Number assigned by "ministry of work and ...". */
	ident_ICO      /**< ICO. */
}epp_identType;

typedef enum {
	TIMEUNIT_MONTH,
	TIMEUNIT_YEAR
}epp_timeunit;

/** Structure holding answer to EPP check command. */
typedef struct {
	int	 avail;  /**< True if object is available, false otherwise. */
	char	*reason; /**< If object is not available, here is the reason. */
}epp_avail;

/** Structure holding answer to EPP creditInfo command. */
typedef struct {
	char	*zone;   /**< True if object is available, false otherwise. */
	unsigned long credit; /**< Credit in cents. */
}epp_zonecredit;

/** DNSSEC extension used for updates. */
typedef struct {
	qhead	chg_ds; /**< Signatures to be changed. */
	qhead	add_ds; /**< Signatures to be added. */
	qhead	rem_ds; /**< Signatures to be removed. */
}epp_ext_domain_upd_dnssec;

typedef struct {
	domain_ext_type extType; /**< Identifier of extension. */
	union {
		char	*ext_enumval; /**< Domain validation.*/
		qhead	 ext_dnssec_cr; /** List of digital sigs for domain. */
		epp_ext_domain_upd_dnssec ext_dnssec_upd; /**< DNSSEC. */
	}ext; /**< Extension. */
}epp_ext_item;


/* ********************************************************************* */


/** Login parameters. */
typedef struct {
	char	*clID;   /**< Client ID. */
	char	*pw;     /**< Password. */
	char	*newPW;  /**< New password. */
	qhead	 objuri; // currently not used
	qhead	 exturi; // currently not used
	unsigned lang;   /**< Language. */
}epps_login;

/** Check contact, domain and nsset parameters. */
typedef struct {
	qhead	ids;    /**< IDs of checked objects. */
	qhead	avails; /**< Booleans + reasons. */
}epps_check;

/** Info contact parameters. */
typedef struct {
	char	*id;       /**< Id of wanted contact (input). */
	char	*handle;   /**< Id of wanted contact (output).*/
	char	*roid;     /**< ROID of object. */
	qhead	 status;   /**< Contact's status. */
	epp_postalInfo pi; /**< Postal info. */
	char	*voice;    /**< Telephone number. */
	char	*fax;      /**< Fax number. */
	char	*email;    /**< Email address. */
	char	*clID;     /**< Owner's ID. */
	char	*crID;     /**< ID of creator. */
	char	*crDate;   /**< Creation date. */
	char	*upID;     /**< ID of last updater. */
	char	*upDate;   /**< Last updated. */
	char	*trDate;   /**< Last transfered. */
	char	*authInfo; /**< Authorization information. */
	epp_discl discl;   /**< Disclose information section. */
	char	*vat;      /**< VAT tax ID. */
	char	*ident;      /**< Contact's unique ident. */
	epp_identType identtype;   /**< Type of unique ident. */
	char	*notify_email; /**< Notification email. */
}epps_info_contact;

/* Info domain parameters. */
typedef struct {
	char	*name;    /**< FQDN of wanted domain (input). */
	char	*handle;  /**< FQDN of wanted domain (output). */
	char	*roid;    /**< ROID of object. */
	qhead	 status;  /**< Domain's status. */
	char	*registrant; /**< Registrant of domain. */
	qhead	 admin;   /**< Admin contact for domain. */
	char	*nsset;   /**< Nsset of domain. */
	char	*clID;    /**< Owner's ID. */
	char	*crID;    /**< ID of creator. */
	char	*crDate;  /**< Creation date. */
	char	*exDate;  /**< Expiration date. */
	char	*upID;    /**< ID of last updater. */
	char	*upDate;  /**< Last updated. */
	char	*trDate;  /**< Last transfered. */
	char	*authInfo;/**< Authorization information. */
	qhead	 extensions; /**< List of domain extensions. */
}epps_info_domain;

/* Info nsset parameters. */
typedef struct {
	char	*id;      /**< Id of wanted nsset (input). */
	char	*handle;  /**< Id of wanted nsset (output). */
	char	*roid;    /**< ROID of object. */
	qhead	 status;  /**< Nsset's status. */
	char	*clID;    /**< Owner's ID. */
	char	*crID;    /**< ID of creator. */
	char	*crDate;  /**< Creation date. */
	char	*upID;    /**< ID of last updater. */
	char	*upDate;  /**< Last updated. */
	char	*trDate;  /**< Last transfered. */
	char	*authInfo;/**< Authorization information. */
	qhead	 ns;      /**< List of nameservers. */
	qhead	 tech;    /**< List of technical contacts for nsset. */
}epps_info_nsset;

/** Poll request parameters. */
typedef struct {
	int	count;   /**< Count of waiting messages. */
	char	*msgid;  /**< ID of next message in a queue. */
	char	*msg;    /**< Text of message. */
	char	*qdate;  /**< Date of message submission. */
}epps_poll_req;

/** Poll acknoledge parameters. */
typedef struct {
	char	*msgid;   /**< ID of acknoledged message. */
	int	 count;   /**< Count of waiting messages. */
	char	*newmsgid;/**< ID of first message in a queue. */
}epps_poll_ack;

/** Create contact parameters. */
typedef struct {
	char	*id;       /**< Id of wanted contact (input). */
	epp_postalInfo pi; /**< Postal info. */
	char	*voice;    /**< Telephone number. */
	char	*fax;      /**< Fax number. */
	char	*email;    /**< Email address. */
	char	*authInfo; /**< Authorization information. */
	epp_discl discl;   /**< Disclose information section. */
	char	*vat;      /**< VAT tax ID. */
	char	*ident;      /**< Contact's unique ident. */
	epp_identType identtype;   /**< Type of unique ident. */
	char	*notify_email; /**< Notification email. */
	char	*crDate;   /**< Creation date of contact. */
}epps_create_contact;

/** Create domain parameters. */
typedef struct {
	char	*name;    /**< FQDN of wanted domain (input). */
	char	*registrant;   /**< Registrant of domain. */
	qhead	 admin;   /**< Admin contact for domain. */
	char	*nsset;   /**< Nsset of domain. */
	int	 period;  /**< Registration period in months. */
	epp_timeunit unit;/**< Registration period's unit. */
	char	*authInfo;/**< Authorization information. */
	qhead	 extensions; /**< List of domain extensions. */
	char	*crDate;  /**< Creation date of domain. */
	char	*exDate;  /**< Expiration date of domain. */
}epps_create_domain;

/** Create nsset parameters. */
typedef struct {
	char	*id;      /**< Id of wanted nsset (input). */
	char	*authInfo;/**< Authorization information. */
	qhead	 ns;      /**< List of nameservers. */
	qhead	 tech;    /**< List of technical contacts for nsset. */
	char	*crDate;  /**< Creation date of nsset. */
}epps_create_nsset;

/** Delete parameters. */
typedef struct {
	char	*id;      /**< ID of object to be deleted. */
}epps_delete;

/** Renew domain parameters. */
typedef struct {
	char	*name;      /**< Name of renewed domain. */
	char	*curExDate; /**< Current expiration date. */
	int	 period;    /**< Renew period. */
	epp_timeunit unit;  /**< Registration period's unit. */
	qhead	 extensions;/**< List of domain extensions. */
	char	*exDate;    /**< New expiration date. */
}epps_renew;

/** Update contact parameters. */
typedef struct {
	char	*id;            /**< Id of wanted contact (input). */
	epp_postalInfo *pi;     /**< Postal info. */
	char	*voice;         /**< Telephone number. */
	char	*fax;           /**< Fax number. */
	char	*email;         /**< Email address. */
	char	*authInfo;      /**< Authorization information. */
	epp_discl discl;        /**< Disclose information section. */
	char	*vat;           /**< VAT tax ID. */
	char	*ident;           /**< Contact's unique ident. */
	epp_identType identtype;    /**< Type of unique ident. */
	char	*notify_email;  /**< Notification email. */
}epps_update_contact;

/** Update domain parameters. */
typedef struct {
	char	*name;         /**< FQDN of wanted domain (input). */
	char	*registrant;   /**< Registrant of domain. */
	qhead	 add_admin;    /**< Admin contacts to be added. */
	qhead	 rem_admin;    /**< Admin contacts to be removed. */
	char	*nsset;        /**< Nsset of domain. */
	char	*authInfo;     /**< Authorization information. */
	qhead	 extensions;   /**< List of domain extensions. */
}epps_update_domain;

/** Update nsset parameters. */
typedef struct {
	char	*id;           /**< Id of wanted nsset (input). */
	qhead	 add_tech;     /**< Technical contacts to be added. */
	qhead	 rem_tech;     /**< Technical contacts to be removed. */
	qhead	 add_ns;       /**< Nameservers to be added. */
	qhead	 rem_ns;       /**< Nameservers to be removed. */
	char	*authInfo;     /**< Authorization information. */
}epps_update_nsset;

/** Transfer parameters. */
typedef struct {
	char	*id;           /**< Id of transfered object. */
	char	*authInfo;     /**< Authorization information. */
}epps_transfer;

/** Parameters of command list. */
typedef struct {
	qhead	 handles;     /**< List of handles. */
}epps_list;

/** SendAuthInfo parameters. */
typedef struct {
	char	*id;          /**< Handle of object. */
}epps_sendAuthInfo;

/** CreditInfo parameters. */
typedef struct {
	qhead	 zonecredits; /**< List of credits for individual zones. */
}epps_creditInfo;

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
	char	*clTRID;/**< client's TRID */
	char	*svTRID;/**< server's TRID */
	int	rc;     /**< EPP return code defined in standard. */
	char	*msg;   /**< Text message coresponding to return code. */
	char	*xml_in;/**< XML as it is received from client. */
	/** List of validation errors or errors from central repository. */
	qhead	 errors;

	/**
	 * Identification of epp command. This value influences selection
	 * from in and out union.
	 */
	epp_command_type type;
	/**
	 * Command data
	 * (Input + output parameters for all possible epp commands).
	 */
	void	*data;
}epp_command_data;


/* ********************************************************************* */


/**
 * @defgroup allocgroup Functions for memory allocation.
 *
 * A memory allocated by these functions is automatically freed when
 * processing of request is finished.
 *
 * @{
 */

/**
 * Allocate memory from memory pool.
 *
 * @param pool    Memory pool.
 * @param size    Number of bytes to allocate.
 * @return        Pointer to allocated memory.
 */
void *epp_malloc(void *pool, unsigned size);

/**
 * Allocate memory from memory pool and prezero it.
 *
 * @param pool   Memory pool.
 * @param size   Number of bytes to allocate.
 * @return       Pointer to allocated memory.
 */
void *epp_calloc(void *pool, unsigned size);

/**
 * Duplicate string from argument, the memory will be allocated from
 * memory pool.
 *
 * @param pool   Memory pool.
 * @param str    String which is going to be duplicated.
 * @return       Pointer duplicated string.
 */
void *epp_strdup(void *pool, const char *str);

/**
 * Duplicate string from argument, the memory will be allocated from
 * memory pool.
 *
 * @param pool   Memory pool.
 * @param str    String which is going to be duplicated.
 * @return       Pointer duplicated string.
 */
void *epp_strdup(void *pool, const char *str);

/**
 * @}
 */

/**
 * Log message formated in printf manner.
 *
 * @param fmt    Format of string.
 */
void *epp_log(const char *fmt, ...);

#endif /* EPP_COMMON_H */
