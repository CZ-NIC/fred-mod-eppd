/*  
 *  Copyright (C) 2007  CZ.NIC, z.s.p.o.
 *
 *  This file is part of FRED.
 *
 *  FRED is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, version 2 of the License.
 *
 *  FRED is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with FRED.  If not, see <http://www.gnu.org/licenses/>.
 */
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

/** Log levels used for logging to eppd log file. */
typedef enum {
	EPP_FATAL = 1,/**< Error, the module is not in operational state. */
	EPP_ERROR,    /**< Error caused usually by client, module is operational. */
	EPP_WARNING,  /**< Errors which are not serious but should be logged. */
	EPP_INFO,     /**< This is the default log level. */
	EPP_DEBUG     /**< Contents of requests and responses are logged. */
}epp_loglevel;

/** EPP context is a group of variables used often together.
 *
 * The two items inside the struct are void pointers because we don't want
 * to export apache datatypes in all other modules sharing this header file.
 */
typedef struct {
	void *pool;
	void *conn;
	int session;
}epp_context;

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
	EPP_TEST_NSSET,
	EPP_CREDITINFO,
	/* info functions */
	EPP_INFO_LIST_CONTACTS,
	EPP_INFO_LIST_DOMAINS,
	EPP_INFO_LIST_NSSETS,
	EPP_INFO_DOMAINS_BY_NSSET,
	EPP_INFO_DOMAINS_BY_CONTACT,
	EPP_INFO_NSSETS_BY_CONTACT,
	EPP_INFO_NSSETS_BY_NS,
	EPP_INFO_GET_RESULTS
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
 * exact specification of errors is needed.
 */
typedef enum {
	errspec_poll_msgID = 0,
	errspec_contact_handle,
	errspec_contact_cc,
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
	errspec_domain_tmpcontact,
	errspec_domain_ext_valDate,
	errspec_domain_ext_valDate_missing,
	errspec_domain_curExpDate,
	errspec_domain_admin_add,
	errspec_domain_admin_rem,
	/* input errors */
	errspec_not_valid,
	errspec_poll_msgID_missing,
	errspec_contact_identtype_missing,
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
	/** Client provided input which caused the error. */
	char	*value;
	/**
	 * Specification of surrounding XML tags.
	 *
	 * For validation errors this is set to errspec_not_valid.
	 */
	epp_errorspec spec;
	/**
	 * Human readable reason of error.
	 *
	 * For schema validity errors it is filled by mod_eppd (by message from
	 * libxml) which is prefixed by localized message retrieved from
	 * central register. In all other cases it is left empty and filled
	 * by CR.
	 */
	char	*reason;
	/** Position of faulty element if it is part of list. */
	int	 position;
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
	unsigned char	voice;/**< Contact's voice (tel. num.) is exceptional. */
	unsigned char	fax;  /**< Contact's fax number is exceptional. */
	unsigned char	email;/**< Contact's email address is exceptional. */
	unsigned char	vat;  /**< Contact's VAT is exceptional. */
	unsigned char	ident;/**< Contact's ident is exceptional. */
	/** Contact's notification emai is exceptional. */
	unsigned char	notifyEmail;
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
	ident_PASSPORT,/**< Number of passport. */
	ident_MPSV,    /**< Number assigned by "ministry of work and ...". */
	ident_ICO,     /**< ICO. */
	ident_BIRTHDAY /**< Date of birth. */
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

/** Type of poll message. */
typedef enum {
	pt_transfer_contact, /**< Contact was transferred. */
	pt_delete_contact,   /**< Contact was deleted because not used. */
	pt_transfer_nsset,   /**< Nsset was transferred. */
	pt_delete_nsset,     /**< Contact was deleted because not used. */
	pt_techcheck,        /**< Technical check results. */
	pt_transfer_domain,  /**< Domain was transferred. */
	pt_impexpiration,    /**< Domain will expire in near future. */
	pt_expiration,       /**< Domain expired. */
	pt_impvalidation,    /**< Domain validation will expire soon. */
	pt_validation,       /**< Domain validation expired. */
	pt_outzone,          /**< Domain was outaged from zone. */
	pt_delete_domain,    /**< Domain was deleted. */
	pt_lowcredit,        /**< Credit of registrator is low. */
}epp_pollType;

/** Structure containing result of one technical test. */
typedef struct {
	char	*testname;
	int	 status;
	char	*note;
}epp_testResult;

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
	qhead	 tmpcontact; /**< Temporary contact used for migration. */
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
	int	 level;   /**< Report level. */
}epps_info_nsset;

/** Poll request parameters. */
typedef struct {
	int	 count;    /**< Count of waiting messages. */
	char	*msgid;    /**< ID of next message in a queue. */
	char	*qdate;    /**< Date of message submission. */
	epp_pollType type; /**< Type of poll message. */
	/** Message data. */
	union {
		char	*handle;
		struct {
			char	*handle;
			char	*date;
			char	*clID;
		}hdt; /**< Handle, date, registrator structure. */
		struct {
			char	*handle;
			char	*date;
		}hd; /**< Handle, date structure. */
		struct {
			char	*handle;
			qhead	 fqdns;
			qhead	 tests;
		}tc; /**< Structure with results of technical tests. */
		struct {
			char	*zone;
			unsigned long limit;
			unsigned long credit;
		}lc; /**< Low credit structure. */
	}msg;
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
	char	*ident;    /**< Contact's unique ident. */
	epp_identType identtype;/**< Type of unique ident. */
	char	*notify_email;  /**< Notification email. */
	char	*crDate;   /**< Creation date of contact. */
}epps_create_contact;

/** Create domain parameters. */
typedef struct {
	char	*name;    /**< FQDN of wanted domain (input). */
	char	*registrant; /**< Registrant of domain. */
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
	int	 level;   /**< Report level. */
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
	char	*ident;         /**< Contact's unique ident. */
	epp_identType identtype;/**< Type of unique ident. */
	char	*notify_email;  /**< Notification email. */
}epps_update_contact;

/** Update domain parameters. */
typedef struct {
	char	*name;         /**< FQDN of wanted domain (input). */
	char	*registrant;   /**< Registrant of domain. */
	qhead	 add_admin;    /**< Admin contacts to be added. */
	qhead	 rem_admin;    /**< Admin contacts to be removed. */
	qhead	 rem_tmpcontact; /**< Temporary contact used for migration. */
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
	int	 level;        /**< Report level. */
}epps_update_nsset;

/** Transfer parameters. */
typedef struct {
	char	*id;           /**< Id of transfered object. */
	char	*authInfo;     /**< Authorization information. */
}epps_transfer;

/** SendAuthInfo parameters. */
typedef struct {
	char	*id;          /**< Handle of object. */
}epps_sendAuthInfo;

/** CreditInfo parameters. */
typedef struct {
	qhead	 zonecredits; /**< List of credits for individual zones. */
}epps_creditInfo;

/** Test parameters. */
typedef struct {
	char	*id;    /**< ID of tested nsset. */
	qhead	 names; /**< Fqdns of domains to be tested with nsset. */
	int	 level; /**< Level of tests (-1 if not overriden). */
}epps_test;

/** Parameters of obsolete command 'list' and getResults command. */
typedef struct {
	qhead	 handles;     /**< List of handles. */
}epps_list;

/**
 * All Info functions, which accept single key on input and count on
 * output (domainsByNsset, domainsByContact, nssetsByContact, nssetsByNs).
 * This structure is used also by new list functions, handle is NULL for them.
 */
typedef struct {
	char	*handle;      /**< Search key. */
	unsigned int count;   /**< Count of results. */
}epps_info;

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
	char	*clTRID;/**< client's TRID */
	char	*svTRID;/**< server's TRID */
	int	 rc;    /**< EPP return code defined in standard. */
	char	*msg;   /**< Text message coresponding to return code. */
	char	*xml_in;/**< XML as it is received from client. */
	/* parsed_doc and xpath_ctx are needed for error reporting. */
	void	*parsed_doc; /**< Parsed XML document tree. */
	void	*xpath_ctx;  /**< XPath context. */
	/** True if there should be no resdata section or msgQ section. */
	short	 noresdata;
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
 * Write a log message to eppd log file.
 *
 * @param epp_ctx EPP context structure (connection, pool and session id).
 * @param level   Log level.
 * @param fmt     Printf-style format string.
 */
void epplog(epp_context *epp_ctx, epp_loglevel level, const char *fmt, ...);

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
char *epp_strdup(void *pool, const char *str);

/**
 * Concatenate two strings in arguments, the memory will be allocated from
 * memory pool.
 *
 * In case of memory allocation failure or if one of arguments is NULL
 * the function returns NULL.
 *
 * @param pool   Memory pool.
 * @param str1   String which will be the first one.
 * @param str2   String which will be appended.
 * @return       Pointer to new string.
 */
char *epp_strcat(void *pool, const char *str1, const char *str2);

/**
 * Print formatted string.
 *
 * @param pool   Memory pool.
 * @param fmt    Format of string.
 * @return       Formatted string allocated from pool.
 */
char *epp_sprintf(void *pool, const char *fmt, ...);

/**
 * @}
 */

#endif /* EPP_COMMON_H */
