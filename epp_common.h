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
	EPP_INFO_CONTACT,
	EPP_INFO_DOMAIN,
	EPP_POLL_REQ,
	EPP_POLL_ACK
}epp_command_type;

/**
 * Stringbool is combination of string and boolean. It is used in check
 * commands as item of list.
 */
typedef struct {
	char	*string;
	int	boolean;
}stringbool;

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
 * This structure gathers outputs of parsing stage and serves as input
 * for corba function call stage and then as input for response generation
 * stage. Structure fits for all kinds of commands. And is self-identifing.
 */
typedef struct {
	char	*clTRID;	/* client TRID - may be null */
	char	*svTRID;	/* server TRID, must not be null */
	int	rc;	/* epp return code */

	epp_command_type type;
	/* logout, dummy have no additional parameters */
	union {
		/* additional login parameters */
		struct {
			char *clID;
			char *pw;
			char *newPW;
			struct circ_list	*objuri; // currently not used
			struct circ_list	*exturi; // currently not used
		}login;
		/* additional check contact and domain parameters */
		struct {
			/* ids (names) combined with bools */
			struct circ_list	*idbools;
		}check;
		/* additional info contact parameters */
		struct {
			char	*id;
			char	*roid;
			struct circ_list	*status;
			char	*name;
			char	*org;
			char	*street;
			char	*sp;	/* state or province */
			char	*pc;	/* postal code */
			char	*cc;	/* country code */
			char	*voice;
			char	*fax;
			char	*email;
			char	*clID;
			char	*crID;
			long	*crDate;
			char	*upID;
			long	*upDate;
			long	*trDate;
			char	*authInfo;
			char	discl_name;
			char	discl_organization;
			char	discl_address;
			char	discl_telephone;
			char	discl_fax;
			char	discl_email;
		}info_contact;
		/* additional info domain parameters */
		struct {
			char	*name;
			char	*roid;
			struct circ_list	*status;
			char	*registrant;
			struct circ_list	*contacts;
			char	*nsset;
			char	*clID;
			char	*crID;
			long	*crDate;
			long	*exDate;
			char	*upID;
			long	*upDate;
			long	*trDate;
			char	*authInfo;
		}info_domain;
		/* additional poll request parameters */
		struct {
			int	count;
			int	msgid;
			long	qdate;
			char	*msg;
			void	*specific_resdata;
		}poll_req;
		/* additional poll acknoledge parameters */
		struct {
			int	msgid;
			int	count;
			int	new_msgid;
		}poll_ack;
	}un;
}epp_command_data;

#endif
