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
	EPP_CHECK_CONTACT
} epp_command_type;

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
	}un;
}epp_command_data;

#endif
