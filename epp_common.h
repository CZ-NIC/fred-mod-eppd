#ifndef EPP_COMMON_H
#define EPP_COMMON_H

/**
 * Enumeration of all commands this software is able to handle.
 */
typedef enum {
	EPP_UNKNOWN_CMD,
	/*
	 * 'dummy' is not a command from point of view of epp client, but is
	 * command from central repozitory's point of view
	 */
	EPP_DUMMY,
	EPP_LOGIN,
	EPP_LOGOUT
} epp_command_type;

/**
 * circular string list
 * sentinel has content == NULL
 */
struct stringlist {
	struct stringlist	*next;
	char	*content;
};

/*
 * macros for manipulation with stringlist
 */
#define SL_NEW(sl)	\
	do {				\
		(sl)->next = (sl);	\
		(sl)->content = NULL;	\
	} while(0)

#define SL_ADD(sl, newsl)	\
	do { 				\
		(newsl)->next = (sl)->next;	\
		(sl)->next = (newsl);		\
	} while(0)

#define FOR_EACH_SL(sl)	\
	for ((sl) = (sl)->next; (sl)->content != NULL; (sl) = (sl)->next)

#define PURGE_SL(sl)	\
	do {				\
		struct stringlist *sl_temp;	\
		for ((sl) = (sl)->next; (sl)->content != NULL;) {	\
			sl_temp = (sl)->next;	\
			free(sl->content);		\
			free(sl);				\
			(sl) = (sl_temp);		\
		}				\
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
	union {
		/* additional login parameters */
		struct {
			char *clID;
			char *pw;
			char *newPW;
			struct stringlist	*objuri; // currently not used
			struct stringlist	*exturi; // currently not used
		}login;
	}un;
} epp_command_data;

#endif
