/**
 * EPP parser is in fact translator. Input is unparsed string from mod_eppd
 * and outputs are function calls to corba client, who performs actual CORBA
 * function calls. This header file specifies interface between mod_eppd and
 * epp parser.
 */

#ifndef EPP_PARSER_H
#define EPP_PARSER_H

/**
 * EPP parser status values (part of mod_eppd - epp_parser interface).
 */
typedef enum {
	PARSER_OK,
	/*
	 * when following status values are returned, connection is closed
	 */
	/* request is not valid xml */
	PARSER_NOT_XML,
	/* request does not validate */
	PARSER_NOT_VALID,
	/* request is not a command */
	PARSER_NOT_COMMAND,
	/*
	 * internal parser error (e.g. malloc failed). This error is
	 * esspecialy serious, therefor its log severity SHOULD be higher
	 * than of the others.
	 */
	PARSER_EINTERNAL
} parser_status;

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
	char	*next;
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
		struct stringlist sl_temp;	\
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
		} login;
} epp_command_data;

/**
 * This structure gathers output parameters for epp_parser_get_greeting.
 */
typedef struct {
	char *greeting;
	char *error_msg;
} epp_greeting_parms_out;

/**
 * This routine should be called in postconfig phase to check that libxml
 * is installed and version is correct. In case of an error, error message
 * is written to standard output and program aborted - this is certainly
 * not the best behaviour .. but still better than to ommit the test.
 * This routine also loads and checks validity of epp scheme.
 * Preprocessed schemes are returned for later use in epp request handler.
 * Corba subsystem is also initialized.
 *
 * @par url_schema URL of schema
 * @ret Opaque server context
 */
void *epp_parser_init(const char *url_schema);

/**
 * This will clean up preprocessed epp schema and message hash table.
 * Corba resources are released as well.
 * @par par Opaque server context
 */
void epp_parser_init_cleanup(void *par);

/**
 * Routine makes up epp greeting frame. It is assumed that Output parameters
 * struct is filled by zeros upon function entry.
 *
 * @par svid EPP server ID
 * @par svdate When the greeting was generated
 * @par parms Output parameters
 */
void epp_parser_greeting(const char *svid, const char *svdate,
		epp_greeting_parms_out *parms);

/**
 * Let the parser take care of allocated output parameters.
 * @par parms Output parameters to be cleaned up
 */
void epp_parser_greeting_cleanup(epp_greeting_parms_out *parms);

/**
 * Parses request and gets structured data.
 * @par	session	Session ID
 * @par	globs	Server context
 * @par request	Request to be processed
 * @par bytes	Length of request
 * @par cdata 	Output of parsing
 * @ret	Status of parsing
 */
parser_status
epp_get_command(
		int session,
		epp_parser_globs globs,
		const char *request,
		unsigned bytes,
		epp_command_data *cdata);

/**
 * epp_parser_parms_out is allocated by mod_eppd but management of items inside
 * the structure is task of parser. This routine cleans up the struct.
 * Routine assumes that parms_out is filled by zeros when called.
 * @par retval Structure to clean up
 */
void epp_command_data_cleanup(epp_command_data *cdata);

#endif /* EPP_PARSER_H */
