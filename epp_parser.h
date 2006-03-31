/**
 * EPP parser is in fact translator. Input is unparsed string from mod_eppd
 * and outputs are function calls to corba client, who performs actual CORBA
 * function calls. This header file specifies interface between mod_eppd and
 * epp parser.
 */

#ifndef EPP_PARSER_H
#define EPP_PARSER_H

/**
 * EPP status values (part of mod_eppd - xml_epp interface).
 */
typedef enum {
	EPP_DEFAULT_STAT,
	EPP_CLOSE_CONN
} epp_status_t;

/**
 * Log levels of messages from the parser. Mapping of epp log levels
 * to apache log levels is task of mod_eppd.
 */
typedef enum {
	EPP_LOG_INFO,
	EPP_LOG_WARNING,
	EPP_LOG_ERROR
} epp_parser_loglevel;

/**
 * Every log message has log level and pointer to next message.
 */
typedef struct Epp_parser_log epp_parser_log;
struct Epp_parser_log {
	epp_parser_log *next;
	epp_parser_loglevel severity;
	char *msg;
};

/**
 * This structure gathers output parameters of epp_parser_process_request.
 * eppd_mod takes case of structure as such and parser takes manages the items
 * inside the struct.
 *
 * The pointer last is there for efficient message inserting to the end of
 * log chain.
 */
typedef struct {
	char *response;
	epp_parser_log *head;
	epp_parser_log *last;
	epp_status_t status;
} epp_command_parms_out;

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
 *
 * @par url_schema URL of schema
 * @ret Zero in case of failure, one in case of success
 */
int epp_parser_init(const char *url_schema);

/**
 * This will clean up preprocessed epp schema and message hash table.
 */
void epp_parser_init_cleanup();

/**
 * This creates and returns context of epp connection, which is used
 * when handling subsequent requests.
 * @ret Connection context
 */
void *epp_parser_connection(void);

/**
 * Since mod_eppd doesn't know anything about connection context structure,
 * at the end of connection is called this routine, to do necessary cleanup.
 * @par Connection context to be cleaned up
 */
void epp_parser_connection_cleanup(void *conn_ctx);

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
 * Parses request and gets response.
 * @par	Connection context
 * @par Request to be processed
 * @par Response containg xml, logs, status, ...
 */
void epp_parser_command(
		void *conn_ctx,
		const char *request,
		epp_command_parms_out *parms);

/**
 * epp_parser_parms_out is allocated by mod_eppd but management of items inside
 * the structure is task of parser. This routine cleans up the struct.
 * Routine assumes that parms_out is filled by zeros when called.
 * @par retval Structure to clean up
 */
void epp_parser_command_cleanup(epp_command_parms_out *parms);

#endif /* EPP_PARSER_H */
