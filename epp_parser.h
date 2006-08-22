/**
 * @file epp_parser.h
 * Interface to component which parses xml documents and returns document's
 * content in form of a structure.
 */
#ifndef EPP_PARSER_H
#define EPP_PARSER_H

/** EPP parser status values. */
typedef enum {
	/**
	 * Request is not command but <hello> frame this indicates that greeting
	 * should be generated.
	 */
	PARSER_HELLO,
	PARSER_CMD_LOGIN, /**< Login command */
	PARSER_CMD_LOGOUT, /**< Logout command */
	PARSER_CMD_OTHER, /**< A command other than login and logout. */
	PARSER_NOT_VALID, /**< Request does not validate. */
	PARSER_NOT_COMMAND, /**< Request is not a command nor hello frame. */
	/*
	 * when following status values are returned, connection is closed
	 */
	PARSER_NOT_XML, /**< Request is not xml. */
	PARSER_ESCHEMA, /**< Error when parsing xml schema. */
	/**
	 * Internal parser error (e.g. malloc failed). This error is
	 * esspecialy serious, therefor its log severity SHOULD be higher
	 * than of the other errors.
	 */
	PARSER_EINTERNAL
}parser_status;

/**
 * This routine initializes libxml's parser and hash table for command
 * recognition.
 */
void epp_parser_init(void);

/**
 * This will cleanup command hash table and libxml's parser.
 */
void epp_parser_init_cleanup(void);

/**
 * This is the main workhorse of parser component. It's task is to parse
 * request and get data saved in structure.
 * @param session	Client's session identifier.
 * @param request	Request to be processed.
 * @param bytes	Length of the request.
 * @param cdata Output of parsing stage (xml converted to structure).
 * @param timestart Time in microseconds at begining of function (perf data).
 * @param timeend Time in microseconds at end of function (perf data).
 * @return Status of parsing.
 */
parser_status
epp_parse_command(
		int session,
		const char *schema_url,
		const char *request,
		unsigned bytes,
		epp_command_data *cdata,
		unsigned long long *timestart,
		unsigned long long *timeend);

/**
 * Cleanup routine taking care of releasing resources pointed by pointers
 * inside cdata structure. All members except the output values (products
 * of corba component) are expected to have value (to be non-NULL).
 * @param cdata Structure containing resources which should be released.
 */
void epp_command_data_cleanup(epp_command_data *cdata);

#endif /* EPP_PARSER_H */
