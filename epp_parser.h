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
	PARSER_CMD_LOGIN,  /**< Login command. */
	PARSER_CMD_LOGOUT, /**< Logout command. */
	PARSER_CMD_OTHER,  /**< A command other than login and logout. */
	PARSER_NOT_VALID,  /**< Request does not validate. */
	PARSER_NOT_COMMAND,/**< Request is not a command nor hello frame. */
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
 * This routine initializes libxml's parser, hash table for command
 * recognition and parses xml schema, which is returned.
 *
 * @param url_schema  XML schema location.
 * @return            Parsed xml schema.
 */
void *
epp_parser_init(const char *url_schema);

/**
 * This will cleanup command hash table, libxml's parser and release
 * parsed xml schema.
 *
 * @param schema    Parsed xml schema.
 */
void epp_parser_init_cleanup(void *schema);

/**
 * This is the main workhorse of parser component. It's task is to parse
 * request and get data saved in structure.
 *
 * @param pool      Pool to allocate memory from.
 * @param session   Client's session identifier.
 * @param schema    Parsed xml schema used for validation.
 * @param request   Request to be processed.
 * @param bytes     Length of the request.
 * @param cdata     Output of parsing stage (xml data converted to structure).
 * @return          Status of parsing.
 */
parser_status
epp_parse_command(void *pool,
		int session,
		void *schema,
		const char *request,
		unsigned bytes,
		epp_command_data **cdata);

#endif /* EPP_PARSER_H */
