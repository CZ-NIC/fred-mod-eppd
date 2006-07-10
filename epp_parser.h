#ifndef EPP_PARSER_H
#define EPP_PARSER_H

/**
 * EPP parser status values (part of mod_eppd - epp_parser interface).
 */
typedef enum {
	PARSER_OK,
	/*
	 * request is not command but <hello> frame
	 * this indicates that greeting should be generated
	 */
	PARSER_HELLO,
	/* request does not validate */
	PARSER_NOT_VALID,
	/* request is not a command */
	PARSER_NOT_COMMAND,
	/*
	 * when following status values are returned, connection is closed
	 */
	/* request is not valid xml */
	PARSER_NOT_XML,
	/* error when parsing xml schemas */
	PARSER_ESCHEMA,
	/*
	 * internal parser error (e.g. malloc failed). This error is
	 * esspecialy serious, therefor its log severity SHOULD be higher
	 * than of the others.
	 */
	PARSER_EINTERNAL
}parser_status;

/**
 * This routine should be called in postconfig phase.
 * This routine loads and checks validity of epp scheme.
 * Preprocessed schemes are returned for later use in epp request handler.
 * @par url_schema URL of schema
 * @ret Opaque server context
 */
void epp_parser_init(void);

/**
 * This will clean up command hash table.
 * @par par Opaque server context
 */
void epp_parser_init_cleanup(void);

/**
 * Parses request and gets structured data.
 * @par	session	Session ID
 * @par request	Request to be processed
 * @par bytes	Length of request
 * @par cdata 	Output of parsing
 * @ret	Status of parsing
 */
parser_status
epp_parse_command(
		int session,
		const char *schema_url,
		const char *request,
		unsigned bytes,
		epp_command_data *cdata);

/**
 */
void epp_command_data_cleanup(epp_command_data *cdata);

#endif /* EPP_PARSER_H */
