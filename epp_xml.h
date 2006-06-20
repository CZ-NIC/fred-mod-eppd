#ifndef EPP_PARSER_H
#define EPP_PARSER_H

#include "epp_common.h"

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
} parser_status;

/**
 * XML generator status values (part of mod_eppd - epp_parser interface).
 */
typedef enum {
	GEN_OK,
	/* could not create xml buffer */
	GEN_EBUFFER,
	/* could not create xml writer */
	GEN_EWRITER,
	/* error when building xml document */
	GEN_EBUILD
} gen_status;

/**
 * Opaque stucture containing variables necessary for xml parsing and
 * generating.
 */
typedef struct epp_xml_globs_t epp_xml_globs;

/**
 * This routine should be called in postconfig phase.
 * This routine loads and checks validity of epp scheme.
 * Preprocessed schemes are returned for later use in epp request handler.
 * @par url_schema URL of schema
 * @ret Opaque server context
 */
epp_xml_globs *epp_xml_init(const char *url_schema);

/**
 * This will clean up preprocessed epp schema and message hash table.
 * Corba resources are released as well.
 * @par par Opaque server context
 */
void epp_xml_init_cleanup(epp_xml_globs *xml_globs);

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
epp_parse_command(
		int session,
		epp_xml_globs *globs,
		const char *request,
		unsigned bytes,
		epp_command_data *cdata);

/**
 * Routine makes up epp greeting frame. It is assumed that Output parameters
 * struct is filled by zeros upon function entry.
 *
 * @par svid EPP server ID
 * @par svdate When the greeting was generated
 * @par greeting Greeting frame
 * @ret GEN_OK or other status in case of failure
 */
gen_status
epp_gen_greeting(const char *svid, char **greeting);

/**
 * Generate command response in XML format.
 * @par xml_globs Used to lookup message in hash table
 * @par cdata Input values
 * @par result Generated string
 * @ret GEN_OK if success
 */
gen_status
epp_gen_response(epp_xml_globs *xml_globs, epp_lang lang,
		epp_command_data *cdata, char **result);

/**
 * free string allocated by generate functions.
 * @par genstring String to be freed
 */
void epp_free_genstring(char *genstring);

/**
 */
void epp_command_data_cleanup(epp_command_data *cdata);

#endif /* EPP_PARSER_H */
