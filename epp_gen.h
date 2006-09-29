/**
 * @file epp_gen.h
 * Interface to component which generates xml documents and returns result
 * in form of a string.
 */
#ifndef EPP_GEN_H
#define EPP_GEN_H

#include "epp_common.h"

/**
 * Namespace used for specifing location of a schema in xml document.
 */
#define XSI	"http://www.w3.org/2001/XMLSchema-instance"

/**
 * XML generator status values.
 */
typedef enum {
	GEN_OK,	/**< No error appeared, everything was allright. */
	GEN_EBUFFER,	/**< Could not create xml buffer. */
	GEN_EWRITER,	/**< Could not create xml writer. */
	GEN_EBUILD,	/**< Error when building xml document. */
	/*
	 * following errors may appear only if response validation is turned on
	 */
	GEN_NOT_XML,	/**< Something what is not xml was generated. */
	GEN_EINTERNAL,	/**< Malloc failure during response validation. */
	GEN_ESCHEMA,	/**< Error when parsing xml schema used for validation. */
	GEN_NOT_VALID	/**< Response does not validate. */
}gen_status;

/**
 * Routine makes up epp greeting frame.
 *
 * @param svid Part of server ID used in svid tag.
 * @param date Current date as returned from server.
 * @param greeting Greeting string.
 * @return Generator status.
 */
gen_status
epp_gen_greeting(void *pool, const char *svid, const char *date, char **greeting);

/**
 * Generate command response in XML format. There is option that response
 * can be validated, the validation errors are then returned together with
 * generated string in form of a list.
 *
 * @param pool Memory pool from which to allocate memory.
 * @param validate Tells if response should be validated or not (boolean).
 * @param schema_url Location of schema against which to validate.
 * @param lang Language selected by the client.
 * @param cdata Input values
 * @param response Result of generation phase = generated string.
 * @param List of validation errors if validation is turned on.
 * @return Generator status.
 */
gen_status
epp_gen_response(
		void *pool,
		int validate,
		void *schema,
		epp_lang lang,
		epp_command_data *cdata,
		char **response,
		struct circ_list **valerr);

#endif /* EPP_GEN_H */

/* vim: set ts=4 sw=4: */
