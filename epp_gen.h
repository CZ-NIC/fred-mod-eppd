#ifndef EPP_GEN_H
#define EPP_GEN_H

#include "epp_common.h"

#define XSI	"http://www.w3.org/2001/XMLSchema-instance"

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
	GEN_EBUILD,
	/*
	 * following errors may appear only if response validation is turned on
	 */
	/* this should be impossible !! - generating something what is not xml */
	GEN_NOT_XML,
	/* malloc failure during response validation */
	GEN_EINTERNAL,
	/* error when parsing schema */
	GEN_ESCHEMA,
	/* response does not validate */
	GEN_NOT_VALID
}gen_status;

typedef struct {
	char	*response;
	struct circ_list	*valerr;
}epp_gen;

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
 * @par val_errors If validation of responses is turned on and response does
 *                 not validate, then this is the place where to look for errors.
 * @ret GEN_OK if success
 */
gen_status
epp_gen_response(
		int validate,
		char *schema_url,
		epp_lang lang,
		epp_command_data *cdata,
		epp_gen *gen);

/**
 * free string allocated by generate functions.
 * @par genstring String to be freed
 */
void epp_free_gen(epp_gen *gen);

void epp_free_greeting(char *greeting);

#endif /* EPP_GEN_H */

