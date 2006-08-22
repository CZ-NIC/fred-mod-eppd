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
 * Return value from generator consists of generated string and validation
 * errors if validation of responses is turned on.
 */
typedef struct {
	char	*response;	/**< Result of generation phase. */
	struct circ_list	*valerr;	/**< List of validation errors. */
}epp_gen;

/**
 * Routine makes up epp greeting frame.
 *
 * @param svid Part of server ID used in svid tag.
 * @param greeting Greeting string.
 * @return Generator status.
 */
gen_status
epp_gen_greeting(const char *svid, char **greeting);

/**
 * Generate command response in XML format. There is option that response
 * can be validated, the validation errors are then returned together with
 * generated string in form of a list.
 *
 * @param validate Tells if response should be validated or not (boolean).
 * @param schema_url Location of schema against which to validate.
 * @param lang Language selected by the client.
 * @param cdata Input values
 * @param gen Generated string and possibly validation errors if validation
 * is turned on.
 * @param timebegin Starting time of function (perf data).
 * @param timeend Ending time of function (perf data).
 * @return Generator status.
 */
gen_status
epp_gen_response(
		int validate,
		char *schema_url,
		epp_lang lang,
		epp_command_data *cdata,
		epp_gen *gen,
		unsigned long long *timestart,
		unsigned long long *timeend);

/**
 * Free response created by response generator and free validation errors.
 * @param gen Result of generator.
 */
void epp_free_gen(epp_gen *gen);

/**
 * Free response created by greeting generator. Simple free() is called
 * on greeting string.
 * @param greeting Greeting string.
 */
void epp_free_greeting(char *greeting);

#endif /* EPP_GEN_H */
