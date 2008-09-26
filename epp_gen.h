/*  
 *  Copyright (C) 2007  CZ.NIC, z.s.p.o.
 *
 *  This file is part of FRED.
 *
 *  FRED is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, version 2 of the License.
 *
 *  FRED is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with FRED.  If not, see <http://www.gnu.org/licenses/>.
 */
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
	GEN_OK,         /**< No error appeared, everything was allright. */
	GEN_EBUFFER,    /**< Could not create xml buffer. */
	GEN_EWRITER,    /**< Could not create xml writer. */
	GEN_EBUILD,     /**< Error when building xml document. */
	/*
	 * following errors may appear only if response validation is turned on
	 */
	GEN_NOT_XML,    /**< Something what is not xml was generated. */
	GEN_EINTERNAL,  /**< Malloc failure during response validation. */
	GEN_ESCHEMA,    /**< Error when parsing xml schema used for validation. */
	GEN_NOT_VALID   /**< Response does not validate. */
}gen_status;

/**
 * Routine makes up epp greeting frame.
 *
 * @param pool     Pool to allocate memory from.
 * @param svid     Part of server ID used in svid tag.
 * @param date     Current date as returned from server.
 * @param greeting Greeting string.
 * @return         Generator status.
 */
gen_status
epp_gen_greeting(void *pool, const char *svid, const char *date, char **greeting);

/**
 * Generate command response in XML format.
 *
 * There is option that response can be validated, the validation errors
 * are then returned together with generated string in form of a list.
 *
 * @param epp_ctx  Epp context (session id, connection and pool).
 * @param validate Tells if response should be validated or not (boolean).
 * @param schema   Schema against which to validate.
 * @param lang     Language selected by the client.
 * @param cdata    Input values
 * @param response Result of generation phase = generated string.
 * @param valerr   List of validation errors if validation is turned on.
 * @return         Generator status.
 */
gen_status
epp_gen_response(epp_context *epp_ctx,
		int validate,
		void *schema,
		epp_lang lang,
		epp_command_data *cdata,
		char **response,
		qhead *valerr);

/**
 * Convenient wrapper around epp_gen_response for error cases.
 * @param p_epp_ctx  Epp context (session id, connection and pool).
 * @param p_cdata    Input values
 * @param pp_response Result of generation phase = generated string.
 */
#define epp_gen_dummy_response(p_epp_ctx, p_cdata, pp_response) \
	epp_gen_response(p_epp_ctx, 0, NULL, LANG_EN, p_cdata, pp_response, NULL)

#endif /* EPP_GEN_H */

/* vim: set ts=4 sw=4: */
