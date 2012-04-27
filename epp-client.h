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
 * @file epp-client.h
 *
 * Interface definition of corba module.
 */
#ifndef EPP_CLIENT_H
#define EPP_CLIENT_H

#include "epp_common.h"
#include "EPP.h"

/**
 * Maximum number of retries when connection failure occurs before
 * the failure is announced to a caller.
 */
#define MAX_RETRIES	3
/** Number of microseconds between retries when connection failure occurs. */
#define RETR_SLEEP  100000

/** Quick test if corba exception was raised. */
#define raised_exception(ev)	((ev)->_major != CORBA_NO_EXCEPTION)


/** Maximal size of property value in database */
#define DB_FIELD_SIZE 2000

/** True if exception is COMM_FAILURE, which is used in retry loop. */
#define IS_NOT_COMM_FAILURE_EXCEPTION(_ev)                             \
	(strcmp((_ev)->_id, "IDL:omg.org/CORBA/COMM_FAILURE:1.0"))
/** True if exception is EPP_ERROR. */
#define IS_EPP_ERROR(_ev)                             \
	(!strcmp((_ev)->_id, "IDL:ccReg/EPP/EppError:1.0"))
/** True if exception is NO_MESSAGES. */
#define IS_NO_MESSAGES(_ev)                             \
	(!strcmp((_ev)->_id, "IDL:ccReg/EPP/NoMessages:1.0"))

/** Possible return values of functions from corba module. */
typedef enum {
	CORBA_OK,   /**< No errors. */
	/** Corba function call failed (e.g. server is not available).  */
	CORBA_ERROR,
	CORBA_INT_ERROR, /**< This should occur unusualy (e.g. malloc failed) */
	/** Epp server is responding but the response is not valid.  */
	CORBA_REMOTE_ERROR
}corba_status;

/** Reference to EPP CORBA service */
typedef void *service_EPP;
/** Reference to fred-logd CORBA service */
typedef void *service_Logger;

/**
 * Function wraps strings passed from XML parser into strings accepted
 * by CORBA.
 *
 * Null strings are transformed to empty strings. The resulting string
 * must be freed with CORBA_free().
 *
 * @param str	Input string.
 * @return      Output string.
 */
char *
wrap_str(const char *str);

/**
 * Purpose of this function is to get version string of ccReg from
 * corba server, which is used as part of server's name in <greeting>
 * frame.
 *
 * @param epp_ctx     Epp context (pool, connection and session id).
 * @param service     EPP service.
 * @param version     Output parameter version string.
 * @param curdate     Output parameter current date.
 * @return            If successfull 1 and 0 if corba function call failed.
 */
int
epp_call_hello(epp_context *epp_ctx,
		service_EPP service,
		char **version,
		char **curdate);

/**
 * Call corba login function, which sets up a session variables.
 *
 * @param epp_ctx     Epp context (pool, connection and session id).
 * @param service     EPP service.
 * @param loginid     If successfully logged in, the session identifier assigned
 *                    by server will be stored in this parameter.
 * @param request_id      fred-logd request ID
 * @param lang        If successfully logged in, the selected language will be
 *                    stored in this parameter.
 * @param fingerprint Fingerprint of client's certificate.
 * @param cdata       Data from parsed xml command.
 * @return            Status.
 */
corba_status
epp_call_login(epp_context *epp_ctx,
		service_EPP service,
		unsigned long long *loginid,
		const ccReg_TID request_id,
		epp_lang *lang,
		const char *fingerprint,
		epp_command_data *cdata);

/**
 * Call corba logout function.
 *
 * @param epp_ctx     Epp context (pool, connection and session id).
 * @param service     EPP service.
 * @param loginid     Session identifier (may change inside).
 * @param request_id      fred-logd request ID
 * @param cdata       Data from parsed xml command.
 * @return            Status.
 */
corba_status
epp_call_logout(epp_context *epp_ctx,
		service_EPP service,
		unsigned long long *loginid,
        const ccReg_TID request_id,
		epp_command_data *cdata);

/**
 * Call generic command corba handler which decides what to do on the basis
 * of cdata content.
 *
 * login, logout commands are not handled by this function.
 * They are rather handled by dedicated functions epp_call_login() and
 * epp_call_logout(). For all other commands use this function.
 *
 * @param epp_ctx     Epp context (pool, connection and session id).
 * @param service     EPP service.
 * @param loginid     Session identifier
 * @param request_id      fred-logd request ID
 * @param cdata       Data from parsed xml command.
 * @return            Status.
 */
corba_status
epp_call_cmd(epp_context *epp_ctx,
		service_EPP service,
		unsigned long long loginid,
                const ccReg_TID request_id,
		epp_command_data *cdata);

/**
 * This function calls corba function which saves generated XML in database.
 *
 * From architectural view THIS IS UGLY HACK! And until
 * serving of EPP request will become complex operation composed from
 * several function calls, it will remain so.
 *
 * @param epp_ctx     Epp context (pool, connection and session id).
 * @param service     EPP service.
 * @param cdata       Used to get svTRID.
 * @param xml         Output XML.
 */
void
epp_call_save_output_xml(epp_context *epp_ctx,
		service_EPP service,
		epp_command_data *cdata,
		const char *xml);

/**
 * Let the CR know that client has closed tcp session.
 *
 * @param epp_ctx     Epp context (pool, connection and session id).
 * @param service     EPP service.
 * @param loginid     Login ID of client.
 */
void
epp_call_CloseSession(epp_context *epp_ctx, service_EPP service,
		unsigned long long loginid);


#define MAX_ERROR_MSG_LEN	100

#endif /* EPP_CLIENT_H */
