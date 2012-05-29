#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "logd-client.h"
#include "epp_parser.h"

#include "apr.h"

/* prototypes for functions using CORBA cals or CORBA data structures */
struct ccReg_RequestProperties;

/** ID of the EPP service according to database table service */
static const long LC_EPP = 3;

/* functions for filling log properties */
ccReg_RequestProperties *epp_property_push_qhead(ccReg_RequestProperties *c_props, qhead *list, char *list_name, CORBA_boolean output, CORBA_boolean child);
ccReg_RequestProperties *epp_property_push(ccReg_RequestProperties *c_props, const char *name, const char *value, CORBA_boolean output, CORBA_boolean child);
ccReg_RequestProperties *epp_property_push_int(ccReg_RequestProperties *c_props, const char *name, int value, CORBA_boolean output);

int epp_log_close_message(epp_context *epp_ctx,
        service_Logger service,
		const char *content,
		ccReg_RequestProperties *properties,
                ccReg_ObjectReferences *objrefs,
		ccReg_TID log_entry_id,
		ccReg_TID session_id,
                CORBA_long result_code,
		char *errmsg);

int epp_log_new_message(epp_context *epp_ctx,
        service_Logger service,
		const char *sourceIP,
		const char *content,
		ccReg_RequestProperties *properties,
                ccReg_ObjectReferences *objrefs,
         	epp_action_type action_type,
         	ccReg_TID *log_entry_id,
		ccReg_TID sessionid,
		char *errmsg);

/* end of prototypes for functions using CORBA cals or CORBA data structures */

#define PUSH_PROPERTY(seq, name, value)								\
	seq = epp_property_push(seq, name, value, CORBA_FALSE, CORBA_FALSE);	\
	if(seq == NULL) {												\
		return LOG_INTERNAL_ERROR;							\
	}

#define PUSH_PROPERTY_INT(seq, name, value)							\
	seq = epp_property_push_int(seq, name, value, CORBA_FALSE);		\
	if(seq == NULL) {												\
		return LOG_INTERNAL_ERROR;							\
	}

#define PUSH_QHEAD(seq, list, name)									\
	seq = epp_property_push_qhead(seq, list, name, CORBA_FALSE, CORBA_FALSE);	\
	if(seq == NULL) {												\
		return LOG_INTERNAL_ERROR;							\
	}


static epp_action_type log_props_login(ccReg_RequestProperties **c_props, epp_command_data *cdata);
static epp_action_type log_props_check(ccReg_RequestProperties **c_props, epp_command_data *cdata);
static epp_action_type log_props_info(ccReg_RequestProperties **c_props, epp_command_data *cdata);
static epp_action_type log_props_poll(ccReg_RequestProperties **c_props, epp_command_data *cdata);
static epp_action_type log_props_create(ccReg_RequestProperties **c_props, epp_command_data *cdata);
static epp_action_type log_props_delete(ccReg_RequestProperties **c_props, epp_command_data *cdata);
static epp_action_type log_props_renew(ccReg_RequestProperties **c_props, epp_command_data *cdata);
static epp_action_type log_props_update(ccReg_RequestProperties **c_props, epp_command_data *cdata);
static epp_action_type log_props_transfer(ccReg_RequestProperties **c_props, epp_command_data *cdata);
static epp_action_type log_props_default_extcmd(ccReg_RequestProperties **c_props, epp_command_data *cdata);
static void log_props_default_extcmd_response(ccReg_RequestProperties **c_props, const epp_command_data *cdata);

/** Maximum property name length for fred-logd logging facility */
static const int LOG_PROP_NAME_LENGTH = 50;

/**
 * Add the content of a qhead linked list to the properties.
 * The list should contain only strings
 *
 * @param c_props	log entry properties or a NULL pointer (in which
 * 					case a new data structure is allocated and returned)
 * @param list		list of strings
 * @param list_name	base name for the inserted properties
 * @param output 	whether the properties are related to output
 * @param child		true if the items in the list are children of the last property
 * 					with child = false
 *
 * @returns 		log entry properties or NULL in case of an allocation error
 *
 */

ccReg_RequestProperties *epp_property_push_qhead(ccReg_RequestProperties *c_props, qhead *list, char *list_name, CORBA_boolean output, CORBA_boolean child)
{
	if (list->count == 0) {
		return c_props;
	}

	q_foreach(list) {
		if ((c_props = epp_property_push(c_props, list_name, (char*)q_content(list), output, child)) == NULL) {
			return NULL;
		}
	}

	return c_props;
}

#define ALLOC_STEP 4

/**
 * Add a name, value pair to the properties. Allocate memory and the property list itself
 * on demand
 * @param c_props	log entry properties or a NULL pointer (in which
 * 					case a new data structure is allocated and returned)
 * @param name		property name
 * @param value		property value
 * @param output	whether the property is related to output
 * @param child 	true if the property is child to the last property with child = false
 *
 * @returns			NULL in case of an allocation error, modified c_props otherwise
 */
ccReg_RequestProperties *epp_property_push(ccReg_RequestProperties *c_props, const char *name, const char *value, CORBA_boolean output, CORBA_boolean child)
{
    if (c_props == NULL) {
        c_props = ccReg_RequestProperties__alloc();
        if (c_props == NULL) {
            return NULL;
        }
        c_props->_maximum = ALLOC_STEP;        

        c_props->_buffer = ccReg_RequestProperties_allocbuf(c_props->_maximum);

        if (c_props->_buffer == NULL) {
            CORBA_free(c_props);
            return NULL;
        }
        c_props->_length = 0;
        c_props->_release = CORBA_TRUE;
    }

    if (value != NULL) {
        int old_length;
        ccReg_RequestProperty new_prop;

        new_prop.name = name;
        new_prop.value = value;
        new_prop.output = output;
        new_prop.child = child;

        old_length = c_props->_length;
        // this function already takes care of _length and _maximum, check orbit unittests :)
        ORBit_sequence_append(c_props, &new_prop);

        if (c_props->_length != old_length + 1) {
            CORBA_free(c_props);
            return NULL;
        }
    }

    return c_props;
}

/**
 * Add a name, value pair to the properties, where value is an integer
 * Allocate buffer on demand.
 *
 * @param c_props	log entry properties or a NULL pointer (in which
 * 					case a new data structure is allocated and returned)
 * @param name		property name
 * @param value		property integer value
 * @param output	true if this property is related to output (response), false otherwise
 *
 * @returns			NULL in case of an allocation error, modified c_props otherwise
 */

ccReg_RequestProperties *epp_property_push_int(ccReg_RequestProperties *c_props, const char *name, int value, CORBA_boolean output)
{
    char str[12];
    int old_length;
    ccReg_RequestProperty new_prop;

    if (c_props == NULL) {
        c_props = ccReg_RequestProperties__alloc();
        if (c_props == NULL) {
            return NULL;
        }
        c_props->_maximum = ALLOC_STEP;        

        c_props->_buffer = ccReg_RequestProperties_allocbuf(c_props->_maximum);

        if (c_props->_buffer == NULL) {
            CORBA_free(c_props);
            return NULL;
        }
        c_props->_length = 0;
        c_props->_release = CORBA_TRUE;
    }

    snprintf(str, 12, "%i", value);

    new_prop.name = name;
    new_prop.value = str;
    new_prop.output = output;
    new_prop.child = CORBA_FALSE;

    old_length = c_props->_length;
    // this function already takes care of _length and _maximum, check orbit unittests :)
    ORBit_sequence_append(c_props, &new_prop);

    if (c_props->_length != old_length + 1) {
        CORBA_free(c_props);
        return NULL;
    }

    return c_props;

}
#undef ALLOC_STEP

/** Log a new session using fred-logd
 * @param service 	Reference to the CORBA service
 * @param name		handle of the registrar
 * @param lang		language (en,cs,...)
 * @param log_session_id id for log_session table
 *
 * @returns		CORBA status code
 */
int epp_log_CreateSession(epp_context *epp_ctx, service_Logger service, const char *user_name, ccReg_TID user_id, ccReg_TID * const log_session_id, char *errmsg)
{
	CORBA_Environment ev[1];
	CORBA_char *c_name;
	ccReg_TID session_id = 0;
	int retr;

	c_name = wrap_str(user_name);
	if(c_name == NULL) {
		return CORBA_INT_ERROR;
	}

	/* retry loop */
	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev); // valid first time
		CORBA_exception_init(ev);

		session_id = ccReg_Logger_createSession((ccReg_Logger) service, user_id, c_name, ev);

		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;

		epplog(epp_ctx, EPP_WARNING, "Retry occured in CreateSession");
		// TODO everywhere

		usleep(RETR_SLEEP);
	}

	CORBA_free(c_name);

	if (raised_exception(ev)) {
		strncpy(errmsg, ev->_id, MAX_ERROR_MSG_LEN - 1);
		errmsg[MAX_ERROR_MSG_LEN - 1] = '\0';
		CORBA_exception_free(ev);
        *log_session_id = 0;
		return CORBA_ERROR;
	}

	CORBA_exception_free(ev);
	/* set session id output param */
	*log_session_id = session_id;
	epplog(epp_ctx, EPP_INFO, "Created session in fred-logd with id: %" APR_UINT64_T_FMT, *log_session_id);

	return CORBA_OK;
}

/** End a log session through fred-logd
 * @param service 	Reference to the CORBA service
 * @param log_session_id id for log_session table - session which is to be ended
 * @param errmsg	error message
 *
 * @returns		CORBA status code
 */
int epp_log_CloseSession(epp_context *epp_ctx, service_Logger service, ccReg_TID log_session_id, char *errmsg)
{
	CORBA_Environment ev[1];
	int retr;

	/* retry loop */
	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev); /* valid first time */
		CORBA_exception_init(ev);

		/* call logger method */

		ccReg_Logger_closeSession((ccReg_Logger) service, log_session_id, ev);

		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;

		epplog(epp_ctx, EPP_WARNING, "Retrying call: closeSession");

		usleep(RETR_SLEEP);
	}

        // TODO properly handle exceptions
        // // return CORBA_REMOTE_ERROR;
	if (raised_exception(ev)) {
		strncpy(errmsg, ev->_id, MAX_ERROR_MSG_LEN - 1);
		errmsg[MAX_ERROR_MSG_LEN - 1] = '\0';
		CORBA_exception_free(ev);
		return CORBA_ERROR;
	}
	CORBA_exception_free(ev);

        return CORBA_OK;
}


/**
 * Log a new event using fred-logd
 *
 * @param service 		Reference to the CORBA service
 * @param sourceIP		IP address of the client
 * @param content		content of the request
 * @param properties	List of properties (name, value pairs)
 * @param log_entry_id		output of ID of the new entry in log_entry database table. Id is used in other calls to logging
 * @param errmsg		Output of a CORBA error message
 *
 * @returns				CORBA status code
 */
int epp_log_new_message(epp_context *epp_ctx,
        service_Logger service,
		const char *source_ip,
		const char *content,
		ccReg_RequestProperties *properties,
                ccReg_ObjectReferences *objrefs,
         	epp_action_type action_type,
         	ccReg_TID *log_entry_id,
		ccReg_TID sessionid,
		char *errmsg)
{
	CORBA_Environment	 ev[1];
	CORBA_char *c_source_ip, *c_content;
	ccReg_TID entry_id = 0;
	int	 retr;  /* retry counter */
	int	 ret;

    /* don't log requests without session (logger restart problem)
     * will be changed when logging become mandatory */
        if (action_type != ClientLogin && action_type != ClientGreeting && sessionid == 0) {
            return CORBA_ERROR;
        }

	c_source_ip = wrap_str(source_ip);
	if(c_source_ip == NULL) {
		return CORBA_INT_ERROR;
	}
	c_content = wrap_str(content);
	if(c_content == NULL) {
		CORBA_free(c_source_ip);
		return CORBA_INT_ERROR;
	}
	if(properties == NULL) {
		properties = ccReg_RequestProperties__alloc();
		if(properties == NULL) {
			CORBA_free(c_source_ip);
			CORBA_free(c_content);
			return CORBA_INT_ERROR;
		}

		properties->_maximum = properties->_length = 0;
	} 
        if(objrefs == NULL) {
                objrefs = ccReg_ObjectReferences__alloc();
                if(objrefs == NULL) {
                        CORBA_free(c_source_ip);
			CORBA_free(c_content);
                        CORBA_free(properties);
			return CORBA_INT_ERROR;
		}

                objrefs->_maximum = objrefs->_length = 0;
        }
                        

	/* retry loop */
	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev); /* valid first time */
		CORBA_exception_init(ev);

		/* call logger method */
		entry_id = ccReg_Logger_createRequest((ccReg_Logger) service, c_source_ip,  LC_EPP, c_content, properties, objrefs, action_type, sessionid, ev);

		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;

		epplog(epp_ctx, EPP_WARNING, "Retrying call: createRequest");

		usleep(RETR_SLEEP);
	}

	CORBA_free(c_source_ip);
	CORBA_free(c_content);
	CORBA_free(properties);
        CORBA_free(objrefs);

	if (raised_exception(ev)) {
		strncpy(errmsg, ev->_id, MAX_ERROR_MSG_LEN - 1);
		errmsg[MAX_ERROR_MSG_LEN - 1] = '\0';
		CORBA_exception_free(ev);
        *log_entry_id = 0;
		return CORBA_ERROR;
	}
	CORBA_exception_free(ev);

	/* set log entry id output param */
	*log_entry_id = entry_id;

	ret = CORBA_OK;
	return ret;
}

/**
 * Finish a log event
 *
 * @param service 		reference to CORBA service
 * @param content		content of the response
 * @param properties	list of properties associated with response
 * @param errmsg		output of CORBA errors
 * @param log_entry_id		ID of entry to close in log_entry table
 * @param session_id		A key to session table obtained by a call to CreateSession
 *
 * @returns			CORBA status code
 */
int epp_log_close_message(epp_context *epp_ctx, service_Logger service,
		const char *content,
		ccReg_RequestProperties *properties,
                ccReg_ObjectReferences *objrefs,
		ccReg_TID log_entry_id,
		ccReg_TID session_id,
                CORBA_long result_code,
		char *errmsg)
{
	CORBA_Environment	 ev[1];
	CORBA_char *c_content;
	int	 retr;  /* retry counter */

	c_content = wrap_str(content);
	if(c_content == NULL) {
		return CORBA_INT_ERROR;
	}

	if(properties == NULL) {
		properties = ccReg_RequestProperties__alloc();
		if(properties == NULL) {
			CORBA_free(c_content);
			return CORBA_INT_ERROR;
		}

		properties->_maximum = properties->_length = 0;
	}

        if(objrefs == NULL) {
                objrefs = ccReg_ObjectReferences__alloc();
                if(objrefs == NULL) {
			CORBA_free(c_content);
                        CORBA_free(properties);
			return CORBA_INT_ERROR;
		}

                objrefs->_maximum = objrefs->_length = 0;
        }
         

	/* retry loop */
	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev); /* valid first time */
		CORBA_exception_init(ev);

		/* call logger method */
                ccReg_Logger_closeRequest((ccReg_Logger) service, log_entry_id, c_content, properties, objrefs, result_code, session_id, ev);

		/* if COMM_FAILURE is not raised then quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;

		epplog(epp_ctx, EPP_WARNING, "Retrying call: closeRequest");

		usleep(RETR_SLEEP);
	}

	CORBA_free(c_content);
	CORBA_free(properties);
        CORBA_free(objrefs);

        //TODO proper handling of exceptions
        // ret = CORBA_REMOTE_ERROR;
	if (raised_exception(ev)) {
		strncpy(errmsg, ev->_id, MAX_ERROR_MSG_LEN - 1);
		errmsg[MAX_ERROR_MSG_LEN - 1] = '\0';
		CORBA_exception_free(ev);
		return CORBA_ERROR;
	}
	CORBA_exception_free(ev);

        return CORBA_OK;
}





/* ********** end of functions using CORBA (originaly from *-client.c file
 */

/**
 * ############################
 * Add qhead with xml errors to properties
 *
 * @param c_props	log entry properties or a NULL pointer (in which
 * 					case a new data structure is allocated and returned)
 * @param list		list of xml elements and error messages
 * @param list_name	base name for the inserted properties
 *
 * @returns 		log entry properties or NULL in case of an allocation error
 *
 */
ccReg_RequestProperties *epp_property_push_valerr(ccReg_RequestProperties *c_props, qhead *list, char *list_name)
{
	char str[LOG_PROP_NAME_LENGTH]; /* property name */

	epp_error *value;			/* ds record data structure */

	if (q_length(*list) > 0) {

		q_foreach(list) {
			value = (epp_error*)q_content(list);

			str[0] = '\0';
			snprintf(str, LOG_PROP_NAME_LENGTH, "%s.%s", list_name, "element");
			if ((c_props = epp_property_push(c_props, str, value->value, CORBA_TRUE, CORBA_FALSE)) == NULL) {
				return NULL;
			}

			str[0] = '\0';
			snprintf(str, LOG_PROP_NAME_LENGTH, "%s.%s", list_name, "reason");
			if ((c_props = epp_property_push(c_props, str, value->reason, CORBA_TRUE, CORBA_FALSE)) == NULL) {
				return NULL;
			}

		}
        }
        return c_props;

}

/**
 * Add qhead with ns records to properties
 *
 * @param c_props	log entry properties or a NULL pointer (in which
 * 					case a new data structure is allocated and returned)
 * @param list		list of ns records
 * @param list_name	base name for the inserted properties
 *
 * @returns 		log entry properties or NULL in case of an allocation error
 *
 */
ccReg_RequestProperties *epp_property_push_nsset(ccReg_RequestProperties *c_props, qhead *list, char *list_name)
{
	char str[LOG_PROP_NAME_LENGTH]; /* property name */

	epp_ns *value;				/* ds record data structure */

	if (q_length(*list) > 0) {

		q_foreach(list) {
			value = (epp_ns*)q_content(list);

			str[0] = '\0';
			snprintf(str, LOG_PROP_NAME_LENGTH, "%s.%s", list_name, "name");
			if ((c_props = epp_property_push(c_props, str, value->name, CORBA_FALSE, CORBA_FALSE)) == NULL) {
				return NULL;
			}

			str[0] = '\0';
			snprintf(str, LOG_PROP_NAME_LENGTH, "%s.%s", list_name, "addr");
			if ((c_props = epp_property_push_qhead(c_props, &value->addr, str, CORBA_FALSE, CORBA_TRUE)) == NULL) {
				return NULL;
			}
		}
        }
        return c_props;

}

/**
 * Add dnskey list to log item properties
 *
 * @param c_props	log entry properties or a NULL pointer (in which
 * 					case a new data structure is allocated and returned)
 * @param list		list of dnskey records
 * @param list_name	base name for the inserted properties
 *
 * @returns 		log entry properties or NULL in case of an allocation error
 *
 */
ccReg_RequestProperties *epp_property_push_dnskey(ccReg_RequestProperties *c_props, qhead *list, char *list_name)
{
	char str[LOG_PROP_NAME_LENGTH];
	epp_dnskey *value;

	if (q_length(*list) > 0) {
		q_foreach(list) {
			value = (epp_dnskey*)q_content(list);

			str[0] = '\0';
			snprintf(str, LOG_PROP_NAME_LENGTH, "%s.%s", list_name, "flags");
			if ((c_props = epp_property_push_int(c_props, str, value->flags, CORBA_FALSE)) == NULL) {
				return NULL;
			}

			str[0] = '\0';
			snprintf(str, LOG_PROP_NAME_LENGTH, "%s.%s", list_name, "protocol");
			if ((c_props = epp_property_push_int(c_props, str, value->protocol, CORBA_FALSE)) == NULL) {
				return NULL;
			}

			str[0] = '\0';
			snprintf(str, LOG_PROP_NAME_LENGTH, "%s.%s", list_name, "alg");
			if ((c_props = epp_property_push_int(c_props, str, value->alg, CORBA_FALSE)) == NULL) {
				return NULL;
			}

			str[0] = '\0';
			snprintf(str, LOG_PROP_NAME_LENGTH, "%s.%s", list_name, "publicKey");
			if ((c_props = epp_property_push(c_props, str, value->public_key, CORBA_FALSE, CORBA_FALSE)) == NULL) {
				return NULL;
			}

		}
	} 
        return c_props;

}

/**
 * 	Add postal info to log item properties
 *  @param 	p 	log entry properties or a NULL pointer (in which
 * 					case a new data structure is allocated and returned)
 *  @param  pi	postal info
 *
 *  @returns 	log entry properties or NULL in case of an allocation error
 */
ccReg_RequestProperties *epp_log_postal_info(ccReg_RequestProperties *p, epp_postalInfo *pi)
{
	if(pi == NULL) return p;

	p = epp_property_push(p, "pi.name", pi->name, CORBA_FALSE, CORBA_FALSE);
	if (p == NULL) return p;
	p = epp_property_push(p, "pi.organization", pi->org, CORBA_FALSE, CORBA_FALSE);
	if (p == NULL) return p;
	p = epp_property_push_qhead(p, &pi->streets, "pi.street", CORBA_FALSE, CORBA_FALSE);
	if (p == NULL) return p;
	p = epp_property_push(p, "pi.city", pi->city, CORBA_FALSE, CORBA_FALSE);
	if (p == NULL) return p;
	p = epp_property_push(p, "pi.state", pi->sp, CORBA_FALSE, CORBA_FALSE);
	if (p == NULL) return p;
	p = epp_property_push(p, "pi.postalCode", pi->pc, CORBA_FALSE, CORBA_FALSE);
	if (p == NULL) return p;
	p = epp_property_push(p, "pi.countryCode", pi->cc, CORBA_FALSE, CORBA_FALSE);
	if (p == NULL) return p;

	return p;
}

/**
 * 	Add disclose info to log item properties
 *  @param 	p 	log entry properties or a NULL pointer (in which
 * 					case a new data structure is allocated and returned)
 *  @param  ed	disclose info
 *
 *  @returns 	log entry properties or NULL in case of an allocation error
 */
ccReg_RequestProperties *epp_log_disclose_info(ccReg_RequestProperties *p, epp_discl *ed)
{
	if(ed->flag == 1) {
		p = epp_property_push(p, "discl.policy", "private", CORBA_FALSE, CORBA_FALSE);
	} else if(ed->flag == 0) {
		p = epp_property_push(p, "discl.policy", "public", CORBA_FALSE, CORBA_FALSE);
	} else {
		p = epp_property_push(p, "discl.policy", "no exceptions", CORBA_FALSE, CORBA_FALSE);
	}

	if (p == NULL) return p;

	p = epp_property_push(p, "discl.name", ed->name ? "true" : "false", CORBA_FALSE, CORBA_FALSE);
	if (p == NULL) return p;
	p = epp_property_push(p, "discl.org", ed->org ? "true" : "false", CORBA_FALSE, CORBA_FALSE);
	if (p == NULL) return p;
	p = epp_property_push(p, "discl.addr", ed->addr ? "true" : "false", CORBA_FALSE, CORBA_FALSE);
	if (p == NULL) return p;
	p = epp_property_push(p, "discl.voice", ed->voice ? "true" : "false", CORBA_FALSE, CORBA_FALSE);
	if (p == NULL) return p;
	p = epp_property_push(p, "discl.fax", ed->fax ? "true" : "false", CORBA_FALSE, CORBA_FALSE);
	if (p == NULL) return p;
	p = epp_property_push(p, "discl.email", ed->email ? "true" : "false", CORBA_FALSE, CORBA_FALSE);
	if (p == NULL) return p;
	p = epp_property_push(p, "discl.vat", ed->vat ? "true" : "false", CORBA_FALSE, CORBA_FALSE);
	if (p == NULL) return p;
	p = epp_property_push(p, "discl.ident", ed->ident ? "true" : "false", CORBA_FALSE, CORBA_FALSE);
	if (p == NULL) return p;
	p = epp_property_push(p, "discl.notifyEmail", ed->notifyEmail ? "true" : "false", CORBA_FALSE, CORBA_FALSE);
	if (p == NULL) return p;

	return p;
}

static epp_action_type log_props_login(ccReg_RequestProperties **c_props, epp_command_data *cdata)
{
    epp_action_type action_type = UnknownAction;
    epps_login *el;

    if (cdata->type == EPP_LOGIN) {
        action_type = ClientLogin;

        el = cdata->data;

        PUSH_PROPERTY(*c_props, "registrarId", el->clID);
        // type epp_lang:
        if (el->lang == LANG_CS) {
            PUSH_PROPERTY(*c_props, "lang", "CZ");
        } else if (el->lang == LANG_EN) {
            PUSH_PROPERTY(*c_props, "lang", "EN");
        } else {
            PUSH_PROPERTY_INT(*c_props, "lang", el->lang);
        }
        PUSH_PROPERTY(*c_props, "password", el->pw);
        PUSH_PROPERTY(*c_props, "newPassword", el->newPW);
    } else {
        epps_sendAuthInfo *ai = cdata->data;

        switch (cdata->type) {
            case EPP_SENDAUTHINFO_CONTACT:
                action_type = ContactSendAuthInfo;
                break;
            case EPP_SENDAUTHINFO_DOMAIN:
                action_type = DomainSendAuthInfo;
                break;
            case EPP_SENDAUTHINFO_NSSET:
                action_type = NSSetSendAuthInfo;
                break;
            case EPP_SENDAUTHINFO_KEYSET:
                action_type = KeySetSendAuthInfo;
                break;

            case EPP_CREDITINFO:
                action_type = ClientCredit;
                break;
            case EPP_TEST_NSSET:
                action_type = nssetTest;
                break;

            case EPP_INFO_LIST_CONTACTS:
                action_type = InfoListContacts;
                break;
            case EPP_INFO_LIST_DOMAINS:
                action_type = InfoListDomains;
                break;
            case EPP_INFO_LIST_NSSETS:
                action_type = InfoListNssets;
                break;
            case EPP_INFO_LIST_KEYSETS:
                action_type = InfoListKeysets;
                break;
            case EPP_INFO_DOMAINS_BY_NSSET:
                action_type = InfoDomainsByNsset;
                break;
            case EPP_INFO_DOMAINS_BY_KEYSET:
                action_type = InfoDomainsByKeyset;
                break;
            case EPP_INFO_DOMAINS_BY_CONTACT:
                action_type = InfoDomainsByContact;
                break;
            case EPP_INFO_NSSETS_BY_CONTACT:
                action_type = InfoNssetsByContact;
                break;
            case EPP_INFO_NSSETS_BY_NS:
                action_type = InfoNssetsByNs;
                break;
            case EPP_INFO_KEYSETS_BY_CONTACT:
                action_type = InfoKeysetsByContact;
                break;
            case EPP_INFO_GET_RESULTS:
                action_type = InfoGetResults;
                break;
            default:
                action_type = UnknownAction;
        }

        PUSH_PROPERTY(*c_props, "handle", ai->id);
    }

    return action_type;
}

static epp_action_type log_props_check(ccReg_RequestProperties **c_props, epp_command_data *cdata)
{
    epp_action_type action_type = UnknownAction;

    switch (cdata->type) {
        case EPP_CHECK_CONTACT:
            action_type = ContactCheck;
            break;
        case EPP_CHECK_DOMAIN:
            action_type = DomainCheck;
            break;
        case EPP_CHECK_NSSET:
            action_type = NSsetCheck;
            break;
        case EPP_CHECK_KEYSET:
            action_type = KeysetCheck;
            break;
        default:
            break;
    }

    return action_type;
}

static void log_props_out_check(ccReg_RequestProperties **c_props, const epp_command_data *cdata)
{
    epps_check *ec;

    ec = cdata->data;

    q_reset(&ec->avails);
    q_reset(&ec->ids);

    q_foreach(&ec->ids) {
        epp_avail *avail;

        if((ec->avails).cur == NULL) break;

        avail = q_content(&ec->avails);

        *c_props = epp_property_push(*c_props, "handle", q_content(&ec->ids), CORBA_TRUE, CORBA_FALSE);
        if(avail->avail) {
	    *c_props = epp_property_push(*c_props, "available", "true", CORBA_TRUE, CORBA_TRUE);
        } else {
	    *c_props = epp_property_push(*c_props, "available", "false", CORBA_TRUE, CORBA_TRUE);
	    *c_props = epp_property_push(*c_props, "reason", avail->reason, CORBA_TRUE, CORBA_TRUE);
        }
        
        q_next(&ec->avails);
    }
}

static epp_action_type log_props_info(ccReg_RequestProperties **c_props, epp_command_data *cdata)
{
    epp_action_type action_type = UnknownAction;

    switch (cdata->type) {
        case EPP_LIST_CONTACT:
            action_type = ListContact;
            break;
        case EPP_LIST_KEYSET:
            action_type = ListKeySet;
            break;
        case EPP_LIST_NSSET:
            action_type = ListNSset;
            break;
        case EPP_LIST_DOMAIN:
            action_type = ListDomain;
            break;

        case EPP_INFO_CONTACT:
        {
            epps_info_contact *i = cdata->data;

            PUSH_PROPERTY(*c_props, "handle", i->id)
            action_type = ContactInfo;
            break;
        }
        case EPP_INFO_KEYSET:
        {
            epps_info_keyset *i = cdata->data;

            PUSH_PROPERTY(*c_props, "handle", i->id)
            action_type = KeysetInfo;
            break;
        }
        case EPP_INFO_NSSET:
        {
            epps_info_nsset *i = cdata->data;

            PUSH_PROPERTY(*c_props, "handle", i->id)
            action_type = NSsetInfo;
            break;
        }
        case EPP_INFO_DOMAIN:
        {
            epps_info_domain *i = cdata->data;

            PUSH_PROPERTY(*c_props, "handle", i->name)
            action_type = DomainInfo;
            break;
        }
        default:
            break;
    }

    return action_type;
}

static epp_action_type log_props_poll(ccReg_RequestProperties **c_props, epp_command_data *cdata)
{
    if (cdata->type == EPP_POLL_ACK) {        
        epps_poll_ack *pa = cdata->data;
        PUSH_PROPERTY(*c_props, "msgId", pa->msgid);
        return PollAcknowledgement;
    } else {
        return PollResponse;
    }
}

static epp_action_type log_props_create(ccReg_RequestProperties **c_props, epp_command_data *cdata)
{
    epp_action_type action_type = UnknownAction;

    switch (cdata->type) {
        case EPP_CREATE_CONTACT:
            action_type = ContactCreate;
            epps_create_contact *cc = cdata->data;

            PUSH_PROPERTY(*c_props, "handle", cc->id);

            // postal info
            if ((*c_props = epp_log_postal_info(*c_props, &cc->pi)) == NULL) {
                return LOG_INTERNAL_ERROR;
            }

            PUSH_PROPERTY(*c_props, "voice", cc->voice);
            PUSH_PROPERTY(*c_props, "fax", cc->fax);
            PUSH_PROPERTY(*c_props, "email", cc->email);
            PUSH_PROPERTY(*c_props, "authInfo", cc->authInfo);

            // disclose info
            if ((*c_props = epp_log_disclose_info(*c_props, &cc->discl)) == NULL) {
                return LOG_INTERNAL_ERROR;
            }

            PUSH_PROPERTY(*c_props, "vat", cc->vat);
            PUSH_PROPERTY(*c_props, "ident", cc->ident);
            switch (cc->identtype) {
                case ident_UNKNOWN: PUSH_PROPERTY(*c_props, "identType", "unknown");
                    break;
                case ident_OP: PUSH_PROPERTY(*c_props, "identType", "ID card");
                    break;
                case ident_PASSPORT: PUSH_PROPERTY(*c_props, "identType", "passport");
                    break;
                case ident_MPSV: PUSH_PROPERTY(*c_props, "identType", "number assinged by ministry");
                    break;
                case ident_ICO: PUSH_PROPERTY(*c_props, "identType", "ICO");
                    break;
                case ident_BIRTHDAY: PUSH_PROPERTY(*c_props, "identType", "birthdate");
                    break;
            }
            PUSH_PROPERTY(*c_props, "notifyEmail", cc->notify_email);
            // COMMON

            break;

        case EPP_CREATE_DOMAIN:
            action_type = DomainCreate;
            epps_create_domain *cd = cdata->data;

            PUSH_PROPERTY(*c_props, "handle", cd->name);
            PUSH_PROPERTY(*c_props, "registrant", cd->registrant);
            PUSH_PROPERTY(*c_props, "nsset", cd->nsset);
            PUSH_PROPERTY(*c_props, "keyset", cd->keyset);
            // qhead	 extensions;   /**< List of domain extensions.
            PUSH_PROPERTY(*c_props, "authInfo", cd->authInfo);
            // COMMON

            PUSH_QHEAD(*c_props, &cd->admin, "admin");
            PUSH_PROPERTY_INT(*c_props, "period", cd->period);
            if (cd->unit == TIMEUNIT_MONTH) {
                PUSH_PROPERTY(*c_props, "timeunit", "Month");
            } else if (cd->unit == TIMEUNIT_YEAR) {
                PUSH_PROPERTY(*c_props, "timeunit", "Year");
            }
            PUSH_PROPERTY(*c_props, "expirationDate", cd->exDate);
            break;

        case EPP_CREATE_NSSET:
            action_type = NSsetCreate;
            epps_create_nsset *cn = cdata->data;

            PUSH_PROPERTY(*c_props, "handle", cn->id);
            PUSH_PROPERTY(*c_props, "authInfo", cn->authInfo);
            // -1 means unspecified
            if(cn->level != -1) {
                PUSH_PROPERTY_INT(*c_props, "reportLevel", cn->level);
            }
            // COMMON
            if ((*c_props = epp_property_push_nsset(*c_props, &cn->ns, "ns")) == NULL) {
                return LOG_INTERNAL_ERROR;
            }
            PUSH_QHEAD(*c_props, &cn->tech, "techC");

            break;
        case EPP_CREATE_KEYSET:
            action_type = KeysetCreate;
            epps_create_keyset *ck = cdata->data;

            PUSH_PROPERTY(*c_props, "handle", ck->id);
            PUSH_PROPERTY(*c_props, "authInfo", ck->authInfo);
            // COMMON

            if ((*c_props = epp_property_push_dnskey(*c_props, &ck->keys, "keys")) == NULL) {
                return LOG_INTERNAL_ERROR;
            }

            PUSH_QHEAD(*c_props, &ck->tech, "techContact");
            break;
        default:
            break;
    }
    return action_type;
}

static epp_action_type log_props_delete(ccReg_RequestProperties **c_props, epp_command_data *cdata)
{
    epp_action_type action_type = UnknownAction;
    epps_delete *ed;

    switch (cdata->type) {
        case EPP_DELETE_CONTACT:
            action_type = ContactDelete;
            break;
        case EPP_DELETE_DOMAIN:
            action_type = DomainDelete;
            break;
        case EPP_DELETE_NSSET:
            action_type = NSsetDelete;
            break;
        case EPP_DELETE_KEYSET:
            action_type = KeysetDelete;
            break;
        default:
            break;
    }
    ed = cdata->data;

    PUSH_PROPERTY(*c_props, "handle", ed->id);
    return action_type;
}

static epp_action_type log_props_renew(ccReg_RequestProperties **c_props, epp_command_data *cdata)
{
    epp_action_type action_type = UnknownAction;
    epps_renew *er;
    action_type = DomainRenew;
    er = cdata->data;

    PUSH_PROPERTY(*c_props, "handle", er->name);
    PUSH_PROPERTY(*c_props, "curExDate", er->curExDate);
    PUSH_PROPERTY_INT(*c_props, "renewPeriod", er->period);
    if (er->unit == TIMEUNIT_MONTH) {
        PUSH_PROPERTY(*c_props, "timeunit", "Month");
    } else if (er->unit == TIMEUNIT_YEAR) {
        PUSH_PROPERTY(*c_props, "timeunit", "Year");
    }
    PUSH_PROPERTY(*c_props, "expirationDate", er->exDate);

    return action_type;
}

static epp_action_type log_props_update(ccReg_RequestProperties **c_props, epp_command_data *cdata)
{
    epp_action_type action_type = UnknownAction;

    switch (cdata->type) {
        case EPP_UPDATE_CONTACT:
            action_type = ContactUpdate;

            epps_update_contact *uc = cdata->data;

            PUSH_PROPERTY(*c_props, "handle", uc->id);

            if ((*c_props = epp_log_postal_info(*c_props, uc->pi)) == NULL) {
                return LOG_INTERNAL_ERROR;
            }

            PUSH_PROPERTY(*c_props, "voice", uc->voice);
            PUSH_PROPERTY(*c_props, "fax", uc->fax);
            PUSH_PROPERTY(*c_props, "email", uc->email);
            PUSH_PROPERTY(*c_props, "authInfo", uc->authInfo);

            if ((*c_props = epp_log_disclose_info(*c_props, &uc->discl)) == NULL) {
                return LOG_INTERNAL_ERROR;
            }

            PUSH_PROPERTY(*c_props, "vat", uc->vat);
            PUSH_PROPERTY(*c_props, "ident", uc->ident);

            switch (uc->identtype) {
                case ident_UNKNOWN: PUSH_PROPERTY(*c_props, "identType", "unknown");
                    break;
                case ident_OP: PUSH_PROPERTY(*c_props, "identType", "ID card");
                    break;
                case ident_PASSPORT: PUSH_PROPERTY(*c_props, "identType", "passport");
                    break;
                case ident_MPSV: PUSH_PROPERTY(*c_props, "identType", "number assinged by ministry");
                    break;
                case ident_ICO: PUSH_PROPERTY(*c_props, "identType", "ICO");
                    break;
                case ident_BIRTHDAY: PUSH_PROPERTY(*c_props, "identType", "birthdate");
                    break;
            }

            PUSH_PROPERTY(*c_props, "notifyEmail", uc->notify_email);
            // COMMON
            break;

        case EPP_UPDATE_DOMAIN:
            action_type = DomainUpdate;

            epps_update_domain *ud = cdata->data;

            PUSH_PROPERTY(*c_props, "handle", ud->name);
            PUSH_PROPERTY(*c_props, "registrant", ud->registrant);
            PUSH_PROPERTY(*c_props, "nsset", ud->nsset);
            PUSH_PROPERTY(*c_props, "keyset", ud->keyset);
            // qhead	 extensions;   /**< List of domain extensions.
            PUSH_PROPERTY(*c_props, "authInfo", ud->authInfo);
            // COMMONs

            PUSH_QHEAD(*c_props, &ud->add_admin, "addAdmin");
            PUSH_QHEAD(*c_props, &ud->rem_admin, "remAdmin");
            PUSH_QHEAD(*c_props, &ud->rem_tmpcontact, "remTmpcontact");

            break;

        case EPP_UPDATE_NSSET:
            action_type = NSsetUpdate;
            epps_update_nsset *un = cdata->data;

            PUSH_PROPERTY(*c_props, "handle", un->id);
            PUSH_PROPERTY(*c_props, "authInfo", un->authInfo);
            // -1 means unspecified
            if(un->level != -1) {
                PUSH_PROPERTY_INT(*c_props, "reportLevel", un->level);
            }
            // COMMON

            PUSH_QHEAD(*c_props, &un->add_tech, "addTechC");
            PUSH_QHEAD(*c_props, &un->rem_tech, "remTechC");
            if ((*c_props = epp_property_push_nsset(*c_props, &un->add_ns, "addNs")) == NULL) {
                return LOG_INTERNAL_ERROR;
            }
            PUSH_QHEAD(*c_props, &un->rem_ns, "remNs");

            break;

        case EPP_UPDATE_KEYSET:
            action_type = KeysetUpdate;
            epps_update_keyset *uk = cdata->data;

            PUSH_PROPERTY(*c_props, "handle", uk->id);
            PUSH_PROPERTY(*c_props, "authInfo", uk->authInfo);
            // COMMON

            PUSH_QHEAD(*c_props, &uk->add_tech, "addTech");
            PUSH_QHEAD(*c_props, &uk->rem_tech, "remTech");

            if ((*c_props = epp_property_push_dnskey(*c_props, &uk->add_dnskey, "addKeys")) == NULL) {
                return LOG_INTERNAL_ERROR;
            }
            if ((*c_props = epp_property_push_dnskey(*c_props, &uk->rem_dnskey, "remKeys")) == NULL) {
                return LOG_INTERNAL_ERROR;
            }

            break;
        default:
            break;
    }
    return action_type;
}

static epp_action_type log_props_transfer(ccReg_RequestProperties **c_props, epp_command_data *cdata)
{
    epp_action_type action_type = UnknownAction;
    epps_transfer *et;
    
    switch (cdata->type) {
        case EPP_TRANSFER_CONTACT:
            action_type = ContactTransfer;
            break;
        case EPP_TRANSFER_DOMAIN:
            action_type = DomainTransfer;
            break;
        case EPP_TRANSFER_NSSET:
            action_type = NSsetTransfer;
            break;
        case EPP_TRANSFER_KEYSET:
            action_type = KeysetTransfer;
            break;
        default:
            break;
    }

    et = cdata->data;

    PUSH_PROPERTY(*c_props, "handle", et->id);

    return action_type;
}

static epp_action_type log_props_default_extcmd(ccReg_RequestProperties **c_props, epp_command_data *cdata)
{
    epp_action_type action_type = UnknownAction;
    epps_test *epp_test;
    epps_sendAuthInfo * auth_info;

    switch (cdata->type) {
        case EPP_TEST_NSSET:
            action_type = nssetTest;
            break;
        case EPP_SENDAUTHINFO_CONTACT:
            action_type = ContactSendAuthInfo;
            break;
        case EPP_SENDAUTHINFO_DOMAIN:
            action_type = DomainSendAuthInfo;
            break;
        case EPP_SENDAUTHINFO_NSSET:
            action_type = NSSetSendAuthInfo;
            break;
        case EPP_SENDAUTHINFO_KEYSET:
            action_type = KeySetSendAuthInfo;
            break;
        case EPP_CREDITINFO:
            action_type = ClientCredit;
            break;
        case EPP_INFO_LIST_DOMAINS:
            action_type = InfoListDomains;
            break;
        case EPP_INFO_LIST_CONTACTS:
            action_type = InfoListContacts;
            break;
        case EPP_INFO_LIST_KEYSETS:
            action_type = InfoListKeysets;
            break;
        case EPP_INFO_LIST_NSSETS:
            action_type = InfoListNssets;
            break;
        case EPP_INFO_DOMAINS_BY_NSSET:
            action_type = InfoDomainsByNsset;
            break;
        case EPP_INFO_DOMAINS_BY_KEYSET:
            action_type = InfoDomainsByKeyset;
            break;
        case EPP_INFO_DOMAINS_BY_CONTACT:
            action_type = InfoDomainsByContact;
            break;
        case EPP_INFO_NSSETS_BY_NS:
            action_type = InfoNssetsByNs;
            break;
        case EPP_INFO_NSSETS_BY_CONTACT:
            action_type = InfoNssetsByContact;
            break;
        case EPP_INFO_GET_RESULTS:
            action_type = InfoGetResults;
            break;
        case EPP_INFO_KEYSETS_BY_CONTACT:
            action_type = InfoKeysetsByContact;
            break;
        default:
            break;
    }

    switch (cdata->type) {
        case EPP_TEST_NSSET:
            epp_test = cdata->data;
 
            PUSH_PROPERTY (*c_props, "handle", epp_test->id);
            PUSH_QHEAD(*c_props, &epp_test->names, "test_domain");
            if(epp_test->level != -1) {
                PUSH_PROPERTY_INT (*c_props, "level", epp_test->level);
            }
            break;
        case EPP_SENDAUTHINFO_CONTACT:
        case EPP_SENDAUTHINFO_DOMAIN:
        case EPP_SENDAUTHINFO_NSSET:
        case EPP_SENDAUTHINFO_KEYSET:
            auth_info = cdata->data;
            PUSH_PROPERTY(*c_props, "handle", auth_info->id);
            break;
        default:
            // other values are handled in log_props_default_extcmd_response
            break;
    }


    return action_type;
}

static void log_props_default_extcmd_response(ccReg_RequestProperties **c_props, const epp_command_data *cdata) {

    epps_creditInfo *credit_info;
    epps_info *result;

    switch (cdata->type) {
        case EPP_CREDITINFO:
            credit_info = cdata->data;

            q_foreach(&credit_info->zonecredits) {
                    epp_zonecredit *zonecredit;

                    zonecredit = q_content(&credit_info->zonecredits);
                    *c_props = epp_property_push(*c_props, "zone", zonecredit->zone, CORBA_TRUE, CORBA_FALSE);
                    *c_props = epp_property_push(*c_props, "credit", zonecredit->credit, CORBA_TRUE, CORBA_TRUE);
            }
            
            break;
        case EPP_INFO_DOMAINS_BY_NSSET:
        case EPP_INFO_DOMAINS_BY_KEYSET:
        case EPP_INFO_DOMAINS_BY_CONTACT:
        case EPP_INFO_NSSETS_BY_NS:
        case EPP_INFO_NSSETS_BY_CONTACT:
        case EPP_INFO_KEYSETS_BY_CONTACT:
            result = cdata->data;

            *c_props = epp_property_push(*c_props, "handle", result->handle, CORBA_TRUE, CORBA_FALSE);
            *c_props = epp_property_push_int(*c_props, "count", result->count, CORBA_TRUE);
            break;
        default:
            // other values were handled in log_props_default_extcmd
            break;
    }

}

/**
 * Log an epp command using fred-logd service. Raw content as well as
 * parsed values inserted as properties are sent to the logging facility
 *
 * @param	service 	a reference to the logging service CORBA object
 * @param	c			connection record
 * @param	request		raw content of the request
 * @param 	cdata		command data, parsed content
 * @param   cmdtype 	command type returned by parse_command function
 * @param 	sessionid   login id for the session
 *
 * @return  database ID of the new logging record or an error code LOG_INTERNAL_ERROR
 */
ccReg_TID log_epp_command(epp_context *epp_ctx, service_Logger *service, char *remote_ip, char *request, epp_command_data *cdata, epp_red_command_type cmdtype, ccReg_TID sessionid)
{
	int res;								/* response from corba call wrapper */
	epp_action_type action_type = UnknownAction;
	ccReg_TID log_entry_id;

	char errmsg[MAX_ERROR_MSG_LEN];			/* error message returned from corba call */
	ccReg_RequestProperties *c_props = NULL;	/* properties to be sent to the log */	
	
								
	errmsg[0] = '\0';
	if(cdata->type == EPP_DUMMY) {
		PUSH_PROPERTY (c_props, "clTRID", cdata->clTRID);

		res = epp_log_new_message(epp_ctx, service, remote_ip, request, c_props, NULL, action_type, &log_entry_id, sessionid, errmsg);

		if(res == CORBA_OK) return log_entry_id;
		else {
            if(errmsg[0] != '\0') {
                epplog(epp_ctx, EPP_ERROR, "fred-logd EPP_DUMMY logging error: %s", errmsg);
            }
            return LOG_INTERNAL_ERROR;
        }
	}
           
	switch(cmdtype) {
                case EPP_RED_HELLO:
                    action_type = ClientGreeting;
                    break;
		case EPP_RED_LOGIN:
                    action_type = log_props_login(&c_props, cdata);
                    break;

		case EPP_RED_LOGOUT:
                    action_type = ClientLogout;
                    break;

		case EPP_RED_CHECK:
                    action_type = log_props_check(&c_props, cdata);
                    break;

		case EPP_RED_INFO:
                    action_type = log_props_info(&c_props, cdata);
                    break;

		case EPP_RED_POLL:
                    action_type = log_props_poll(&c_props, cdata);
                    break;

		case EPP_RED_CREATE:
                    action_type = log_props_create(&c_props, cdata);
                    break;

		case EPP_RED_DELETE:
                    action_type = log_props_delete(&c_props, cdata);
                    break;

		case EPP_RED_RENEW:
                    action_type = log_props_renew(&c_props, cdata);
                    break;

		case EPP_RED_UPDATE:
                    action_type = log_props_update(&c_props, cdata);
                    break;

		case EPP_RED_TRANSFER:
                    action_type = log_props_transfer(&c_props, cdata);
                    break;

		case EPP_RED_EXTCMD:
		default:
                    action_type = log_props_default_extcmd(&c_props, cdata);
                    break;
	}

  	PUSH_PROPERTY (c_props, "clTRID", cdata->clTRID);
        res = epp_log_new_message(epp_ctx, service, remote_ip, request, c_props, NULL, action_type, &log_entry_id, sessionid, errmsg);

	if(res == CORBA_OK) {
        return log_entry_id;
    } else {
        if(errmsg[0] != '\0') {
            epplog(epp_ctx, EPP_ERROR, "fred-logd createRequest logging error: %s", errmsg);
        }

        return LOG_INTERNAL_ERROR;
    }

}

#undef PUSH_PROPERTY
#undef PUSH_PROPERTY_INT
#undef PUSH_QHEAD

/**
 * Log an epp response using fred-logd service. Raw content as well as
 * parsed values inserted as properties are sent to the logging facility
 *
 * @param	log_service a reference to the logging service CORBA object
 * @param	c			connection record
 * @param	valerr		list of errors in input xml
 * @param	response	raw content of the response
 * @param 	cdata		command data, parsed content
 * @param 	session_id		Id into the login database table for this session
 * @param	log_entry_id 	Id of the log_entry record which will be updated by this call. The Id was obtained by log_epp_command()
 *
 * @return  status LOG_INTERNAL_ERROR or LOG_SUCCESS
 */
int log_epp_response(epp_context *epp_ctx, service_Logger *log_service, qhead *valerr, const char *response, const epp_command_data *cdata, ccReg_TID session_id, ccReg_TID log_entry_id)
{
	int res;

	char errmsg[MAX_ERROR_MSG_LEN];			/* error message returned from corba call */
	ccReg_RequestProperties *c_props = NULL;	/* properties to be sent to the log */

	errmsg[0] = '\0';
	// output properties
	if (cdata != NULL) {
                c_props = epp_property_push(c_props, "svTRID", cdata->svTRID, CORBA_TRUE, CORBA_FALSE);
                if (c_props == NULL) {
                    return LOG_INTERNAL_ERROR;
                }

		c_props = epp_property_push_int(c_props, "rc", cdata->rc, CORBA_TRUE);
		if (c_props == NULL) {
			return LOG_INTERNAL_ERROR;
		}

		c_props = epp_property_push(c_props, "msg", cdata->msg, CORBA_TRUE, CORBA_FALSE);
		if (c_props == NULL) {
			return LOG_INTERNAL_ERROR;
		}

                if (cdata->type == EPP_CHECK_CONTACT 
                 || cdata->type == EPP_CHECK_DOMAIN 
                 || cdata->type == EPP_CHECK_NSSET 
                 || cdata->type == EPP_CHECK_KEYSET) {
                    log_props_out_check(&c_props, cdata);

                } else if(cdata->type ==  EPP_CREATE_CONTACT) {
                        epps_create_contact *cc = cdata->data;
                        c_props = epp_property_push(c_props, "creationDate", cc->crDate, CORBA_TRUE, CORBA_FALSE);

                } else if(cdata->type ==  EPP_CREATE_DOMAIN) {
                        epps_create_domain *cd = cdata->data;
                        c_props = epp_property_push(c_props, "creationDate", cd->crDate, CORBA_TRUE, CORBA_FALSE);

                } else if(cdata->type ==  EPP_CREATE_KEYSET) {
                        epps_create_keyset *ck = cdata->data;
                        c_props = epp_property_push(c_props, "creationDate", ck->crDate, CORBA_TRUE, CORBA_FALSE);

                } else if(cdata->type ==  EPP_CREATE_NSSET) {
                        epps_create_nsset *cn = cdata->data;
                        c_props = epp_property_push(c_props, "creationDate", cn->crDate, CORBA_TRUE, CORBA_FALSE);

                }

                log_props_default_extcmd_response(&c_props, cdata);
	}

	if (valerr != NULL && (c_props = epp_property_push_valerr(c_props, valerr, "xmlError")) == NULL) {
		return LOG_INTERNAL_ERROR;
	}

        if(cdata != NULL) {
            res = epp_log_close_message(epp_ctx, log_service, response, c_props, NULL, log_entry_id, session_id, cdata->rc, errmsg);
        } else {
            res = epp_log_close_message(epp_ctx, log_service, response, c_props, NULL, log_entry_id, session_id, 2400, errmsg);
        }

	if(res == CORBA_OK) return LOG_SUCCESS;
	else {
        if(errmsg[0] != '\0') {
            epplog(epp_ctx, EPP_ERROR, "fred-logd logging error: %s", errmsg);
        }
        return LOG_INTERNAL_ERROR;
    }
}
