/**
 * @file epp_gen.c
 *
 * Component for generating greeting frame and responses to EPP commands
 * in form of xml documents. Result of generator is the generated string
 * and validation errors if validation of responses is turned on. Greeting
 * frame is not validated, therefore only string is returned (without the list
 * of validation errors).
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <libxml/parser.h>
#include <libxml/xmlwriter.h>

#include "epp_common.h"
#include "epp_xmlcommon.h"
#include "epp_gen.h"
#include "epp_version.h"

/**
 * @defgroup xmlwritegroup Macros for convenient xml document construction.
 * Following macros are shortcuts used for document creation. So that
 * we don't have to clutter the code with error checking and other stuff.
 * That makes the code much more readable.
 *
 * All macros assume that
 *    - err_handler: parameter is the place where to jump when error occurs
 *    - writer: is is initialized and it is xml writer
 *    - elem: is name of a tag to be written
 *    - str: is value which should be written inside of a tag
 *    - attr_name: is a name of attribute
 *    - attr_value: is a value of an attribute
 *
 * @{
 */

/** Wrapper around libxml's xmlTestWriterStartElement() function. */
#define START_ELEMENT(writer, err_handler, elem)	\
	do {										\
		if (xmlTextWriterStartElement(writer, BAD_CAST (elem)) < 0) goto err_handler;	\
	}while(0)

/** Wrapper around libxml's xmlTestWriterWriteElement() function. */
#define WRITE_ELEMENT(writer, err_handler, elem, str)	\
	do {										\
		if (((char *) str)[0] != '\0')						\
			if (xmlTextWriterWriteElement(writer, BAD_CAST (elem), BAD_CAST (str)) < 0) goto err_handler;	\
	}while(0)

/** Wrapper around libxml's xmlTestWriterWriteString() function. */
#define WRITE_STRING(writer, err_handler, str)		\
	do {										\
		if (xmlTextWriterWriteString(writer, BAD_CAST (str)) < 0) goto err_handler;	\
	}while(0)

/** Wrapper around libxml's xmlTestWriterWriteAttribute() function. */
#define WRITE_ATTRIBUTE(writer, err_handler, attr_name, attr_value)	\
	do {										\
		if (xmlTextWriterWriteAttribute(writer, BAD_CAST (attr_name), BAD_CAST (attr_value)) < 0) goto err_handler;	\
	}while(0)

/** Wrapper around libxml's xmlTestWriterEndElement() function. */
#define END_ELEMENT(writer, err_handler)	\
	do {										\
		if (xmlTextWriterEndElement(writer) < 0) goto err_handler; \
	}while(0)

/**
 * @}
 */

gen_status
epp_gen_greeting(const char *svid, char **greeting)
{
	xmlBufferPtr buf;
	xmlTextWriterPtr writer;
	char	strdate[50];	/* buffer used to hold date in string form */
	int	error_seen = 1;

	assert(svid != NULL);

	buf = xmlBufferCreate();
	if (buf == NULL) {
		return GEN_EBUFFER;
	}
	writer = xmlNewTextWriterMemory(buf, 0);
	if (writer == NULL) {
		xmlBufferFree(buf);
		return GEN_EWRITER;
	}

	if (xmlTextWriterStartDocument(writer, NULL, "UTF-8", NULL) < 0)
		goto greeting_err;

	/* epp header */
	START_ELEMENT(writer, greeting_err, "epp");
	WRITE_ATTRIBUTE(writer, greeting_err, "xmlns", NS_EPP);
	WRITE_ATTRIBUTE(writer, greeting_err, "xmlns:xsi", XSI);
	WRITE_ATTRIBUTE(writer, greeting_err, "xsi:schemaLocation", LOC_EPP);

	/* greeting part */
	START_ELEMENT(writer, greeting_err, "greeting");
	WRITE_ELEMENT(writer, greeting_err, "svID", svid);
	get_rfc3339_date(time(NULL), strdate);
	WRITE_ELEMENT(writer, greeting_err, "svDate", strdate);
	START_ELEMENT(writer, greeting_err, "svcMenu");
	WRITE_ELEMENT(writer, greeting_err, "version" , MODEPPD_VERSION);
	WRITE_ELEMENT(writer, greeting_err, "lang", "en");
	WRITE_ELEMENT(writer, greeting_err, "lang", "cs");
	WRITE_ELEMENT(writer, greeting_err, "objURI", NS_CONTACT);
	WRITE_ELEMENT(writer, greeting_err, "objURI", NS_DOMAIN);
	WRITE_ELEMENT(writer, greeting_err, "objURI", NS_NSSET);
	START_ELEMENT(writer, greeting_err, "svcExtension");
	/* not yet
	WRITE_ELEMENT(writer, greeting_err, "extURI", NS_SECDNS);
	*/
	WRITE_ELEMENT(writer, greeting_err, "extURI", NS_ENUMVAL);
	END_ELEMENT(writer, greeting_err); /* svcExtension */
	END_ELEMENT(writer, greeting_err); /* svcMenu */
	/* dcp part */
	START_ELEMENT(writer, greeting_err, "dcp");
	START_ELEMENT(writer, greeting_err, "access");
	START_ELEMENT(writer, greeting_err, "all");
	END_ELEMENT(writer, greeting_err);
	END_ELEMENT(writer, greeting_err);
	START_ELEMENT(writer, greeting_err, "statement");
	START_ELEMENT(writer, greeting_err, "purpose");
	START_ELEMENT(writer, greeting_err, "admin");
	END_ELEMENT(writer, greeting_err);
	START_ELEMENT(writer, greeting_err, "prov");
	END_ELEMENT(writer, greeting_err);
	END_ELEMENT(writer, greeting_err);
	START_ELEMENT(writer, greeting_err, "recipient");
	START_ELEMENT(writer, greeting_err, "public");
	END_ELEMENT(writer, greeting_err);
	END_ELEMENT(writer, greeting_err);
	START_ELEMENT(writer, greeting_err, "retention");
	START_ELEMENT(writer, greeting_err, "stated");

	/* this has side effect of flushing document to buffer */
	if (xmlTextWriterEndDocument(writer) < 0)  goto greeting_err;

	error_seen = 0;

greeting_err:
	xmlFreeTextWriter(writer);
	if (!error_seen) {
		/* successful end */
		*greeting = strdup((char *) buf->content);
		xmlBufferFree(buf);
		return GEN_OK;
	}

	/* failure */
	xmlBufferFree(buf);
	*greeting = NULL;
	return GEN_EBUILD;
}

/**
 * This is assistant function for generating info contact <resData>
 * xml subtree.
 *
 * @param writer XML writer.
 * @param cdata Data needed to generate XML.
 * @return 1 if OK, 0 in case of failure.
 */
static char
gen_info_contact(xmlTextWriterPtr writer, epp_command_data *cdata)
{
	epp_postalInfo	*pi;
	epp_discl	*discl;
	char	strbuf[25]; /* is enough even for 64-bit number and for a date */

	START_ELEMENT(writer, simple_err, "resData");
	START_ELEMENT(writer, simple_err, "contact:infData");
	WRITE_ATTRIBUTE(writer, simple_err, "xmlns:contact", NS_CONTACT);
	WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_CONTACT);
	WRITE_ELEMENT(writer, simple_err, "contact:id", cdata->in->info.id);
	WRITE_ELEMENT(writer, simple_err, "contact:roid",
			cdata->out->info_contact.roid);
	CL_RESET(cdata->out->info_contact.status);
	CL_FOREACH(cdata->out->info_contact.status) {
		START_ELEMENT(writer, simple_err, "contact:status");
		WRITE_ATTRIBUTE(writer, simple_err, "s",
				CL_CONTENT(cdata->out->info_contact.status));
		END_ELEMENT(writer, simple_err);
	}
	// postal info
	pi = cdata->out->info_contact.postalInfo;
	START_ELEMENT(writer, simple_err, "contact:postalInfo");
	WRITE_ELEMENT(writer, simple_err, "contact:name", pi->name);
	WRITE_ELEMENT(writer, simple_err, "contact:org", pi->org);
	START_ELEMENT(writer, simple_err, "contact:addr");
	WRITE_ELEMENT(writer, simple_err, "contact:street", pi->street[0]);
	WRITE_ELEMENT(writer, simple_err, "contact:street", pi->street[1]);
	WRITE_ELEMENT(writer, simple_err, "contact:street", pi->street[2]);
	WRITE_ELEMENT(writer, simple_err, "contact:city", pi->city);
	WRITE_ELEMENT(writer, simple_err, "contact:sp", pi->sp);
	WRITE_ELEMENT(writer, simple_err, "contact:pc", pi->pc);
	WRITE_ELEMENT(writer, simple_err, "contact:cc", pi->cc);
	END_ELEMENT(writer, simple_err); /* addr */
	END_ELEMENT(writer, simple_err); /* postal info */
	WRITE_ELEMENT(writer, simple_err, "contact:voice",
			cdata->out->info_contact.voice);
	WRITE_ELEMENT(writer, simple_err, "contact:fax",
			cdata->out->info_contact.fax);
	WRITE_ELEMENT(writer, simple_err, "contact:email",
			cdata->out->info_contact.email);
	WRITE_ELEMENT(writer, simple_err, "contact:clID",
			cdata->out->info_contact.clID);
	WRITE_ELEMENT(writer, simple_err, "contact:crID",
			cdata->out->info_contact.crID);
	get_rfc3339_date(cdata->out->info_contact.crDate, strbuf);
	WRITE_ELEMENT(writer, simple_err, "contact:crDate", strbuf);
	WRITE_ELEMENT(writer, simple_err, "contact:upID",
			cdata->out->info_contact.upID);
	if (cdata->out->info_contact.upDate > 0) {
		get_rfc3339_date(cdata->out->info_contact.upDate, strbuf);
		WRITE_ELEMENT(writer, simple_err, "contact:upDate", strbuf);
	}
	if (cdata->out->info_contact.trDate > 0) {
		get_rfc3339_date(cdata->out->info_contact.trDate, strbuf);
		WRITE_ELEMENT(writer, simple_err, "contact:trDate", strbuf);
	}
	if (*cdata->out->info_contact.authInfo != '\0') {
		START_ELEMENT(writer, simple_err, "contact:authInfo");
		WRITE_ELEMENT(writer, simple_err, "contact:pw",
				cdata->out->info_contact.authInfo);
		END_ELEMENT(writer, simple_err); /* auth info */
	}
	/* output disclose section only if there is at least one discl element */
	discl = cdata->out->info_contact.discl;
	if (!discl->name || !discl->org || !discl->addr ||
			!discl->voice || !discl->fax || !discl->email)
	{
		START_ELEMENT(writer, simple_err, "contact:disclose");
		WRITE_ATTRIBUTE(writer, simple_err, "flag", "0");
		if (!discl->name) {
			START_ELEMENT(writer, simple_err, "contact:name");
			END_ELEMENT(writer, simple_err);
		}
		if (!discl->org) {
			START_ELEMENT(writer, simple_err, "contact:org");
			END_ELEMENT(writer, simple_err);
		}
		if (!discl->addr) {
			START_ELEMENT(writer, simple_err, "contact:addr");
			END_ELEMENT(writer, simple_err);
		}
		if (!discl->voice) {
			START_ELEMENT(writer, simple_err, "contact:voice");
			END_ELEMENT(writer, simple_err);
		}
		if (!discl->fax) {
			START_ELEMENT(writer, simple_err, "contact:fax");
			END_ELEMENT(writer, simple_err);
		}
		if (!discl->email) {
			START_ELEMENT(writer, simple_err, "contact:email");
			END_ELEMENT(writer, simple_err);
		}
		END_ELEMENT(writer, simple_err); /* disclose */
	}
	WRITE_ELEMENT(writer, simple_err, "contact:vat",
			cdata->out->info_contact.vat);
	if (*cdata->out->info_contact.ssn != '\0') {
		char	*type;

		switch (cdata->out->info_contact.ssntype) {
			case SSN_OP:
				type = strdup("op");
				break;
			case SSN_RC:
				type = strdup("rc");
				break;
			case SSN_PASSPORT:
				type = strdup("passport");
				break;
			case SSN_MPSV:
				type = strdup("mpsv");
				break;
			case SSN_ICO:
				type = strdup("ico");
				break;
			default:
				/* what should we do? We will create nonvalidating document. */
				type = strdup("unknown");
				break;
		}
		START_ELEMENT(writer, simple_err, "contact:ssn");
		WRITE_ATTRIBUTE(writer, simple_err, "type", type);
		WRITE_STRING(writer, simple_err, cdata->out->info_contact.ssn);
		END_ELEMENT(writer, simple_err); /* ssn */
		free(type);
	}
	WRITE_ELEMENT(writer, simple_err, "contact:notifyEmail",
			cdata->out->info_contact.notify_email);
	END_ELEMENT(writer, simple_err); /* infdata */
	END_ELEMENT(writer, simple_err); /* resdata */
	return 1;

simple_err:
	return 0;
}

/**
 * This is assistant function for generating info domain <resData>
 * xml subtree.
 *
 * @param writer XML writer.
 * @param cdata Data needed to generate XML.
 * @return 1 if OK, 0 in case of failure.
 */
static char
gen_info_domain(xmlTextWriterPtr writer, epp_command_data *cdata)
{
	char	strbuf[25]; /* is enough even for 64-bit number and for a date */

	START_ELEMENT(writer, simple_err, "resData");
	START_ELEMENT(writer, simple_err, "domain:infData");
	WRITE_ATTRIBUTE(writer, simple_err, "xmlns:domain", NS_DOMAIN);
	WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_DOMAIN);
	WRITE_ELEMENT(writer, simple_err, "domain:name",cdata->in->info.id);
	WRITE_ELEMENT(writer, simple_err, "domain:roid",
			cdata->out->info_domain.roid);
	CL_RESET(cdata->out->info_domain.status);
	CL_FOREACH(cdata->out->info_domain.status) {
		START_ELEMENT(writer, simple_err, "domain:status");
		WRITE_ATTRIBUTE(writer, simple_err, "s",
				CL_CONTENT(cdata->out->info_domain.status));
		END_ELEMENT(writer, simple_err);
	}
	WRITE_ELEMENT(writer, simple_err, "domain:registrant",
			cdata->out->info_domain.registrant);
	CL_RESET(cdata->out->info_domain.admin);
	CL_FOREACH(cdata->out->info_domain.admin) {
		WRITE_ELEMENT(writer, simple_err, "domain:admin",
				CL_CONTENT(cdata->out->info_domain.admin));
	}
	WRITE_ELEMENT(writer, simple_err, "domain:nsset",
			cdata->out->info_domain.nsset);
	WRITE_ELEMENT(writer, simple_err, "domain:clID",
			cdata->out->info_domain.clID);
	WRITE_ELEMENT(writer, simple_err, "domain:crID",
			cdata->out->info_domain.crID);
	get_rfc3339_date(cdata->out->info_domain.crDate, strbuf);
	WRITE_ELEMENT(writer, simple_err, "domain:crDate", strbuf);
	WRITE_ELEMENT(writer, simple_err, "domain:upID",
			cdata->out->info_domain.upID);
	if (cdata->out->info_domain.upDate > 0) {
		get_rfc3339_date(cdata->out->info_domain.upDate, strbuf);
		WRITE_ELEMENT(writer, simple_err, "domain:upDate", strbuf);
	}
	get_rfc3339_date(cdata->out->info_domain.exDate, strbuf);
	WRITE_ELEMENT(writer, simple_err, "domain:exDate", strbuf);
	if (cdata->out->info_domain.trDate > 0) {
		get_rfc3339_date(cdata->out->info_domain.trDate, strbuf);
		WRITE_ELEMENT(writer, simple_err, "domain:trDate", strbuf);
	}
	if (*cdata->out->info_domain.authInfo != '\0') {
		START_ELEMENT(writer, simple_err, "domain:authInfo");
		WRITE_ELEMENT(writer, simple_err, "domain:pw",
				cdata->out->info_domain.authInfo);
		END_ELEMENT(writer, simple_err); /* auth info */
	}
	END_ELEMENT(writer, simple_err); /* infdata */
	END_ELEMENT(writer, simple_err); /* resdata */
	/* optional extensions */
	if (cdata->out->info_domain.valExDate > 0) {
			/*
			... || cl_length(cdata->out->info_domain.ds) > 0) {
			*/
		START_ELEMENT(writer, simple_err, "extension");
		if (cdata->out->info_domain.valExDate > 0) {
			START_ELEMENT(writer, simple_err, "enumval:infData");
			WRITE_ATTRIBUTE(writer, simple_err, "xmlns:enumval", NS_ENUMVAL);
			WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation",
					LOC_ENUMVAL);
			get_stripped_date(cdata->out->info_domain.valExDate, strbuf);
			WRITE_ELEMENT(writer, simple_err, "enumval:valExDate", strbuf);
			END_ELEMENT(writer, simple_err); /* infdata (enumval) */
		}
		/*
		 * NOTE: This does not have any effect because ds records are
		 * initialized to empty list in corba component untill the dnssec
		 * extension will be fully implemented.
		 */
		if (cl_length(cdata->out->info_domain.ds) > 0) {
			START_ELEMENT(writer, simple_err, "secdns:infData");
			WRITE_ATTRIBUTE(writer, simple_err, "xmlns:secdns", NS_SECDNS);
			WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation",
					LOC_SECDNS);
			CL_RESET(cdata->out->info_domain.ds);
			CL_FOREACH(cdata->out->info_domain.ds) {
				epp_ds	*ds = CL_CONTENT(cdata->out->info_domain.ds);
				START_ELEMENT(writer, simple_err, "secdns:dsData");
				snprintf(strbuf, 24, "%u", ds->keytag);
				WRITE_ELEMENT(writer, simple_err, "secdns:keyTag", strbuf);
				snprintf(strbuf, 24, "%u", ds->alg);
				WRITE_ELEMENT(writer, simple_err, "secdns:alg", strbuf);
				snprintf(strbuf, 24, "%u", ds->digestType);
				WRITE_ELEMENT(writer, simple_err, "secdns:digestType", strbuf);
				WRITE_ELEMENT(writer, simple_err, "secdns:digest", ds->digest);
				if (ds->maxSigLife > 0) {
					snprintf(strbuf, 24, "%u", ds->maxSigLife);
					WRITE_ELEMENT(writer, simple_err, "secdns:maxSigLife",
							strbuf);
				}
				/*
				 * all fields of keyData should be filled in or none of them.
				 * We test value of pubkey and decide according to its value.
				 */
				if (*ds->pubkey != '\0') {
					START_ELEMENT(writer, simple_err, "secdns:keyData");
					snprintf(strbuf, 24, "%u", ds->flags);
					WRITE_ELEMENT(writer, simple_err, "secdns:flags", strbuf);
					snprintf(strbuf, 24, "%u", ds->protocol);
					WRITE_ELEMENT(writer, simple_err, "secdns:protocol", strbuf);
					snprintf(strbuf, 24, "%u", ds->alg);
					WRITE_ELEMENT(writer, simple_err, "secdns:alg", strbuf);
					WRITE_ELEMENT(writer, simple_err, "secdns:pubKey",
							ds->pubkey);
					END_ELEMENT(writer, simple_err); // keyData
				}
				END_ELEMENT(writer, simple_err); // dsData
			}
			END_ELEMENT(writer, simple_err); // infdata (secdns)
		}
		END_ELEMENT(writer, simple_err); /* extension */
	}
	return 1;

simple_err:
	return 0;
}

/**
 * This is assistant function for generating info nsset <resData>
 * xml subtree.
 *
 * @param writer XML writer.
 * @param cdata Data needed to generate XML.
 * @return 1 if OK, 0 in case of failure.
 */
static char
gen_info_nsset(xmlTextWriterPtr writer, epp_command_data *cdata)
{
	char	strbuf[25]; /* is enough even for 64-bit number and for a date */

	START_ELEMENT(writer, simple_err, "resData");
	START_ELEMENT(writer, simple_err, "nsset:infData");
	WRITE_ATTRIBUTE(writer, simple_err, "xmlns:nsset", NS_NSSET);
	WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_NSSET);
	WRITE_ELEMENT(writer, simple_err, "nsset:id",cdata->in->info.id);
	WRITE_ELEMENT(writer, simple_err, "nsset:roid",cdata->out->info_nsset.roid);
	/* status flags */
	CL_RESET(cdata->out->info_nsset.status);
	CL_FOREACH(cdata->out->info_nsset.status) {
		START_ELEMENT(writer, simple_err, "nsset:status");
		WRITE_ATTRIBUTE(writer, simple_err, "s",
				CL_CONTENT(cdata->out->info_nsset.status));
		END_ELEMENT(writer, simple_err);
	}
	WRITE_ELEMENT(writer, simple_err, "nsset:clID", cdata->out->info_nsset.clID);
	WRITE_ELEMENT(writer, simple_err, "nsset:crID", cdata->out->info_nsset.crID);
	get_rfc3339_date(cdata->out->info_nsset.crDate, strbuf);
	WRITE_ELEMENT(writer, simple_err, "nsset:crDate", strbuf);
	WRITE_ELEMENT(writer, simple_err, "nsset:upID", cdata->out->info_nsset.upID);
	if (cdata->out->info_nsset.upDate > 0) {
		get_rfc3339_date(cdata->out->info_nsset.upDate, strbuf);
		WRITE_ELEMENT(writer, simple_err, "nsset:upDate", strbuf);
	}
	if (cdata->out->info_nsset.trDate > 0) {
		get_rfc3339_date(cdata->out->info_nsset.trDate, strbuf);
		WRITE_ELEMENT(writer, simple_err, "nsset:trDate", strbuf);
	}
	if (*cdata->out->info_nsset.authInfo != '\0') {
		START_ELEMENT(writer, simple_err, "nsset:authInfo");
		WRITE_ELEMENT(writer, simple_err, "nsset:pw",
				cdata->out->info_nsset.authInfo);
		END_ELEMENT(writer, simple_err); /* authInfo */
	}
	CL_RESET(cdata->out->info_nsset.ns);
	/* print nameservers */
	CL_FOREACH(cdata->out->info_nsset.ns) {
		epp_ns	*ns = (epp_ns *) CL_CONTENT(cdata->out->info_nsset.ns);
		START_ELEMENT(writer, simple_err, "nsset:ns");
		WRITE_ELEMENT(writer, simple_err, "nsset:name", ns->name);
		/* print addrs of nameserver */
		CL_RESET(ns->addr);
		CL_FOREACH(ns->addr) {
			WRITE_ELEMENT(writer, simple_err, "nsset:addr",
					CL_CONTENT(ns->addr));
		}
		END_ELEMENT(writer, simple_err); /* ns */
	}
	/* print tech contacts */
	CL_FOREACH(cdata->out->info_nsset.tech) {
		WRITE_ELEMENT(writer, simple_err, "nsset:tech",
				CL_CONTENT(cdata->out->info_nsset.tech));
	}
	END_ELEMENT(writer, simple_err); /* infdata */
	END_ELEMENT(writer, simple_err); /* resdata */
	return 1;

simple_err:
	return 0;
}

/**
 * Function completes xml tags to both ends of value provided by client
 * which cased error on side of central register. The standard requires
 * to return client provided value INCLUDING bordering xml tags. Because
 * central register is not aware of any xml, it returns just parameter
 * which caused the error and on us is to accompany that parameter value
 * with appropriate xml tags. This should be considered as temporary hack,
 * since we are anyway not able to complete exactly the same tags as the client
 * provided, when it is done this way. But untill we find better solution
 * this is sufficient.
 *
 * @param e Error specification (the field e->value is changed inside
 * the function).
 */
static void
complete_tags(epp_error	*e)
{
	char	*newstr;
	int	len;

	/* this is same for all switch cases, so we will do it here. */
	len = strlen(e->value);

	switch (e->spec) {
		case errspec_pollAck_msgID:
			len += strlen("<poll op=\"ack\" msgID=\"");
			len += strlen("\"/>");
			newstr = malloc(len + 1);
			*newstr = '\0';
			strcat(newstr, "<poll op=\"ack\" msgID=\"");
			strcat(newstr, e->value);
			strcat(newstr, "\"/>");
			break;
		case errspec_contactUpdate_cc:
		case errspec_contactCreate_cc:
			len += 2 * strlen("<cc>") + 1;
			newstr = malloc(len + 1);
			*newstr = '\0';
			strcat(newstr, "<cc>");
			strcat(newstr, e->value);
			strcat(newstr, "</cc>");
			break;
		case errspec_contactInfo_handle:
		case errspec_contactCreate_handle:
		case errspec_nssetInfo_handle:
		case errspec_nssetCreate_handle:
			len += 2 * strlen("<id>") + 1;
			newstr = malloc(len + 1);
			*newstr = '\0';
			strcat(newstr, "<id>");
			strcat(newstr, e->value);
			strcat(newstr, "</id>");
			break;
		case errspec_domainInfo_fqdn:
		case errspec_domainCreate_fqdn:
			len += 2 * strlen("<name>") + 1;
			newstr = malloc(len + 1);
			*newstr = '\0';
			strcat(newstr, "<name>");
			strcat(newstr, e->value);
			strcat(newstr, "</name>");
			break;
		case errspec_contactUpdate_status_add:
		case errspec_contactUpdate_status_rem:
		case errspec_nssetUpdate_status_add:
		case errspec_nssetUpdate_status_rem:
		case errspec_domainUpdate_status_add:
		case errspec_domainUpdate_status_rem:
			len += strlen("<status s=\"");
			len += strlen("\"/>");
			newstr = malloc(len + 1);
			*newstr = '\0';
			strcat(newstr, "<status s=\"");
			strcat(newstr, e->value);
			strcat(newstr, "\"/>");
			break;
		case errspec_nssetCreate_tech:
		case errspec_nssetUpdate_tech_add:
		case errspec_nssetUpdate_tech_rem:
			len += 2 * strlen("<tech>") + 1;
			newstr = malloc(len + 1);
			*newstr = '\0';
			strcat(newstr, "<tech>");
			strcat(newstr, e->value);
			strcat(newstr, "</tech>");
			break;
		case errspec_nssetCreate_ns_name:
		case errspec_nssetUpdate_ns_name_add:
		case errspec_nssetUpdate_ns_name_rem:
			len += 2 * strlen("<name>") + 1;
			newstr = malloc(len + 1);
			*newstr = '\0';
			strcat(newstr, "<name>");
			strcat(newstr, e->value);
			strcat(newstr, "</name>");
			break;
		case errspec_nssetCreate_ns_addr:
		case errspec_nssetUpdate_ns_addr_add:
		case errspec_nssetUpdate_ns_addr_rem:
			len += 2 * strlen("<addr>") + 1;
			newstr = malloc(len + 1);
			*newstr = '\0';
			strcat(newstr, "<addr>");
			strcat(newstr, e->value);
			strcat(newstr, "</addr>");
			break;
		case errspec_domainCreate_registrant:
		case errspec_domainUpdate_registrant:
			len += 2 * strlen("<registrant>") + 1;
			newstr = malloc(len + 1);
			*newstr = '\0';
			strcat(newstr, "<registrant>");
			strcat(newstr, e->value);
			strcat(newstr, "</registrant>");
			break;
		case errspec_domainCreate_nsset:
		case errspec_domainUpdate_nsset:
			len += 2 * strlen("<nsset>") + 1;
			newstr = malloc(len + 1);
			*newstr = '\0';
			strcat(newstr, "<nsset>");
			strcat(newstr, e->value);
			strcat(newstr, "</nsset>");
			break;
		case errspec_domainCreate_period:
		case errspec_domainRenew_period:
			len += 2 * strlen("<period>") + 1;
			newstr = malloc(len + 1);
			*newstr = '\0';
			strcat(newstr, "<period>");
			strcat(newstr, e->value);
			strcat(newstr, "</period>");
			break;
		case errspec_domainCreate_admin:
		case errspec_domainUpdate_admin_add:
		case errspec_domainUpdate_admin_rem:
			len += 2 * strlen("<admin>") + 1;
			newstr = malloc(len + 1);
			*newstr = '\0';
			strcat(newstr, "<admin>");
			strcat(newstr, e->value);
			strcat(newstr, "</admin>");
			break;
		case errspec_domainCreate_ext_valdate:
		case errspec_domainUpdate_ext_valdate:
		case errspec_domainRenew_ext_valDate:
			len += 2 * strlen("<valExDate>") + 1;
			newstr = malloc(len + 1);
			*newstr = '\0';
			strcat(newstr, "<valExDate>");
			strcat(newstr, e->value);
			strcat(newstr, "</valExDate>");
			break;
		case errspec_domainRenew_curExpDate:
			len += 2 * strlen("<curExpDate>") + 1;
			newstr = malloc(len + 1);
			*newstr = '\0';
			strcat(newstr, "<curExpDate>");
			strcat(newstr, e->value);
			strcat(newstr, "</curExpDate>");
			break;
		default:
			len += 2 * strlen("<unknown>") + 1;
			newstr = malloc(len + 1);
			*newstr = '\0';
			strcat(newstr, "<unknown>");
			strcat(newstr, e->value);
			strcat(newstr, "</unknown>");
			break;
	}
	free(e->value);
	e->value = newstr;
}

gen_status
epp_gen_response(
		int validate,
		char *schema_url,
		epp_lang lang,
		epp_command_data *cdata,
		epp_gen *gen)
{
	xmlBufferPtr buf;
	xmlTextWriterPtr writer;
	char	strbuf[25]; /* is enough even for 64-bit number and for a date */
	char	res_code[5];
	char	error_seen = 1;

	assert(schema_url != NULL);
	assert(cdata != NULL);

	/* initialize default return values */
	gen->response = NULL;
	gen->valerr = NULL;

	// make up response
	buf = xmlBufferCreate();
	if (buf == NULL) {
		return GEN_EBUFFER;
	}
	writer = xmlNewTextWriterMemory(buf, 0);
	if (writer == NULL) {
		xmlBufferFree(buf);
		return GEN_EWRITER;
	}

	if (xmlTextWriterStartDocument(writer, NULL, "UTF-8", NULL) < 0)
		goto simple_err;

	// epp header
	START_ELEMENT(writer, simple_err, "epp");
	WRITE_ATTRIBUTE(writer, simple_err, "xmlns", NS_EPP);
	WRITE_ATTRIBUTE(writer, simple_err, "xmlns:xsi", XSI);
	WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_EPP);

	// epp response
	START_ELEMENT(writer, simple_err, "response");
	START_ELEMENT(writer, simple_err, "result");
	snprintf(res_code, 5, "%d", cdata->rc);
	WRITE_ATTRIBUTE(writer, simple_err, "code", res_code);
	START_ELEMENT(writer, simple_err, "msg");
	if (lang != LANG_EN)
		WRITE_ATTRIBUTE(writer, simple_err, "lang", "cs");
	WRITE_STRING(writer, simple_err, cdata->msg);
	END_ELEMENT(writer, simple_err); /* msg */
	CL_RESET(cdata->errors);
	CL_FOREACH(cdata->errors) {
		epp_error	*e = (epp_error *) CL_CONTENT(cdata->errors);
		START_ELEMENT(writer, simple_err, "extValue");
		/*
		 * we cannot use standard macro WRITE_ELEMENT because we want
		 * to preserve <,> chars, otherwise they would be substituted
		 * by &lt;, &gt; respectively.
		 */
		START_ELEMENT(writer, simple_err, "value");
		if (!e->standalone) complete_tags(e);
		if (xmlTextWriterWriteRaw(writer, BAD_CAST e->value) < 0)
			goto simple_err;
		END_ELEMENT(writer, simple_err); /* value */
		START_ELEMENT(writer, simple_err, "reason");
		if (lang != LANG_EN)
			WRITE_ATTRIBUTE(writer, simple_err, "lang", "cs");
		WRITE_STRING(writer, simple_err, e->reason);
		END_ELEMENT(writer, simple_err); /* reason */
		END_ELEMENT(writer, simple_err); /* extValue */
	}
	END_ELEMENT(writer, simple_err); /* result */

	/*
	 * Here is handler for each kind of response
	 * Short reponses are coded directly into swich, long responses are
	 * coded into separate functions called within the switch
	 */
	switch (cdata->type) {
		case EPP_DUMMY:
		/* commands with no <resData> element */
		case EPP_LOGIN:
		case EPP_LOGOUT:
		case EPP_DELETE_DOMAIN:
		case EPP_DELETE_CONTACT:
		case EPP_DELETE_NSSET:
		case EPP_UPDATE_DOMAIN:
		case EPP_UPDATE_CONTACT:
		case EPP_UPDATE_NSSET:
		case EPP_TRANSFER_DOMAIN:
		case EPP_TRANSFER_NSSET:
			break;
		/* commands with <msgQ> element */
		case EPP_POLL_REQ:
			if (cdata->rc != 1301) break;
			START_ELEMENT(writer, simple_err, "msgQ");
			snprintf(strbuf, 25, "%d", cdata->out->poll_req.count);
			WRITE_ATTRIBUTE(writer, simple_err, "count", strbuf);
			snprintf(strbuf, 25, "%d", cdata->out->poll_req.msgid);
			WRITE_ATTRIBUTE(writer, simple_err, "id", strbuf);
			get_rfc3339_date(cdata->out->poll_req.qdate, strbuf);
			WRITE_ELEMENT(writer, simple_err, "qDate", strbuf);
			WRITE_ELEMENT(writer, simple_err, "msg", cdata->out->poll_req.msg);
			END_ELEMENT(writer, simple_err); /* msgQ */
			break;
		case EPP_POLL_ACK:
			if (cdata->rc != 1000) break;
			START_ELEMENT(writer, simple_err, "msgQ");
			snprintf(strbuf, 25, "%d", cdata->out->poll_ack.count);
			WRITE_ATTRIBUTE(writer, simple_err, "count", strbuf);
			snprintf(strbuf, 25, "%d", cdata->out->poll_ack.msgid);
			WRITE_ATTRIBUTE(writer, simple_err, "id", strbuf);
			END_ELEMENT(writer, simple_err); /* msgQ */
			break;
		/* query commands with <resData> element */
		case EPP_CHECK_DOMAIN:
			if (cdata->rc != 1000) break;
			START_ELEMENT(writer, simple_err, "resData");
			START_ELEMENT(writer, simple_err, "domain:chkData");
			WRITE_ATTRIBUTE(writer, simple_err, "xmlns:domain", NS_DOMAIN);
			WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation",
					LOC_DOMAIN);
			CL_RESET(cdata->in->check.ids);
			CL_RESET(cdata->out->check.avails);
			CL_FOREACH(cdata->in->check.ids) {
				epp_avail	*avail;

				CL_NEXT(cdata->out->check.avails);
				avail = CL_CONTENT(cdata->out->check.avails);
				START_ELEMENT(writer, simple_err, "domain:cd");
				START_ELEMENT(writer, simple_err, "domain:name");
				if (avail->avail)
					WRITE_ATTRIBUTE(writer, simple_err, "avail", "1");
				else
					WRITE_ATTRIBUTE(writer, simple_err, "avail", "0");
				WRITE_STRING(writer, simple_err,
						CL_CONTENT(cdata->in->check.ids));
				END_ELEMENT(writer, simple_err); /* name */
				if (!avail->avail)
					WRITE_ELEMENT(writer, simple_err, "domain:reason",
							avail->reason);
				END_ELEMENT(writer, simple_err); /* cd (check data) */
			}
			END_ELEMENT(writer, simple_err); /* chkData */
			END_ELEMENT(writer, simple_err); /* resData */
			break;
		case EPP_CHECK_CONTACT:
			if (cdata->rc != 1000) break;
			START_ELEMENT(writer, simple_err, "resData");
			START_ELEMENT(writer, simple_err, "contact:chkData");
			WRITE_ATTRIBUTE(writer, simple_err, "xmlns:contact", NS_CONTACT);
			WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation",
					LOC_CONTACT);
			CL_RESET(cdata->in->check.ids);
			CL_RESET(cdata->out->check.avails);
			CL_FOREACH(cdata->in->check.ids) {
				epp_avail	*avail;

				CL_NEXT(cdata->out->check.avails);
				avail = CL_CONTENT(cdata->out->check.avails);
				START_ELEMENT(writer, simple_err, "contact:cd");
				START_ELEMENT(writer, simple_err, "contact:name");
				if (avail->avail)
					WRITE_ATTRIBUTE(writer, simple_err, "avail", "1");
				else
					WRITE_ATTRIBUTE(writer, simple_err, "avail", "0");
				WRITE_STRING(writer, simple_err,
						CL_CONTENT(cdata->in->check.ids));
				END_ELEMENT(writer, simple_err); /* name */
				if (!avail->avail)
					WRITE_ELEMENT(writer, simple_err, "contact:reason",
							avail->reason);
				END_ELEMENT(writer, simple_err); /* cd (check data) */
			}
			END_ELEMENT(writer, simple_err); /* chkData */
			END_ELEMENT(writer, simple_err); /* resData */
			break;
		case EPP_CHECK_NSSET:
			if (cdata->rc != 1000) break;
			START_ELEMENT(writer, simple_err, "resData");
			START_ELEMENT(writer, simple_err, "nsset:chkData");
			WRITE_ATTRIBUTE(writer, simple_err, "xmlns:nsset", NS_NSSET);
			WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation",LOC_NSSET);
			CL_RESET(cdata->in->check.ids);
			CL_RESET(cdata->out->check.avails);
			CL_FOREACH(cdata->in->check.ids) {
				epp_avail	*avail;

				CL_NEXT(cdata->out->check.avails);
				avail = CL_CONTENT(cdata->out->check.avails);
				START_ELEMENT(writer, simple_err, "nsset:cd");
				START_ELEMENT(writer, simple_err, "nsset:name");
				if (avail->avail)
					WRITE_ATTRIBUTE(writer, simple_err, "avail", "1");
				else
					WRITE_ATTRIBUTE(writer, simple_err, "avail", "0");
				WRITE_STRING(writer, simple_err,
						CL_CONTENT(cdata->in->check.ids));
				END_ELEMENT(writer, simple_err); /* name */
				if (!avail->avail)
					WRITE_ELEMENT(writer, simple_err, "nsset:reason",
							avail->reason);
				END_ELEMENT(writer, simple_err); /* cd (check data) */
			}
			END_ELEMENT(writer, simple_err); /* chkData */
			END_ELEMENT(writer, simple_err); /* resData */
			break;
		case EPP_INFO_DOMAIN:
			if (cdata->rc != 1000) break;
			if (!gen_info_domain(writer, cdata)) goto simple_err;
			break;
		case EPP_INFO_CONTACT:
			if (cdata->rc != 1000) break;
			if (!gen_info_contact(writer, cdata)) goto simple_err;
			break;
		case EPP_INFO_NSSET:
			if (cdata->rc != 1000) break;
			if (!gen_info_nsset(writer, cdata)) goto simple_err;
			break;
		/* transform commands with <resData> element */
		case EPP_CREATE_DOMAIN:
			if (cdata->rc != 1000) break;
			START_ELEMENT(writer, simple_err, "resData");
			START_ELEMENT(writer, simple_err, "domain:creData");
			WRITE_ATTRIBUTE(writer, simple_err, "xmlns:domain", NS_DOMAIN);
			WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation",
					LOC_DOMAIN);
			WRITE_ELEMENT(writer, simple_err, "domain:name",
					cdata->in->create_domain.name);
			get_rfc3339_date(cdata->out->create.crDate, strbuf);
			WRITE_ELEMENT(writer, simple_err, "domain:crDate", strbuf);
			get_rfc3339_date(cdata->out->create.exDate, strbuf);
			WRITE_ELEMENT(writer, simple_err, "domain:exDate", strbuf);
			END_ELEMENT(writer, simple_err); /* credata */
			END_ELEMENT(writer, simple_err); /* resdata */
			break;
		case EPP_CREATE_CONTACT:
			if (cdata->rc != 1000) break;
			START_ELEMENT(writer, simple_err, "resData");
			START_ELEMENT(writer, simple_err, "contact:creData");
			WRITE_ATTRIBUTE(writer, simple_err, "xmlns:contact", NS_CONTACT);
			WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation",
					LOC_CONTACT);
			WRITE_ELEMENT(writer, simple_err, "contact:id",
					cdata->in->create_contact.id);
			get_rfc3339_date(cdata->out->create.crDate, strbuf);
			WRITE_ELEMENT(writer, simple_err, "contact:crDate", strbuf);
			END_ELEMENT(writer, simple_err); /* credata */
			END_ELEMENT(writer, simple_err); /* resdata */
			break;
		case EPP_CREATE_NSSET:
			if (cdata->rc != 1000) break;
			START_ELEMENT(writer, simple_err, "resData");
			START_ELEMENT(writer, simple_err, "nsset:creData");
			WRITE_ATTRIBUTE(writer, simple_err, "xmlns:nsset", NS_NSSET);
			WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_NSSET);
			WRITE_ELEMENT(writer, simple_err, "nsset:id",
					cdata->in->create_nsset.id);
			get_rfc3339_date(cdata->out->create.crDate, strbuf);
			WRITE_ELEMENT(writer, simple_err, "nsset:crDate", strbuf);
			END_ELEMENT(writer, simple_err); /* credata */
			END_ELEMENT(writer, simple_err); /* resdata */
			break;
		case EPP_RENEW_DOMAIN:
			if (cdata->rc != 1000) break;
			START_ELEMENT(writer, simple_err, "resData");
			START_ELEMENT(writer, simple_err, "domain:renData");
			WRITE_ATTRIBUTE(writer, simple_err, "xmlns:domain", NS_DOMAIN);
			WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation",
					LOC_DOMAIN);
			WRITE_ELEMENT(writer, simple_err, "domain:name",
					cdata->in->renew.name);
			get_rfc3339_date(cdata->out->renew.exDate, strbuf);
			WRITE_ELEMENT(writer, simple_err, "domain:exDate", strbuf);
			END_ELEMENT(writer, simple_err); /* renData */
			END_ELEMENT(writer, simple_err); /* resData */
			break;
		case EPP_LIST_CONTACT:
			if (cdata->rc != 1000) break;
			START_ELEMENT(writer, simple_err, "resData");
			START_ELEMENT(writer, simple_err, "contact:listData");
			WRITE_ATTRIBUTE(writer, simple_err, "xmlns:contact", NS_CONTACT);
			WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation",
					LOC_CONTACT);
			CL_FOREACH(cdata->out->list.handles) {
				WRITE_ELEMENT(writer, simple_err, "contact:id",
						CL_CONTENT(cdata->out->list.handles));
			}
			END_ELEMENT(writer, simple_err); /* listData */
			END_ELEMENT(writer, simple_err); /* resData */
			break;
		case EPP_LIST_DOMAIN:
			if (cdata->rc != 1000) break;
			START_ELEMENT(writer, simple_err, "resData");
			START_ELEMENT(writer, simple_err, "domain:listData");
			WRITE_ATTRIBUTE(writer, simple_err, "xmlns:domain", NS_DOMAIN);
			WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation",
					LOC_DOMAIN);
			CL_FOREACH(cdata->out->list.handles) {
				WRITE_ELEMENT(writer, simple_err, "domain:name",
						CL_CONTENT(cdata->out->list.handles));
			}
			END_ELEMENT(writer, simple_err); /* listData */
			END_ELEMENT(writer, simple_err); /* resData */
			break;
		case EPP_LIST_NSSET:
			if (cdata->rc != 1000) break;
			START_ELEMENT(writer, simple_err, "resData");
			START_ELEMENT(writer, simple_err, "nsset:listData");
			WRITE_ATTRIBUTE(writer, simple_err, "xmlns:nsset", NS_NSSET);
			WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation",
					LOC_NSSET);
			CL_FOREACH(cdata->out->list.handles) {
				WRITE_ELEMENT(writer, simple_err, "nsset:id",
						CL_CONTENT(cdata->out->list.handles));
			}
			END_ELEMENT(writer, simple_err); /* listData */
			END_ELEMENT(writer, simple_err); /* resData */
			break;
		default:
			assert(1 == 0);
	}

	// epp epilog
	START_ELEMENT(writer, simple_err, "trID");
	WRITE_ELEMENT(writer, simple_err, "clTRID", cdata->clTRID);
	WRITE_ELEMENT(writer, simple_err, "svTRID", cdata->svTRID);

	/* this has side effect of flushing document to buffer */
	if (xmlTextWriterEndDocument(writer) < 0)  goto simple_err;

	/* we don't take into account validation errors */
	error_seen = 0;

simple_err:
	xmlFreeTextWriter(writer);
	if (error_seen) {
		xmlBufferFree(buf);
		return GEN_EBUILD;
	}

	gen->response = strdup((char *) buf->content);
	xmlBufferFree(buf);

	/* optional add on - response validation */
	if (validate) {
		xmlDocPtr	doc;
		valid_status	val_ret;
		gen_status	ret;

		/* parse xml request */
		doc = xmlParseMemory(gen->response, strlen(gen->response));
		if (doc == NULL) return GEN_NOT_XML;

		/*
		 * create validation error callback and initialize list which is used
		 * for error cumulation.
		 */
		if ((gen->valerr = malloc(sizeof (*gen->valerr))) == NULL) {
			xmlFreeDoc(doc);
			return GEN_EINTERNAL;
		}
		CL_NEW(gen->valerr);

		val_ret = validate_doc(schema_url, doc, gen->valerr);
		switch (val_ret) {
			case VAL_OK:
				ret = GEN_OK;
				break;
			case VAL_NOT_VALID:
				ret = GEN_NOT_VALID;
				break;
			case VAL_ESCHEMA:
				ret = GEN_ESCHEMA;
				break;
			case VAL_EINTERNAL:
				ret = GEN_EINTERNAL;
				break;
			default:
				ret = GEN_EINTERNAL;
				break;
		}

		xmlFreeDoc(doc);
		return ret;
	}

	return GEN_OK;
}

void epp_free_gen(epp_gen *gen)
{
	assert(gen != NULL);
	if (gen->response != NULL) free(gen->response);
	if (gen->valerr != NULL) {
		CL_FOREACH(gen->valerr) {
			epp_error	*e = CL_CONTENT(gen->valerr);
			free(e->value);
			free(e->reason);
			free(e);
		}
		cl_purge(gen->valerr);
	}
}

void epp_free_greeting(char *greeting)
{
	assert(greeting != NULL);
	free(greeting);
}
