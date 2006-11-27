/**
 * @file epp_gen.c
 *
 * Component for generating greeting frame and responses to EPP commands
 * in form of xml documents.
 *
 * Result of generator is the generated string
 * and validation errors if validation of responses is turned on. Greeting
 * frame is not validated, therefore only string is returned (without the list
 * of validation errors).
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/xmlschemas.h>
#include <libxml/xmlwriter.h>

#include "epp_common.h"
#include "epp_xmlcommon.h"
#include "epp_gen.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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
#define START_ELEMENT(writer, err_handler, elem)    \
	do {                                            \
		if (xmlTextWriterStartElement(writer, BAD_CAST (elem)) < 0) goto err_handler;\
	}while(0)

/** Wrapper around libxml's xmlTestWriterWriteElement() function. */
#define WRITE_ELEMENT(writer, err_handler, elem, str)  \
	do {                                               \
		if ((str) != NULL)                             \
			if (xmlTextWriterWriteElement(writer, BAD_CAST (elem), BAD_CAST (str)) < 0) goto err_handler;\
	}while(0)

/** Wrapper around libxml's xmlTestWriterWriteString() function. */
#define WRITE_STRING(writer, err_handler, str)    \
	do {                                          \
		if ((str) != NULL)                        \
			if (xmlTextWriterWriteString(writer, BAD_CAST (str)) < 0) goto err_handler;\
	}while(0)

/** Wrapper around libxml's xmlTestWriterWriteAttribute() function. */
#define WRITE_ATTRIBUTE(writer, err_handler, attr_name, attr_value) \
	do {                                                            \
		if ((attr_value) != NULL)                                   \
			if (xmlTextWriterWriteAttribute(writer, BAD_CAST (attr_name), BAD_CAST (attr_value)) < 0) goto err_handler;\
	}while(0)

/** Wrapper around libxml's xmlTestWriterEndElement() function. */
#define END_ELEMENT(writer, err_handler)        \
	do {                                        \
		if (xmlTextWriterEndElement(writer) < 0) goto err_handler;\
	}while(0)

/**
 * @}
 */

gen_status
epp_gen_greeting(void *pool, const char *svid, const char *date, char **greeting)
{
	xmlBufferPtr buf;
	xmlTextWriterPtr writer;
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
	WRITE_ELEMENT(writer, greeting_err, "svDate", date);
	START_ELEMENT(writer, greeting_err, "svcMenu");
	WRITE_ELEMENT(writer, greeting_err, "version" , PACKAGE_VERSION);
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
		*greeting = epp_strdup(pool, (char *) buf->content);
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
 * @param writer   XML writer.
 * @param cdata    Data needed to generate XML.
 * @return         1 if OK, 0 in case of failure.
 */
static char
gen_info_contact(xmlTextWriterPtr writer, epp_command_data *cdata)
{
	epps_info_contact	*info_contact;

	info_contact = cdata->data;

	START_ELEMENT(writer, simple_err, "resData");
	START_ELEMENT(writer, simple_err, "contact:infData");
	WRITE_ATTRIBUTE(writer, simple_err, "xmlns:contact", NS_CONTACT);
	WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_CONTACT);
	WRITE_ELEMENT(writer, simple_err, "contact:id", info_contact->handle);
	WRITE_ELEMENT(writer, simple_err, "contact:roid", info_contact->roid);
	q_foreach(&info_contact->status) {
		epp_status	*status;

		status = q_content(&info_contact->status);
		START_ELEMENT(writer, simple_err, "contact:status");
		WRITE_ATTRIBUTE(writer, simple_err, "s", status->value);
		WRITE_STRING(writer, simple_err, status->text);
		END_ELEMENT(writer, simple_err);
	}
	// postal info
	START_ELEMENT(writer, simple_err, "contact:postalInfo");
	WRITE_ELEMENT(writer, simple_err, "contact:name", info_contact->pi.name);
	WRITE_ELEMENT(writer, simple_err, "contact:org", info_contact->pi.org);
	START_ELEMENT(writer, simple_err, "contact:addr");
	q_foreach(&info_contact->pi.streets) {
		WRITE_ELEMENT(writer, simple_err, "contact:street",
				q_content(&info_contact->pi.streets));
	}
	WRITE_ELEMENT(writer, simple_err, "contact:city", info_contact->pi.city);
	WRITE_ELEMENT(writer, simple_err, "contact:sp", info_contact->pi.sp);
	WRITE_ELEMENT(writer, simple_err, "contact:pc", info_contact->pi.pc);
	WRITE_ELEMENT(writer, simple_err, "contact:cc", info_contact->pi.cc);
	END_ELEMENT(writer, simple_err); /* addr */
	END_ELEMENT(writer, simple_err); /* postal info */
	WRITE_ELEMENT(writer, simple_err, "contact:voice", info_contact->voice);
	WRITE_ELEMENT(writer, simple_err, "contact:fax", info_contact->fax);
	WRITE_ELEMENT(writer, simple_err, "contact:email", info_contact->email);
	WRITE_ELEMENT(writer, simple_err, "contact:clID", info_contact->clID);
	WRITE_ELEMENT(writer, simple_err, "contact:crID", info_contact->crID);
	WRITE_ELEMENT(writer, simple_err, "contact:crDate",info_contact->crDate);
	WRITE_ELEMENT(writer, simple_err, "contact:upID", info_contact->upID);
	WRITE_ELEMENT(writer, simple_err, "contact:upDate",info_contact->upDate);
	WRITE_ELEMENT(writer, simple_err, "contact:trDate",info_contact->trDate);
	WRITE_ELEMENT(writer, simple_err, "contact:authInfo",
			info_contact->authInfo);
	/* output disclose section if it is not empty */
	if (info_contact->discl.flag != -1) {
		START_ELEMENT(writer, simple_err, "contact:disclose");
		if (info_contact->discl.flag == 0)
			WRITE_ATTRIBUTE(writer, simple_err, "flag", "0");
		else
			WRITE_ATTRIBUTE(writer, simple_err, "flag", "1");
		if (info_contact->discl.name) {
			START_ELEMENT(writer, simple_err, "contact:name");
			END_ELEMENT(writer, simple_err);
		}
		if (info_contact->discl.org) {
			START_ELEMENT(writer, simple_err, "contact:org");
			END_ELEMENT(writer, simple_err);
		}
		if (info_contact->discl.addr) {
			START_ELEMENT(writer, simple_err, "contact:addr");
			END_ELEMENT(writer, simple_err);
		}
		if (info_contact->discl.voice) {
			START_ELEMENT(writer, simple_err, "contact:voice");
			END_ELEMENT(writer, simple_err);
		}
		if (info_contact->discl.fax) {
			START_ELEMENT(writer, simple_err, "contact:fax");
			END_ELEMENT(writer, simple_err);
		}
		if (info_contact->discl.email) {
			START_ELEMENT(writer, simple_err, "contact:email");
			END_ELEMENT(writer, simple_err);
		}
		END_ELEMENT(writer, simple_err); /* disclose */
	}
	WRITE_ELEMENT(writer, simple_err, "contact:vat", info_contact->vat);
	if (info_contact->ident != NULL) {
		char	type[15];

		switch (info_contact->identtype) {
			case ident_OP:
				snprintf(type, 15, "%s", "op");
				break;
			case ident_RC:
				snprintf(type, 15, "%s", "rc");
				break;
			case ident_PASSPORT:
				snprintf(type, 15, "%s", "passport");
				break;
			case ident_MPSV:
				snprintf(type, 15, "%s", "mpsv");
				break;
			case ident_ICO:
				snprintf(type, 15, "%s", "ico");
				break;
			default:
				/*
				 * what should we do? We will create
				 * nonvalidating document.
				 */
				snprintf(type, 15, "%s", "unknown");
				break;
		}
		type[14] = '\0'; /* just to be sure */
		START_ELEMENT(writer, simple_err, "contact:ident");
		WRITE_ATTRIBUTE(writer, simple_err, "type", type);
		WRITE_STRING(writer, simple_err, info_contact->ident);
		END_ELEMENT(writer, simple_err); /* ident */
	}
	WRITE_ELEMENT(writer, simple_err, "contact:notifyEmail",
			info_contact->notify_email);
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
 * @param writer   XML writer.
 * @param cdata    Data needed to generate XML.
 * @return         1 if OK, 0 in case of failure.
 */
static char
gen_info_domain(xmlTextWriterPtr writer, epp_command_data *cdata)
{
	epps_info_domain	*info_domain;
	int	print_ext;

	info_domain = cdata->data;

	START_ELEMENT(writer, simple_err, "resData");
	START_ELEMENT(writer, simple_err, "domain:infData");
	WRITE_ATTRIBUTE(writer, simple_err, "xmlns:domain", NS_DOMAIN);
	WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_DOMAIN);
	WRITE_ELEMENT(writer, simple_err, "domain:name", info_domain->handle);
	WRITE_ELEMENT(writer, simple_err, "domain:roid", info_domain->roid);
	q_foreach(&info_domain->status) {
		epp_status	*status;

		status = q_content(&info_domain->status);
		START_ELEMENT(writer, simple_err, "domain:status");
		WRITE_ATTRIBUTE(writer, simple_err, "s", status->value);
		WRITE_STRING(writer, simple_err, status->text);
		END_ELEMENT(writer, simple_err);
	}
	WRITE_ELEMENT(writer, simple_err, "domain:registrant",
			info_domain->registrant);
	q_foreach(&info_domain->admin) {
		WRITE_ELEMENT(writer, simple_err, "domain:admin",
				q_content(&info_domain->admin));
	}
	WRITE_ELEMENT(writer, simple_err, "domain:nsset", info_domain->nsset);
	WRITE_ELEMENT(writer, simple_err, "domain:clID", info_domain->clID);
	WRITE_ELEMENT(writer, simple_err, "domain:crID", info_domain->crID);
	WRITE_ELEMENT(writer, simple_err, "domain:crDate", info_domain->crDate);
	WRITE_ELEMENT(writer, simple_err, "domain:upID", info_domain->upID);
	WRITE_ELEMENT(writer, simple_err, "domain:upDate", info_domain->upDate);
	WRITE_ELEMENT(writer, simple_err, "domain:exDate", info_domain->exDate);
	WRITE_ELEMENT(writer, simple_err, "domain:trDate", info_domain->trDate);
	WRITE_ELEMENT(writer, simple_err, "domain:authInfo",
			info_domain->authInfo);
	END_ELEMENT(writer, simple_err); /* infdata */
	END_ELEMENT(writer, simple_err); /* resdata */
	/* optional extensions */
	print_ext = 0;
	q_foreach(&info_domain->extensions) {
		epp_ext_item	*ext_item;

		if (!print_ext) {
			START_ELEMENT(writer, simple_err, "extension");
			print_ext = 1;
		}
		ext_item = q_content(&info_domain->extensions);
		if (ext_item->extType == EPP_EXT_ENUMVAL) {
			START_ELEMENT(writer, simple_err, "enumval:infData");
			WRITE_ATTRIBUTE(writer, simple_err, "xmlns:enumval",
					NS_ENUMVAL);
			WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation",
					LOC_ENUMVAL);
			WRITE_ELEMENT(writer, simple_err, "enumval:valExDate",
					ext_item->ext.ext_enumval);
			END_ELEMENT(writer, simple_err); /* infdata (enumval) */
		}
	}
	if (print_ext)
		END_ELEMENT(writer, simple_err); /* extension */
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
	epps_info_nsset	*info_nsset;

	info_nsset = cdata->data;

	START_ELEMENT(writer, simple_err, "resData");
	START_ELEMENT(writer, simple_err, "nsset:infData");
	WRITE_ATTRIBUTE(writer, simple_err, "xmlns:nsset", NS_NSSET);
	WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_NSSET);
	WRITE_ELEMENT(writer, simple_err, "nsset:id", info_nsset->handle);
	WRITE_ELEMENT(writer, simple_err, "nsset:roid", info_nsset->roid);
	/* status flags */
	q_foreach(&info_nsset->status) {
		epp_status	*status;

		status = q_content(&info_nsset->status);
		START_ELEMENT(writer, simple_err, "nsset:status");
		WRITE_ATTRIBUTE(writer, simple_err, "s", status->value);
		WRITE_STRING(writer, simple_err, status->text);
		END_ELEMENT(writer, simple_err);
	}
	WRITE_ELEMENT(writer, simple_err, "nsset:clID", info_nsset->clID);
	WRITE_ELEMENT(writer, simple_err, "nsset:crID", info_nsset->crID);
	WRITE_ELEMENT(writer, simple_err, "nsset:crDate", info_nsset->crDate);
	WRITE_ELEMENT(writer, simple_err, "nsset:upID", info_nsset->upID);
	WRITE_ELEMENT(writer, simple_err, "nsset:upDate", info_nsset->upDate);
	WRITE_ELEMENT(writer, simple_err, "nsset:trDate", info_nsset->trDate);
	WRITE_ELEMENT(writer, simple_err, "nsset:authInfo",info_nsset->authInfo);
	/* print nameservers */
	q_foreach(&info_nsset->ns) {
		epp_ns	*ns;
		
		ns = (epp_ns *) q_content(&info_nsset->ns);
		START_ELEMENT(writer, simple_err, "nsset:ns");
		WRITE_ELEMENT(writer, simple_err, "nsset:name", ns->name);
		/* print addrs of nameserver */
		q_foreach(&ns->addr) {
			WRITE_ELEMENT(writer, simple_err, "nsset:addr",
					q_content(&ns->addr));
		}
		END_ELEMENT(writer, simple_err); /* ns */
	}
	/* print tech contacts */
	q_foreach(&info_nsset->tech) {
		WRITE_ELEMENT(writer, simple_err, "nsset:tech",
				q_content(&info_nsset->tech));
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
 * @param pool   Pool to allocate memory from.
 * @param e      Error specification (the field e->value is changed inside
 *               the function).
 */
static void
complete_tags(void *pool, epp_error *e)
{
	char	*newstr;
	int	len;

	/* this is same for all switch cases, so we will do it here. */
	len = strlen(e->value);

	switch (e->spec) {
		case errspec_pollAck_msgID:
			len += strlen("<poll op=\"ack\" msgID=\"");
			len += strlen("\"/>");
			newstr = epp_malloc(pool, len + 1);
			*newstr = '\0';
			strcat(newstr, "<poll op=\"ack\" msgID=\"");
			strcat(newstr, e->value);
			strcat(newstr, "\"/>");
			break;
		case errspec_pollAck_msgID_missing:
			newstr = epp_strdup(pool, "<poll op=\"ack\"/>");
			break;
		case errspec_contactUpdate_identtype_missing:
			len += 2 * strlen("<ident>") + 1;
			newstr = epp_malloc(pool, len + 1);
			*newstr = '\0';
			strcat(newstr, "<ident>");
			strcat(newstr, e->value);
			strcat(newstr, "</ident>");
			break;
		case errspec_contactUpdate_cc:
		case errspec_contactCreate_cc:
			len += 2 * strlen("<cc>") + 1;
			newstr = epp_malloc(pool, len + 1);
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
			newstr = epp_malloc(pool, len + 1);
			*newstr = '\0';
			strcat(newstr, "<id>");
			strcat(newstr, e->value);
			strcat(newstr, "</id>");
			break;
		case errspec_domainInfo_fqdn:
		case errspec_domainCreate_fqdn:
		case errspec_domainRenew_fqdn:
		case errspec_domainUpdate_fqdn:
			len += 2 * strlen("<name>") + 1;
			newstr = epp_malloc(pool, len + 1);
			*newstr = '\0';
			strcat(newstr, "<name>");
			strcat(newstr, e->value);
			strcat(newstr, "</name>");
			break;
		case errspec_nssetCreate_tech:
		case errspec_nssetUpdate_tech_add:
		case errspec_nssetUpdate_tech_rem:
			len += 2 * strlen("<tech>") + 1;
			newstr = epp_malloc(pool, len + 1);
			*newstr = '\0';
			strcat(newstr, "<tech>");
			strcat(newstr, e->value);
			strcat(newstr, "</tech>");
			break;
		case errspec_nssetCreate_ns_name:
		case errspec_nssetUpdate_ns_name_add:
		case errspec_nssetUpdate_ns_name_rem:
			len += 2 * strlen("<name>") + 1;
			newstr = epp_malloc(pool, len + 1);
			*newstr = '\0';
			strcat(newstr, "<name>");
			strcat(newstr, e->value);
			strcat(newstr, "</name>");
			break;
		case errspec_nssetCreate_ns_addr:
		case errspec_nssetUpdate_ns_addr_add:
		case errspec_nssetUpdate_ns_addr_rem:
			len += 2 * strlen("<addr>") + 1;
			newstr = epp_malloc(pool, len + 1);
			*newstr = '\0';
			strcat(newstr, "<addr>");
			strcat(newstr, e->value);
			strcat(newstr, "</addr>");
			break;
		case errspec_domainCreate_registrant:
		case errspec_domainUpdate_registrant:
			len += 2 * strlen("<registrant>") + 1;
			newstr = epp_malloc(pool, len + 1);
			*newstr = '\0';
			strcat(newstr, "<registrant>");
			strcat(newstr, e->value);
			strcat(newstr, "</registrant>");
			break;
		case errspec_domainCreate_nsset:
		case errspec_domainUpdate_nsset:
			len += 2 * strlen("<nsset>") + 1;
			newstr = epp_malloc(pool, len + 1);
			*newstr = '\0';
			strcat(newstr, "<nsset>");
			strcat(newstr, e->value);
			strcat(newstr, "</nsset>");
			break;
		case errspec_domainCreate_period:
		case errspec_domainRenew_period:
			len += 2 * strlen("<period>") + 1;
			newstr = epp_malloc(pool, len + 1);
			*newstr = '\0';
			strcat(newstr, "<period>");
			strcat(newstr, e->value);
			strcat(newstr, "</period>");
			break;
		case errspec_domainCreate_admin:
		case errspec_domainUpdate_admin_add:
		case errspec_domainUpdate_admin_rem:
			len += 2 * strlen("<admin>") + 1;
			newstr = epp_malloc(pool, len + 1);
			*newstr = '\0';
			strcat(newstr, "<admin>");
			strcat(newstr, e->value);
			strcat(newstr, "</admin>");
			break;
		case errspec_domainCreate_ext_valDate:
		case errspec_domainUpdate_ext_valDate:
		case errspec_domainRenew_ext_valDate:
			len += 2 * strlen("<valExDate>") + 1;
			newstr = epp_malloc(pool, len + 1);
			*newstr = '\0';
			strcat(newstr, "<valExDate>");
			strcat(newstr, e->value);
			strcat(newstr, "</valExDate>");
			break;
		case errspec_domainRenew_curExpDate:
			len += 2 * strlen("<curExpDate>") + 1;
			newstr = epp_malloc(pool, len + 1);
			*newstr = '\0';
			strcat(newstr, "<curExpDate>");
			strcat(newstr, e->value);
			strcat(newstr, "</curExpDate>");
			break;
		case errspec_transfer_op:
			len += strlen("<transfer op=\"");
			len += strlen("\"/>");
			newstr = epp_malloc(pool, len + 1);
			*newstr = '\0';
			strcat(newstr, "<transfer op=\"");
			strcat(newstr, e->value);
			strcat(newstr, "\">");
			break;
		default:
			/*
			 * surrounding tags are already included, don't
			 * do anything
			 */
			return;
	}
	e->value = newstr;
}

gen_status
epp_gen_response(void *pool,
		int validate,
		void *schema,
		epp_lang lang,
		epp_command_data *cdata,
		char **response,
		qhead *valerr)
{
	xmlTextWriterPtr	writer;
	xmlBufferPtr	buf;
	char	strbuf[25]; /* is enough even for 64-bit number and for a date */
	char	res_code[5];
	char	error_seen = 1;
	gen_status	ret;

	assert(pool != NULL);
	assert(schema != NULL);
	assert(cdata != NULL);
	assert(valerr->body == NULL);

	/* initialize default return values */
	*response = NULL;

	/* make up response */
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

	/* epp header */
	START_ELEMENT(writer, simple_err, "epp");
	WRITE_ATTRIBUTE(writer, simple_err, "xmlns", NS_EPP);
	WRITE_ATTRIBUTE(writer, simple_err, "xmlns:xsi", XSI);
	WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_EPP);

	/* epp response */
	START_ELEMENT(writer, simple_err, "response");
	START_ELEMENT(writer, simple_err, "result");
	snprintf(res_code, 5, "%d", cdata->rc);
	WRITE_ATTRIBUTE(writer, simple_err, "code", res_code);
	START_ELEMENT(writer, simple_err, "msg");
	if (lang != LANG_EN)
		WRITE_ATTRIBUTE(writer, simple_err, "lang", "cs");
	WRITE_STRING(writer, simple_err, cdata->msg);
	END_ELEMENT(writer, simple_err); /* msg */
	q_foreach(&cdata->errors) {
		epp_error	*e;
		
		e = (epp_error *) q_content(&cdata->errors);
		START_ELEMENT(writer, simple_err, "extValue");
		/*
		 * we cannot use standard macro WRITE_ELEMENT because we want
		 * to preserve <,> chars, otherwise they would be substituted
		 * by &lt;, &gt; respectively.
		 */
		START_ELEMENT(writer, simple_err, "value");
		if (e->spec != errspec_unknown)
			complete_tags(pool, e);
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
		case EPP_TRANSFER_CONTACT:
		case EPP_TRANSFER_NSSET:
		case EPP_SENDAUTHINFO_DOMAIN:
		case EPP_SENDAUTHINFO_CONTACT:
		case EPP_SENDAUTHINFO_NSSET:
			break;
		/* commands with <msgQ> element */
		case EPP_POLL_REQ:
			if (cdata->rc == 1301) {
				epps_poll_req	*poll_req;
				
				poll_req = cdata->data;
				START_ELEMENT(writer, simple_err, "msgQ");
				snprintf(strbuf, 25, "%d", poll_req->count);
				WRITE_ATTRIBUTE(writer, simple_err, "count",
						strbuf);
				WRITE_ATTRIBUTE(writer, simple_err, "id",
						poll_req->msgid);
				WRITE_ELEMENT(writer, simple_err, "qDate",
						poll_req->qdate);
				WRITE_ELEMENT(writer, simple_err, "msg",
						poll_req->msg);
				END_ELEMENT(writer, simple_err); /* msgQ */
			}
			break;
		case EPP_POLL_ACK:
			if (cdata->rc == 1000) {
				epps_poll_ack	*poll_ack;

				poll_ack = cdata->data;
				START_ELEMENT(writer, simple_err, "msgQ");
				snprintf(strbuf, 25, "%d", poll_ack->count);
				WRITE_ATTRIBUTE(writer, simple_err, "count",
						strbuf);
				WRITE_ATTRIBUTE(writer, simple_err, "id",
						poll_ack->newmsgid);
				END_ELEMENT(writer, simple_err); /* msgQ */
			}
			break;
		/* query commands with <resData> element */
		case EPP_CHECK_DOMAIN:
			if (cdata->rc == 1000)
			{
			epps_check	*check;

			check = cdata->data;
			START_ELEMENT(writer, simple_err, "resData");
			START_ELEMENT(writer, simple_err, "domain:chkData");
			WRITE_ATTRIBUTE(writer, simple_err, "xmlns:domain",
					NS_DOMAIN);
			WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation",
					LOC_DOMAIN);
			q_reset(&check->avails);
			q_foreach(&check->ids) {
				epp_avail	*avail;

				avail = q_content(&check->avails);
				START_ELEMENT(writer, simple_err, "domain:cd");
				START_ELEMENT(writer, simple_err, "domain:name");
				if (avail->avail)
					WRITE_ATTRIBUTE(writer, simple_err,
							"avail", "1");
				else
					WRITE_ATTRIBUTE(writer, simple_err,
							"avail", "0");
				WRITE_STRING(writer, simple_err,
						q_content(&check->ids));
				END_ELEMENT(writer, simple_err); /* name */
				if (!avail->avail) {
					START_ELEMENT(writer, simple_err,
							"domain:reason");
					if (lang != LANG_EN)
						WRITE_ATTRIBUTE(writer, simple_err, "lang", "cs");
					WRITE_STRING(writer, simple_err,
							avail->reason);
					END_ELEMENT(writer, simple_err); /* reason */
				}
				END_ELEMENT(writer, simple_err); /* cd */
				q_next(&check->avails);
			}
			END_ELEMENT(writer, simple_err); /* chkData */
			END_ELEMENT(writer, simple_err); /* resData */
			}
			break;
		case EPP_CHECK_CONTACT:
			if (cdata->rc == 1000)
			{
			epps_check	*check;

			check = cdata->data;
			START_ELEMENT(writer, simple_err, "resData");
			START_ELEMENT(writer, simple_err, "contact:chkData");
			WRITE_ATTRIBUTE(writer, simple_err, "xmlns:contact",
					NS_CONTACT);
			WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation",
					LOC_CONTACT);
			q_reset(&check->avails);
			q_foreach(&check->ids) {
				epp_avail	*avail;

				avail = q_content(&check->avails);
				START_ELEMENT(writer, simple_err, "contact:cd");
				START_ELEMENT(writer, simple_err, "contact:id");
				if (avail->avail)
					WRITE_ATTRIBUTE(writer, simple_err,
							"avail", "1");
				else
					WRITE_ATTRIBUTE(writer, simple_err,
							"avail", "0");
				WRITE_STRING(writer, simple_err,
						q_content(&check->ids));
				END_ELEMENT(writer, simple_err); /* name */
				if (!avail->avail)
					WRITE_ELEMENT(writer, simple_err,
							"contact:reason",
							avail->reason);
				END_ELEMENT(writer, simple_err); /* cd (check data) */
				q_next(&check->avails);
			}
			END_ELEMENT(writer, simple_err); /* chkData */
			END_ELEMENT(writer, simple_err); /* resData */
			}
			break;
		case EPP_CHECK_NSSET:
			if (cdata->rc == 1000)
			{
			epps_check	*check;

			check = cdata->data;
			START_ELEMENT(writer, simple_err, "resData");
			START_ELEMENT(writer, simple_err, "nsset:chkData");
			WRITE_ATTRIBUTE(writer, simple_err, "xmlns:nsset",
					NS_NSSET);
			WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation",
					LOC_NSSET);
			q_reset(&check->avails);
			q_foreach(&check->ids) {
				epp_avail	*avail;

				avail = q_content(&check->avails);
				START_ELEMENT(writer, simple_err, "nsset:cd");
				START_ELEMENT(writer, simple_err, "nsset:id");
				if (avail->avail)
					WRITE_ATTRIBUTE(writer, simple_err,
							"avail", "1");
				else
					WRITE_ATTRIBUTE(writer, simple_err,
							"avail", "0");
				WRITE_STRING(writer, simple_err,
						q_content(&check->ids));
				END_ELEMENT(writer, simple_err); /* name */
				if (!avail->avail)
					WRITE_ELEMENT(writer, simple_err,
							"nsset:reason",
							avail->reason);
				END_ELEMENT(writer, simple_err); /* cd (check data) */
				q_next(&check->avails);
			}
			END_ELEMENT(writer, simple_err); /* chkData */
			END_ELEMENT(writer, simple_err); /* resData */
			}
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
			if (cdata->rc == 1000) {
				epps_create_domain	*create_domain;

				create_domain = cdata->data;
				START_ELEMENT(writer, simple_err, "resData");
				START_ELEMENT(writer, simple_err,
						"domain:creData");
				WRITE_ATTRIBUTE(writer, simple_err,
						"xmlns:domain", NS_DOMAIN);
				WRITE_ATTRIBUTE(writer, simple_err,
						"xsi:schemaLocation",
						LOC_DOMAIN);
				WRITE_ELEMENT(writer, simple_err, "domain:name",
						create_domain->name);
				WRITE_ELEMENT(writer, simple_err,"domain:crDate",
						create_domain->crDate);
				WRITE_ELEMENT(writer, simple_err,"domain:exDate",
						create_domain->exDate);
				END_ELEMENT(writer, simple_err); /* credata */
				END_ELEMENT(writer, simple_err); /* resdata */
			}
			break;
		case EPP_CREATE_CONTACT:
			if (cdata->rc == 1000) {
				epps_create_contact	*create_contact;

				create_contact = cdata->data;
				START_ELEMENT(writer, simple_err, "resData");
				START_ELEMENT(writer, simple_err,
						"contact:creData");
				WRITE_ATTRIBUTE(writer, simple_err,
						"xmlns:contact", NS_CONTACT);
				WRITE_ATTRIBUTE(writer, simple_err,
						"xsi:schemaLocation",
						LOC_CONTACT);
				WRITE_ELEMENT(writer, simple_err, "contact:id",
						create_contact->id);
				WRITE_ELEMENT(writer, simple_err,
						"contact:crDate",
						create_contact->crDate);
				END_ELEMENT(writer, simple_err); /* credata */
				END_ELEMENT(writer, simple_err); /* resdata */
			}
			break;
		case EPP_CREATE_NSSET:
			if (cdata->rc == 1000) {
				epps_create_nsset	*create_nsset;

				create_nsset = cdata->data;
				START_ELEMENT(writer, simple_err, "resData");
				START_ELEMENT(writer, simple_err,
						"nsset:creData");
				WRITE_ATTRIBUTE(writer, simple_err,
						"xmlns:nsset", NS_NSSET);
				WRITE_ATTRIBUTE(writer, simple_err,
						"xsi:schemaLocation", LOC_NSSET);
				WRITE_ELEMENT(writer, simple_err, "nsset:id",
						create_nsset->id);
				WRITE_ELEMENT(writer, simple_err, "nsset:crDate",
						create_nsset->crDate);
				END_ELEMENT(writer, simple_err); /* credata */
				END_ELEMENT(writer, simple_err); /* resdata */
			}
			break;
		case EPP_RENEW_DOMAIN:
			if (cdata->rc == 1000) {
				epps_renew	*renew;

				renew = cdata->data;
				START_ELEMENT(writer, simple_err, "resData");
				START_ELEMENT(writer, simple_err,
						"domain:renData");
				WRITE_ATTRIBUTE(writer, simple_err,
						"xmlns:domain", NS_DOMAIN);
				WRITE_ATTRIBUTE(writer, simple_err,
						"xsi:schemaLocation",LOC_DOMAIN);
				WRITE_ELEMENT(writer, simple_err, "domain:name",
						renew->name);
				WRITE_ELEMENT(writer, simple_err, "domain:exDate",
						renew->exDate);
				END_ELEMENT(writer, simple_err); /* renData */
				END_ELEMENT(writer, simple_err); /* resData */
			}
			break;
		case EPP_LIST_CONTACT:
			if (cdata->rc == 1000) {
				epps_list	*list;

				list = cdata->data;
				START_ELEMENT(writer, simple_err, "resData");
				START_ELEMENT(writer, simple_err,
						"contact:listData");
				WRITE_ATTRIBUTE(writer, simple_err,
						"xmlns:contact", NS_CONTACT);
				WRITE_ATTRIBUTE(writer, simple_err,
						"xsi:schemaLocation",
						LOC_CONTACT);
				q_foreach(&list->handles) {
					WRITE_ELEMENT(writer, simple_err,
							"contact:id",
							q_content(&list->handles));
				}
				END_ELEMENT(writer, simple_err); /* listData */
				END_ELEMENT(writer, simple_err); /* resData */
			}
			break;
		case EPP_LIST_DOMAIN:
			if (cdata->rc == 1000) {
				epps_list	*list;

				list = cdata->data;
				START_ELEMENT(writer, simple_err, "resData");
				START_ELEMENT(writer, simple_err,
						"domain:listData");
				WRITE_ATTRIBUTE(writer, simple_err,
						"xmlns:domain", NS_DOMAIN);
				WRITE_ATTRIBUTE(writer, simple_err,
						"xsi:schemaLocation",LOC_DOMAIN);
				q_foreach(&list->handles) {
					WRITE_ELEMENT(writer, simple_err,
							"domain:name",
							q_content(&list->handles));
				}
				END_ELEMENT(writer, simple_err); /* listData */
				END_ELEMENT(writer, simple_err); /* resData */
			}
			break;
		case EPP_LIST_NSSET:
			if (cdata->rc == 1000) {
				epps_list	*list;

				list = cdata->data;
				START_ELEMENT(writer, simple_err, "resData");
				START_ELEMENT(writer, simple_err,
						"nsset:listData");
				WRITE_ATTRIBUTE(writer, simple_err,
						"xmlns:nsset", NS_NSSET);
				WRITE_ATTRIBUTE(writer, simple_err,
						"xsi:schemaLocation", LOC_NSSET);
				q_foreach(&list->handles) {
					WRITE_ELEMENT(writer, simple_err,
							"nsset:id",
							q_content(&list->handles));
				}
				END_ELEMENT(writer, simple_err); /* listData */
				END_ELEMENT(writer, simple_err); /* resData */
			}
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

	error_seen = 0;

simple_err:
	xmlFreeTextWriter(writer);
	if (error_seen) {
		xmlBufferFree(buf);
		return GEN_EBUILD;
	}

	*response = epp_strdup(pool, (char *) buf->content);
	xmlBufferFree(buf);
	if (*response == NULL) {
		return GEN_EBUILD;
	}

	ret = GEN_OK;

	/* optional add on - response validation */
	if (validate) {
		xmlDocPtr	doc;
		valid_status	val_ret;

		/* parse xml request */
		doc = xmlParseMemory(*response, strlen(*response));
		if (doc == NULL) return GEN_NOT_XML;

		val_ret = validate_doc(pool, (xmlSchemaPtr) schema, doc, valerr);
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
	}
	return ret;
}

/* vim: set ts=8 sw=8: */
