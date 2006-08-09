/**
 * @file epp_xmlcommon.h
 *
 * This file gathers declarations common to both libxml components
 * (parser and generator).
 */

#ifndef EPP_XMLCOMMON_H
#define EPP_XMLCOMMON_H

/** Standard EPP xml namespace */
#define NS_EPP	"urn:ietf:params:xml:ns:epp-1.0"
/** Standard EPP xml namespace */
#define NS_EPPCOM	"urn:ietf:params:xml:ns:eppcom-1.0"
/** Our custom namespace used for contact object */
#define NS_CONTACT	"http://www.nic.cz/xml/epp/contact-1.0"
/** Our custom namespace used for domain object */
#define NS_DOMAIN	"http://www.nic.cz/xml/epp/domain-1.0"
/** Our custom namespace used for nsset object */
#define NS_NSSET	"http://www.nic.cz/xml/epp/nsset-1.0"
/** Standard namespace used for secDNS extension (currently not used) */
#define NS_SECDNS	"urn:ietf:params:xml:ns:secDNS-1.0"
/** Our custom namespace used for enum validation extension */
#define NS_ENUMVAL	"http://www.nic.cz/xml/epp/enumval-1.0"
/** Namespace + location of epp xml schema */
#define LOC_EPP	NS_EPP " epp-1.0.xsd"
/** Namespace + location of contact xml schema */
#define LOC_CONTACT	NS_CONTACT " contact-1.0.xsd"
/** Namespace + location of domain xml schema */
#define LOC_DOMAIN	NS_DOMAIN " domain-1.0.xsd"
/** Namespace + location of nsset xml schema */
#define LOC_NSSET	NS_NSSET " nsset-1.0.xsd"
/** Namespace + location of secDNS xml schema */
#define LOC_SECDNS	NS_SECDNS " secDNS-1.0.xsd"
/** Namespace + location of enumval xml schema */
#define LOC_ENUMVAL	NS_ENUMVAL " enumval-1.0.xsd"

/**
 * Enumaration of statuses returned by validator.
 */
typedef enum {
	VAL_OK,	/**< Document is valid. */
	VAL_NOT_VALID,	/**< Document does not validate. */
	VAL_ESCHEMA,	/**< Error when loading or parsing schema. */
	VAL_EINTERNAL,	/**< Internal error (malloc failed). */
}valid_status;

/**
 * Function for validating xml document.
 *
 * @param url_schema Location of schema used for validation.
 * @param doc XML document.
 * @param err_list Initialized and empty list for storing encountered errors.
 * @return Status (see #valid_status).
 */
valid_status validate_doc(
		const char *url_schema,
		xmlDocPtr doc,
		struct circ_list *err_list);

#endif /* EPP_XMLCOMMON_H */