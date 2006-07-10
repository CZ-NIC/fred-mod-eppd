#ifndef EPP_XMLCOMMON_H
#define EPP_XMLCOMMON_H

#define NS_EPP	"urn:ietf:params:xml:ns:epp-1.0"
#define NS_EPPCOM	"urn:ietf:params:xml:ns:eppcom-1.0"
#define NS_CONTACT	"http://www.nic.cz/xml/epp/contact-1.0"
#define NS_DOMAIN	"http://www.nic.cz/xml/epp/domain-1.0"
#define NS_NSSET	"http://www.nic.cz/xml/epp/nsset-1.0"
#define NS_SECDNS	"urn:ietf:params:xml:ns:secDNS-1.0"
#define NS_ENUMVAL	"http://www.nic.cz/xml/epp/enumval-1.0"
#define LOC_EPP	NS_EPP " epp-1.0.xsd"
#define LOC_CONTACT	NS_CONTACT " contact-1.0.xsd"
#define LOC_DOMAIN	NS_DOMAIN " domain-1.0.xsd"
#define LOC_NSSET	NS_NSSET " nsset-1.0.xsd"
#define LOC_SECDNS	NS_SECDNS " secDNS-1.0.xsd"
#define LOC_ENUMVAL	NS_ENUMVAL " enumval-1.0.xsd"

typedef enum {
	VAL_OK,
	VAL_NOT_VALID,
	VAL_ESCHEMA,
	VAL_EINTERNAL,
}valid_status;

void get_rfc3339_date(long long date, char *str);
void get_stripped_date(long long date, char *str);
valid_status validate_doc(
		const char *url_schema,
		xmlDocPtr doc,
		struct circ_list *err_list);

#endif /* EPP_XMLCOMMON_H */
