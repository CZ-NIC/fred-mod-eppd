/*
 * Copyright statement
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/xmlschemas.h>
#include <libxml/xmlwriter.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include "epp_parser.h"
#include "epp_corba.h"

#define XSI	"http://www.w3.org/2001/XMLSchema-instance"
#define NS_EPP	"urn:ietf:params:xml:ns:epp-1.0"
#define NS_EPPCOM	"urn:ietf:params:xml:ns:eppcom-1.0"
#define NS_CONTACT	"urn:ietf:params:xml:ns:contact-1.0"
#define NS_DOMAIN	"urn:ietf:params:xml:ns:domain-1.0"
#define LOC_EPP	NS_EPP " epp-1.0.xsd"
#define CONTACT_OBJ	1
#define DOMAIN_OBJ	2
/* should be less than 255 since hash value is unsigned char */
#define HASH_SIZE	60

/*
 * Following macros are shortcuts used for document creation. So that
 * we don't have to clutter the code with error checking and other stuff.
 * That makes the code much more readable.
 *
 * All macros assume that
 *    err_handler parameter is the place where to jump when error occurs
 *    err is defined and is of type (char *)
 *    err_seen is defined and is of type int or char
 *    writer is is initialized and it is xml writer
 * When error occurs the err_seen variable is set to 1 and err contains
 * error message, which has to be freed when not used anymore.
 */
#define START_DOCUMENT(err_handler)	\
	do {										\
		if (xmlTextWriterStartDocument(writer, NULL, "UTF-8", NULL) < 0) {\
			sprintf(err, "Could not start xml document in %s", __func__);\
			err_seen = 1;						\
			goto err_handler;					\
		}										\
	}while(0)

#define END_DOCUMENT(err_handler)	\
	do {										\
		if (xmlTextWriterEndDocument(writer) < 0) {\
			sprintf(err, "Could not start xml document in %s", __func__);\
			err_seen = 1;						\
			goto err_handler;					\
		}										\
	}while(0)

#define START_ELEMENT(elem, err_handler)	\
	do {										\
		if (xmlTextWriterStartElement(writer, BAD_CAST elem) < 0) {\
			sprintf(err, "Could not write xml element %s in %s", elem, __func__);\
			err_seen = 1;						\
			goto err_handler;					\
		}										\
	}while(0)

#define WRITE_ELEMENT(elem, str, err_handler)	\
	do {										\
		if (xmlTextWriterWriteElement(writer, BAD_CAST elem, BAD_CAST str) < 0) {\
			sprintf(err, "Could not write xml element %s in %s", elem, __func__);\
			err_seen = 1;						\
			goto err_handler;					\
		}										\
	}while(0)

#define WRITE_ATTRIBUTE(attr_name, attr_value, err_handler)	\
	do {										\
		if (xmlTextWriterWriteAttribute(writer, BAD_CAST attr_name, BAD_CAST attr_value) < 0) {\
			sprintf(err, "Could not write xml attribute %s in %s", attr_name, __func__);\
			err_seen = 1;						\
			goto err_handler;					\
		}										\
	}while(0)

#define END_ELEMENT(err_handler)	\
	do {										\
		if (xmlTextWriterEndElement(writer) < 0) {\
			sprintf(err, "Could not end xml element in %s", __func__);\
			err_seen = 1;						\
			goto err_handler;					\
		}										\
	}while(0)


/**
 * epp connection context struct used to store information associated
 * with connection between subsequent calls to request parser.
 */
typedef struct {
	int sessionID;
} epp_connection_ctx;

/* item of hash table */
typedef struct hash_item_t hash_item;
struct hash_item_t {
	hash_item	*next;
	int	rc;	/* hash key (return code) */
	char	*msg;	/* message for the rc */
};


/* schema against which are validated requests */
static xmlSchemaPtr schema;
/* hash table for mapping return codes to textual messages */
static hash_item	*hash_msg[HASH_SIZE];

/**
 * Function counts simple hash value from given 4 bytes.
 * @par rc input number to hash function
 * @ret hash value
 */
static unsigned char get_rc_hash(int rc) {
	int	i;
	unsigned char	hash = 0;
	char	*rc_bytes = (char *) &rc;

	/* return code has 4 digits */
	for (i = 0; i < 4; i++) hash ^= rc_bytes[i];
	return hash % HASH_SIZE;
}

/**
 * Function inserts item in hash table.
 * @par key Input key for hash algorithm
 * @par msg Message associated with key
 * @ret Zero in case of success, one in case of failure
 */
static char msg_hash_insert(int key, const char *msg)
{
	hash_item	*hi;
	int	index;

	assert(hash_msg != NULL);
	assert(msg != NULL);

	if ((hi = malloc(sizeof *hi)) == NULL) return 0;
	hi->rc = key;
	if ((hi->msg = strdup(msg)) == NULL) {
		free(hi);
		return 1;
	}
	index = get_rc_hash(key);
	hi->next = hash_msg[index];
	hash_msg[index] = hi;

	return 0;
}

/**
 * This Routine does traditional hash lookup.
 * @par rc Result code (key) which is going to be translated
 * @ret Appropriate message (value)
 */
static char *msg_hash_lookup(int rc)
{
	hash_item	*hi;

	assert(hash_msg != NULL);

	/* iterate through hash chain */
	for (hi = hash_msg[get_rc_hash(rc)]; hi != NULL; hi = hi->next) {
		if (hi->rc == rc) break;
	}

	/* did we find anything? */
	if (hi) return hi->msg;

	return NULL;
}

/**
 * Function frees all items in hash table.
 */
static void msg_hash_clean(void)
{
	hash_item	*tmp;
	int	i;

	assert(hash_msg != NULL);

	for (i = 0; i < HASH_SIZE; i++) {
		while (hash_msg[i]) {
			tmp = hash_msg[i]->next;
			free(hash_msg[i]->msg);
			free(hash_msg[i]);
			hash_msg[i] = tmp;
		}
	}
}

int epp_parser_init(const char *url_schema)
{
	xmlSchemaParserCtxtPtr spctx;
	char rc;

	/* test libxml version */
	LIBXML_TEST_VERSION

	/* parse epp schema */
	spctx = xmlSchemaNewParserCtxt(url_schema);
	if (spctx == NULL) return 0;
	schema = xmlSchemaParse(spctx);
	xmlSchemaFreeParserCtxt(spctx);

	rc = 0;
	rc |= msg_hash_insert(1000, "Command completed successfully");
	rc |= msg_hash_insert(1001, "Command completed successfully; action pending");
	rc |= msg_hash_insert(1300, "Command completed successfully; no messages");
	rc |= msg_hash_insert(1301, "Command completed successfully; ack to dequeue");
	rc |= msg_hash_insert(1500, "Command completed successfully; ending session");
	rc |= msg_hash_insert(2000, "Unknown command");
	rc |= msg_hash_insert(2001, "Command syntax error");
	rc |= msg_hash_insert(2002, "Command use error");
	rc |= msg_hash_insert(2003, "Required parameter missing");
	rc |= msg_hash_insert(2004, "Parameter value range error");
	rc |= msg_hash_insert(2005, "Parameter value syntax error");
	rc |= msg_hash_insert(2100, "Unimplemented protocol version");
	rc |= msg_hash_insert(2101, "Unimplemented command");
	rc |= msg_hash_insert(2102, "Unimplemented option");
	rc |= msg_hash_insert(2103, "Unimplemented extension");
	rc |= msg_hash_insert(2104, "Billing failure");
	rc |= msg_hash_insert(2105, "Object is not eligible for renewal");
	rc |= msg_hash_insert(2106, "Object is not eligible for transfer");
	rc |= msg_hash_insert(2200, "Authentication error");
	rc |= msg_hash_insert(2201, "Authorization error");
	rc |= msg_hash_insert(2202, "Invalid authorization information");
	rc |= msg_hash_insert(2300, "Object pending transfer");
	rc |= msg_hash_insert(2301, "Object not pending transfer");
	rc |= msg_hash_insert(2302, "Object exists");
	rc |= msg_hash_insert(2303, "Object does not exist");
	rc |= msg_hash_insert(2304, "Object status prohibits operation");
	rc |= msg_hash_insert(2305, "Object association prohibits operation");
	rc |= msg_hash_insert(2306, "Parameter value policy error");
	rc |= msg_hash_insert(2307, "Unimplemented object service");
	rc |= msg_hash_insert(2308, "Data management policy violation");
	rc |= msg_hash_insert(2400, "Command failed");
	rc |= msg_hash_insert(2500, "Command failed; server closing connection");
	rc |= msg_hash_insert(2501, "Authentication error; server closing connection");
	rc |= msg_hash_insert(2502, "Session limit exceeded; server closing connection");

	if (rc) {
		/* error has been spotted */
		msg_hash_clean();
		return 0;
	}

	xmlInitParser();
	return 1;
}

void epp_parser_init_cleanup(void)
{
	assert(schema != NULL);

	xmlSchemaFree(schema);
	msg_hash_clean();
	xmlCleanupParser();
}

void *epp_parser_connection(void)
{
	epp_connection_ctx *ctx;

	if ((ctx = malloc(sizeof *ctx)) == NULL) return NULL;
	ctx->sessionID = 0;

	return (void *) ctx;
}

void epp_parser_connection_cleanup(void *conn_ctx)
{
	epp_connection_ctx *ctx = (epp_connection_ctx *) conn_ctx;

	free(ctx);
}

/**
 * Put new log message at the end of log chain.
 * @par parms Output parameters of parser
 * @par severity Severity of log message
 * @par msg Content of log message
 */
static void parser_log(epp_command_parms_out *parms,
		epp_parser_loglevel severity, const char *msg)
{
	epp_parser_log *new;

	new = malloc(sizeof *new);
	if (new == NULL) return;
	new->next = NULL;
	new->severity = severity;
	new->msg = strdup(msg);

	/* is it first log in chain? */
	if (parms->head == NULL) {
		parms->last = parms->head = new;
		return;
	}

	assert(parms->last != NULL);
	assert(parms->last->next == NULL);

	parms->last->next = new;
	parms->last = new;
}

void epp_parser_greeting(const char *svid, const char *svdate,
		epp_greeting_parms_out *parms)
{
	xmlBufferPtr buf;
	xmlTextWriterPtr writer;
	char	*err = NULL;
	char	err_seen = 0;

	buf = xmlBufferCreate();
	if (buf == NULL) {
		parms->error_msg = strdup("Could not create buffer for writer");
		return;
	}
	writer = xmlNewTextWriterMemory(buf, 0);
	if (writer == NULL) {
		parms->error_msg = strdup("Could not create xml writer");
		xmlBufferFree(buf);
		return;
	}

	START_DOCUMENT(greeting_end);
			
	/* epp header */
	START_ELEMENT("epp", greeting_end);
	WRITE_ATTRIBUTE("xmlns", NS_EPP, greeting_end);
	WRITE_ATTRIBUTE("xmlns:xsi", XSI, greeting_end);
	WRITE_ATTRIBUTE("xsi:schemaLocation", LOC_EPP, greeting_end);

	/* greeting part */
	START_ELEMENT("greeting", greeting_end);
	WRITE_ELEMENT("svID", svid, greeting_end);
	WRITE_ELEMENT("svDate", svdate, greeting_end);
	START_ELEMENT("svcMenu", greeting_end);
	WRITE_ELEMENT("version", "1.0", greeting_end);
	WRITE_ELEMENT("lang", "en", greeting_end);
	END_ELEMENT(greeting_end);
	START_ELEMENT("svcs", greeting_end);
	WRITE_ELEMENT("objURI", NS_CONTACT, greeting_end);
	WRITE_ELEMENT("objURI", NS_DOMAIN, greeting_end);
	END_ELEMENT(greeting_end);

	/* dcp part */
	START_ELEMENT("dcp", greeting_end);
	START_ELEMENT("access", greeting_end);
	START_ELEMENT("all", greeting_end);
	END_ELEMENT(greeting_end);
	END_ELEMENT(greeting_end);
	START_ELEMENT("statement", greeting_end);
	START_ELEMENT("purpose", greeting_end);
	START_ELEMENT("admin", greeting_end);
	END_ELEMENT(greeting_end);
	START_ELEMENT("prov", greeting_end);
	END_ELEMENT(greeting_end);
	END_ELEMENT(greeting_end);
	START_ELEMENT("recipient", greeting_end);
	START_ELEMENT("public", greeting_end);
	END_ELEMENT(greeting_end);
	END_ELEMENT(greeting_end);
	START_ELEMENT("retention", greeting_end);
	START_ELEMENT("stated", greeting_end);

	END_DOCUMENT(greeting_end);

greeting_end:
	xmlFreeTextWriter(writer);

	if (err_seen)
		parms->error_msg = err;
	else
		parms->greeting = strdup((const char *) buf->content);

	xmlBufferFree(buf);
}

void epp_parser_greeting_cleanup(epp_greeting_parms_out *parms)
{
	if (parms->error_msg != NULL) free(parms->error_msg);
	if (parms->greeting != NULL) free(parms->greeting);
}

/**
 * Purpose of this function is to make things little bit easier
 * when generating simple frames, containing only code and message.
 * This is used mostly for generating error frames.
 *
 * @par code	Result code
 * @par clTRID	Client transaction ID
 * @par svTRID	Server transaction ID
 * ret String containing response, which has to be freed by free()
 */
static char *simple_response(int code, const xmlChar *clTRID,
		const char *svTRID, epp_command_parms_out *parms) {

	xmlBufferPtr buf;
	xmlTextWriterPtr writer;
	char	*str;
	char	*err;
	char	res_code[5];
	char	err_seen = 0;

	/* make up response */
	buf = xmlBufferCreate();
	if (buf == NULL) {
		parser_log(parms, EPP_LOG_ERROR, "Could not create buffer for writer");
		return NULL;
	}
	writer = xmlNewTextWriterMemory(buf, 0);
	if (writer == NULL) {
		xmlBufferFree(buf);
		parser_log(parms, EPP_LOG_ERROR, "Could not create xml writer");
		return NULL;
	}

	START_DOCUMENT(simple_err);

	/* epp header */
	START_ELEMENT("epp", simple_err);
	WRITE_ATTRIBUTE("xmlns", NS_EPP, simple_err);
	WRITE_ATTRIBUTE("xmlns:xsi", XSI, simple_err);
	WRITE_ATTRIBUTE("xsi:schemaLocation", LOC_EPP, simple_err);

	/* epp response */
	START_ELEMENT("response", simple_err);
	START_ELEMENT("result", simple_err);
	snprintf(res_code, 5, "%d", code);
	str = msg_hash_lookup(code);
	WRITE_ATTRIBUTE("code", res_code, simple_err);
	WRITE_ELEMENT("msg", str, simple_err);
	END_ELEMENT(simple_err);
	START_ELEMENT("trID", simple_err);
	if (clTRID) WRITE_ELEMENT("clTRID", clTRID, simple_err);
	WRITE_ELEMENT("svTRID", svTRID, simple_err);
	END_DOCUMENT(simple_err);

simple_err:
	xmlFreeTextWriter(writer);
	if (err_seen) {
		xmlBufferFree(buf);
		parser_log(parms, EPP_LOG_ERROR, err);
		return NULL;
	}

	str = strdup((const char *) buf->content);
	xmlBufferFree(buf);
	return str;
}

/**
 * Login handler.
 * checks:
 *   - language supported
 *   - correct epp version
 *   - objects validity
 * data in:
 *   - client ID
 *   - password
 *   - new password (optional)
 *   - managed objects (including extensions)
 */
static void epp_login_cmd(xmlDocPtr doc, xmlXPathContextPtr xpathCtx,
		epp_connection_ctx *conn_ctx, xmlChar *clTRID,
		epp_command_parms_out *parms)
{
	xmlXPathObjectPtr	xpathObj;
	xmlNodeSetPtr	nodeset;
	xmlNode	*node;
	xmlChar	*str;
	epp_data_login	login_data;
	stringlist	*item;
	int	i;

	/* check if the user has not already logged in */
	if (conn_ctx->sessionID != 0) {
		parser_log(parms, EPP_LOG_WARNING,
			"User trying to log in but is already logged in");
		return;
	}

	/* check if language matches */
	xpathObj = xmlXPathEvalExpression(
		BAD_CAST "/epp:epp/epp:command/epp:login/epp:options/epp:lang",
		xpathCtx);
	if (xpathObj == NULL) {
		parser_log(parms, EPP_LOG_ERROR, "XPath evaluation failed");
		return;
	}
	nodeset = xpathObj->nodesetval;
	assert(nodeset->nodeNr == 1);
	node = nodeset->nodeTab[0];
	str = xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
	if (!xmlStrEqual(str, BAD_CAST "en")) {
		parser_log(parms, EPP_LOG_WARNING,
				"Selected language not supported");
		xmlFree(str);
		xmlXPathFreeObject(xpathObj);
		return;
	}
	xmlFree(str);
	xmlXPathFreeObject(xpathObj);

	/* check if EPP version matches */
	xpathObj = xmlXPathEvalExpression(BAD_CAST
		"/epp:epp/epp:command/epp:login/epp:options/epp:version",
		xpathCtx);
	if (xpathObj == NULL) {
		parser_log(parms, EPP_LOG_ERROR, "XPath evaluation failed");
		return;
	}
	nodeset = xpathObj->nodesetval;
	assert(nodeset->nodeNr == 1);
	node = nodeset->nodeTab[0];
	str = xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
	if (!xmlStrEqual(str, BAD_CAST "1.0")) {
		parser_log(parms, EPP_LOG_WARNING,
				"Selected EPP version not supported");
		xmlFree(str);
		xmlXPathFreeObject(xpathObj);
		return;
	}
	xmlFree(str);
	xmlXPathFreeObject(xpathObj);

	/* fill in login data structure */
	bzero(&login_data, sizeof login_data);

	/* clID */
	xpathObj = xmlXPathEvalExpression(
		BAD_CAST "/epp:epp/epp:command/epp:login/epp:clID", xpathCtx);
	if (xpathObj == NULL) {
		parser_log(parms, EPP_LOG_ERROR, "XPath evaluation failed");
		return;
	}
	nodeset = xpathObj->nodesetval;
	assert(nodeset->nodeNr == 1);
	node = nodeset->nodeTab[0];
	login_data.clID = (char *)
			xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
	xmlXPathFreeObject(xpathObj);

	/* pw */
	xpathObj = xmlXPathEvalExpression(
		BAD_CAST "/epp:epp/epp:command/epp:login/epp:pw", xpathCtx);
	if (xpathObj == NULL) {
		parser_log(parms, EPP_LOG_ERROR, "XPath evaluation failed");
		return;
	}
	nodeset = xpathObj->nodesetval;
	assert(nodeset->nodeNr == 1);
	node = nodeset->nodeTab[0];
	login_data.pw = (char *)
			xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
	xmlXPathFreeObject(xpathObj);

	/* newPW (optional) */
	xpathObj = xmlXPathEvalExpression(
		BAD_CAST "/epp:epp/epp:command/epp:login/epp:newPW", xpathCtx);
	if (xpathObj == NULL) {
		parser_log(parms, EPP_LOG_ERROR, "XPath evaluation failed");
		return;
	}
	nodeset = xpathObj->nodesetval;
	if (nodeset && nodeset->nodeNr) {
		node = nodeset->nodeTab[0];
		login_data.newPW = (char *)
			xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
	}
	xmlXPathFreeObject(xpathObj);

	/* objects the client wants to work with */
	xpathObj = xmlXPathEvalExpression(BAD_CAST
		"/epp:epp/epp:command/epp:login/epp:svcs/epp:objURI",
		xpathCtx);
	if (xpathObj == NULL) {
		parser_log(parms, EPP_LOG_ERROR, "XPath evaluation failed");
		return;
	}
	nodeset = xpathObj->nodesetval;
	if (nodeset != NULL) {
		for (i = 0; i < nodeset->nodeNr; i++) {
			if ((item = malloc(sizeof *item)) == NULL) {
				parser_log(parms, EPP_LOG_ERROR, "alloc of stringlist failed");
				return;
			}
			node = nodeset->nodeTab[i];
			str = xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
			/* enqueue objuri to list */
			item->content = (char *) str;
			item->next = login_data.objuri;
			login_data.objuri = item;
		}
	}
	xmlXPathFreeObject(xpathObj);

	/* extensions the client wants to work with */
	xpathObj = xmlXPathEvalExpression(BAD_CAST "/epp:epp/epp:command/epp:login/epp:svcs/epp:svcExtension/epp:extURI", xpathCtx);
	if (xpathObj == NULL) {
		parser_log(parms, EPP_LOG_ERROR, "XPath evaluation failed");
		return;
	}
	nodeset = xpathObj->nodesetval;
	if (nodeset != NULL) {
		for (i = 0; i < nodeset->nodeNr; i++) {
			if ((item = malloc(sizeof *item)) == NULL) {
				parser_log(parms, EPP_LOG_ERROR, "alloc of stringlist failed");
				return;
			}
			node = nodeset->nodeTab[i];
			str = xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
			/* enqueue exturi to list */
			item->content = (char *) str;
			item->next = login_data.exturi;
			login_data.exturi = item;
		}
	}
	xmlXPathFreeObject(xpathObj);

	login_data.clTRID = (char *) clTRID;

	/* XXX CORBA function call */
	corba_login(&login_data);

	parms->response = simple_response(login_data.rc, clTRID,
			login_data.svTRID, parms);
	/*
	 * What should we do if we are not successful? We cannot send any
	 * response, so we will behave as if we hadn't received any login -
	 * this means, we will not update sessionID.
	 */
	if (parms->response && login_data.rc == 1000) {
		conn_ctx->sessionID = login_data.sessionID;
	}
	/* clean up login_data structure */
	xmlFree(BAD_CAST login_data.clID);
	xmlFree(BAD_CAST login_data.pw);
	if (login_data.newPW) xmlFree(BAD_CAST login_data.newPW);
	xmlFree(BAD_CAST login_data.clTRID);
	/* delete list of objuris */
	while (login_data.objuri) {
		item = login_data.objuri->next;
		xmlFree(login_data.objuri->content);
		free(login_data.objuri);
		login_data.objuri = item;
	}
	/* delete list of exturis */
	while (login_data.exturi) {
		item = login_data.exturi->next;
		xmlFree(login_data.exturi->content);
		free(login_data.exturi);
		login_data.exturi = item;
	}
	if (login_data.svTRID) xmlFree(BAD_CAST login_data.svTRID);
}

void epp_parser_command(void *conn_ctx_par, const char *request,
		epp_command_parms_out *parms)
{
	int	rc;
	xmlDocPtr	doc;
	xmlSchemaValidCtxtPtr	svctx;
	xmlXPathContextPtr	xpathCtx;
	xmlXPathObjectPtr	xpathObj;
	epp_connection_ctx	*conn_ctx = (epp_connection_ctx *) conn_ctx_par;

	assert(request != NULL);
	assert(conn_ctx != NULL);
	assert(parms != NULL);

	/* parse request */
	doc = xmlParseMemory(request, strlen(request)); /* TODO optimize */
	if (doc == NULL) {
		parser_log(parms, EPP_LOG_ERROR, "Request is not XML");
		return;
	}

	/* validate request against schema */
	svctx = xmlSchemaNewValidCtxt(schema);
	if (svctx == NULL) {
		parser_log(parms, EPP_LOG_ERROR,
				"Validation context could not be created");
		return;
	}
	rc = xmlSchemaValidateDoc(svctx, doc);
	if (rc < 0) {
		parser_log(parms, EPP_LOG_ERROR, "Internal validator error");
		xmlSchemaFreeValidCtxt(svctx);
		xmlFreeDoc(doc);
		return;
	}
	if (rc > 0) {
		parser_log(parms, EPP_LOG_ERROR, "Request doesn't validate");
		xmlSchemaFreeValidCtxt(svctx);
		xmlFreeDoc(doc);
		return;
	}
	xmlSchemaFreeValidCtxt(svctx);


	/* create XPath context */
	xpathCtx = xmlXPathNewContext(doc);
	if (xpathCtx == NULL) {
		parser_log(parms, EPP_LOG_ERROR,
				"Error when initializing XPath context");
		xmlFreeDoc(doc);
		return;
	}
	/* register namespaces and their prefixes */
	if (xmlXPathRegisterNs(xpathCtx, BAD_CAST "epp", BAD_CAST NS_EPP)) {
		parser_log(parms, EPP_LOG_ERROR,
				"Could not register epp namespace");
		xmlXPathFreeContext(xpathCtx);
		xmlFreeDoc(doc);
		return;
	}
	if (xmlXPathRegisterNs(xpathCtx, BAD_CAST "eppcom", BAD_CAST NS_EPPCOM)) {
		parser_log(parms, EPP_LOG_ERROR,
				"Could not register eppcom namespace");
		xmlXPathFreeContext(xpathCtx);
		xmlFreeDoc(doc);
		return;
	}

	/*
	 * is it command at all? We have to check this, so that we can decide
	 * wether to answer at all
	 */
	xpathObj = xmlXPathEvalExpression(BAD_CAST "/epp:epp/epp:command",
				xpathCtx);
	if (xpathObj == NULL) {
		parser_log(parms, EPP_LOG_ERROR, "XPath evaluation failed");
		xmlXPathFreeContext(xpathCtx);
		xmlFreeDoc(doc);
		return;
	}
	if (xpathObj->nodesetval == NULL || xpathObj->nodesetval->nodeNr == 0) {
		xmlXPathFreeObject(xpathObj);
		parser_log(parms, EPP_LOG_ERROR, "EPP frame is not a command");
	}
	else {
		xmlChar	*clTRID;
		xmlChar	*command;
		xmlNodeSetPtr	nodeset;

		xmlXPathFreeObject(xpathObj);

		/* it is a command, get clTRID if it is there */
		xpathObj = xmlXPathEvalExpression(BAD_CAST
				"/epp:epp/epp:command/epp:clTRID", xpathCtx);
		if (xpathObj == NULL) {
			parser_log(parms, EPP_LOG_ERROR, "XPath evaluation failed");
			xmlXPathFreeContext(xpathCtx);
			xmlFreeDoc(doc);
			return;
		}
		nodeset = xpathObj->nodesetval;
		if (nodeset && nodeset->nodeNr)
			clTRID = xmlNodeListGetString(doc,
				nodeset->nodeTab[0]->xmlChildrenNode, 1);
		else clTRID = NULL;
		xmlXPathFreeObject(xpathObj);

		/* get command */
		xpathObj = xmlXPathEvalExpression(BAD_CAST "/epp:epp/epp:command/*",
						xpathCtx);
		if (xpathObj == NULL) {
			parser_log(parms, EPP_LOG_ERROR, "XPath evaluation failed");
			xmlFree(clTRID);
			xmlXPathFreeContext(xpathCtx);
			xmlFreeDoc(doc);
			return;
		}
		nodeset = xpathObj->nodesetval;
		assert(nodeset && nodeset->nodeNr);
		command = xmlStrdup(nodeset->nodeTab[0]->name);
		xmlXPathFreeObject(xpathObj);

		/* compare command step by step */
		if (xmlStrEqual(command, BAD_CAST "login")) {
			epp_login_cmd(doc, xpathCtx, conn_ctx, clTRID, parms);
		}
		else {
			parser_log(parms, EPP_LOG_ERROR,
				"EPP frame is not a command or is unknown command");
			parms->response = simple_response(2000, clTRID, "", parms);
		}
		xmlFree(command);
		if (clTRID != NULL) xmlFree(clTRID);
	}

	xmlXPathFreeContext(xpathCtx);
	xmlFreeDoc(doc);
	xmlMemoryDump();

	/* pass struct parms as it is to mod_eppd */
}

void epp_parser_command_cleanup(epp_command_parms_out *parms_out)
{
	epp_parser_log *cur, *next;

	if (parms_out->response) free(parms_out->response);

	next = parms_out->head;
	while ((cur = next) != NULL) {
		next = cur->next;
		free(cur->msg);
		free(cur);
	}
}
