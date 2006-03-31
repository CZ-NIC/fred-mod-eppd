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
#define HASH_SIZE	30

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
		if (xmlTextWriterWriteFormatElement(writer, BAD_CAST elem, BAD_CAST str) < 0) {\
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

#define END_ELEMENT	(err_handler)	\
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
	char *user;	 /* user id */
	int	objects; /* objects an user is going to work with */
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
static int get_rc_hash(int rc) {
	int	i;
	int	hash = 0;
	char	*rc_bytes = (char *) &rc;

	/* return code has 4 digits */
	for (i = 0; i < 4; i++) hash ^= rc[i];
	return hash % HASH_SIZE;
}

/**
 * Function inserts item in hash table.
 * @par key Input key for hash algorithm
 * @par msg Message associated with key
 * @ret Zero in case of failure, one in case of success
 */
static char msg_hash_insert(int key, const char *msg)
{
	hash_item	*hi, **tmp;
	int	index;

	assert(hash_msg != NULL);
	assert(msg != NULL);

	if ((hi = malloc(sizeof *hi)) == NULL) return 0;
	hi->rc = key;
	if ((hi->msg = strdup(msg)) == NULL) {
		free(hi);
		return 0;
	}
	index = get_rc_hash(key);
	hi->next = hash_msg[index];
	hash_msg[index] = hi;

	return 1;
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
	int	i;
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
	ctx->user = NULL;
	ctx->objects = 0;
	ctx->sessionID = 0;

	return (void *) ctx;
}

void epp_parser_connection_cleanup(void *conn_ctx)
{
	epp_connection_ctx *ctx = (epp_connection_ctx *) conn_ctx;

	if (ctx->user) free(ctx->user);
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
	char	err_seen;
	char	*err;

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
	WRITE_ELEMENT("all", "", greeting_end);
	END_ELEMENT(greeting_end);
	START_ELEMENT("statement", greeting_end);
	START_ELEMENT("purpose", greeting_end);
	WRITE_ELEMENT("admin", "", greeting_end);
	WRITE_ELEMENT("prov", "", greeting_end);
	END_ELEMENT(greeting_end);
	START_ELEMENT("recipient", greeting_end);
	WRITE_ELEMENT("public", "", greeting_end);
	END_ELEMENT(greeting_end);
	START_ELEMENT("retention", greeting_end);
	WRITE_ELEMENT("stated", "", greeting_end);
	END_ELEMENT(greeting_end);

	END_DOCUMENT(greeting_end);

greeting_end:
	if (err_seen)
		parms->error_msg = err;
	else
		parms->greeting = strdup((const char *) buf->content);

	xmlFreeTextWriter(writer);
	xmlBufferFree(buf);
}

void epp_parser_greeting_cleanup(epp_greeting_parms_out *parms)
{
	if (parms->error_msg != NULL) free(parms->error_msg);
	if (parms->greeting != NULL) free(parms->greeting);
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
		epp_connection_ctx *conn_ctx, epp_command_parms_out *parms)
{
	xmlXPathObjectPtr	xpathObj;
	xmlNodeSetPtr	nodeset;
	xmlNode	*node;
	xmlChar	*str;
	epp_data_login	login_data;
	char	*err_msg;
	char	*res_msg;
	char	res_code[5];
	char	err_seen = 0;

	/* check if the user has not already logged in */
	if (conn_ctx->user != NULL) {
		parser_log(parms, EPP_LOG_WARNING,
			"User trying to log in but is already logged in");
		return;
	}

	/* check if language matches */
	xpathObj = xmlXPathEvalExpression(
		BAD_CAST "/epp:epp/epp:command/epp:login/epp:options/epp:lang",
		xpathCtx);
	nodeset = xpathObj->nodesetval;
	assert(nodeset->nodeNr == 1);
	node = nodeset->nodeTab[0];
	str = xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
	if (!xmlStrEqual(str, "en")) {
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
	nodeset = xpathObj->nodesetval;
	assert(nodeset->nodeNr == 1);
	node = nodeset->nodeTab[0];
	str = xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
	if (!xmlStrEqual(str, "1.0")) {
		parser_log(parms, EPP_LOG_WARNING,
				"Selected EPP version not supported");
		xmlFree(str);
		xmlXPathFreeObject(xpathObj);
		return;
	}
	xmlFree(str);
	xmlXPathFreeObject(xpathObj);

	/* objects and extensions the client wants to work with */
	xpathObj = xmlXPathEvalExpression(BAD_CAST
		"/epp:epp/epp:command/epp:login/epp:options/epp:svcs/epp:objURI",
		xpathCtx);
	nodeset = xpathObj->nodesetval;
	for (i = 0; i < nodeset->nodeNr; i++) {
		node = nodeset->nodeTab[i];
		str = xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
		/* set object flags */
		if (xmlStrEqual(str, BAD_CAST NS_CONTACT))
			conn_ctx->objects |= CONTACT_OBJ;
		else if (xmlStrEqual(str, BAD_CAST NS_DOMAIN))
			conn_ctx->objects |= DOMAIN_OBJ;
		else
			parser_log(parms, EPP_LOG_WARNING,
					"Unknown object cannot be managed");
		xmlFree(str);
	}
	xmlXPathFreeObject(xpathObj);
	xpathObj = xmlXPathEvalExpression(BAD_CAST "/epp:epp/epp:command/epp:login/epp:options/epp:svcs/epp:svcExtension/epp:extURI", xpathCtx);
	nodeset = xpathObj->nodesetval;
	for (i = 0; i < nodeset->nodeNr; i++) {
		node = nodeset->nodeTab[i];
		str = xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
		/* set object flags */
		if (xmlStrEqual(str, BAD_CAST "Nonexistent"))
			conn_ctx->objects |= CONTACT_OBJ;
		else
			parser_log(parms, EPP_LOG_WARNING, "Unknown object extension");
		xmlFree(str);
	}
	xmlXPathFreeObject(xpathObj);

	/* fill in login data structure */
	bzero(&login_data, sizeof login_data);

	/* clID */
	xpathObj = xmlXPathEvalExpression(
		BAD_CAST "/epp:epp/epp:command/epp:login/epp:clID", xpathCtx);
	nodeset = xpathObj->nodesetval;
	assert(nodeset->nodeNr == 1);
	node = nodeset->nodeTab[0];
	login_data.clID = (char *)
			xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
	xmlXPathFreeObject(xpathObj);

	/* pw */
	xpathObj = xmlXPathEvalExpression(
		BAD_CAST "/epp:epp/epp:command/epp:login/epp:pw", xpathCtx);
	nodeset = xpathObj->nodesetval;
	assert(nodeset->nodeNr == 1);
	node = nodeset->nodeTab[0];
	login_data.pw = (char *)
			xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
	xmlXPathFreeObject(xpathObj);

	/* newPW (optional) */
	xpathObj = xmlXPathEvalExpression(
		BAD_CAST "/epp:epp/epp:command/epp:login/epp:newPW", xpathCtx);
	nodeset = xpathObj->nodesetval;
	if (nodeset->nodeNr) {
		node = nodeset->nodeTab[0];
		login_data.newPW = (char *)
			xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
	}
	xmlXPathFreeObject(xpathObj);

	/* get clTRID */
	xpathObj = xmlXPathEvalExpression(BAD_CAST
			"/epp:epp/epp:command/epp:clTRID", xpathCtx);
	nodeset = xpathObj->nodesetval;
	assert(nodeset->nodeNr == 1);
	node = nodeset->nodeTab[0];
	str = xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
	xmlFree(str);
	xmlXPathFreeObject(xpathObj);

	/* XXX CORBA function call */
	corba_login(&login_data);

	/* make up response */
	buf = xmlBufferCreate();
	if (buf == NULL) {
		parser_log(parms, EPP_LOG_ERROR, "Could not create buffer for writer");
		err_seen = 3;
		goto login_end;
	}
	writer = xmlNewTextWriterMemory(buf, 0);
	if (writer == NULL) {
		parser_log(parms, EPP_LOG_ERROR, "Could not create xml writer");
		err_seen = 2;
		goto login_end;
	}

	START_DOCUMENT(login_end);

	/* epp header */
	START_ELEMENT("epp", login_end);
	WRITE_ATTRIBUTE("xmlns", NS_EPP, login_end);
	WRITE_ATTRIBUTE("xmlns:xsi", XSI, login_end);
	WRITE_ATTRIBUTE("xsi:schemaLocation", LOC_EPP, login_end);

	/* epp response */
	START_ELEMENT("response", login_end);
	START_ELEMENT("result", login_end);
	snprintf(res_code, 5, "%d", rc);
	res_msg = msg_hash_lookup(login_data.rc);
	WRITE_ATTRIBUTE("code", res_code, login_end);
	WRITE_ELEMENT("msg", res_msg, login_end);
	END_ELEMENT(login_end);
	START_ELEMENT("trID", login_end);
	WRITE_ELEMENT("clTRID", login_data.clTRID, login_end);
	WRITE_ELEMENT("svTRID", login_data.svTRID, login_end);
	END_DOCUMENT(login_end);

login_end:
	if (!err_seen) {
		parms->response = strdup((const char *) buf->content);
		conn_ctx->sessionID = login_data.sessionID;
	}
	if (err_seen < 2) {
		xmlFreeTextWriter(writer);
	}
	if (err_seen < 3) {
		xmlBufferFree(buf);
	}
	xmlFree(BAD_CAST login_data.clID);
	xmlFree(BAD_CAST login_data.pw);
	xmlFree(BAD_CAST login_data.clTRID);
	if (login_data.newPW) xmlFree(BAD_CAST login_data.newPW);
	if (login_data.svTRID) xmlFree(BAD_CAST login_data.svTRID);
}

void epp_parser_command(void *conn_ctx_par, const char *request,
		epp_command_parms_out *parms)
{
	int	rc;
	const xmlChar	*clTRID;
	xmlDocPtr	doc;
	xmlNode	*element;
	xmlSchemaValidCtxtPtr	svctx;
	xmlXPathContextPtr	xpathCtx;
	xmlXPathObjectPtr	xpathObj;
	xmlNodeSetPtr	nodeset;
	epp_connection_ctx	*conn_ctx = (epp_connection_ctx *) conn_ctx_par;
	epp_parser_ctx	*parser_ctx = (epp_parser_ctx *) parser_ctx_par;

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

	/*
	 * check if it is a <command>, other elements are errors.
	 * (XXX what about <hello>)
	 */

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

	/* check directly for individual commands (XXX could be optimized) */
	xpathObj = xmlXPathEvalExpression(BAD_CAST
			"/epp:epp/epp:command/epp:login",
			xpathCtx);
	nodeset = xpathObj->nodesetval;
	if (nodeset->nodeNr)
		epp_login_cmd(doc, xpathCtx, conn_ctx, parms);

	else {
		parser_log(parms, EPP_LOG_ERROR,
			"EPP frame is not a command or is unknown command");
	}

	xmlXPathFreeObject(xpathObj);
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
	while (cur = next) {
		next = cur->next;
		free(cur->msg);
		free(cur);
	}
}
