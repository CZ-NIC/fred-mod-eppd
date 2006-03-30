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
#include "epp_data.h"

#define XSI	"http://www.w3.org/2001/XMLSchema-instance"
#define NS_EPP	"urn:ietf:params:xml:ns:epp-1.0"
#define NS_EPPCOM	"urn:ietf:params:xml:ns:eppcom-1.0"
#define LOC_EPP	NS_EPP " epp-1.0.xsd"

/**
 * epp connection context struct used to store information associated
 * with connection between subsequent calls to request parser.
 */
typedef struct {
	char *user;
} epp_connection_ctx;

typedef struct {
	xmlSchemaPtr schema;
} epp_parser_ctx;

void *epp_parser_init(const char *url_schema)
{
	epp_parser_ctx *ctx;
	xmlSchemaParserCtxtPtr spctx;

	LIBXML_TEST_VERSION

	ctx = malloc(sizeof *ctx);
	if (ctx == NULL) {
		return NULL;
	}
	ctx->schema = NULL;

	spctx = xmlSchemaNewParserCtxt(url_schema);
	if (spctx == NULL) {
		return NULL;
	}
	ctx->schema = xmlSchemaParse(spctx);
	xmlSchemaFreeParserCtxt(spctx);

	return (void *) ctx;
}

void epp_parser_init_cleanup(void *parser_ctx)
{
	epp_parser_ctx *ctx = (epp_parser_ctx *) parser_ctx;

	if (ctx != NULL) {
		if (ctx->schema != NULL) xmlSchemaFree(ctx->schema);
		free(ctx);
	}
}

void *epp_parser_connection(void)
{
	epp_connection_ctx *ctx;

	xmlInitParser(); /* XXX not thread safe */

	if ((ctx = malloc(sizeof *ctx)) == NULL) return NULL;
	ctx->user = NULL;

	return (void *) ctx;
}

void epp_parser_connection_cleanup(void *conn_ctx)
{
	epp_connection_ctx *ctx = (epp_connection_ctx *) conn_ctx;

	free(ctx);
	xmlCleanupParser(); /* XXX not thread safe */
}

/**
 * Put new log message at the end of log chain.
 * @par parms Output parameters of parser
 * @par severity Severity of log message
 * @par msg Content of log message
 */
static void parser_log(epp_command_parms_out *parms, epp_parser_loglevel severity,
		const char *msg)
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
	int rc;

#define INTERNAL_ERROR	"XML writer internal error"
#define WRITE_ELEMENT_ERROR	"XML writer could not create element"
#define WRITE_ATTRIBUTE_ERROR	"XML writer could not create attribute"

	buf = xmlBufferCreate();
	if (buf == NULL) {
		parms->error_msg = strdup(INTERNAL_ERROR);
		return;
	}
	writer = xmlNewTextWriterMemory(buf, 0);
	if (writer == NULL) {
		parms->error_msg = strdup(INTERNAL_ERROR);
		return;
	}
	rc = xmlTextWriterStartDocument(writer, NULL, "UTF-8", NULL);
	if (rc < 0) {
		parms->error_msg = strdup(INTERNAL_ERROR);
		return;
	}

	/* epp header */
	rc = xmlTextWriterStartElement(writer, BAD_CAST "epp");
	if (rc < 0) {
		parms->error_msg = strdup(WRITE_ELEMENT_ERROR);
		return;
	}
	rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "xmlns", BAD_CAST NS_EPP);
	if (rc < 0) {
		parms->error_msg = strdup(WRITE_ATTRIBUTE_ERROR);
		return;
	}
	rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "xmlns:xsi", BAD_CAST XSI);
	if (rc < 0) {
		parms->error_msg = strdup(WRITE_ATTRIBUTE_ERROR);
		return;
	}
	rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "xsi:schemaLocation",
			BAD_CAST LOC_EPP);
	if (rc < 0) {
		parms->error_msg = strdup(WRITE_ATTRIBUTE_ERROR);
		return;
	}

	/* greeting part */
	rc = xmlTextWriterStartElement(writer, BAD_CAST "greeting");
	if (rc < 0) {
		parms->error_msg = strdup(WRITE_ELEMENT_ERROR);
		return;
	}
	rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "svID",
			"%s", svid);
	if (rc < 0) {
		parms->error_msg = strdup(WRITE_ELEMENT_ERROR);
		return;
	}
	rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "svDate",
			"%s", svdate);
	if (rc < 0) {
		parms->error_msg = strdup(WRITE_ELEMENT_ERROR);
		return;
	}
	rc = xmlTextWriterStartElement(writer, BAD_CAST "svcMenu");
	if (rc < 0) {
		parms->error_msg = strdup(WRITE_ELEMENT_ERROR);
		return;
	}
	rc = xmlTextWriterWriteElement(writer, BAD_CAST "version", "1.0");
	if (rc < 0) {
		parms->error_msg = strdup(WRITE_ELEMENT_ERROR);
		return;
	}
	rc = xmlTextWriterWriteElement(writer, BAD_CAST "lang", "en");
	if (rc < 0) {
		parms->error_msg = strdup(WRITE_ELEMENT_ERROR);
		return;
	}
	rc = xmlTextWriterWriteElement(writer, BAD_CAST "objURI",
			"urn:ietf:params:xml:ns:obj1");
	if (rc < 0) {
		parms->error_msg = strdup(WRITE_ELEMENT_ERROR);
		return;
	}
	rc = xmlTextWriterWriteElement(writer, BAD_CAST "objURI",
			"urn:ietf:params:xml:ns:obj2");
	if (rc < 0) {
		parms->error_msg = strdup(WRITE_ELEMENT_ERROR);
		return;
	}
	rc = xmlTextWriterEndElement(writer);

	/* dcp part */
	rc = xmlTextWriterStartElement(writer, BAD_CAST "dcp");
	if (rc < 0) {
		parms->error_msg = strdup(WRITE_ELEMENT_ERROR);
		return;
	}
	rc = xmlTextWriterStartElement(writer, BAD_CAST "access");
	if (rc < 0) {
		parms->error_msg = strdup(WRITE_ELEMENT_ERROR);
		return;
	}
	rc = xmlTextWriterWriteElement(writer, BAD_CAST "all", "");
	if (rc < 0) {
		parms->error_msg = strdup(WRITE_ELEMENT_ERROR);
		return;
	}
	rc = xmlTextWriterEndElement(writer);

	rc = xmlTextWriterStartElement(writer, BAD_CAST "statement");
	if (rc < 0) {
		parms->error_msg = strdup(WRITE_ELEMENT_ERROR);
		return;
	}
	rc = xmlTextWriterStartElement(writer, BAD_CAST "purpose");
	if (rc < 0) {
		parms->error_msg = strdup(WRITE_ELEMENT_ERROR);
		return;
	}
	rc = xmlTextWriterWriteElement(writer, BAD_CAST "admin", "");
	if (rc < 0) {
		parms->error_msg = strdup(WRITE_ELEMENT_ERROR);
		return;
	}
	rc = xmlTextWriterWriteElement(writer, BAD_CAST "prov", "");
	if (rc < 0) {
		parms->error_msg = strdup(WRITE_ELEMENT_ERROR);
		return;
	}
	rc = xmlTextWriterEndElement(writer);

	rc = xmlTextWriterStartElement(writer, BAD_CAST "recipient");
	if (rc < 0) {
		parms->error_msg = strdup(WRITE_ELEMENT_ERROR);
		return;
	}
	rc = xmlTextWriterWriteElement(writer, BAD_CAST "ours", "");
	if (rc < 0) {
		parms->error_msg = strdup(WRITE_ELEMENT_ERROR);
		return;
	}
	rc = xmlTextWriterWriteElement(writer, BAD_CAST "public", "");
	if (rc < 0) {
		parms->error_msg = strdup(WRITE_ELEMENT_ERROR);
		return;
	}
	rc = xmlTextWriterEndElement(writer);

	rc = xmlTextWriterStartElement(writer, BAD_CAST "retention");
	if (rc < 0) {
		parms->error_msg = strdup(WRITE_ELEMENT_ERROR);
		return;
	}
	rc = xmlTextWriterWriteElement(writer, BAD_CAST "stated", "");
	if (rc < 0) {
		parms->error_msg = strdup(WRITE_ELEMENT_ERROR);
		return;
	}
	rc = xmlTextWriterEndElement(writer);

	rc = xmlTextWriterEndDocument(writer);
	if (rc < 0) {
		parms->error_msg = strdup(INTERNAL_ERROR);
		return;
	}

	xmlFreeTextWriter(writer);
	parms->greeting = strdup((const char *) buf->content);
	xmlBufferFree(buf);

#undef INTERNAL_ERROR
#undef WRITE_ELEMENT_ERROR
#undef WRITE_ATTRIBUTE_ERROR
}

void epp_parser_greeting_cleanup(epp_greeting_parms_out *parms)
{
	if (parms->error_msg != NULL) free(parms->error_msg);
	if (parms->greeting != NULL) free(parms->greeting);
}

/*
 * Login handler.
 */
static void epp_login_cmd(xmlDocPtr doc, xmlXPathContextPtr xpathCtx,
		epp_connection_ctx *conn_ctx, epp_command_parms_out *parms)
{
	xmlXPathObjectPtr	xpathObj;
	xmlNodeSetPtr	nodeset;
	xmlNode	*node;
	xmlChar	*str;
	epp_data_login	login_data;

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

	/*
	 * fill in login data structure
	 * we need to get: clID, pw, newPW (optional)
	 */
	bzero(&login_data, sizeof login_data);

	/* clID */
	xpathObj = xmlXPathEvalExpression(
		BAD_CAST "/epp:epp/epp:command/epp:login/epp:clID", xpathCtx);
	nodeset = xpathObj->nodesetval;
	assert(nodeset->nodeNr == 1);
	node = nodeset->nodeTab[0];
	login_data.clID = (char *) xmlCharStrdup(
			xmlNodeListGetString(doc, node->xmlChildrenNode, 1));
	xmlXPathFreeObject(xpathObj);

	/* pw */
	xpathObj = xmlXPathEvalExpression(
		BAD_CAST "/epp:epp/epp:command/epp:login/epp:pw", xpathCtx);
	nodeset = xpathObj->nodesetval;
	assert(nodeset->nodeNr == 1);
	node = nodeset->nodeTab[0];
	login_data.pw = (char *) xmlCharStrdup(
			xmlNodeListGetString(doc, node->xmlChildrenNode, 1));
	xmlXPathFreeObject(xpathObj);

	/* newPW (optional) */
	xpathObj = xmlXPathEvalExpression(
		BAD_CAST "/epp:epp/epp:command/epp:login/epp:newPW", xpathCtx);
	nodeset = xpathObj->nodesetval;
	if (nodeset->nodeNr) {
		node = nodeset->nodeTab[0];
		login_data.newPW = (char *) xmlCharStrdup(
			xmlNodeListGetString(doc, node->xmlChildrenNode, 1));
	}
	xmlXPathFreeObject(xpathObj);

	/* XXX CORBA function call */

	xmlFree(login_data.clID);
	xmlFree(login_data.pw);
	xmlFree(login_data.newPW);
}

void epp_parser_command(void *conn_ctx_par, void *parser_ctx_par,
		const char *request,
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
	assert(parser_ctx != NULL);
	assert(parms != NULL);

	/* parse request */
	doc = xmlParseMemory(request, strlen(request)); /* TODO optimize */
	if (doc == NULL) {
		parser_log(parms, EPP_LOG_ERROR, "Request is not XML");
		return;
	}

	/* validate request against schemas */
	svctx = xmlSchemaNewValidCtxt(parser_ctx->schema);
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
