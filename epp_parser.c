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
#include "epp-client.h"

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
 * Corba dummy call is generated so often that it is beneficial to create
 * macro for that.
 */
#define CORBA_DUMMY_CALL(_server_ctx, _rc, _clTRID, _ctx, _parms)	\
	do {										\
		epp_data_dummy	dummy_data;				\
		orb_rc_t	orb_rc;						\
		bzero(&dummy_data, sizeof dummy_data);	\
		dummy_data.clTRID = (_clTRID);			\
		dummy_data.rc = (_rc);					\
		orb_rc = corba_dummy((_ctx)->corba_service, (_ctx)->sessionID, &dummy_data);		\
		if (orb_rc != ORB_OK) {					\
			parser_log((_parms), EPP_LOG_ERROR, "Additionally corba dummy call failed");\
			(_parms)->response = simple_response(_server_ctx, 2400, (_clTRID), "Non-existent-svTRID", (_parms));\
		}										\
		else {									\
			(_parms)->response = simple_response(_server_ctx, (_rc), (_clTRID), dummy_data.svTRID, (_parms));\
			free(dummy_data.svTRID);			\
		}										\
	}while(0)


/**
 * epp connection context struct used to store information associated
 * with connection between subsequent calls to request parser.
 */
typedef struct {
	int sessionID;
	void	*corba_service;
	void	*corba;
} epp_connection_ctx;

/* item of hash table */
typedef struct hash_item_t hash_item;
struct hash_item_t {
	hash_item	*next;
	int	rc;	/* hash key (return code) */
	char	*msg;	/* message for the rc */
};

/**
 * Structure holds items which are valid for whole server. This are
 * initialized during apache startup and then are only readable.
 */
typedef struct {
	xmlSchemaPtr schema; /* schema against which are validated requests */
	/* hash table for mapping return codes to textual messages */
	hash_item	*hash_msg[HASH_SIZE];
} epp_server_ctx;



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
static char msg_hash_insert(hash_item *hash_msg[], int key, const char *msg)
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
static char *msg_hash_lookup(hash_item *hash_msg[], int rc)
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
static void msg_hash_clean(hash_item *hash_msg[])
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

void *epp_parser_init(const char *url_schema)
{
	xmlSchemaParserCtxtPtr spctx;
	epp_server_ctx	*server_ctx;
	char rc;

	/* test libxml version */
	LIBXML_TEST_VERSION

	/* allocate and initialize server context structure */
	server_ctx = calloc(1, sizeof *server_ctx);
	if (server_ctx == NULL) return NULL;

	/* parse epp schema */
	spctx = xmlSchemaNewParserCtxt(url_schema);
	if (spctx == NULL) return NULL;
	server_ctx->schema = xmlSchemaParse(spctx);
	xmlSchemaFreeParserCtxt(spctx);

	rc = 0;
	rc |= msg_hash_insert(server_ctx->hash_msg, 1000,
			"Command completed successfully");
	rc |= msg_hash_insert(server_ctx->hash_msg, 1001,
			"Command completed successfully; action pending");
	rc |= msg_hash_insert(server_ctx->hash_msg, 1300,
			"Command completed successfully; no messages");
	rc |= msg_hash_insert(server_ctx->hash_msg, 1301,
			"Command completed successfully; ack to dequeue");
	rc |= msg_hash_insert(server_ctx->hash_msg, 1500,
			"Command completed successfully; ending session");
	rc |= msg_hash_insert(server_ctx->hash_msg, 2000,
			"Unknown command");
	rc |= msg_hash_insert(server_ctx->hash_msg, 2001,
			"Command syntax error");
	rc |= msg_hash_insert(server_ctx->hash_msg, 2002,
			"Command use error");
	rc |= msg_hash_insert(server_ctx->hash_msg, 2003,
			"Required parameter missing");
	rc |= msg_hash_insert(server_ctx->hash_msg, 2004,
			"Parameter value range error");
	rc |= msg_hash_insert(server_ctx->hash_msg, 2005,
			"Parameter value syntax error");
	rc |= msg_hash_insert(server_ctx->hash_msg, 2100,
			"Unimplemented protocol version");
	rc |= msg_hash_insert(server_ctx->hash_msg, 2101,
			"Unimplemented command");
	rc |= msg_hash_insert(server_ctx->hash_msg, 2102,
			"Unimplemented option");
	rc |= msg_hash_insert(server_ctx->hash_msg, 2103,
			"Unimplemented extension");
	rc |= msg_hash_insert(server_ctx->hash_msg, 2104,
			"Billing failure");
	rc |= msg_hash_insert(server_ctx->hash_msg, 2105,
			"Object is not eligible for renewal");
	rc |= msg_hash_insert(server_ctx->hash_msg, 2106,
			"Object is not eligible for transfer");
	rc |= msg_hash_insert(server_ctx->hash_msg, 2200,
			"Authentication error");
	rc |= msg_hash_insert(server_ctx->hash_msg, 2201,
			"Authorization error");
	rc |= msg_hash_insert(server_ctx->hash_msg, 2202,
			"Invalid authorization information");
	rc |= msg_hash_insert(server_ctx->hash_msg, 2300,
			"Object pending transfer");
	rc |= msg_hash_insert(server_ctx->hash_msg, 2301,
			"Object not pending transfer");
	rc |= msg_hash_insert(server_ctx->hash_msg, 2302,
			"Object exists");
	rc |= msg_hash_insert(server_ctx->hash_msg, 2303,
			"Object does not exist");
	rc |= msg_hash_insert(server_ctx->hash_msg, 2304,
			"Object status prohibits operation");
	rc |= msg_hash_insert(server_ctx->hash_msg, 2305,
			"Object association prohibits operation");
	rc |= msg_hash_insert(server_ctx->hash_msg, 2306,
			"Parameter value policy error");
	rc |= msg_hash_insert(server_ctx->hash_msg, 2307,
			"Unimplemented object service");
	rc |= msg_hash_insert(server_ctx->hash_msg, 2308,
			"Data management policy violation");
	rc |= msg_hash_insert(server_ctx->hash_msg, 2400,
			"Command failed");
	rc |= msg_hash_insert(server_ctx->hash_msg, 2500,
			"Command failed; server closing connection");
	rc |= msg_hash_insert(server_ctx->hash_msg, 2501,
			"Authentication error; server closing connection");
	rc |= msg_hash_insert(server_ctx->hash_msg, 2502,
			"Session limit exceeded; server closing connection");

	if (rc) {
		/* error has been spotted */
		msg_hash_clean(server_ctx->hash_msg);
		return NULL;
	}

	xmlInitParser();

	return (void *) server_ctx;
}

void epp_parser_init_cleanup(void *par)
{
	epp_server_ctx	*server_ctx = par;

	assert(server_ctx != NULL);
	assert(server_ctx->schema != NULL);
	assert(server_ctx->hash_msg != NULL);

	xmlSchemaFree(server_ctx->schema);
	msg_hash_clean(server_ctx->hash_msg);
	xmlCleanupParser();
}

void *epp_parser_connection(void)
{
	epp_connection_ctx *ctx;

	/* allocate context structure */
	if ((ctx = malloc(sizeof *ctx)) == NULL) return NULL;
	ctx->sessionID = 0;

	/* obtain corba service handle */
	if (corba_init(&ctx->corba_service, &ctx->corba) != ORB_OK) {
		free(ctx);
		return NULL;
	}

	return (void *) ctx;
}

void epp_parser_connection_cleanup(void *conn_ctx)
{
	epp_connection_ctx *ctx = (epp_connection_ctx *) conn_ctx;

	corba_cleanup(ctx->corba_service, ctx->corba);
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
static char *simple_response(epp_server_ctx *server_ctx, int code,
		const xmlChar *clTRID,
		const char *svTRID,
		epp_command_parms_out *parms) {

	xmlBufferPtr buf;
	xmlTextWriterPtr writer;
	char	*str;
	char	res_code[5];
	char	err_seen = 0;
	char	*err = NULL;

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
	str = msg_hash_lookup(server_ctx->hash_msg, code);
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
		epp_server_ctx *server_ctx, epp_connection_ctx *conn_ctx,
		xmlChar *clTRID, epp_command_parms_out *parms)
{
	xmlXPathObjectPtr	xpathObj;
	xmlNodeSetPtr	nodeset;
	xmlNode	*node;
	xmlChar	*str;
	epp_data_login	login_data;
	orb_rc_t	orb_rc;

	/* check if the user has not already logged in */
	if (conn_ctx->sessionID != 0) {
		parser_log(parms, EPP_LOG_WARNING,
				"User trying to log in but is already logged in");
		CORBA_DUMMY_CALL(server_ctx, 2002, clTRID, conn_ctx, parms);
		return;
	}

	/* check if language matches */
	xpathObj = xmlXPathEvalExpression(
		BAD_CAST "/epp:epp/epp:command/epp:login/epp:options/epp:lang",
		xpathCtx);
	if (xpathObj == NULL) {
		parser_log(parms, EPP_LOG_ERROR, "XPath evaluation failed");
		CORBA_DUMMY_CALL(server_ctx, 2400, clTRID, conn_ctx, parms);
		return;
	}
	nodeset = xpathObj->nodesetval;
	assert(nodeset->nodeNr == 1);
	node = nodeset->nodeTab[0];
	str = xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
	if (!xmlStrEqual(str, BAD_CAST "en")) {
		parser_log(parms, EPP_LOG_WARNING, "Selected language not supported");
		xmlFree(str);
		xmlXPathFreeObject(xpathObj);
		CORBA_DUMMY_CALL(server_ctx, 2102, clTRID, conn_ctx, parms);
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
		CORBA_DUMMY_CALL(server_ctx, 2400, clTRID, conn_ctx, parms);
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
		CORBA_DUMMY_CALL(server_ctx, 2100, clTRID, conn_ctx, parms);
		return;
	}
	xmlFree(str);
	xmlXPathFreeObject(xpathObj);

	/* ok, checking done, start to fill login_data structure */
	bzero(&login_data, sizeof login_data);
	login_data.clTRID = clTRID;

	/* clID */
	xpathObj = xmlXPathEvalExpression(
		BAD_CAST "/epp:epp/epp:command/epp:login/epp:clID", xpathCtx);
	if (xpathObj == NULL) {
		parser_log(parms, EPP_LOG_ERROR, "XPath evaluation failed");
		CORBA_DUMMY_CALL(server_ctx, 2400, clTRID, conn_ctx, parms);
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
		CORBA_DUMMY_CALL(server_ctx, 2400, clTRID, conn_ctx, parms);
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
		CORBA_DUMMY_CALL(server_ctx, 2400, clTRID, conn_ctx, parms);
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
		CORBA_DUMMY_CALL(server_ctx, 2400, clTRID, conn_ctx, parms);
		return;
	}
	nodeset = xpathObj->nodesetval;
	if (nodeset != NULL) {
		stringlist	*item;
		int	i;

		for (i = 0; i < nodeset->nodeNr; i++) {
			if ((item = malloc(sizeof *item)) == NULL) {
				parser_log(parms, EPP_LOG_ERROR, "alloc of stringlist failed");
				CORBA_DUMMY_CALL(server_ctx, 2400, clTRID, conn_ctx, parms);
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
		CORBA_DUMMY_CALL(server_ctx, 2400, clTRID, conn_ctx, parms);
		return;
	}
	nodeset = xpathObj->nodesetval;
	if (nodeset != NULL) {
		stringlist	*item;
		int	i;

		for (i = 0; i < nodeset->nodeNr; i++) {
			if ((item = malloc(sizeof *item)) == NULL) {
				parser_log(parms, EPP_LOG_ERROR, "alloc of stringlist failed");
				CORBA_DUMMY_CALL(server_ctx, 2400, clTRID, conn_ctx, parms);
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

	/* *** CORBA login function call *** */
	orb_rc = corba_login(conn_ctx, &conn_ctx->sessionID, &login_data);
	if (orb_rc != ORB_OK) {
		parser_log(parms, EPP_LOG_ERROR, "corba login function call failed");
		parms->response = simple_response(server_ctx, 2400, clTRID, "Non-existent-svTRID",
				parms);
	}
	else {
		parms->response = simple_response(server_ctx, login_data.rc, clTRID,
				login_data.svTRID, parms);
		free(login_data.svTRID);
	}
	/* clean up login_data structure */
	xmlFree(BAD_CAST login_data.clID);
	xmlFree(BAD_CAST login_data.pw);
	if (login_data.newPW) xmlFree(BAD_CAST login_data.newPW);
	/* delete list of objuris */
	while (login_data.objuri) {
		stringlist	*item = login_data.objuri->next;
		xmlFree(login_data.objuri->content);
		free(login_data.objuri);
		login_data.objuri = item;
	}
	/* delete list of exturis */
	while (login_data.exturi) {
		stringlist	*item = login_data.exturi->next;
		xmlFree(login_data.exturi->content);
		free(login_data.exturi);
		login_data.exturi = item;
	}
}

/**
 * Logout handler.
 */
static void epp_logout_cmd(xmlDocPtr doc, xmlXPathContextPtr xpathCtx,
		epp_server_ctx *server_ctx, epp_connection_ctx *conn_ctx,
		xmlChar *clTRID, epp_command_parms_out *parms)
{
	epp_data_logout	logout_data;
	orb_rc_t	orb_rc;

	/* check if the user did not forget to log in */
	if (conn_ctx->sessionID == 0) {
		parser_log(parms, EPP_LOG_WARNING,
				"User trying to logout and is not logged in");
		CORBA_DUMMY_CALL(server_ctx, 2002, clTRID, conn_ctx, parms);
		return;
	}

	/* fill in logout data structure */
	bzero(&logout_data, sizeof logout_data);
	logout_data.clTRID = clTRID;

	/* *** CORBA function call *** */
	orb_rc = corba_logout(conn_ctx->corba_service, conn_ctx->sessionID,
			&logout_data);

	if (orb_rc != ORB_OK) {
		parser_log(parms, EPP_LOG_ERROR, "corba logout function call failed");
		parms->response = simple_response(server_ctx, 2400, clTRID,
				"Non-existent-svTRID", parms);
	}
	else {
		parms->response = simple_response(server_ctx, logout_data.rc, clTRID,
				logout_data.svTRID, parms);
		if (parms->response && logout_data.rc == 1000) {
			parms->status = EPP_CLOSE_CONN;
		}
		free(logout_data.svTRID);
	}
}

void epp_parser_command(void *server_ctx_par, void *conn_ctx_par,
		const char *request, unsigned bytes, epp_command_parms_out *parms)
{
	int	rc;
	xmlDocPtr	doc;
	xmlSchemaValidCtxtPtr	svctx;
	xmlXPathContextPtr	xpathCtx;
	xmlXPathObjectPtr	xpathObj;
	epp_server_ctx	*server_ctx = (epp_server_ctx *) server_ctx_par;
	epp_connection_ctx	*conn_ctx = (epp_connection_ctx *) conn_ctx_par;

	assert(server_ctx != NULL);
	assert(conn_ctx != NULL);
	assert(request != NULL);
	assert(parms != NULL);

	/* parse request */
	doc = xmlParseMemory(request, bytes);
	if (doc == NULL) {
		parser_log(parms, EPP_LOG_ERROR, "Request is not XML");
		parms->status = EPP_CLOSE_CONN;
		return;
	}

	/* validate request against schema */
	svctx = xmlSchemaNewValidCtxt(server_ctx->schema);
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
		parms->status = EPP_CLOSE_CONN;
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
		parms->status = EPP_CLOSE_CONN;
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
			epp_login_cmd(doc, xpathCtx, server_ctx, conn_ctx, clTRID, parms);
		}
		else if (xmlStrEqual(command, BAD_CAST "logout")) {
			epp_logout_cmd(doc, xpathCtx, server_ctx, conn_ctx, clTRID, parms);
		}
		else {
			parser_log(parms, EPP_LOG_ERROR,
					"EPP frame is not a command or is unknown command");
			parms->response = simple_response(server_ctx, 2000, clTRID,
					"Non-existent-svTRID", parms);
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
