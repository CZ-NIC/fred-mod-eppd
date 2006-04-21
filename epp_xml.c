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

#include "epp_common.h"
#include "epp_xml.h"	/* parser interface */

#define XSI	"http://www.w3.org/2001/XMLSchema-instance"
#define NS_EPP	"urn:ietf:params:xml:ns:epp-1.0"
#define NS_EPPCOM	"urn:ietf:params:xml:ns:eppcom-1.0"
#define NS_CONTACT	"urn:ietf:params:xml:ns:contact-1.0"
#define NS_DOMAIN	"urn:ietf:params:xml:ns:domain-1.0"
#define LOC_EPP	NS_EPP " epp-1.0.xsd"
/* should be less than 255 since hash value is unsigned char */
#define HASH_SIZE	60

/*
 * Following macros are shortcuts used for document creation. So that
 * we don't have to clutter the code with error checking and other stuff.
 * That makes the code much more readable.
 *
 * All macros assume that
 *    err_handler parameter is the place where to jump when error occurs
 *    writer is is initialized and it is xml writer
 */
#define START_DOCUMENT(writer, err_handler)		\
	do {										\
		if (xmlTextWriterStartDocument(writer, NULL, "UTF-8", NULL) < 0) goto err_handler;					\
	}while(0)

#define END_DOCUMENT(writer, err_handler)		\
	do {										\
		if (xmlTextWriterEndDocument(writer) < 0)  goto err_handler; \
	}while(0)

#define START_ELEMENT(writer, err_handler, elem)	\
	do {										\
		if (xmlTextWriterStartElement(writer, BAD_CAST elem) < 0) goto err_handler;	\
	}while(0)

#define WRITE_ELEMENT(writer, err_handler, elem, str)	\
	do {										\
		if (xmlTextWriterWriteElement(writer, BAD_CAST elem, BAD_CAST str) < 0) goto err_handler;	\
	}while(0)

#define WRITE_ATTRIBUTE(writer, err_handler, attr_name, attr_value)	\
	do {										\
		if (xmlTextWriterWriteAttribute(writer, BAD_CAST attr_name, BAD_CAST attr_value) < 0) goto err_handler;	\
	}while(0)

#define END_ELEMENT(writer, err_handler)	\
	do {										\
		if (xmlTextWriterEndElement(writer) < 0) goto err_handler; \
	}while(0)

/**
 * Corba dummy call is generated so often that it is beneficial to create
 * macro for that.
 *
#define COMMAND_DUMMY(_rc, _clTRID, _ctx, _parms)	\
	do {										\
		epp_data_dummy	dummy_data;				\
		bzero(&dummy_data, sizeof dummy_data);	\
		dummy_data.clTRID = (_clTRID);			\
		dummy_data.rc = (_rc);					\

			(_parms)->response = simple_response((_ctx)->server_ctx, (_rc), (_clTRID), dummy_data.svTRID, (_parms));\
			free(dummy_data.svTRID);			\
		}										\
	}while(0)
 */

/* item of hash table */
typedef struct hash_item_t hash_item;
struct hash_item_t {
	hash_item	*next;
	int	rc;	/* hash key (return code) */
	char	*msg;	/* message for the rc */
};

/**
 * Structure holds items which are valid for parser as such. This are
 * initialized during apache startup and then are only readable. They
 * represent global variables and are accessible through parser context
 * struct.
 */
typedef struct {
	xmlSchemaPtr schema; /* schema against which are validated requests */
	/* hash table for mapping return codes to textual messages */
	hash_item	*hash_msg[HASH_SIZE];
}epp_xml_globs;



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
static void
msg_hash_clean(hash_item *hash_msg[])
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

void *epp_xml_init(const char *url_schema)
{
	xmlSchemaParserCtxtPtr spctx;
	epp_xml_globs	*globs;
	char rc;

	/* allocate and initialize server context structure */
	globs = calloc(1, sizeof *globs);
	if (globs == NULL) return NULL;

	/* parse epp schema */
	spctx = xmlSchemaNewParserCtxt(url_schema);
	if (spctx == NULL) return NULL;
	globs->schema = xmlSchemaParse(spctx);
	xmlSchemaFreeParserCtxt(spctx);

	rc = 0;
	rc |= msg_hash_insert(globs->hash_msg, 1000,
			"Command completed successfully");
	rc |= msg_hash_insert(globs->hash_msg, 1001,
			"Command completed successfully; action pending");
	rc |= msg_hash_insert(globs->hash_msg, 1300,
			"Command completed successfully; no messages");
	rc |= msg_hash_insert(globs->hash_msg, 1301,
			"Command completed successfully; ack to dequeue");
	rc |= msg_hash_insert(globs->hash_msg, 1500,
			"Command completed successfully; ending session");
	rc |= msg_hash_insert(globs->hash_msg, 2000,
			"Unknown command");
	rc |= msg_hash_insert(globs->hash_msg, 2001,
			"Command syntax error");
	rc |= msg_hash_insert(globs->hash_msg, 2002,
			"Command use error");
	rc |= msg_hash_insert(globs->hash_msg, 2003,
			"Required parameter missing");
	rc |= msg_hash_insert(globs->hash_msg, 2004,
			"Parameter value range error");
	rc |= msg_hash_insert(globs->hash_msg, 2005,
			"Parameter value syntax error");
	rc |= msg_hash_insert(globs->hash_msg, 2100,
			"Unimplemented protocol version");
	rc |= msg_hash_insert(globs->hash_msg, 2101,
			"Unimplemented command");
	rc |= msg_hash_insert(globs->hash_msg, 2102,
			"Unimplemented option");
	rc |= msg_hash_insert(globs->hash_msg, 2103,
			"Unimplemented extension");
	rc |= msg_hash_insert(globs->hash_msg, 2104,
			"Billing failure");
	rc |= msg_hash_insert(globs->hash_msg, 2105,
			"Object is not eligible for renewal");
	rc |= msg_hash_insert(globs->hash_msg, 2106,
			"Object is not eligible for transfer");
	rc |= msg_hash_insert(globs->hash_msg, 2200,
			"Authentication error");
	rc |= msg_hash_insert(globs->hash_msg, 2201,
			"Authorization error");
	rc |= msg_hash_insert(globs->hash_msg, 2202,
			"Invalid authorization information");
	rc |= msg_hash_insert(globs->hash_msg, 2300,
			"Object pending transfer");
	rc |= msg_hash_insert(globs->hash_msg, 2301,
			"Object not pending transfer");
	rc |= msg_hash_insert(globs->hash_msg, 2302,
			"Object exists");
	rc |= msg_hash_insert(globs->hash_msg, 2303,
			"Object does not exist");
	rc |= msg_hash_insert(globs->hash_msg, 2304,
			"Object status prohibits operation");
	rc |= msg_hash_insert(globs->hash_msg, 2305,
			"Object association prohibits operation");
	rc |= msg_hash_insert(globs->hash_msg, 2306,
			"Parameter value policy error");
	rc |= msg_hash_insert(globs->hash_msg, 2307,
			"Unimplemented object service");
	rc |= msg_hash_insert(globs->hash_msg, 2308,
			"Data management policy violation");
	rc |= msg_hash_insert(globs->hash_msg, 2400,
			"Command failed");
	rc |= msg_hash_insert(globs->hash_msg, 2500,
			"Command failed; server closing connection");
	rc |= msg_hash_insert(globs->hash_msg, 2501,
			"Authentication error; server closing connection");
	rc |= msg_hash_insert(globs->hash_msg, 2502,
			"Session limit exceeded; server closing connection");

	if (rc) {
		/* error has been spotted */
		msg_hash_clean(globs->hash_msg);
		return NULL;
	}

	xmlInitParser();

	return (void *) globs;
}

void epp_xml_init_cleanup(void *par)
{
	epp_xml_globs	*globs = (epp_xml_globs *) par;

	assert(globs != NULL);
	assert(globs->schema != NULL);
	assert(globs->hash_msg != NULL);

	xmlSchemaFree(globs->schema);
	msg_hash_clean(globs->hash_msg);
	xmlCleanupParser();
}

gen_status
epp_gen_greeting(const char *svid, const char *svdate, char **greeting)
{
	xmlBufferPtr buf;
	xmlTextWriterPtr writer;
	int	error_seen = 1;

	assert(svid != NULL);
	assert(svdate != NULL);

	buf = xmlBufferCreate();
	if (buf == NULL) {
		return GEN_EBUFFER;
	}
	writer = xmlNewTextWriterMemory(buf, 0);
	if (writer == NULL) {
		xmlBufferFree(buf);
		return GEN_EWRITER;
	}

	START_DOCUMENT(writer, greeting_err);
			
	/* epp header */
	START_ELEMENT(writer, greeting_err, "epp");
	WRITE_ATTRIBUTE(writer, greeting_err, "xmlns", NS_EPP);
	WRITE_ATTRIBUTE(writer, greeting_err, "xmlns:xsi", XSI);
	WRITE_ATTRIBUTE(writer, greeting_err, "xsi:schemaLocation", LOC_EPP);

	/* greeting part */
	START_ELEMENT(writer, greeting_err, "greeting");
	WRITE_ELEMENT(writer, greeting_err, "svID", svid);
	WRITE_ELEMENT(writer, greeting_err, "svDate", svdate);
	START_ELEMENT(writer, greeting_err, "svcMenu");
	WRITE_ELEMENT(writer, greeting_err, "version", "1.0");
	WRITE_ELEMENT(writer, greeting_err, "lang", "en");
	END_ELEMENT(writer, greeting_err);
	START_ELEMENT(writer, greeting_err, "svcs");
	WRITE_ELEMENT(writer, greeting_err, "objURI", NS_CONTACT);
	WRITE_ELEMENT(writer, greeting_err, "objURI", NS_DOMAIN);
	END_ELEMENT(writer, greeting_err);

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

	END_DOCUMENT(writer, greeting_err);

	error_seen = 0;

greeting_err:
	xmlFreeTextWriter(writer);
	if (!error_seen) {
		/* succesfull end */
		*greeting = strdup(buf->content);
		xmlBufferFree(buf);
		return GEN_OK;
	}

	/* failure */
	xmlBufferFree(buf);
	*greeting = NULL;
	return GEN_EBUILD;
}

void epp_free_greeting(char *greeting)
{
	assert(greeting != NULL);
	free(greeting);
}

/**
 * Purpose of this function is to make things little bit easier
 * when generating simple frames, containing only code and message.
 * This is used mostly for generating error frames.
 * @par hash_msg	Hash for textual message lookup
 * @par code	Result code
 * @par clTRID	Client transaction ID
 * @par svTRID	Server transaction ID
 * ret String containing response, NULL in case of failure
 */
static gen_status
simple_response(
		hash_item **hash_msg,
		int code,
		const char *clTRID,
		const char *svTRID,
		char **result)
{
	xmlBufferPtr buf;
	xmlTextWriterPtr writer;
	char	*str;
	char	res_code[5];
	char	error_seen = 1;

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

	START_DOCUMENT(writer, simple_err);

	// epp header
	START_ELEMENT(writer, simple_err, "epp");
	WRITE_ATTRIBUTE(writer, simple_err, "xmlns", NS_EPP);
	WRITE_ATTRIBUTE(writer, simple_err, "xmlns:xsi", XSI);
	WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_EPP);

	// epp response
	START_ELEMENT(writer, simple_err, "response");
	START_ELEMENT(writer, simple_err, "result");
	snprintf(res_code, 5, "%d", code);
	str = msg_hash_lookup(hash_msg, code);
	WRITE_ATTRIBUTE(writer, simple_err, "code", res_code);
	WRITE_ELEMENT(writer, simple_err, "msg", str);
	END_ELEMENT(writer, simple_err);
	START_ELEMENT(writer, simple_err, "trID");
	if (clTRID) WRITE_ELEMENT(writer, simple_err, "clTRID", clTRID);
	WRITE_ELEMENT(writer, simple_err, "svTRID", svTRID);
	END_DOCUMENT(writer, simple_err);

	error_seen = 0;

simple_err:
	xmlFreeTextWriter(writer);
	if (error_seen) {
		xmlBufferFree(buf);
		return GEN_EBUILD;
	}

	*result = strdup(buf->content);
	xmlBufferFree(buf);
	return GEN_OK;
}

/**
 * Login parser.
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
static void
parse_login(
		int session,
		xmlDocPtr doc,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	xmlXPathObjectPtr	xpathObj;
	xmlNodeSetPtr	nodeset;
	xmlNode	*node;
	xmlChar	*str;

	/* check if the user has not already logged in */
	if (session != 0) {
		cdata->type = EPP_DUMMY;
		cdata->rc = 2002;
		return;
	}

	/* check if language matches */
	xpathObj = xmlXPathEvalExpression(
		BAD_CAST "/epp:epp/epp:command/epp:login/epp:options/epp:lang",
		xpathCtx);
	if (xpathObj == NULL) {
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	nodeset = xpathObj->nodesetval;
	assert(nodeset->nodeNr == 1);
	node = nodeset->nodeTab[0];
	str = xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
	if (!xmlStrEqual(str, BAD_CAST "en")) {
		cdata->type = EPP_DUMMY;
		cdata->rc = 2102;
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
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	nodeset = xpathObj->nodesetval;
	assert(nodeset->nodeNr == 1);
	node = nodeset->nodeTab[0];
	str = xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
	if (!xmlStrEqual(str, BAD_CAST "1.0")) {
		xmlFree(str);
		xmlXPathFreeObject(xpathObj);
		cdata->rc = 2100;
		cdata->type = EPP_DUMMY;
		return;
	}
	xmlFree(str);
	xmlXPathFreeObject(xpathObj);

	/* ok, checking done */
	xpathObj = xmlXPathEvalExpression(
		BAD_CAST "/epp:epp/epp:command/epp:login/epp:clID", xpathCtx);
	if (xpathObj == NULL) {
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	nodeset = xpathObj->nodesetval;
	assert(nodeset->nodeNr == 1);
	node = nodeset->nodeTab[0];
	cdata->un.login.clID = (char *)
			xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
	xmlXPathFreeObject(xpathObj);

	/* pw */
	xpathObj = xmlXPathEvalExpression(
		BAD_CAST "/epp:epp/epp:command/epp:login/epp:pw", xpathCtx);
	if (xpathObj == NULL) {
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	nodeset = xpathObj->nodesetval;
	assert(nodeset->nodeNr == 1);
	node = nodeset->nodeTab[0];
	cdata->un.login.pw = (char *)
			xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
	xmlXPathFreeObject(xpathObj);

	/* newPW (optional) */
	xpathObj = xmlXPathEvalExpression(
		BAD_CAST "/epp:epp/epp:command/epp:login/epp:newPW", xpathCtx);
	if (xpathObj == NULL) {
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	nodeset = xpathObj->nodesetval;
	if (nodeset && nodeset->nodeNr) {
		node = nodeset->nodeTab[0];
		cdata->un.login.newPW = (char *)
			xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
	}
	else {
		/* newPW cannot stay NULL */
		cdata->un.login.newPW = xmlStrdup("");
	}
	xmlXPathFreeObject(xpathObj);

	/* objects the client wants to work with */
	xpathObj = xmlXPathEvalExpression(BAD_CAST
		"/epp:epp/epp:command/epp:login/epp:svcs/epp:objURI",
		xpathCtx);
	if (xpathObj == NULL) {
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	nodeset = xpathObj->nodesetval;
	if (nodeset != NULL) {
		struct stringlist	*item;
		int	i;

		if ((cdata->un.login.objuri = malloc(sizeof *item)) == NULL)
		{
			cdata->rc = 2400;
			cdata->type = EPP_DUMMY;
			xmlXPathFreeObject(xpathObj);
			return;
		}
		SL_NEW(cdata->un.login.objuri);
		for (i = 0; i < nodeset->nodeNr; i++) {
			/* allocate new item */
			if ((item = malloc(sizeof *item)) == NULL) {
				cdata->rc = 2400;
				cdata->type = EPP_DUMMY;
				xmlXPathFreeObject(xpathObj);
				PURGE_SL(cdata->un.login.objuri);
				return;
			}
			node = nodeset->nodeTab[i];
			str = xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
			/* enqueue objuri to list */
			item->content = (char *) str;
			SL_ADD(cdata->un.login.objuri, item);
		}
	}
	xmlXPathFreeObject(xpathObj);

	/* extensions the client wants to work with */
	xpathObj = xmlXPathEvalExpression(BAD_CAST
		"/epp:epp/epp:command/epp:login/epp:svcs/epp:extURI",
		xpathCtx);
	if (xpathObj == NULL) {
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	nodeset = xpathObj->nodesetval;
	if (nodeset != NULL) {
		struct stringlist	*item;
		int	i;

		if ((cdata->un.login.exturi = malloc(sizeof *item)) == NULL) {
			cdata->rc = 2400;
			cdata->type = EPP_DUMMY;
			xmlXPathFreeObject(xpathObj);
			return;
		}
		SL_NEW(cdata->un.login.exturi);
		for (i = 0; i < nodeset->nodeNr; i++) {
			/* allocate new item */
			if ((item = malloc(sizeof *item)) == NULL) {
				cdata->rc = 2400;
				cdata->type = EPP_DUMMY;
				xmlXPathFreeObject(xpathObj);
				PURGE_SL(cdata->un.login.exturi);
				return;
			}
			node = nodeset->nodeTab[i];
			str = xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
			/* enqueue exturi to list */
			item->content = (char *) str;
			SL_ADD(cdata->un.login.exturi, item);
		}
	}
	xmlXPathFreeObject(xpathObj);

	cdata->type = EPP_LOGIN;
	return;
}

gen_status
epp_gen_login(void *globs, epp_command_data *cdata, char **result)
{
	assert(globs != NULL);
	assert(cdata != NULL);
	return simple_response(((epp_xml_globs *) globs)->hash_msg,
			cdata->rc, cdata->clTRID, cdata->svTRID, result);
}

gen_status
epp_gen_logout(void *globs, epp_command_data *cdata, char **result)
{
	assert(globs != NULL);
	assert(cdata != NULL);
	return simple_response(((epp_xml_globs *) globs)->hash_msg,
			cdata->rc, cdata->clTRID, cdata->svTRID, result);
}

gen_status
epp_gen_dummy(void *globs, epp_command_data *cdata, char **result)
{
	assert(globs != NULL);
	assert(cdata != NULL);
	return simple_response(((epp_xml_globs *) globs)->hash_msg,
			cdata->rc, cdata->clTRID, cdata->svTRID, result);
}

void epp_free_genstring(char *genstring)
{
	assert(genstring != NULL);
	free(genstring);
}

parser_status
epp_parse_command(
		int session,
		void *par_globs,
		const char *request,
		unsigned bytes,
		epp_command_data *cdata)
{
	int	rc;
	xmlDocPtr	doc;
	xmlSchemaValidCtxtPtr	svctx;
	xmlXPathContextPtr	xpathCtx;
	xmlXPathObjectPtr	xpathObj;
	xmlChar	*command;
	xmlNodeSetPtr	nodeset;
	epp_xml_globs	*globs = (epp_xml_globs *) par_globs;

	/* check input parameters */
	assert(globs != NULL);
	assert(request != NULL);
	assert(bytes != 0);

	/* parse xml request */
	doc = xmlParseMemory(request, bytes);
	if (doc == NULL) {
		return PARSER_NOT_XML;
	}

	/* validate request against schema */
	svctx = xmlSchemaNewValidCtxt(globs->schema);
	if (svctx == NULL) {
		xmlFreeDoc(doc);
		return PARSER_EINTERNAL;
	}
	rc = xmlSchemaValidateDoc(svctx, doc);
	if (rc < 0) {
		xmlSchemaFreeValidCtxt(svctx);
		xmlFreeDoc(doc);
		return PARSER_EINTERNAL;
	}
	if (rc > 0) {
		xmlSchemaFreeValidCtxt(svctx);
		xmlFreeDoc(doc);
		return PARSER_NOT_VALID;
	}
	xmlSchemaFreeValidCtxt(svctx);

	/* create XPath context */
	xpathCtx = xmlXPathNewContext(doc);
	if (xpathCtx == NULL) {
		xmlFreeDoc(doc);
		return PARSER_EINTERNAL;
	}
	/* register namespaces and their prefixes in XPath context */
	if (xmlXPathRegisterNs(xpathCtx, BAD_CAST "epp", BAD_CAST NS_EPP)) {
		xmlXPathFreeContext(xpathCtx);
		xmlFreeDoc(doc);
		return PARSER_EINTERNAL;
	}
	if (xmlXPathRegisterNs(xpathCtx, BAD_CAST "eppcom", BAD_CAST NS_EPPCOM)) {
		xmlXPathFreeContext(xpathCtx);
		xmlFreeDoc(doc);
		return PARSER_EINTERNAL;
	}

	/* is it command? This question must be answered first */
	xpathObj = xmlXPathEvalExpression(BAD_CAST "/epp:epp/epp:command",
				xpathCtx);
	if (xpathObj == NULL) {
		xmlXPathFreeContext(xpathCtx);
		xmlFreeDoc(doc);
		return PARSER_EINTERNAL;
	}
	if (xpathObj->nodesetval == NULL || xpathObj->nodesetval->nodeNr == 0) {
		xmlXPathFreeObject(xpathObj);
		xmlFreeDoc(doc);
		return PARSER_NOT_COMMAND;
	}
	xmlXPathFreeObject(xpathObj);

	/*
	 * command recognition part
	 */
	/* it is a command, get clTRID if there is any */
	xpathObj = xmlXPathEvalExpression(BAD_CAST
			"/epp:epp/epp:command/epp:clTRID", xpathCtx);
	if (xpathObj == NULL) {
		xmlXPathFreeContext(xpathCtx);
		xmlFreeDoc(doc);
		return PARSER_EINTERNAL;
	}
	nodeset = xpathObj->nodesetval;
	if (nodeset && nodeset->nodeNr)
		cdata->clTRID = xmlNodeListGetString(doc,
				nodeset->nodeTab[0]->xmlChildrenNode, 1);
	else {
		/* we cannot leave clTRID NULL */
		cdata->clTRID = xmlStrdup("");
	}
	xmlXPathFreeObject(xpathObj);

	/* get command name */
	xpathObj = xmlXPathEvalExpression(BAD_CAST "/epp:epp/epp:command/*",
					xpathCtx);
	if (xpathObj == NULL) {
		xmlFree(cdata->clTRID);
		xmlXPathFreeContext(xpathCtx);
		xmlFreeDoc(doc);
		return PARSER_EINTERNAL;
	}
	nodeset = xpathObj->nodesetval;
	assert(nodeset && nodeset->nodeNr);
	command = xmlStrdup(nodeset->nodeTab[0]->name);
	xmlXPathFreeObject(xpathObj);

	/* compare command step by step (TODO optimize) */
	if (xmlStrEqual(command, BAD_CAST "login")) {
		parse_login(session, doc, xpathCtx, cdata);
	}
	else if (xmlStrEqual(command, BAD_CAST "logout")) {
		/* check if the user is logged in */
		if (session == 0) {
			cdata->rc = 2002;
			cdata->type = EPP_DUMMY;
		}
		else {
			cdata->type = EPP_LOGOUT;
		}
	}
	else {
		cdata->rc = 2000;
		cdata->type = EPP_DUMMY;
	}

	xmlFree(command);
	xmlXPathFreeContext(xpathCtx);
	xmlFreeDoc(doc);
	xmlMemoryDump();

	return PARSER_OK;
}

void epp_command_data_cleanup(epp_command_data *cdata)
{
	assert(cdata != NULL);

	/*
	 * corba function might not be called and therefore svTRID might be
	 * still NULL
	 */
	if (cdata->svTRID != NULL) free(cdata->svTRID);
	free(cdata->clTRID);

	switch (cdata->type) {
		case EPP_LOGIN:
			free(cdata->un.login.clID);
			free(cdata->un.login.pw);
			free(cdata->un.login.newPW);
			PURGE_SL(cdata->un.login.objuri);
			PURGE_SL(cdata->un.login.exturi);
		case EPP_LOGOUT:
		case EPP_DUMMY:
		default:
			break;
	}
}
