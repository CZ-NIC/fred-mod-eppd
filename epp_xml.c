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
#define LOC_CONTACT	NS_CONTACT " contact-1.0.xsd"
#define LOC_DOMAIN	NS_DOMAIN " domain-1.0.xsd"
/*
 * should be less than 255 since hash value is unsigned char.
 * applies to both hashes (message and command hash)
 */
#define HASH_SIZE_MSG	60
#define HASH_SIZE_CMD	30

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
 * Enumeration of all implemented EPP commands as defined in rfc.
 * This is REDuced form - without object suffix.
 */
typedef enum {
	EPP_RED_UNKNOWN_CMD,
	EPP_RED_LOGIN,
	EPP_RED_LOGOUT,
	EPP_RED_CHECK,
	EPP_RED_INFO,
	EPP_RED_POLL,
	EPP_RED_TRANSFER,
	EPP_RED_CREATE,
	EPP_RED_DELETE,
	EPP_RED_RENEW,
	EPP_RED_UPDATE
}epp_red_command_type;

/**
 * Enumeration of obejcts this server operates on.
 */
typedef enum {
	EPP_UNKNOWN_OBJ,
	EPP_CONTACT,
	EPP_DOMAIN
}epp_object_type;

/* item of message hash table */
typedef struct msg_hash_item_t msg_hash_item;
struct msg_hash_item_t {
	msg_hash_item	*next;
	int	rc;	/* hash key (return code) */
	char	*msg;	/* message for the rc */
};

/* item of command hash table */
typedef struct cmd_hash_item_t cmd_hash_item;
struct cmd_hash_item_t {
	cmd_hash_item	*next;
	char	*key;	/* hash key (command name) */
	epp_command_type	val;	/* hash value (command type) */
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
	msg_hash_item	*hash_msg[HASH_SIZE_MSG];
	/* hash table for quick command lookup */
	cmd_hash_item	*hash_cmd[HASH_SIZE_CMD];
}epp_xml_globs;



/**
 * Function counts simple hash value from given 4 bytes.
 * @par rc input number to hash function
 * @ret hash value
 */
static unsigned char get_rc_hash(int rc)
{
	int	i;
	unsigned char	hash = 0;
	char	*rc_bytes = (char *) &rc;

	/* return code has 4 digits */
	for (i = 0; i < 4; i++) hash ^= rc_bytes[i];
	return hash % HASH_SIZE_MSG;
}

/**
 * Function makes xor of first 4 bytes of command name.
 * We assume that command names are at least 4 bytes long and that there
 * are no 2 command with the same first four letters - that's true for
 * EPP commands.
 * @par key Command name
 * @ret Hash value
 */
static unsigned char get_cmd_hash(const char *key)
{
	int	i;
	unsigned char	hash = 0;

	/* return code has 4 digits */
	for (i = 0; i < 4; i++) hash ^= key[i];
	return hash % HASH_SIZE_CMD;
}

/**
 * Function inserts item in message hash table.
 * @par key Input key for hash algorithm
 * @par msg Message associated with key
 * @ret Zero in case of success, one in case of failure
 */
static char msg_hash_insert(msg_hash_item *hash_msg[], int key, const char *msg)
{
	msg_hash_item	*hi;
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
 * Function inserts item in command hash table.
 * @par key Input key for hash algorithm
 * @par type Command type associated with given key
 * @ret Zero in case of success, one in case of failure
 */
static char cmd_hash_insert(
		cmd_hash_item *hash_cmd[],
		const char *key,
		epp_command_type type)
{
	cmd_hash_item	*hi;
	int	index;

	assert(hash_cmd != NULL);
	assert(key != NULL);

	if ((hi = malloc(sizeof *hi)) == NULL) return 0;
	hi->val = type;
	if ((hi->key = strdup(key)) == NULL) {
		free(hi);
		return 1;
	}
	index = get_cmd_hash(key);
	hi->next = hash_cmd[index];
	hash_cmd[index] = hi;

	return 0;
}

/**
 * This Routine does traditional hash lookup on message hash.
 * @par rc Result code (key) which is going to be translated
 * @ret Appropriate message (value)
 */
static char *msg_hash_lookup(msg_hash_item *hash_msg[], int rc)
{
	msg_hash_item	*hi;

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
 * This Routine does traditional hash lookup on command hash table.
 * @par key Command name
 * @ret Command type
 */
static epp_command_type
cmd_hash_lookup(cmd_hash_item *hash_cmd[], const char *key)
{
	cmd_hash_item	*hi;

	assert(hash_cmd != NULL);

	/* iterate through hash chain */
	for (hi = hash_cmd[get_cmd_hash(key)]; hi != NULL; hi = hi->next) {
		if (!strncmp(hi->key, key, 4)) break;
	}

	/* did we find anything? */
	if (hi) return hi->val;

	return EPP_UNKNOWN_CMD;
}

/**
 * Function frees all items in message hash table.
 */
static void
msg_hash_clean(msg_hash_item *hash_msg[])
{
	msg_hash_item	*tmp;
	int	i;

	assert(hash_msg != NULL);

	for (i = 0; i < HASH_SIZE_MSG; i++) {
		while (hash_msg[i]) {
			tmp = hash_msg[i]->next;
			free(hash_msg[i]->msg);
			free(hash_msg[i]);
			hash_msg[i] = tmp;
		}
	}
}

/**
 * Function frees all items in command hash table.
 */
static void
cmd_hash_clean(cmd_hash_item *hash_cmd[])
{
	cmd_hash_item	*tmp;
	int	i;

	assert(hash_cmd != NULL);

	for (i = 0; i < HASH_SIZE_CMD; i++) {
		while (hash_cmd[i]) {
			tmp = hash_cmd[i]->next;
			free(hash_cmd[i]->key);
			free(hash_cmd[i]);
			hash_cmd[i] = tmp;
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

	/* initialize message hash table */
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

	/* initialize command hash table */
	rc = 0;
	rc |= cmd_hash_insert(globs->hash_cmd, "login", EPP_RED_LOGIN);
	rc |= cmd_hash_insert(globs->hash_cmd, "logout", EPP_RED_LOGOUT);
	rc |= cmd_hash_insert(globs->hash_cmd, "check", EPP_RED_CHECK);
	rc |= cmd_hash_insert(globs->hash_cmd, "info", EPP_RED_INFO);
	rc |= cmd_hash_insert(globs->hash_cmd, "poll", EPP_RED_POLL);
	rc |= cmd_hash_insert(globs->hash_cmd, "transfer", EPP_RED_TRANSFER);
	rc |= cmd_hash_insert(globs->hash_cmd, "create", EPP_RED_CREATE);
	rc |= cmd_hash_insert(globs->hash_cmd, "delete", EPP_RED_DELETE);
	rc |= cmd_hash_insert(globs->hash_cmd, "renew", EPP_RED_RENEW);
	rc |= cmd_hash_insert(globs->hash_cmd, "update", EPP_RED_UPDATE);
	if (rc) {
		/* error has been spotted */
		msg_hash_clean(globs->hash_msg);
		cmd_hash_clean(globs->hash_cmd);
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
	assert(globs->hash_cmd != NULL);

	xmlSchemaFree(globs->schema);
	msg_hash_clean(globs->hash_msg);
	cmd_hash_clean(globs->hash_cmd);
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
		msg_hash_item **hash_msg,
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
		struct circ_list	*item;
		int	i;

		if ((cdata->un.login.objuri = malloc(sizeof *item)) == NULL)
		{
			cdata->rc = 2400;
			cdata->type = EPP_DUMMY;
			xmlXPathFreeObject(xpathObj);
			return;
		}
		CL_NEW(cdata->un.login.objuri);
		for (i = 0; i < nodeset->nodeNr; i++) {
			/* allocate new item */
			if ((item = malloc(sizeof *item)) == NULL) {
				cdata->rc = 2400;
				cdata->type = EPP_DUMMY;
				xmlXPathFreeObject(xpathObj);
				CL_FOREACH(cdata->un.login.objuri)
					free(cdata->un.login.objuri->content);
				CL_PURGE(cdata->un.login.objuri);
				return;
			}
			node = nodeset->nodeTab[i];
			str = xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
			/* enqueue objuri to list */
			item->content = (char *) str;
			CL_ADD(cdata->un.login.objuri, item);
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
		struct circ_list	*item;
		int	i;

		if ((cdata->un.login.exturi = malloc(sizeof *item)) == NULL) {
			cdata->rc = 2400;
			cdata->type = EPP_DUMMY;
			xmlXPathFreeObject(xpathObj);
			return;
		}
		CL_NEW(cdata->un.login.exturi);
		for (i = 0; i < nodeset->nodeNr; i++) {
			/* allocate new item */
			if ((item = malloc(sizeof *item)) == NULL) {
				cdata->rc = 2400;
				cdata->type = EPP_DUMMY;
				xmlXPathFreeObject(xpathObj);
				CL_FOREACH(cdata->un.login.exturi)
					free(cdata->un.login.exturi->content);
				CL_PURGE(cdata->un.login.exturi);
				return;
			}
			node = nodeset->nodeTab[i];
			str = xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
			/* enqueue exturi to list */
			item->content = (char *) str;
			CL_ADD(cdata->un.login.exturi, item);
		}
	}
	xmlXPathFreeObject(xpathObj);

	cdata->type = EPP_LOGIN;
	return;
}

/**
 * <check> parser for domain and contact object.
 * data in:
 *   - names of objects to be checked
 */
static void
parse_check(
		int session,
		xmlDocPtr doc,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	xmlXPathObjectPtr	xpathObj;
	xmlNodeSetPtr	nodeset;
	xmlNode	*node;
	stringbool	*strbool;
	epp_object_type	obj_type;
	struct circ_list	*item;
	int	i;

	/* check if the user is logged in */
	if (session == 0) {
		cdata->type = EPP_DUMMY;
		cdata->rc = 2002;
		return;
	}

	/* get object type - contact or domain */
	xpathObj = xmlXPathEvalExpression(BAD_CAST
			"/epp:epp/epp:command/epp:check/contact:check",
			xpathCtx);
	if (xpathObj == NULL) {
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	if (xpathObj->nodesetval == NULL || xpathObj->nodesetval->nodeNr == 0) {
		xmlXPathFreeObject(xpathObj);
		xpathObj = xmlXPathEvalExpression(BAD_CAST
				"/epp:epp/epp:command/epp:check/domain:check",
				xpathCtx);
		if (xpathObj == NULL) {
			cdata->rc = 2400;
			cdata->type = EPP_DUMMY;
			return;
		}
		if (xpathObj->nodesetval == NULL || xpathObj->nodesetval->nodeNr == 0) {
			/* unexpected object type */
			xmlXPathFreeObject(xpathObj);
			cdata->rc = 2000;
			cdata->type = EPP_DUMMY;
		}
		/* object is domain */
		else obj_type = EPP_DOMAIN;
	}
	/* object is contact */
	else obj_type = EPP_CONTACT;
	xmlXPathFreeObject(xpathObj);

	/*  --- code length optimization ---
	 *  since contact and domain <check> have the same structure and the
	 *  only difference is in names of two xml tags, the code for passing
	 *  is mostly shared
	 */
	if (obj_type == EPP_CONTACT)
		xpathObj = xmlXPathEvalExpression(
			BAD_CAST "/epp:epp/epp:command/epp:check/contact:check/contact:id",
			xpathCtx);
	else
		xpathObj = xmlXPathEvalExpression(
			BAD_CAST "/epp:epp/epp:command/epp:check/domain:check/domain:name",
			xpathCtx);
	if (xpathObj == NULL) {
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	nodeset = xpathObj->nodesetval;
	assert(nodeset && nodeset->nodeNr > 0);

	if ((cdata->un.check.idbools = malloc(sizeof *item)) == NULL) {
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		xmlXPathFreeObject(xpathObj);
		return;
	}
	CL_NEW(cdata->un.check.idbools);
	for (i = 0; i < nodeset->nodeNr; i++) {
		/* allocate new string list item allocate new string-bool item */
		if (((strbool = malloc(sizeof *strbool)) == NULL) ||
			((item = malloc(sizeof *item)) == NULL))
		{
			if (item == NULL) free(strbool);
			cdata->rc = 2400;
			cdata->type = EPP_DUMMY;
			xmlXPathFreeObject(xpathObj);
			/* free so far allocated items */
			CL_FOREACH(cdata->un.check.idbools) {
				free(((stringbool *)
							cdata->un.check.idbools->content)->string);
				free(cdata->un.check.idbools->content);
			}
			CL_PURGE(cdata->un.check.idbools);
			return;
		}
		node = nodeset->nodeTab[i];
		/* enqueue contact id to list */
		strbool->string = xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
		strbool->boolean = 0;
		item->content = (void *) strbool;
		CL_ADD(cdata->un.check.idbools, item);
	}
	xmlXPathFreeObject(xpathObj);

	if (obj_type == EPP_CONTACT) cdata->type = EPP_CHECK_CONTACT;
	else cdata->type = EPP_CHECK_DOMAIN;
	return;
}

/**
 * <info> parser for domain and contact object.
 * Ignores authinfo.
 */
static void
parse_info(
		int session,
		xmlDocPtr doc,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	xmlXPathObjectPtr	xpathObj;
	xmlNodeSetPtr	nodeset;
	xmlNode	*node;
	epp_object_type	obj_type;

	/* check if the user is logged in */
	if (session == 0) {
		cdata->type = EPP_DUMMY;
		cdata->rc = 2002;
		return;
	}

	/* get object type - contact or domain */
	xpathObj = xmlXPathEvalExpression(BAD_CAST
			"/epp:epp/epp:command/epp:info/contact:info",
			xpathCtx);
	if (xpathObj == NULL) {
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	if (xpathObj->nodesetval == NULL || xpathObj->nodesetval->nodeNr == 0) {
		xmlXPathFreeObject(xpathObj);
		xpathObj = xmlXPathEvalExpression(BAD_CAST
				"/epp:epp/epp:command/epp:info/domain:info",
				xpathCtx);
		if (xpathObj == NULL) {
			cdata->rc = 2400;
			cdata->type = EPP_DUMMY;
			return;
		}
		if (xpathObj->nodesetval == NULL || xpathObj->nodesetval->nodeNr == 0) {
			/* unexpected object type */
			xmlXPathFreeObject(xpathObj);
			cdata->rc = 2000;
			cdata->type = EPP_DUMMY;
		}
		/* object is domain */
		else obj_type = EPP_DOMAIN;
	}
	/* object is contact */
	else obj_type = EPP_CONTACT;
	xmlXPathFreeObject(xpathObj);

	/*  --- code length optimization ---
	 *  since contact and domain <info> have the same structure and the
	 *  only difference is in names of two xml tags, the code for passing
	 *  is mostly shared
	 */
	if (obj_type == EPP_CONTACT)
		xpathObj = xmlXPathEvalExpression(
			BAD_CAST "/epp:epp/epp:command/epp:info/contact:info/contact:id",
			xpathCtx);
	else
		xpathObj = xmlXPathEvalExpression(
			BAD_CAST "/epp:epp/epp:command/epp:info/domain:info/domain:name",
			xpathCtx);
	if (xpathObj == NULL) {
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	nodeset = xpathObj->nodesetval;
	assert(nodeset && nodeset->nodeNr == 1);

	node = nodeset->nodeTab[0];
	if (obj_type == EPP_CONTACT)
		cdata->un.info_contact.id =
			xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
	else
		cdata->un.info_domain.name =
			xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
	xmlXPathFreeObject(xpathObj);

	if (obj_type == EPP_CONTACT) cdata->type = EPP_INFO_CONTACT;
	else cdata->type = EPP_INFO_DOMAIN;
	return;
}

/**
 * <poll> parser.
 */
static void
parse_poll(
		int session,
		xmlDocPtr doc,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	xmlXPathObjectPtr	xpathObj;
	xmlNodeSetPtr	nodeset;
	xmlNode	*node;
	stringbool	*strbool;
	struct circ_list	*item;
	int	i;

	/* check if the user is logged in */
	if (session == 0) {
		cdata->type = EPP_DUMMY;
		cdata->rc = 2002;
		return;
	}

	/* get poll type - request or acknoledge */
	xpathObj = xmlXPathEvalExpression(BAD_CAST
			"/epp:epp/epp:command/epp:poll[@op='req']",
			xpathCtx);
	if (xpathObj == NULL) {
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	if (xpathObj->nodesetval == NULL || xpathObj->nodesetval->nodeNr == 0) {
		xmlXPathFreeObject(xpathObj);
		xpathObj = xmlXPathEvalExpression(BAD_CAST
				"/epp:epp/epp:command/epp:poll[@op='ack']",
				xpathCtx);
		if (xpathObj == NULL) {
			cdata->rc = 2400;
			cdata->type = EPP_DUMMY;
			return;
		}
		if (xpathObj->nodesetval == NULL || xpathObj->nodesetval->nodeNr == 0) {
			/* unexpected attr value */
			xmlXPathFreeObject(xpathObj);
			cdata->rc = 2000;
			cdata->type = EPP_DUMMY;
		}
		/* it is request */
		else {
			xmlXPathFreeObject(xpathObj);
			cdata->type = EPP_POLL_REQ;
			return;
		}
	}
	/* it is acknoledge */

	/* XXX get value of attr msgID */

	xmlXPathFreeObject(xpathObj);
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

/**
 * This routine is same for contact and domain object. Except small
 * peaces the code is same. The fourth parameter is object type.
 */
static gen_status
epp_gen_check(
		void *globs,
		epp_command_data *cdata,
		char **result,
		epp_object_type obj_type)
{
	xmlBufferPtr buf;
	xmlTextWriterPtr writer;
	char	*str;
	char	res_code[5];
	stringbool	*strbool;
	char	error_seen = 1;
	const char	*no = "0";
	const char	*yes = "1";

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

	// epp traditional part of response
	START_ELEMENT(writer, simple_err, "response");
	START_ELEMENT(writer, simple_err, "result");
	snprintf(res_code, 5, "%d", cdata->rc);
	str = msg_hash_lookup(( (epp_xml_globs *) globs)->hash_msg, cdata->rc);
	WRITE_ATTRIBUTE(writer, simple_err, "code", res_code);
	WRITE_ELEMENT(writer, simple_err, "msg", str);
	END_ELEMENT(writer, simple_err);

	// specific part of response
	START_ELEMENT(writer, simple_err, "resData");
	if (obj_type == EPP_CONTACT) {
		START_ELEMENT(writer, simple_err, "contact:chkData");
		WRITE_ATTRIBUTE(writer, simple_err, "xmlns:contact", NS_CONTACT);
		WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_CONTACT);
	}
	else {
		START_ELEMENT(writer, simple_err, "domain:chkData");
		WRITE_ATTRIBUTE(writer, simple_err, "xmlns:domain", NS_DOMAIN);
		WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_DOMAIN);
	}
	CL_RESET(cdata->un.check.idbools);
	CL_FOREACH(cdata->un.check.idbools) {
		strbool = (stringbool *) cdata->un.check.idbools->content;
		if (obj_type == EPP_CONTACT) {
			START_ELEMENT(writer, simple_err, "contact:cd");
			WRITE_ELEMENT(writer, simple_err, "contact:id", strbool->string);
		}
		else {
			START_ELEMENT(writer, simple_err, "domain:cd");
			WRITE_ELEMENT(writer, simple_err, "domain:name", strbool->string);
		}
		WRITE_ATTRIBUTE(writer, simple_err, "avail",
				(strbool->boolean) ? yes : no);
		END_ELEMENT(writer, simple_err);
	}
	END_ELEMENT(writer, simple_err);

	// traditional end of response
	START_ELEMENT(writer, simple_err, "trID");
	if (cdata->clTRID)
		WRITE_ELEMENT(writer, simple_err, "clTRID", cdata->clTRID);
	WRITE_ELEMENT(writer, simple_err, "svTRID", cdata->svTRID);
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

gen_status
epp_gen_check_contact(void *globs, epp_command_data *cdata, char **result)
{
	assert(globs != NULL);
	assert(cdata != NULL);
	return epp_gen_check(globs, cdata, result, EPP_CONTACT);
}

gen_status
epp_gen_check_domain(void *globs, epp_command_data *cdata, char **result)
{
	assert(globs != NULL);
	assert(cdata != NULL);
	return epp_gen_check(globs, cdata, result, EPP_DOMAIN);
}

gen_status
epp_gen_info_contact(void *xml_globs, epp_command_data *cdata, char **result);
{
	assert(globs != NULL);
	assert(cdata != NULL);
	return GEN_OK;
}

gen_status
epp_gen_info_domain(void *xml_globs, epp_command_data *cdata, char **result);
{
	assert(globs != NULL);
	assert(cdata != NULL);
	return GEN_OK;
}

gen_status
epp_gen_poll_req(void *xml_globs, epp_command_data *cdata, char **result);
{
	assert(globs != NULL);
	assert(cdata != NULL);
	return GEN_OK;
}

gen_status
epp_gen_poll_ack(void *xml_globs, epp_command_data *cdata, char **result);
{
	assert(globs != NULL);
	assert(cdata != NULL);
	return GEN_OK;
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
	xmlNodeSetPtr	nodeset;
	epp_red_command_type	cmd;
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
	if (xmlXPathRegisterNs(xpathCtx, BAD_CAST "contact", BAD_CAST NS_CONTACT)) {
		xmlXPathFreeContext(xpathCtx);
		xmlFreeDoc(doc);
		return PARSER_EINTERNAL;
	}
	if (xmlXPathRegisterNs(xpathCtx, BAD_CAST "domain", BAD_CAST NS_DOMAIN)) {
		xmlXPathFreeContext(xpathCtx);
		xmlFreeDoc(doc);
		return PARSER_EINTERNAL;
	}

	/* is it a command? This question must be answered first */
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
		/* we cannot leave clTRID NULL because of corba */
		cdata->clTRID = xmlStrdup("");
	}
	xmlXPathFreeObject(xpathObj);

	/*
	 * command recognition part
	 */
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

	/* command lookup through hash table .. huraaa :) */
	cmd = cmd_hash_lookup(globs->hash_cmd, nodeset->nodeTab[0]->name);
	xmlXPathFreeObject(xpathObj);

	switch (cmd) {
		case EPP_RED_LOGIN:
			parse_login(session, doc, xpathCtx, cdata);
			break;
		case EPP_RED_LOGOUT:
			/*
			 * logout is so simple that we don't use dedicated parsing function
			 */
			if (session == 0) {
				cdata->rc = 2002;
				cdata->type = EPP_DUMMY;
			}
			else {
				cdata->type = EPP_LOGOUT;
			}
			break;
		case EPP_RED_CHECK:
			parse_check(session, doc, xpathCtx, cdata);
			break;
		case EPP_RED_INFO:
			parse_info(session, doc, xpathCtx, cdata);
			break;
		case EPP_RED_POLL:
			parse_poll(session, doc, xpathCtx, cdata);
			break;
		case EPP_RED_TRANSFER:
		case EPP_RED_CREATE:
		case EPP_RED_DELETE:
		case EPP_RED_RENEW:
		case EPP_RED_UPDATE:
		case EPP_RED_UNKNOWN_CMD:
		default:
			cdata->rc = 2000;
			cdata->type = EPP_DUMMY;
			break;
	}

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
			/* destroy objuri list */
			CL_RESET(cdata->un.login.objuri);
			CL_FOREACH(cdata->un.login.objuri)
				free(cdata->un.login.objuri->content);
			CL_PURGE(cdata->un.login.objuri);
			/* destroy exturi list */
			CL_RESET(cdata->un.login.exturi);
			CL_FOREACH(cdata->un.login.exturi)
				free(cdata->un.login.exturi->content);
			CL_PURGE(cdata->un.login.exturi);
			break;
		case EPP_CHECK_CONTACT:
		case EPP_CHECK_DOMAIN:
			/* destroy ids and bools */
			CL_RESET(cdata->un.check.idbools);
			CL_FOREACH(cdata->un.check.idbools) {
				free(( (stringbool *)
							cdata->un.check.idbools->content)->string);
				free(cdata->un.check.idbools->content);
			}
			CL_PURGE(cdata->un.check.idbools);
		case EPP_INFO_CONTACT:
			free(cdata->un.info_contact.id);
			break;
		case EPP_INFO_DOMAIN:
			free(cdata->un.info_domain.name);
			break;
		case EPP_POLL_REQ:
		case EPP_POLL_ACK:
		case EPP_LOGOUT:
		case EPP_DUMMY:
		default:
			break;
	}
}
