/*
 * Copyright statement
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
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
#define NS_CONTACT	"http://www.nic.cz/xml/epp/contact-1.0"
#define NS_DOMAIN	"http://www.nic.cz/xml/epp/domain-1.0"
#define NS_NSSET	"http://www.nic.cz/xml/epp/nsset-1.0"
#define LOC_EPP	NS_EPP " epp-1.0.xsd"
#define LOC_CONTACT	NS_CONTACT " contact-1.0.xsd"
#define LOC_DOMAIN	NS_DOMAIN " domain-1.0.xsd"
#define LOC_NSSET	NS_NSSET " nsset-1.0.xsd"
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
		if (xmlTextWriterStartElement(writer, BAD_CAST (elem)) < 0) goto err_handler;	\
	}while(0)

#define WRITE_ELEMENT(writer, err_handler, elem, str)	\
	do {										\
		if (((char *) str)[0] != '\0')						\
			if (xmlTextWriterWriteElement(writer, BAD_CAST (elem), BAD_CAST (str)) < 0) goto err_handler;	\
	}while(0)

#define WRITE_STRING(writer, err_handler, str)		\
	do {										\
		if (xmlTextWriterWriteString(writer, BAD_CAST (str)) < 0) goto err_handler;	\
	}while(0)

#define WRITE_ATTRIBUTE(writer, err_handler, attr_name, attr_value)	\
	do {										\
		if (xmlTextWriterWriteAttribute(writer, BAD_CAST (attr_name), BAD_CAST (attr_value)) < 0) goto err_handler;	\
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
 * Function for converting number of seconds from 1970 ... to string
 * formated in rfc 3339 way. This is required by EPP protocol.
 * @par date Number of seconds since ...
 * @par str buffer allocated for date (should be at least 25 bytes long)
 */
static void get_rfc3339_date(long long date, char *str)
{
	struct tm t;
	time_t	time = date;

	/* we will leave empty buffer if gmtime failes */
	if (gmtime_r(&time, &t) == NULL) {
		str[0] = '\0';
		return;
	}
	snprintf(str, 25, "%04d-%02d-%02dT%02d:%02d:%02d.0Z",
			1900 + t.tm_year, t.tm_mon, t.tm_mday,
			t.tm_hour, t.tm_min, t.tm_sec);
}

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
epp_gen_greeting(const char *svid, char **greeting)
{
	xmlBufferPtr buf;
	xmlTextWriterPtr writer;
	char	strdate[50];
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

	START_DOCUMENT(writer, greeting_err);
			
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
	WRITE_ELEMENT(writer, greeting_err, "version", "1.0");
	WRITE_ELEMENT(writer, greeting_err, "lang", "en");
	END_ELEMENT(writer, greeting_err); /* svcMenu */
	START_ELEMENT(writer, greeting_err, "svcs");
	WRITE_ELEMENT(writer, greeting_err, "objURI", NS_CONTACT);
	WRITE_ELEMENT(writer, greeting_err, "objURI", NS_DOMAIN);
	WRITE_ELEMENT(writer, greeting_err, "objURI", NS_NSSET);
	END_ELEMENT(writer, greeting_err); /* svcs */
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
 * Purpose of this function is to make things little bit easier
 * when generating simple frames, containing only code and message.
 * This is used mostly for generating error frames, but also for login
 * and logout responses.
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

	*result = strdup((char *) buf->content);
	xmlBufferFree(buf);
	return GEN_OK;
}

/**
 * Login parser.
 * checks:
 *   - language supported
 *   - correct epp version
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

	/* ok, checking done. now get input parameters for corba function call */
	if ((cdata->in = calloc(1, sizeof (*cdata->in))) == NULL) {
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	xpathObj = xmlXPathEvalExpression(
		BAD_CAST "/epp:epp/epp:command/epp:login/epp:clID", xpathCtx);
	if (xpathObj == NULL) {
		free(cdata->in);
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	nodeset = xpathObj->nodesetval;
	assert(nodeset->nodeNr == 1);
	node = nodeset->nodeTab[0];
	cdata->in->login.clID = (char *)
			xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
	xmlXPathFreeObject(xpathObj);

	/* pw */
	xpathObj = xmlXPathEvalExpression(
		BAD_CAST "/epp:epp/epp:command/epp:login/epp:pw", xpathCtx);
	if (xpathObj == NULL) {
		free(cdata->in);
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	nodeset = xpathObj->nodesetval;
	assert(nodeset->nodeNr == 1);
	node = nodeset->nodeTab[0];
	cdata->in->login.pw = (char *)
			xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
	xmlXPathFreeObject(xpathObj);

	/* newPW (optional) */
	xpathObj = xmlXPathEvalExpression(
		BAD_CAST "/epp:epp/epp:command/epp:login/epp:newPW", xpathCtx);
	if (xpathObj == NULL) {
		free(cdata->in);
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	nodeset = xpathObj->nodesetval;
	if (nodeset && nodeset->nodeNr) {
		node = nodeset->nodeTab[0];
		cdata->in->login.newPW = (char *)
			xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
	}
	else {
		/* newPW cannot stay NULL */
		cdata->in->login.newPW = (char *) xmlStrdup((xmlChar *) "");
	}
	xmlXPathFreeObject(xpathObj);

	/* objects the client wants to work with */
	xpathObj = xmlXPathEvalExpression(BAD_CAST
		"/epp:epp/epp:command/epp:login/epp:svcs/epp:objURI",
		xpathCtx);
	if (xpathObj == NULL) {
		free(cdata->in);
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	nodeset = xpathObj->nodesetval;
	if (nodeset != NULL) {
		struct circ_list	*item;
		int	i;

		if ((cdata->in->login.objuri = malloc(sizeof *item)) == NULL)
		{
			free(cdata->in);
			cdata->rc = 2400;
			cdata->type = EPP_DUMMY;
			xmlXPathFreeObject(xpathObj);
			return;
		}
		CL_NEW(cdata->in->login.objuri);
		for (i = 0; i < nodeset->nodeNr; i++) {
			/* allocate new item */
			if ((item = malloc(sizeof *item)) == NULL) {
				CL_FOREACH(cdata->in->login.objuri)
					free(CL_CONTENT(cdata->in->login.objuri));
				CL_PURGE(cdata->in->login.objuri);
				free(cdata->in);
				cdata->rc = 2400;
				cdata->type = EPP_DUMMY;
				xmlXPathFreeObject(xpathObj);
				return;
			}
			node = nodeset->nodeTab[i];
			str = xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
			/* enqueue objuri to list */
			CL_CONTENT(item) = (char *) str;
			CL_ADD(cdata->in->login.objuri, item);
		}
	}
	xmlXPathFreeObject(xpathObj);

	/* extensions the client wants to work with */
	xpathObj = xmlXPathEvalExpression(BAD_CAST
		"/epp:epp/epp:command/epp:login/epp:svcs/epp:extURI",
		xpathCtx);
	if (xpathObj == NULL) {
		free(cdata->in);
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	nodeset = xpathObj->nodesetval;
	if (nodeset != NULL) {
		struct circ_list	*item;
		int	i;

		if ((cdata->in->login.exturi = malloc(sizeof *item)) == NULL) {
			free(cdata->in);
			cdata->rc = 2400;
			cdata->type = EPP_DUMMY;
			xmlXPathFreeObject(xpathObj);
			return;
		}
		CL_NEW(cdata->in->login.exturi);
		for (i = 0; i < nodeset->nodeNr; i++) {
			/* allocate new item */
			if ((item = malloc(sizeof *item)) == NULL) {
				xmlXPathFreeObject(xpathObj);
				CL_FOREACH(cdata->in->login.exturi)
					free(CL_CONTENT(cdata->in->login.exturi));
				CL_PURGE(cdata->in->login.exturi);
				free(cdata->in);
				cdata->rc = 2400;
				cdata->type = EPP_DUMMY;
				return;
			}
			node = nodeset->nodeTab[i];
			str = xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
			/* enqueue exturi to list */
			CL_CONTENT(item) = (char *) str;
			CL_ADD(cdata->in->login.exturi, item);
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
	epp_object_type	obj_type;
	struct circ_list	*item;
	int	i;

	/* check if the user is logged in */
	if (session == 0) {
		cdata->type = EPP_DUMMY;
		cdata->rc = 2002;
		return;
	}

	/* get object type - contact, domain or nsset */
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
			xmlXPathFreeObject(xpathObj);
			xpathObj = xmlXPathEvalExpression(BAD_CAST
					"/epp:epp/epp:command/epp:check/nsset:check",
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
				return;
			}
			/* object is a nsset */
			else obj_type = EPP_NSSET;
		}
		/* object is a domain */
		else obj_type = EPP_DOMAIN;
	}
	/* object is contact */
	else obj_type = EPP_CONTACT;
	xmlXPathFreeObject(xpathObj);

	/*  --- code length optimization ---
	 *  since contact, domain and nsset <check> have the same structure and the
	 *  only difference is in names of two xml tags, the code for passing
	 *  is mostly shared
	 */
	if (obj_type == EPP_CONTACT) {
		cdata->type = EPP_CHECK_CONTACT;
		xpathObj = xmlXPathEvalExpression(
			BAD_CAST "/epp:epp/epp:command/epp:check/contact:check/contact:id",
			xpathCtx);
	}
	else if (obj_type == EPP_DOMAIN) {
		cdata->type = EPP_CHECK_DOMAIN;
		xpathObj = xmlXPathEvalExpression(
			BAD_CAST "/epp:epp/epp:command/epp:check/domain:check/domain:name",
			xpathCtx);
	}
	else {
		assert(obj_type == EPP_NSSET);
		cdata->type = EPP_CHECK_NSSET;
		xpathObj = xmlXPathEvalExpression(
			BAD_CAST "/epp:epp/epp:command/epp:check/nsset:check/nsset:id",
			xpathCtx);
	}
	if (xpathObj == NULL) {
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	nodeset = xpathObj->nodesetval;
	assert(nodeset && nodeset->nodeNr > 0);

	if ((cdata->in = calloc(1, sizeof (*cdata->in))) == NULL) {
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		xmlXPathFreeObject(xpathObj);
		return;
	}
	if ((cdata->in->check.ids = malloc(sizeof *item)) == NULL) {
		xmlXPathFreeObject(xpathObj);
		free(cdata->in);
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	CL_NEW(cdata->in->check.ids);
	for (i = 0; i < nodeset->nodeNr; i++) {
		/* allocate new string list item */
		if ((item = malloc(sizeof *item)) == NULL)
		{
			xmlXPathFreeObject(xpathObj);
			/* free so far allocated items */
			CL_FOREACH(cdata->in->check.ids)
				free(CL_CONTENT(cdata->in->check.ids));
			CL_PURGE(cdata->in->check.ids);
			free(cdata->in);
			cdata->rc = 2400;
			cdata->type = EPP_DUMMY;
			return;
		}
		node = nodeset->nodeTab[i];
		/* enqueue contact id to list */
		CL_CONTENT(item) = (void *)
			xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
		CL_ADD(cdata->in->check.ids, item);
	}
	xmlXPathFreeObject(xpathObj);

	return;
}

/**
 * <info> parser for domain, contact and nsset object.
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
			xmlXPathFreeObject(xpathObj);
			xpathObj = xmlXPathEvalExpression(BAD_CAST
					"/epp:epp/epp:command/epp:info/nsset:info",
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
				return;
			}
			/* object is domain */
			else obj_type = EPP_NSSET;
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
	if (obj_type == EPP_CONTACT) {
		cdata->type = EPP_INFO_CONTACT;
		xpathObj = xmlXPathEvalExpression(
			BAD_CAST "/epp:epp/epp:command/epp:info/contact:info/contact:id",
			xpathCtx);
	}
	else if (obj_type == EPP_DOMAIN) {
		cdata->type = EPP_INFO_DOMAIN;
		xpathObj = xmlXPathEvalExpression(
			BAD_CAST "/epp:epp/epp:command/epp:info/domain:info/domain:name",
			xpathCtx);
	}
	else {
		assert(obj_type == EPP_NSSET);
		cdata->type = EPP_INFO_NSSET;
		xpathObj = xmlXPathEvalExpression(
			BAD_CAST "/epp:epp/epp:command/epp:info/nsset:info/nsset:id",
			xpathCtx);
	}
	if (xpathObj == NULL) {
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	nodeset = xpathObj->nodesetval;
	assert(nodeset && nodeset->nodeNr == 1);

	if ((cdata->in = calloc(1, sizeof (*cdata->in))) == NULL) {
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		xmlXPathFreeObject(xpathObj);
		return;
	}
	node = nodeset->nodeTab[0];
	cdata->in->info.id = (char *)
		xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
	xmlXPathFreeObject(xpathObj);

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
	xmlChar	*str;

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
			return;
		}
		/* it is acknoledge */
		if ((cdata->in = calloc(1, sizeof (*cdata->in))) == NULL) {
			xmlXPathFreeObject(xpathObj);
			cdata->rc = 2400;
			cdata->type = EPP_DUMMY;
			return;
		}
		/* get value of attr msgID */
		str = xmlGetNsProp(xpathObj->nodesetval->nodeTab[0],
				BAD_CAST "msgID", BAD_CAST NS_EPP);
		/* conversion is safe, if str in not a number, validator catches it */
		cdata->in->poll_ack.msgid = atoi((char *) str);
		xmlFree(str);
		cdata->type = EPP_POLL_ACK;
	}
	/* it is request */
	else cdata->type = EPP_POLL_REQ;

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
 * This routine is same for contact, domain and nsset object except small
 * peaces of the code. The fourth parameter is object type.
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
	char	error_seen = 1;

	/* catch error responses */
	if (cdata->rc != 1000) {
		simple_response(((epp_xml_globs *) globs)->hash_msg,
				cdata->rc, cdata->clTRID, cdata->svTRID, result);
		return GEN_OK;
	}

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
	else if (obj_type == EPP_DOMAIN) {
		START_ELEMENT(writer, simple_err, "domain:chkData");
		WRITE_ATTRIBUTE(writer, simple_err, "xmlns:domain", NS_DOMAIN);
		WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_DOMAIN);
	}
	else {
		assert(obj_type == EPP_NSSET);
		START_ELEMENT(writer, simple_err, "nsset:chkData");
		WRITE_ATTRIBUTE(writer, simple_err, "xmlns:nsset", NS_NSSET);
		WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_NSSET);
	}
	CL_RESET(cdata->in->check.ids);
	CL_RESET(cdata->out->check.bools);
	CL_FOREACH(cdata->in->check.ids) {
		CL_NEXT(cdata->out->check.bools);
		if (obj_type == EPP_CONTACT) {
			START_ELEMENT(writer, simple_err, "contact:cd");
			START_ELEMENT(writer, simple_err, "contact:id");
		}
		else if (obj_type == EPP_DOMAIN) {
			START_ELEMENT(writer, simple_err, "domain:cd");
			START_ELEMENT(writer, simple_err, "domain:name");
		}
		else {
			START_ELEMENT(writer, simple_err, "nsset:cd");
			START_ELEMENT(writer, simple_err, "nsset:name");
		}
		WRITE_ATTRIBUTE(writer, simple_err, "avail",
				CL_CONTENT(cdata->out->check.bools) ? "1" : "0");
		WRITE_STRING(writer, simple_err, CL_CONTENT(cdata->in->check.ids));
		END_ELEMENT(writer, simple_err);
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

	*result = strdup((char *) buf->content);
	xmlBufferFree(buf);
	return GEN_OK;
}

gen_status
epp_gen_check_contact(void *globs, epp_command_data *cdata, char **result)
{
	assert(globs != NULL);
	assert(cdata != NULL);
	assert(cdata->out != NULL);
	return epp_gen_check(globs, cdata, result, EPP_CONTACT);
}

gen_status
epp_gen_check_domain(void *globs, epp_command_data *cdata, char **result)
{
	assert(globs != NULL);
	assert(cdata != NULL);
	assert(cdata->out != NULL);
	return epp_gen_check(globs, cdata, result, EPP_DOMAIN);
}

gen_status
epp_gen_check_nsset(void *globs, epp_command_data *cdata, char **result)
{
	assert(globs != NULL);
	assert(cdata != NULL);
	assert(cdata->out != NULL);
	return epp_gen_check(globs, cdata, result, EPP_NSSET);
}

gen_status
epp_gen_info_contact(void *globs, epp_command_data *cdata, char **result)
{
	epp_postalInfo	*pi;
	epp_discl	*discl;
	xmlBufferPtr buf;
	xmlTextWriterPtr writer;
	char	*str;
	char	strbuf[25]; /* is enough even for 64-bit number and for a date */
	char	error_seen = 1;

	assert(globs != NULL);
	assert(cdata != NULL);
	assert(cdata->out != NULL);

	/* catch error responses */
	if (cdata->rc != 1000) {
		simple_response(((epp_xml_globs *) globs)->hash_msg,
				cdata->rc, cdata->clTRID, cdata->svTRID, result);
		return GEN_OK;
	}

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
	snprintf(strbuf, 5, "%d", cdata->rc);
	str = msg_hash_lookup(( (epp_xml_globs *) globs)->hash_msg, cdata->rc);
	WRITE_ATTRIBUTE(writer, simple_err, "code", strbuf);
	WRITE_ELEMENT(writer, simple_err, "msg", str);
	END_ELEMENT(writer, simple_err);

	// specific part of response
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
	WRITE_ELEMENT(writer, simple_err, "contact:street", pi->street1);
	WRITE_ELEMENT(writer, simple_err, "contact:street", pi->street2);
	WRITE_ELEMENT(writer, simple_err, "contact:street", pi->street3);
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
	get_rfc3339_date(cdata->out->info_contact.upDate, strbuf);
	WRITE_ELEMENT(writer, simple_err, "contact:upDate", strbuf);
	get_rfc3339_date(cdata->out->info_contact.trDate, strbuf);
	WRITE_ELEMENT(writer, simple_err, "contact:trDate", strbuf);
	START_ELEMENT(writer, simple_err, "contact:authInfo");
	WRITE_ELEMENT(writer, simple_err, "contact:pw",
			cdata->out->info_contact.authInfo);
	END_ELEMENT(writer, simple_err); /* auth info */
	/* disclose section */
	discl = cdata->out->info_contact.discl;
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
	END_ELEMENT(writer, simple_err); /* infdata */
	END_ELEMENT(writer, simple_err); /* resdata */

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

	*result = strdup((char *) buf->content);
	xmlBufferFree(buf);
	return GEN_OK;
}

gen_status
epp_gen_info_domain(void *globs, epp_command_data *cdata, char **result)
{
	xmlBufferPtr buf;
	xmlTextWriterPtr writer;
	char	*str;
	char	strbuf[25]; /* is enough even for 64-bit number and for a date */
	char	error_seen = 1;

	assert(globs != NULL);
	assert(cdata != NULL);
	assert(cdata->out != NULL);

	/* catch error responses */
	if (cdata->rc != 1000) {
		simple_response(((epp_xml_globs *) globs)->hash_msg,
				cdata->rc, cdata->clTRID, cdata->svTRID, result);
		return GEN_OK;
	}

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
	snprintf(strbuf, 5, "%d", cdata->rc);
	str = msg_hash_lookup(( (epp_xml_globs *) globs)->hash_msg, cdata->rc);
	WRITE_ATTRIBUTE(writer, simple_err, "code", strbuf);
	WRITE_ELEMENT(writer, simple_err, "msg", str);
	END_ELEMENT(writer, simple_err);

	// specific part of response
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
		START_ELEMENT(writer, simple_err, "domain:contact");
		WRITE_ATTRIBUTE(writer, simple_err, "type", "admin");
		WRITE_STRING(writer, simple_err,
				CL_CONTENT(cdata->out->info_domain.admin));
		END_ELEMENT(writer, simple_err);
	}
	WRITE_ELEMENT(writer, simple_err, "domain:nsset",
			cdata->out->info_domain.nsset);
	WRITE_ELEMENT(writer, simple_err, "domain:clID",
			cdata->out->info_domain.clID);
	WRITE_ELEMENT(writer, simple_err, "domain:crID",
			cdata->out->info_domain.crID);
	get_rfc3339_date(cdata->out->info_domain.crDate, strbuf);
	WRITE_ELEMENT(writer, simple_err, "domain:crDate", strbuf);
	get_rfc3339_date(cdata->out->info_domain.exDate, strbuf);
	WRITE_ELEMENT(writer, simple_err, "domain:exDate", strbuf);
	WRITE_ELEMENT(writer, simple_err, "domain:upID",
			cdata->out->info_domain.upID);
	get_rfc3339_date(cdata->out->info_domain.upDate, strbuf);
	WRITE_ELEMENT(writer, simple_err, "domain:upDate", strbuf);
	get_rfc3339_date(cdata->out->info_domain.trDate, strbuf);
	WRITE_ELEMENT(writer, simple_err, "domain:trDate", strbuf);
	START_ELEMENT(writer, simple_err, "domain:authInfo");
	WRITE_ELEMENT(writer, simple_err, "domain:pw",
			cdata->out->info_domain.authInfo);
	END_ELEMENT(writer, simple_err); /* auth info */
	END_ELEMENT(writer, simple_err); /* infdata */
	END_ELEMENT(writer, simple_err); /* resdata */

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

	*result = strdup((char *) buf->content);
	xmlBufferFree(buf);
	return GEN_OK;
}

gen_status
epp_gen_info_nsset(void *globs, epp_command_data *cdata, char **result)
{
	xmlBufferPtr buf;
	xmlTextWriterPtr writer;
	char	*str;
	char	strbuf[25]; /* is enough even for 64-bit number and for a date */
	char	error_seen = 1;

	assert(globs != NULL);
	assert(cdata != NULL);
	assert(cdata->out != NULL);

	/* catch error responses */
	if (cdata->rc != 1000) {
		simple_response(((epp_xml_globs *) globs)->hash_msg,
				cdata->rc, cdata->clTRID, cdata->svTRID, result);
		return GEN_OK;
	}

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
	snprintf(strbuf, 5, "%d", cdata->rc);
	str = msg_hash_lookup(( (epp_xml_globs *) globs)->hash_msg, cdata->rc);
	WRITE_ATTRIBUTE(writer, simple_err, "code", strbuf);
	WRITE_ELEMENT(writer, simple_err, "msg", str);
	END_ELEMENT(writer, simple_err);

	// specific part of response
	START_ELEMENT(writer, simple_err, "resData");
	START_ELEMENT(writer, simple_err, "nsset:infData");
	WRITE_ATTRIBUTE(writer, simple_err, "xmlns:nsset", NS_NSSET);
	WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_NSSET);
	WRITE_ELEMENT(writer, simple_err, "nsset:id",cdata->in->info.id);
	WRITE_ELEMENT(writer, simple_err, "nsset:roid", cdata->out->info_nsset.roid);
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
	get_rfc3339_date(cdata->out->info_nsset.upDate, strbuf);
	WRITE_ELEMENT(writer, simple_err, "nsset:upDate", strbuf);
	get_rfc3339_date(cdata->out->info_nsset.trDate, strbuf);
	WRITE_ELEMENT(writer, simple_err, "nsset:trDate", strbuf);
	WRITE_ELEMENT(writer, simple_err, "nsset:authInfo",
			cdata->out->info_nsset.authInfo);
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
			END_ELEMENT(writer, simple_err); /* ns */
		}
	}
	END_ELEMENT(writer, simple_err); /* infdata */
	END_ELEMENT(writer, simple_err); /* resdata */

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

	*result = strdup((char *) buf->content);
	xmlBufferFree(buf);
	return GEN_OK;
}

gen_status
epp_gen_poll_req(void *globs, epp_command_data *cdata, char **result)
{
	xmlBufferPtr buf;
	xmlTextWriterPtr writer;
	char	*str;
	char	strbuf[25]; /* is enough even for 64-bit number and for a date */
	char	error_seen = 1;

	assert(globs != NULL);
	assert(cdata != NULL);
	assert(cdata->out != NULL);

	/* catch error responses */
	if (cdata->rc != 1301) {
		simple_response(((epp_xml_globs *) globs)->hash_msg,
				cdata->rc, cdata->clTRID, cdata->svTRID, result);
		return GEN_OK;
	}

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
	snprintf(strbuf, 5, "%d", cdata->rc);
	str = msg_hash_lookup(( (epp_xml_globs *) globs)->hash_msg, cdata->rc);
	WRITE_ATTRIBUTE(writer, simple_err, "code", strbuf);
	WRITE_ELEMENT(writer, simple_err, "msg", str);
	END_ELEMENT(writer, simple_err);

	// specific part of response
	START_ELEMENT(writer, simple_err, "msgQ");
	snprintf(strbuf, 25, "%d", cdata->out->poll_req.count);
	WRITE_ATTRIBUTE(writer, simple_err, "count", strbuf);
	snprintf(strbuf, 25, "%d", cdata->out->poll_req.msgid);
	WRITE_ATTRIBUTE(writer, simple_err, "msgid", strbuf);
	get_rfc3339_date(cdata->out->poll_req.qdate, strbuf);
	WRITE_ELEMENT(writer, simple_err, "qDate", strbuf);
	WRITE_ELEMENT(writer, simple_err, "msg", cdata->out->poll_req.msg);
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

	*result = strdup((char *) buf->content);
	xmlBufferFree(buf);
	return GEN_OK;
}

gen_status
epp_gen_poll_ack(void *globs, epp_command_data *cdata, char **result)
{
	xmlBufferPtr buf;
	xmlTextWriterPtr writer;
	char	*str;
	char	strbuf[25]; /* is enough even for 64-bit number and for a date */
	char	error_seen = 1;

	assert(globs != NULL);
	assert(cdata != NULL);
	assert(cdata->out != NULL);

	/* catch error responses */
	if (cdata->rc != 1000) {
		simple_response(((epp_xml_globs *) globs)->hash_msg,
				cdata->rc, cdata->clTRID, cdata->svTRID, result);
		return GEN_OK;
	}

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
	snprintf(strbuf, 5, "%d", cdata->rc);
	str = msg_hash_lookup(( (epp_xml_globs *) globs)->hash_msg, cdata->rc);
	WRITE_ATTRIBUTE(writer, simple_err, "code", strbuf);
	WRITE_ELEMENT(writer, simple_err, "msg", str);
	END_ELEMENT(writer, simple_err);

	// specific part of response
	START_ELEMENT(writer, simple_err, "msgQ");
	snprintf(strbuf, 25, "%d", cdata->out->poll_ack.count);
	WRITE_ATTRIBUTE(writer, simple_err, "count", strbuf);
	snprintf(strbuf, 25, "%d", cdata->out->poll_ack.msgid);
	WRITE_ATTRIBUTE(writer, simple_err, "msgid", strbuf);
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

	*result = strdup((char *) buf->content);
	xmlBufferFree(buf);
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
	if (xmlXPathRegisterNs(xpathCtx, BAD_CAST "nsset", BAD_CAST NS_NSSET)) {
		xmlXPathFreeContext(xpathCtx);
		xmlFreeDoc(doc);
		return PARSER_EINTERNAL;
	}

	/* if it is a <hello> frame, we will send greeting and return */
	xpathObj = xmlXPathEvalExpression(BAD_CAST "/epp:epp/epp:hello", xpathCtx);
	if (xpathObj == NULL) {
		xmlXPathFreeContext(xpathCtx);
		xmlFreeDoc(doc);
		return PARSER_EINTERNAL;
	}
	if (xpathObj->nodesetval && xpathObj->nodesetval->nodeNr == 1) {
		xmlXPathFreeObject(xpathObj);
		xmlFreeDoc(doc);
		return PARSER_HELLO;
	}
	xmlXPathFreeObject(xpathObj);

	/* is it a command? */
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
		cdata->clTRID = (char *) xmlNodeListGetString(doc,
				nodeset->nodeTab[0]->xmlChildrenNode, 1);
	else {
		/* we cannot leave clTRID NULL becauseof corba */
		cdata->clTRID = (char *) xmlStrdup(BAD_CAST "");
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
	cmd = cmd_hash_lookup(globs->hash_cmd,
			(char *) nodeset->nodeTab[0]->name);
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

/**
 * This is very good chance to perform integrity checks. Therefore
 * there are so many asserts inside this function.
 */
void epp_command_data_cleanup(epp_command_data *cdata)
{
	assert(cdata != NULL);

	assert(cdata->clTRID != NULL);
	free(cdata->clTRID);
	/*
	 * corba function might not be called and therefore svTRID might be
	 * still NULL.
	 */
	if (cdata->svTRID != NULL)
		free(cdata->svTRID);

	switch (cdata->type) {
		case EPP_LOGIN:
			assert(cdata->out == NULL); /* login has no output parameters */
			assert(cdata->in != NULL);
			free(cdata->in->login.clID);
			free(cdata->in->login.pw);
			free(cdata->in->login.newPW);
			/* destroy objuri list */
			CL_RESET(cdata->in->login.objuri);
			CL_FOREACH(cdata->in->login.objuri)
				free(CL_CONTENT(cdata->in->login.objuri));
			CL_PURGE(cdata->in->login.objuri);
			/* destroy exturi list */
			CL_RESET(cdata->in->login.exturi);
			CL_FOREACH(cdata->in->login.exturi)
				free(CL_CONTENT(cdata->in->login.exturi));
			CL_PURGE(cdata->in->login.exturi);
			break;
		case EPP_CHECK_CONTACT:
		case EPP_CHECK_DOMAIN:
		case EPP_CHECK_NSSET:
			assert(cdata->in != NULL);
			/* destroy ids */
			CL_RESET(cdata->in->check.ids);
			CL_FOREACH(cdata->in->check.ids) {
				free(CL_CONTENT(cdata->in->check.ids));
			}
			CL_PURGE(cdata->in->check.ids);
			/* destroy bools */
			if (cdata->out != NULL) {
				CL_RESET(cdata->out->check.bools);
				CL_FOREACH(cdata->out->check.bools) {
					free(CL_CONTENT(cdata->out->check.bools));
				}
				CL_PURGE(cdata->out->check.bools);
			}
			break;
		case EPP_INFO_CONTACT:
			assert(cdata->in != NULL);
			free(cdata->in->info.id);
			if (cdata->out != NULL) {
				epp_postalInfo	*pi;
				epp_discl	*discl;

				free(cdata->out->info_contact.roid);
				/* status */
				CL_RESET(cdata->out->info_contact.status);
				CL_FOREACH(cdata->out->info_contact.status)
					free(CL_CONTENT(cdata->out->info_contact.status));
				CL_PURGE(cdata->out->info_contact.status);
				/* postal info */
				pi = cdata->out->info_contact.postalInfo;
				assert(pi != NULL);
				free(pi->name);
				free(pi->org);
				free(pi->street1);
				free(pi->street2);
				free(pi->street3);
				free(pi->city);
				free(pi->sp);
				free(pi->pc);
				free(pi->cc);
				free(cdata->out->info_contact.postalInfo);
				free(cdata->out->info_contact.voice);
				free(cdata->out->info_contact.fax);
				free(cdata->out->info_contact.email);
				free(cdata->out->info_contact.notify_email);	/* ext */
				free(cdata->out->info_contact.clID);
				free(cdata->out->info_contact.crID);
				free(cdata->out->info_contact.upID);
				free(cdata->out->info_contact.authInfo);
				free(cdata->out->info_contact.vat);	/* ext */
				free(cdata->out->info_contact.ssn);	/* ext */
				/* disclose info */
				discl = cdata->out->info_contact.discl;
				assert(discl != NULL);
				free(discl);
			}
			break;
		case EPP_INFO_DOMAIN:
			assert(cdata->in != NULL);
			free(cdata->in->info.id);
			if (cdata->out != NULL) {
				free(cdata->out->info_domain.roid);
				/* status */
				CL_RESET(cdata->out->info_domain.status);
				CL_FOREACH(cdata->out->info_domain.status)
					free(CL_CONTENT(cdata->out->info_domain.status));
				CL_PURGE(cdata->out->info_domain.status);
				free(cdata->out->info_domain.registrant);
				/* admin contacts */
				CL_RESET(cdata->out->info_domain.admin);
				CL_FOREACH(cdata->out->info_domain.admin)
					free(CL_CONTENT(cdata->out->info_domain.admin));
				CL_PURGE(cdata->out->info_domain.admin);
				free(cdata->out->info_domain.nsset);
				free(cdata->out->info_domain.clID);
				free(cdata->out->info_domain.crID);
				free(cdata->out->info_domain.upID);
				free(cdata->out->info_domain.authInfo);
			}
			break;
		case EPP_INFO_NSSET:
			assert(cdata->in != NULL);
			free(cdata->in->info.id);
			if (cdata->out != NULL) {
				free(cdata->out->info_nsset.roid);
				/* ns */
				CL_RESET(cdata->out->info_nsset.ns);
				CL_FOREACH(cdata->out->info_nsset.ns) {
					epp_ns	*ns = (epp_ns *)
						CL_CONTENT(cdata->out->info_nsset.ns);
					free(ns->name);
					/* addr */
					CL_RESET(ns->addr);
					CL_FOREACH(ns->addr) free(CL_CONTENT(ns->addr));
					CL_PURGE(ns->addr);
					free(CL_CONTENT(cdata->out->info_nsset.ns));
				}
				CL_PURGE(cdata->out->info_nsset.ns);
				/* tech */
				CL_RESET(cdata->out->info_nsset.tech);
				CL_FOREACH(cdata->out->info_nsset.tech)
					free(CL_CONTENT(cdata->out->info_nsset.tech));
				CL_PURGE(cdata->out->info_nsset.tech);
			}
			break;
		case EPP_POLL_REQ:
			if (cdata->out != NULL)
				free(cdata->out->poll_req.msg);
			break;
		case EPP_POLL_ACK:
			assert(cdata->in != NULL);
			break;
		case EPP_LOGOUT:
			assert(cdata->in == NULL);
			assert(cdata->out == NULL);
			break;
		case EPP_DUMMY:
			break;
		default:
			assert(1 == 2);
			break;
	}
	/* same for all */
	if (cdata->in != NULL) free(cdata->in);
	if (cdata->out != NULL) free(cdata->out);
}
