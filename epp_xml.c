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
 * Following macros are shortcuts for xpath evaluation.
 */
/*
 * This Combines xpath evaluation and error handling if unsuccessful
 */
#define XPATH_EVAL(obj, ctx, err_handler, expr)	\
	do {	\
		(obj) = xmlXPathEvalExpression(BAD_CAST (expr), (ctx));	\
		if (obj == NULL) goto err_handler;	\
	}while(0);

/*
 * In str is put the content of element described by xpath expression.
 * The element must be only one and is required to exist.
 */
#define XPATH_REQ1(str, doc, ctx, err_handler, expr)            \
	do {                                                        \
		xmlXPathObjectPtr obj = xmlXPathEvalExpression(BAD_CAST (expr), (ctx));\
		if (obj == NULL) goto err_handler;                    \
		assert(obj->nodesetval && obj->nodesetval->nodeNr == 1);\
		(str) = xmlNodeListGetString((doc), obj->nodesetval->nodeTab[0]->xmlChildrenNode, 1);\
		xmlXPathFreeObject(obj);                                \
	}while(0);

/*
 * In str is put the content of element described by xpath expression.
 * The element must be only one and if the element does not exist
 * empty string is copied to str.
 */
#define XPATH_TAKE1(str, doc, ctx, err_handler, expr)           \
	do {                                                        \
		xmlXPathObjectPtr obj = xmlXPathEvalExpression(BAD_CAST (expr), (ctx));\
		if (obj == NULL) goto err_handler;                    \
		if (obj->nodesetval && obj->nodesetval->nodeNr == 1) {  \
			(str) = xmlNodeListGetString((doc), obj->nodesetval->nodeTab[0]->xmlChildrenNode, 1);\
		}                                                       \
		else (str) = strdup("");                                \
		xmlXPathFreeObject(obj);                                \
	}while(0);

/*
 * Same as above but fills a list of values instead of just one.
 */
#define XPATH_TAKEN(list, doc, ctx, err_handler, expr)               \
	do {                                                        \
		int	i;                                                  \
		struct circ_list	*item;                              \
		xmlXPathObjectPtr obj = xmlXPathEvalExpression(BAD_CAST (expr), (ctx));\
		if (obj == NULL) goto err_handler;                      \
		if (obj->nodesetval && obj->nodesetval->nodeNr > 0) {   \
			for (i = 0; i < obj->nodesetval->nodeNr; i++) {     \
				if ((item = malloc(sizeof *item)) == NULL) {    \
					xmlXPathFreeObject(obj);                    \
					goto err_handler;                           \
				}                                               \
				CL_CONTENT(item) = (void *) xmlNodeListGetString((doc), obj->nodesetval->nodeTab[i]->xmlChildrenNode, 1);\
				CL_ADD((list), item);                             \
			}                                                   \
		}                                                       \
		xmlXPathFreeObject(xpathObj);                           \
	}while(0);


/*
 * This is "carefull free". Pointer is freed only if not NULL.
 */
#define FREENULL(pointer)	if (pointer) free(pointer);

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
struct epp_xml_globs_t {
	xmlSchemaPtr schema; /* schema against which are validated requests */
	/* hash table for mapping return codes to textual messages */
	msg_hash_item	*hash_msg[HASH_SIZE_MSG];
	/* hash table for quick command lookup */
	cmd_hash_item	*hash_cmd[HASH_SIZE_CMD];
};


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

epp_xml_globs *epp_xml_init(const char *url_schema)
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

	return globs;
}

void epp_xml_init_cleanup(epp_xml_globs *par)
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
		xmlDocPtr doc,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	xmlXPathObjectPtr	xpathObj;
	xmlChar	*str;
	struct circ_list	*item;

	/* allocate necessary structures */
	if ((cdata->in = calloc(1, sizeof (*cdata->in))) == NULL) {
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	if ((cdata->in->login.objuri = malloc(sizeof *item)) == NULL) {
		free(cdata->in);
		cdata->in = NULL;
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	CL_NEW(cdata->in->login.objuri);
	if ((cdata->in->login.exturi = malloc(sizeof *item)) == NULL) {
		free(cdata->in->login.objuri);
		free(cdata->in);
		cdata->in = NULL;
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	CL_NEW(cdata->in->login.exturi);

	/* check if language matches */
	XPATH_REQ1(str, doc, xpathCtx, error_l,
			"/epp:epp/epp:command/epp:login/epp:options/epp:lang");
	if (!xmlStrEqual(str, BAD_CAST "en")) {
		xmlFree(str);
		cdata->type = EPP_DUMMY;
		cdata->rc = 2102;
		return;
	}
	xmlFree(str);

	/* check if EPP version matches */
	XPATH_REQ1(str, doc, xpathCtx, error_l,
			"/epp:epp/epp:command/epp:login/epp:options/epp:version");
	if (!xmlStrEqual(str, BAD_CAST "1.0")) {
		xmlFree(str);
		cdata->type = EPP_DUMMY;
		cdata->rc = 2100;
		return;
	}
	xmlFree(str);

	/* ok, checking done. now get input parameters for corba function call */
	XPATH_REQ1(cdata->in->login.clID, doc, xpathCtx, error_l,
			"/epp:epp/epp:command/epp:login/epp:clID");
	XPATH_REQ1(cdata->in->login.pw, doc, xpathCtx, error_l,
			"/epp:epp/epp:command/epp:login/epp:pw");
	XPATH_TAKE1(cdata->in->login.newPW, doc, xpathCtx, error_l,
			"/epp:epp/epp:command/epp:login/epp:newPW");
	XPATH_TAKEN(cdata->in->login.objuri, doc, xpathCtx, error_l,
			"/epp:epp/epp:command/epp:login/epp:svcs/epp:objURI");
	XPATH_TAKEN(cdata->in->login.exturi, doc, xpathCtx, error_l,
			"/epp:epp/epp:command/epp:login/epp:svcs/epp:extURI");

	cdata->type = EPP_LOGIN;
	return;

	/*
	 * nasty error's epilog
	 * Used in case of internal critical failure. It is not terribly
	 * effecient but this case should not occure very often.
	 */
error_l:
	FREENULL(cdata->in->login.clID);
	FREENULL(cdata->in->login.pw);
	FREENULL(cdata->in->login.newPW);
	CL_FOREACH(cdata->in->login.objuri)
		free(CL_CONTENT(cdata->in->login.objuri));
	CL_PURGE(cdata->in->login.objuri);
	CL_FOREACH(cdata->in->login.exturi)
		free(CL_CONTENT(cdata->in->login.exturi));
	CL_PURGE(cdata->in->login.exturi);
	free(cdata->in);
	cdata->in = NULL;
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * <check> parser for domain, contact and nsset object.
 * data in:
 *   - names of objects to be checked
 */
static void
parse_check(
		xmlDocPtr doc,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	xmlXPathObjectPtr	xpathObj;
	epp_object_type	obj_type;
	struct circ_list	*item;

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
	/* allocate necessary structures */
	if ((cdata->in = calloc(1, sizeof (*cdata->in))) == NULL) {
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	if ((cdata->in->check.ids = malloc(sizeof *item)) == NULL) {
		free(cdata->in);
		cdata->in = NULL;
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	CL_NEW(cdata->in->check.ids);
	/* get data */
	if (obj_type == EPP_CONTACT) {
		cdata->type = EPP_CHECK_CONTACT;
		XPATH_TAKEN(cdata->in->check.ids, doc, xpathCtx, error_ch,
				"/epp:epp/epp:command/epp:check/contact:check/contact:id");
	}
	else if (obj_type == EPP_DOMAIN) {
		cdata->type = EPP_CHECK_DOMAIN;
		XPATH_TAKEN(cdata->in->check.ids, doc, xpathCtx, error_ch,
				"/epp:epp/epp:command/epp:check/domain:check/domain:name");
	}
	else {
		assert(obj_type == EPP_NSSET);
		cdata->type = EPP_CHECK_NSSET;
		XPATH_TAKEN(cdata->in->check.ids, doc, xpathCtx, error_ch,
				"/epp:epp/epp:command/epp:check/nsset:check/nsset:id");
	}

	return;

	/*
	 * nasty error's epilog
	 * Used in case of internal critical failure. It is not terribly
	 * effecient but this case should not occure very often.
	 */
error_ch:
	CL_FOREACH(cdata->in->check.ids)
		free(CL_CONTENT(cdata->in->check.ids));
	CL_PURGE(cdata->in->check.ids);
	free(cdata->in);
	cdata->in = NULL;
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * <info> parser for domain, contact and nsset object.
 * Ignores authinfo.
 */
static void
parse_info(
		xmlDocPtr doc,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	xmlXPathObjectPtr	xpathObj;
	epp_object_type	obj_type;

	/* get object type - contact, nsset or domain */
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
	/* allocate necessary structures */
	if ((cdata->in = calloc(1, sizeof (*cdata->in))) == NULL) {
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	/* get data */
	if (obj_type == EPP_CONTACT) {
		cdata->type = EPP_INFO_CONTACT;
		XPATH_REQ1(cdata->in->info.id, doc, xpathCtx, error_i,
				"/epp:epp/epp:command/epp:info/contact:info/contact:id");
	}
	else if (obj_type == EPP_DOMAIN) {
		cdata->type = EPP_INFO_DOMAIN;
		XPATH_REQ1(cdata->in->info.id, doc, xpathCtx, error_i,
				"/epp:epp/epp:command/epp:info/domain:info/domain:name");
	}
	else {
		assert(obj_type == EPP_NSSET);
		cdata->type = EPP_INFO_NSSET;
		XPATH_REQ1(cdata->in->info.id, doc, xpathCtx, error_i,
				"/epp:epp/epp:command/epp:info/nsset:info/nsset:id");
	}

	return;

	/*
	 * nasty error's epilog
	 * Used in case of internal critical failure. It is not terribly
	 * effecient but this case should not occure very often.
	 */
error_i:
	FREENULL(cdata->in->info.id);
	free(cdata->in);
	cdata->in = NULL;
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * <poll> parser.
 */
static void
parse_poll(
		xmlDocPtr doc,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	xmlXPathObjectPtr	xpathObj;
	xmlChar	*str;

	/* get poll type - request or acknoledge */
	xpathObj = xmlXPathEvalExpression(BAD_CAST
			"/epp:epp/epp:command/epp:poll[@op='req']",
			xpathCtx);
	if (xpathObj == NULL) {
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	if (xpathObj->nodesetval != NULL && xpathObj->nodesetval->nodeNr == 1) {
		/* it is request */
		cdata->type = EPP_POLL_REQ;
		xmlXPathFreeObject(xpathObj);
		return;
	}
	xmlXPathFreeObject(xpathObj);

	/* it should be acknoledge */
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
	xmlXPathFreeObject(xpathObj);
	/* conversion is safe, if str in not a number, validator catches it */
	cdata->in->poll_ack.msgid = atoi((char *) str);
	xmlFree(str);
	cdata->type = EPP_POLL_ACK;
}

/**
 * Assistant procedure for parsing <create> domain
 */
static void
parse_create_domain(
		xmlDocPtr doc,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	xmlXPathObjectPtr	xpathObj;
	struct circ_list	*item;

	/* allocate necessary structures */
	if ((cdata->in = calloc(1, sizeof (*cdata->in))) == NULL) {
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	if ((cdata->in->create_domain.admin = malloc(sizeof *item)) == NULL) {
		free(cdata->in);
		cdata->in = NULL;
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	CL_NEW(cdata->in->create_domain.admin);
	/* get the domain data */
	XPATH_REQ1(cdata->in->create_domain.name, doc, xpathCtx, cd_error,
			"/epp:epp/epp:command/epp:create/domain:create/domain:name");
	XPATH_TAKE1(cdata->in->create_domain.registrant, doc, xpathCtx, cd_error,
			"/epp:epp/epp:command/epp:create/domain:create/domain:registrant");
	XPATH_TAKE1(cdata->in->create_domain.nsset, doc, xpathCtx, cd_error,
			"/epp:epp/epp:command/epp:create/domain:create/domain:nsset");
	XPATH_REQ1(cdata->in->create_domain.authInfo, doc, xpathCtx, cd_error,
			"/epp:epp/epp:command/epp:create/domain:create/domain:authInfo");
	/* domain period handling is slightly more difficult */
	XPATH_EVAL(xpathObj, xpathCtx, cd_error,
			"/epp:epp/epp:command/epp:create/domain:create/domain:period");
	if (xpathObj->nodesetval && xpathObj->nodesetval->nodeNr == 1) {
		xmlChar	*str;
		cdata->in->create_domain.period = atoi(str);
		xmlFree(str);
		/* correct period value if given in years and not months */
		str = xmlGetNsProp(xpathObj->nodesetval->nodeTab[0],
				BAD_CAST "unit", BAD_CAST NS_DOMAIN);
		assert(str != NULL);
		if (*str == 'y') cdata->in->create_domain.period *= 12;
		xmlFree(str);
	}
	else cdata->in->create_domain.period = 0;
	xmlXPathFreeObject(xpathObj);
	/* process "unbounded" number of contacts */
	XPATH_TAKEN(cdata->in->create_domain.admin, doc, xpathCtx, cd_error,
			"/epp:epp/epp:command/epp:create/domain:create/domain:contact");

	cdata->type = EPP_CREATE_DOMAIN;
	return;

	/*
	 * nasty error's epilog
	 * Used in case of internal critical failure. It is not terribly
	 * effecient but this case should not occure very often.
	 */
cd_error:
	FREENULL(cdata->in->create_domain.name);
	FREENULL(cdata->in->create_domain.registrant);
	FREENULL(cdata->in->create_domain.admin);
	FREENULL(cdata->in->create_domain.nsset);
	FREENULL(cdata->in->create_domain.authInfo);
	CL_FOREACH(cdata->in->create_domain.admin)
		free(CL_CONTENT(cdata->in->create_domain.admin));
	CL_PURGE(cdata->in->create_domain.admin);
	free(cdata->in);
	cdata->in = NULL;
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Assistant procedure for parsing <create> contact
 */
static void
parse_create_contact(
		xmlDocPtr doc,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	/* allocate necessary structures */
	if ((cdata->in = calloc(1, sizeof (*cdata->in))) == NULL) {
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	if ((cdata->in->create_contact.postalInfo = calloc(1, sizeof
					(*cdata->in->create_contact.postalInfo))) == NULL) {
		free(cdata->in);
		cdata->in = NULL;
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	if ((cdata->in->create_contact.discl = calloc(1, sizeof
					(*cdata->in->create_contact.discl))) == NULL) {
		free(cdata->in->create_contact.postalInfo);
		free(cdata->in);
		cdata->in = NULL;
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	/* get the contact data */
	XPATH_REQ1(cdata->in->create_contact.id, doc, xpathCtx, cc_error,
			"/epp:epp/epp:command/epp:create/contact:create/contact:id");
	XPATH_TAKE1(cdata->in->create_contact.voice, doc, xpathCtx, cc_error,
			"/epp:epp/epp:command/epp:create/contact:create/contact:voice");
	XPATH_TAKE1(cdata->in->create_contact.fax, doc, xpathCtx, cc_error,
			"/epp:epp/epp:command/epp:create/contact:create/contact:fax");
	XPATH_REQ1(cdata->in->create_contact.email, doc, xpathCtx, cc_error,
			"/epp:epp/epp:command/epp:create/contact:create/contact:email");
	XPATH_TAKE1(cdata->in->create_contact.authInfo, doc, xpathCtx, cc_error,
			"/epp:epp/epp:command/epp:create/contact:create/contact:authInfo");
	XPATH_TAKE1(cdata->in->create_contact.vat, doc, xpathCtx, cc_error,
			"/epp:epp/epp:command/epp:create/contact:create/contact:vat");
	XPATH_TAKE1(cdata->in->create_contact.ssn, doc, xpathCtx, cc_error,
			"/epp:epp/epp:command/epp:create/contact:create/contact:ssn");
	/* disclose info */
	/* TODO parse disclose Info */
	/* postal info */
	XPATH_REQ1(cdata->in->create_contact.postalInfo->name, doc, xpathCtx,
			cc_error,
			"/epp:epp/epp:command/epp:create/contact:create/contact:postalInfo"
			"/contact:name");
	XPATH_TAKE1(cdata->in->create_contact.postalInfo->org, doc, xpathCtx,
			cc_error,
			"/epp:epp/epp:command/epp:create/contact:create/contact:postalInfo"
			"/contact:org");
	/* TODO parse streets */
	cdata->in->create_contact.postalInfo->street1 = strdup("");
	cdata->in->create_contact.postalInfo->street2 = strdup("");
	cdata->in->create_contact.postalInfo->street3 = strdup("");
	XPATH_REQ1(cdata->in->create_contact.postalInfo->city, doc, xpathCtx,
			cc_error,
			"/epp:epp/epp:command/epp:create/contact:create/contact:postalInfo"
			"/contact:addr/contact:city");
	XPATH_TAKE1(cdata->in->create_contact.postalInfo->sp, doc, xpathCtx,
			cc_error,
			"/epp:epp/epp:command/epp:create/contact:create/contact:postalInfo"
			"/contact:addr/contact:sp");
	XPATH_TAKE1(cdata->in->create_contact.postalInfo->pc, doc, xpathCtx,
			cc_error,
			"/epp:epp/epp:command/epp:create/contact:create/contact:postalInfo"
			"/contact:addr/contact:pc");
	XPATH_REQ1(cdata->in->create_contact.postalInfo->cc, doc, xpathCtx,
			cc_error,
			"/epp:epp/epp:command/epp:create/contact:create/contact:postalInfo"
			"/contact:addr/contact:cc");

	cdata->type = EPP_CREATE_CONTACT;
	return;

	/*
	 * nasty error's epilog
	 * Used in case of internal critical failure. It is not terribly
	 * effecient but this case should not occure very often.
	 */
cc_error:
	FREENULL(cdata->in->create_contact.id);
	FREENULL(cdata->in->create_contact.voice);
	FREENULL(cdata->in->create_contact.fax);
	FREENULL(cdata->in->create_contact.email);
	FREENULL(cdata->in->create_contact.authInfo);
	FREENULL(cdata->in->create_contact.notify_email);
	FREENULL(cdata->in->create_contact.vat);
	FREENULL(cdata->in->create_contact.ssn);
	/* postal info */
	FREENULL(cdata->in->create_contact.postalInfo->name);
	FREENULL(cdata->in->create_contact.postalInfo->org);
	FREENULL(cdata->in->create_contact.postalInfo->street1);
	FREENULL(cdata->in->create_contact.postalInfo->street2);
	FREENULL(cdata->in->create_contact.postalInfo->street3);
	FREENULL(cdata->in->create_contact.postalInfo->city);
	FREENULL(cdata->in->create_contact.postalInfo->sp);
	FREENULL(cdata->in->create_contact.postalInfo->pc);
	FREENULL(cdata->in->create_contact.postalInfo->cc);
	FREENULL(cdata->in->create_contact.postalInfo);
	/* disclose info */
	FREENULL(cdata->in->create_contact.discl);
	free(cdata->in);
	cdata->in = NULL;
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Assistant procedure for parsing <create> nsset
 */
static void
parse_create_nsset(
		xmlDocPtr doc,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	xmlXPathObjectPtr	xpathObj;
	struct circ_list	*item;

	/* allocate necessary structures */
	if ((cdata->in = calloc(1, sizeof (*cdata->in))) == NULL) {
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	if ((cdata->in->create_nsset.tech = malloc(sizeof *item)) == NULL) {
		free(cdata->in);
		cdata->in = NULL;
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	CL_NEW(cdata->in->create_nsset.tech);
	if ((cdata->in->create_nsset.ns = malloc(sizeof *item)) == NULL) {
		free(cdata->in->create_nsset.tech);
		free(cdata->in);
		cdata->in = NULL;
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	CL_NEW(cdata->in->create_nsset.ns);
	/* get the domain data */
	XPATH_REQ1(cdata->in->create_nsset.id, doc, xpathCtx, cn_error,
			"/epp:epp/epp:command/epp:create/nsset:create/nsset:id");
	XPATH_REQ1(cdata->in->create_nsset.authInfo, doc, xpathCtx, cn_error,
			"/epp:epp/epp:command/epp:create/nsset:create/nsset:authInfo");
	/* process "unbounded" number of tech contacts */
	XPATH_TAKEN(cdata->in->create_nsset.ns, doc, xpathCtx, cn_error,
			"/epp:epp/epp:command/epp:create/nsset:create/nsset:tech");
	/* TODO process ns list */
	cdata->type = EPP_CREATE_NSSET;
	return;

	/*
	 * nasty error's epilog
	 * Used in case of internal critical failure. It is not terribly
	 * effecient but this case should not occure very often.
	 */
cn_error:
	FREENULL(cdata->in->create_nsset.id);
	FREENULL(cdata->in->create_nsset.authInfo);
	CL_FOREACH(cdata->in->create_nsset.tech)
		free(CL_CONTENT(cdata->in->create_nsset.tech));
	CL_PURGE(cdata->in->create_nsset.tech);
	free(cdata->in);
	cdata->in = NULL;
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * <create> parser for domain, contact and nsset object.
 */
static void
parse_create(
		xmlDocPtr doc,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	xmlXPathObjectPtr	xpathObj;

	/* get object type - contact, domain or nsset */
	xpathObj = xmlXPathEvalExpression(BAD_CAST
			"/epp:epp/epp:command/epp:create/contact:create",
			xpathCtx);
	if (xpathObj == NULL) {
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	if (xpathObj->nodesetval == NULL || xpathObj->nodesetval->nodeNr == 0) {
		xmlXPathFreeObject(xpathObj);
		xpathObj = xmlXPathEvalExpression(BAD_CAST
				"/epp:epp/epp:command/epp:create/domain:create",
				xpathCtx);
		if (xpathObj == NULL) {
			cdata->rc = 2400;
			cdata->type = EPP_DUMMY;
			return;
		}
		if (xpathObj->nodesetval == NULL || xpathObj->nodesetval->nodeNr == 0) {
			xmlXPathFreeObject(xpathObj);
			xpathObj = xmlXPathEvalExpression(BAD_CAST
					"/epp:epp/epp:command/epp:create/nsset:create",
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
			else parse_create_nsset(doc, xpathCtx, cdata);
		}
		/* object is a domain */
		else parse_create_domain(doc, xpathCtx, cdata);
	}
	/* object is contact */
	else parse_create_contact(doc, xpathCtx, cdata);
}

gen_status
epp_gen_login(epp_xml_globs *globs, epp_command_data *cdata, char **result)
{
	assert(globs != NULL);
	assert(cdata != NULL);
	return simple_response(((epp_xml_globs *) globs)->hash_msg,
			cdata->rc, cdata->clTRID, cdata->svTRID, result);
}

gen_status
epp_gen_logout(epp_xml_globs *globs, epp_command_data *cdata, char **result)
{
	assert(globs != NULL);
	assert(cdata != NULL);
	return simple_response(((epp_xml_globs *) globs)->hash_msg,
			cdata->rc, cdata->clTRID, cdata->svTRID, result);
}

gen_status
epp_gen_dummy(epp_xml_globs *globs, epp_command_data *cdata, char **result)
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
		epp_xml_globs *globs,
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
epp_gen_check_contact(epp_xml_globs *globs, epp_command_data *cdata, char **result)
{
	assert(globs != NULL);
	assert(cdata != NULL);
	assert(cdata->out != NULL);
	return epp_gen_check(globs, cdata, result, EPP_CONTACT);
}

gen_status
epp_gen_check_domain(epp_xml_globs *globs, epp_command_data *cdata, char **result)
{
	assert(globs != NULL);
	assert(cdata != NULL);
	assert(cdata->out != NULL);
	return epp_gen_check(globs, cdata, result, EPP_DOMAIN);
}

gen_status
epp_gen_check_nsset(epp_xml_globs *globs, epp_command_data *cdata, char **result)
{
	assert(globs != NULL);
	assert(cdata != NULL);
	assert(cdata->out != NULL);
	return epp_gen_check(globs, cdata, result, EPP_NSSET);
}

gen_status
epp_gen_info_contact(epp_xml_globs *globs, epp_command_data *cdata, char **result)
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
epp_gen_info_domain(epp_xml_globs *globs, epp_command_data *cdata, char **result)
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
epp_gen_info_nsset(epp_xml_globs *globs, epp_command_data *cdata, char **result)
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
epp_gen_poll_req(epp_xml_globs *globs, epp_command_data *cdata, char **result)
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
epp_gen_poll_ack(epp_xml_globs *globs, epp_command_data *cdata, char **result)
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

static gen_status
epp_gen_create(epp_xml_globs *globs, epp_command_data *cdata,
		char **result, epp_object_type obj_type)
{
	xmlBufferPtr buf;
	xmlTextWriterPtr writer;
	char	*str;
	char	strbuf[25]; /* is enough even for 64-bit number and for a date */
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
	snprintf(strbuf, 5, "%d", cdata->rc);
	str = msg_hash_lookup(( (epp_xml_globs *) globs)->hash_msg, cdata->rc);
	WRITE_ATTRIBUTE(writer, simple_err, "code", strbuf);
	WRITE_ELEMENT(writer, simple_err, "msg", str);
	END_ELEMENT(writer, simple_err);

	// specific part of response
	START_ELEMENT(writer, simple_err, "resData");
	get_rfc3339_date(cdata->out->create.crDate, strbuf);
	/* object dependent fork */
	if (obj_type == EPP_CONTACT) {
		START_ELEMENT(writer, simple_err, "contact:creData");
		WRITE_ATTRIBUTE(writer, simple_err, "xmlns:nsset", NS_CONTACT);
		WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_CONTACT);
		WRITE_ELEMENT(writer, simple_err, "contact:id",
				cdata->in->create_contact.id);
		WRITE_ELEMENT(writer, simple_err, "contact:crDate", strbuf);
	}
	else if (obj_type == EPP_NSSET) {
		START_ELEMENT(writer, simple_err, "nsset:creData");
		WRITE_ATTRIBUTE(writer, simple_err, "xmlns:nsset", NS_NSSET);
		WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_NSSET);
		WRITE_ELEMENT(writer, simple_err, "nsset:id",
				cdata->in->create_nsset.id);
		WRITE_ELEMENT(writer, simple_err, "nsset:crDate", strbuf);
	}
	else {
		START_ELEMENT(writer, simple_err, "domain:creData");
		WRITE_ATTRIBUTE(writer, simple_err, "xmlns:nsset", NS_DOMAIN);
		WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_DOMAIN);
		WRITE_ELEMENT(writer, simple_err, "domain:id",
				cdata->in->create_domain.name);
		WRITE_ELEMENT(writer, simple_err, "domain:crDate", strbuf);
		get_rfc3339_date(cdata->out->create.exDate, strbuf);
		WRITE_ELEMENT(writer, simple_err, "domain:exDate", strbuf);
	}
	END_ELEMENT(writer, simple_err); /* credata */
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
epp_gen_create_contact(epp_xml_globs *globs, epp_command_data *cdata,
		char **result)
{
	assert(globs != NULL);
	assert(cdata != NULL);
	assert(cdata->out != NULL);
	assert(cdata->in != NULL);

	return epp_gen_create(globs, cdata, result, EPP_CONTACT);
}

gen_status
epp_gen_create_domain(epp_xml_globs *globs, epp_command_data *cdata,
		char **result)
{
	assert(globs != NULL);
	assert(cdata != NULL);
	assert(cdata->out != NULL);
	assert(cdata->in != NULL);

	return epp_gen_create(globs, cdata, result, EPP_DOMAIN);
}

gen_status
epp_gen_create_nsset(epp_xml_globs *globs, epp_command_data *cdata,
		char **result)
{
	assert(globs != NULL);
	assert(cdata != NULL);
	assert(cdata->out != NULL);
	assert(cdata->in != NULL);

	return epp_gen_create(globs, cdata, result, EPP_NSSET);
}

void epp_free_genstring(char *genstring)
{
	assert(genstring != NULL);
	free(genstring);
}

parser_status
epp_parse_command(
		int session,
		epp_xml_globs *globs,
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

	/*
	 * Do validity checking for following cases:
	 * 	- the user is not logged in and attempts to issue a command
	 * 	- the user is already logged in and issues another login
	 */
	if (cmd != EPP_RED_LOGIN) {
		if (session == 0) {
			cdata->type = EPP_DUMMY;
			cdata->rc = 2002;
			xmlXPathFreeContext(xpathCtx);
			xmlFreeDoc(doc);
			return PARSER_OK;
		}
	}
	else {
		if (session != 0) {
			cdata->type = EPP_DUMMY;
			cdata->rc = 2002;
			xmlXPathFreeContext(xpathCtx);
			xmlFreeDoc(doc);
			return PARSER_OK;
		}
	}


	switch (cmd) {
		case EPP_RED_LOGIN:
			parse_login(doc, xpathCtx, cdata);
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
			parse_check(doc, xpathCtx, cdata);
			break;
		case EPP_RED_INFO:
			parse_info(doc, xpathCtx, cdata);
			break;
		case EPP_RED_POLL:
			parse_poll(doc, xpathCtx, cdata);
			break;
		case EPP_RED_CREATE:
			parse_create(doc, xpathCtx, cdata);
			break;
		case EPP_RED_DELETE:
		case EPP_RED_RENEW:
		case EPP_RED_UPDATE:
		case EPP_RED_TRANSFER:
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
		case EPP_CREATE_DOMAIN:
			assert(cdata->in != NULL);
			free(cdata->in->create_domain.name);
			free(cdata->in->create_domain.registrant);
			free(cdata->in->create_domain.nsset);
			free(cdata->in->create_domain.authInfo);
			/* admin */
			CL_RESET(cdata->in->create_domain.admin);
			CL_FOREACH(cdata->in->create_domain.admin)
				free(CL_CONTENT(cdata->in->create_domain.admin));
			CL_PURGE(cdata->in->create_domain.admin);
			break;
		case EPP_CREATE_CONTACT:
			assert(cdata->in != NULL);
			free(cdata->in->create_contact.id);
			free(cdata->in->create_contact.voice);
			free(cdata->in->create_contact.fax);
			free(cdata->in->create_contact.email);
			free(cdata->in->create_contact.authInfo);
			free(cdata->in->create_contact.notify_email);
			free(cdata->in->create_contact.vat);
			free(cdata->in->create_contact.ssn);
			assert(cdata->in->create_contact.postalInfo != NULL);
			{
				epp_postalInfo	*pi = cdata->in->create_contact.postalInfo;
				free(pi->name);
				free(pi->org);
				free(pi->street1);
				free(pi->street2);
				free(pi->street3);
				free(pi->city);
				free(pi->sp);
				free(pi->pc);
				free(pi->cc);
				free(pi);
			}
			assert(cdata->in->create_contact.discl != NULL);
			free(cdata->in->create_contact.discl);
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
