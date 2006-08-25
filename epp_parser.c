/*
 * @file epp_parser.c
 *
 * Component for parsing EPP requests in form of xml documents.
 * The product is a data structure which contains data from xml document.
 * This file also contains routine which handles deallocation of this
 * structure. Currently the component is based on libxml library.
 */

#include <string.h>
#define __USE_XOPEN
#include <time.h>	/* strptime */
#include <sys/time.h>	/* perfdata */
#include <stdlib.h>
#include <assert.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/xmlschemas.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include "epp_common.h"
#include "epp_xmlcommon.h"
#include "epp_parser.h"

#define BS_CHAR	8	/**< Backspace ASCII code. */
/**
 * Size of hash table used for hashing command names. The size is tradeof
 * between size of hash table and lookup speed, it should be less than 255
 * since hash value is unsigned char.
 */
#define HASH_SIZE_CMD	30


/**
 * @defgroup xpathgroup Macros and functions for convenient usage of xpath
 * queries.
 * Following macro parameters are used often and have following meaning.
 * 	- ctx: XPath context.
 * 	- err_handler: Label used in goto statement when anything goes wrong.
 * 	- expr: XPath expression.
 * 	- doc: XML document.
 * 	- str: string where is stored return value (content of xml tag)
 * 	- list: list of strings where are stored return values (content of xml tags)
 *
 * @{
 */

/**
 * This combines xpath evaluation and error handling if unsuccessful.
 * It is not used very often, instead other higher level functions and macros
 * are used, if it is possible.
 */
#define XPATH_EVAL(obj, ctx, err_handler, expr)	\
	do {                                        \
		(obj) = xmlXPathEvalExpression(BAD_CAST (expr), (ctx));\
		if (obj == NULL) goto err_handler;      \
	}while(0);

/**
 * Sometimes we want to know only if the element is there or not.
 * If error occures we return 0, which means: object is not there
 * (I hope that it doesn't do much damage).
 *
 * @param ctx XPath context.
 * @param expr XPath expression.
 * @return 1 if the element described by expr is there, otherwise 0.
 */
static inline
int xpath_exists(xmlXPathContextPtr ctx, const char *expr)
{
		int ret;

		xmlXPathObjectPtr obj = xmlXPathEvalExpression(BAD_CAST expr, ctx);
		if (obj == NULL) return 0;
		ret = xmlXPathNodeSetGetLength(obj->nodesetval);
		xmlXPathFreeObject(obj);
		return ret;
}

/**
 * Into str is put the content of element described by xpath expression.
 * The element must be only one and is required to exist, otherwise assert
 * aborts the program.
 */
#define XPATH_REQ1(str, doc, ctx, err_handler, expr)            \
	do {                                                        \
		xmlXPathObjectPtr obj = xmlXPathEvalExpression(BAD_CAST (expr), (ctx));\
		if (obj == NULL) goto err_handler;                      \
		assert(xmlXPathNodeSetGetLength(obj->nodesetval) == 1); \
		(str) = (char *) xmlNodeListGetString((doc), xmlXPathNodeSetItem(obj->nodesetval, 0)->xmlChildrenNode, 1);\
		if ((str) == NULL) (str) = strdup("");                  \
		xmlXPathFreeObject(obj);                                \
	}while(0);

/**
 * Into str is put the content of element described by xpath expression.
 * The element must be only one and if the element does not exist
 * empty string is copied to str.
 */
#define XPATH_TAKE1(str, doc, ctx, err_handler, expr)           \
	do {                                                        \
		xmlXPathObjectPtr obj = xmlXPathEvalExpression(BAD_CAST (expr), (ctx));\
		if (obj == NULL) goto err_handler;                      \
		if (xmlXPathNodeSetGetLength(obj->nodesetval) == 1) {   \
			(str) = (char *) xmlNodeListGetString((doc), xmlXPathNodeSetItem(obj->nodesetval, 0)->xmlChildrenNode, 1);\
			if ((str) == NULL) (str) = strdup("");              \
		}                                                       \
		else (str) = strdup("");                                \
		xmlXPathFreeObject(obj);                                \
	}while(0);

/**
 * Into str is put the content of element described by xpath expression.
 * The element must be only one and if the element does not exist,
 * resulting str is NULL. In addition to previous macro, if element
 * does exist and its content has zero length, resulting string is
 * one char - backspace. This is used in processing of update request
 * to distinguish between element which is not updated and element
 * which is erased (Note that we cannot use NULL value because CORBA
 * doesn't like it).
 */
#define XPATH_TAKE1_UPD(str, doc, ctx, err_handler, expr)       \
	do {                                                        \
		xmlXPathObjectPtr obj = xmlXPathEvalExpression(BAD_CAST (expr), (ctx));\
		if (obj == NULL) goto err_handler;                      \
		if (xmlXPathNodeSetGetLength(obj->nodesetval) == 1) {   \
			(str) = (char *) xmlNodeListGetString((doc), xmlXPathNodeSetItem(obj->nodesetval, 0)->xmlChildrenNode, 1);\
			if ((str) == NULL) (str) = strdup("");              \
			if (*(str) == '\0') {                               \
				free(str);                                      \
				if ((str = malloc(2)) == NULL) {                \
					xmlXPathFreeObject(obj);                    \
					goto err_handler;                           \
				}                                               \
				str[0] = BS_CHAR;                               \
				str[1] = '\0';                                  \
			}                                                   \
		}                                                       \
		else (str) = strdup("");                                \
		xmlXPathFreeObject(obj);                                \
	}while(0);

/**
 * Into list is put the content of elements described by xpath expression.
 * There may be more elements matching xpath expression, their content is
 * copied in a list.
 */
#define XPATH_TAKEN(list, doc, ctx, err_handler, expr)          \
	do {                                                        \
		int	i;                                                  \
		struct circ_list	*item;                              \
		xmlXPathObjectPtr obj = xmlXPathEvalExpression(BAD_CAST (expr), (ctx));\
		if (obj == NULL) goto err_handler;                      \
		if (xmlXPathNodeSetGetLength(obj->nodesetval) > 0) {    \
			for (i = 0; i < xmlXPathNodeSetGetLength(obj->nodesetval); i++) {\
				if ((item = malloc(sizeof *item)) == NULL) {    \
					xmlXPathFreeObject(obj);                    \
					goto err_handler;                           \
				}                                               \
				CL_CONTENT(item) = (void *) xmlNodeListGetString((doc), xmlXPathNodeSetItem(obj->nodesetval, i)->xmlChildrenNode, 1);\
				if (CL_CONTENT(item) == NULL) CL_CONTENT(item) = strdup("");\
				CL_ADD((list), item);                           \
			}                                                   \
		}                                                       \
		xmlXPathFreeObject(obj);                           \
	}while(0);

/*
 * Into list is put the values of attribute of name attr of elements matching
 * xpath expression expr.
 */
#define XPATH_TAKEN_ATTR(list, ctx, err_handler, expr, attr)    \
	do {                                                        \
		int	i;                                                  \
		struct circ_list	*item;                              \
		xmlXPathObjectPtr obj = xmlXPathEvalExpression(BAD_CAST (expr), (ctx));\
		if (obj == NULL) goto err_handler;                      \
		if (xmlXPathNodeSetGetLength(obj->nodesetval) > 0) {    \
			for (i = 0; i < xmlXPathNodeSetGetLength(obj->nodesetval); i++) {\
				if ((item = malloc(sizeof *item)) == NULL) {    \
					xmlXPathFreeObject(obj);                    \
					goto err_handler;                           \
				}                                               \
				CL_CONTENT(item) = (void *) xmlGetProp(xmlXPathNodeSetItem(obj->nodesetval, i), (xmlChar *) (attr));\
				if (CL_CONTENT(item) == NULL) CL_CONTENT(item) = strdup("");\
				CL_ADD((list), item);                           \
			}                                                   \
		}                                                       \
		xmlXPathFreeObject(obj);                                \
	}while(0);

/**
 * @}
 */

/**
 * This is a "carefull free", which means pointer is freed only if it is
 * not NULL. This is used so often in cleanup code that it is worth of
 * creating such a macro.
 */
#define FREENULL(pointer)	if (pointer) free(pointer);

/**
 * Enumeration of all implemented EPP commands as defined in rfc.
 * It is REDuced form - without object suffix. And is used as hash
 * value in command hash table for fast recognition of commands.
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

typedef struct cmd_hash_item_t cmd_hash_item;

/**
 * Item of command hash table used for fast command recognition.
 */
struct cmd_hash_item_t {
	cmd_hash_item	*next;	/**< Next item in hash table. */
	char	*key;	/**< Hash key (command name). */
	epp_command_type	val;	/**< Hash value (command type). */
};

/**
 * Hash table of epp commands used for fast command lookup.
 * Once the table is initialized, it is read-only. There for it is thread-safe
 * eventhough it is declared as static.
 */
static cmd_hash_item *hash_cmd[HASH_SIZE_CMD];

/**
 * Function for hashing of command name.
 * Function makes xor of first 4 bytes of command name, which is sufficient
 * since first 4 letters are unique for all EPP commands. It is both simple
 * and fast. We assume that command names are at least 4 bytes long and that
 * there are no 2 command with the same first four letters - that's true for
 * EPP commands.
 * @param key Command name.
 * @return Hash value.
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
 * Function inserts command in hash table.
 * @param key Input key for hash algorithm
 * @param type Command type associated with given key
 * @return 0 in case of success, 1 in case of failure (Theese non-standard
 * return values are due to the way the results are processed in
 * epp_parser_init()).
 */
static char cmd_hash_insert(
		const char *key,
		epp_command_type type)
{
	cmd_hash_item	*hi;
	int	index;

	assert(key != NULL);
	assert(strlen(key) >= 4);

	/* allocate and initialize new item */
	if ((hi = malloc(sizeof *hi)) == NULL) return 1;
	hi->val = type;
	if ((hi->key = strdup(key)) == NULL) {
		free(hi);
		return 1;
	}
	/* enqueue new item in hash table */
	index = get_cmd_hash(key);
	hi->next = hash_cmd[index];
	hash_cmd[index] = hi;

	return 0;
}

/**
 * This routine does traditional lookup on hash table containing commands.
 * @param key Command name.
 * @return Command type, if command is not found in hash table, value
 * EPP_UNKNOWN_CMD is returned.
 */
static epp_command_type
cmd_hash_lookup(const char *key)
{
	cmd_hash_item	*hi;

	/* iterate through hash chain */
	for (hi = hash_cmd[get_cmd_hash(key)]; hi != NULL; hi = hi->next) {
		if (!strncmp(hi->key, key, 4)) break;
	}
	/* did we find anything? */
	if (hi) return hi->val;
	/* command is not there */
	return EPP_UNKNOWN_CMD;
}

/**
 * Function releases all items in command hash table.
 */
static void
cmd_hash_clean(void)
{
	cmd_hash_item	*tmp;
	int	i;

	/* step through all hash table indexes */
	for (i = 0; i < HASH_SIZE_CMD; i++) {
		/* free one hash chain */
		while (hash_cmd[i]) {
			tmp = hash_cmd[i]->next;
			free(hash_cmd[i]->key);
			free(hash_cmd[i]);
			hash_cmd[i] = tmp;
		}
	}
}

void *
epp_parser_init(const char *url_schema)
{
	xmlSchemaPtr	schema; /* parsed schema */
	xmlSchemaParserCtxtPtr	spctx;	/* schema parser's context */
	char rc;

	/* just to be sure the table is empty */
	cmd_hash_clean();

	/* initialize command hash table */
	rc = 0;
	rc |= cmd_hash_insert("login", EPP_RED_LOGIN);
	rc |= cmd_hash_insert("logout", EPP_RED_LOGOUT);
	rc |= cmd_hash_insert("check", EPP_RED_CHECK);
	rc |= cmd_hash_insert("info", EPP_RED_INFO);
	rc |= cmd_hash_insert("poll", EPP_RED_POLL);
	rc |= cmd_hash_insert("transfer", EPP_RED_TRANSFER);
	rc |= cmd_hash_insert("create", EPP_RED_CREATE);
	rc |= cmd_hash_insert("delete", EPP_RED_DELETE);
	rc |= cmd_hash_insert("renew", EPP_RED_RENEW);
	rc |= cmd_hash_insert("update", EPP_RED_UPDATE);
	if (rc) {
		/* at least one error has been spotted */
		cmd_hash_clean();
		return NULL;
	}

	/*
	 * It seems libxml is working well even without parser and xpath
	 * initialization, but we will rather invoke them.
	 */
	xmlInitParser();
	xmlXPathInit();

	/* parse epp schema */
	spctx = xmlSchemaNewParserCtxt(url_schema);
	if (spctx == NULL) return NULL;
	schema = xmlSchemaParse(spctx);
	xmlSchemaFreeParserCtxt(spctx);
	/*
	 * schema might be corrupted though it is unlikely, in that case
	 * schema has NULL value
	 */
	return (void *) schema;
}

/**
 * Function releases command hash table and calls libxml's parser cleanup
 * routine.
 * @param schema Parsed xml schema.
 */
void epp_parser_init_cleanup(void *schema)
{
	xmlSchemaFree((xmlSchemaPtr) schema);
	cmd_hash_clean();
	xmlCleanupParser();
}

/**
 * Convert string with date to number of seconds since ...
 * @param str Date in string format.
 * @return Number of seconds.
 */
static unsigned long long
str2timestamp(const char *str)
{
	struct tm t;
	char	buf[20];

	bzero(&t, sizeof t);
	snprintf(buf, 19, "%s UTC", str);
	strptime(buf, "%Y-%m-%d %z", &t);
	/* XXX is timegm thread-safe? */
	return timegm(&t);
}

/**
 * Parser of EPP login command.
 * @param doc Parsed XML document.
 * @param xpathCtx XPath context.
 * @param cdata Output of parsing stage.
 */
static void
parse_login(xmlDocPtr doc, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
	char	*str;
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
			"epp:login/epp:options/epp:lang");
	if (xmlStrEqual((xmlChar *) str, BAD_CAST "en"))
		cdata->in->login.lang = LANG_EN;
	else if (xmlStrEqual((xmlChar *) str, BAD_CAST "cs"))
		cdata->in->login.lang = LANG_CS;
	else {
		xmlFree(str);
		cdata->type = EPP_DUMMY;
		cdata->rc = 2102;
		return;
	}
	xmlFree(str);

	/* check if EPP version matches */
	XPATH_REQ1(str, doc, xpathCtx, error_l,
			"epp:login/epp:options/epp:version");
	if (!xmlStrEqual((xmlChar *) str, BAD_CAST "1.0")) {
		xmlFree(str);
		cdata->type = EPP_DUMMY;
		cdata->rc = 2100;
		return;
	}
	xmlFree(str);

	/* ok, checking done. now get input parameters for corba function call */
	XPATH_REQ1(cdata->in->login.clID, doc, xpathCtx, error_l,
			"epp:login/epp:clID");
	XPATH_REQ1(cdata->in->login.pw, doc, xpathCtx, error_l,
			"epp:login/epp:pw");
	XPATH_TAKE1(cdata->in->login.newPW, doc, xpathCtx, error_l,
			"epp:login/epp:newPW");
	XPATH_TAKEN(cdata->in->login.objuri, doc, xpathCtx, error_l,
			"epp:login/epp:svcs/epp:objURI");
	XPATH_TAKEN(cdata->in->login.exturi, doc, xpathCtx, error_l,
			"epp:login/epp:svcs/epp:extURI");

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
	cl_purge(cdata->in->login.objuri);
	CL_FOREACH(cdata->in->login.exturi)
		free(CL_CONTENT(cdata->in->login.exturi));
	cl_purge(cdata->in->login.exturi);
	free(cdata->in);
	cdata->in = NULL;
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP check command.
 * @param doc Parsed XML document.
 * @param xpathCtx XPath context.
 * @param cdata Output of parsing stage.
 */
static void
parse_check(xmlDocPtr doc, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
	struct circ_list	*item;

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

	/* get object type - contact, domain or nsset */
	if (xpath_exists(xpathCtx, "epp:check/contact:check"))
	{
		/* object is contact */
		XPATH_TAKEN(cdata->in->check.ids, doc, xpathCtx, error_ch,
				"epp:check/contact:check/contact:id");
		cdata->type = EPP_CHECK_CONTACT;
	}
	else if (xpath_exists(xpathCtx,
				"epp:check/domain:check"))
	{
		/* object is a domain */
		XPATH_TAKEN(cdata->in->check.ids, doc, xpathCtx, error_ch,
				"epp:check/domain:check/domain:name");
		cdata->type = EPP_CHECK_DOMAIN;
	}
	else if (xpath_exists(xpathCtx,
				"epp:check/nsset:check"))
	{
		/* object is a nsset */
		XPATH_TAKEN(cdata->in->check.ids, doc, xpathCtx, error_ch,
				"epp:check/nsset:check/nsset:id");
		cdata->type = EPP_CHECK_NSSET;
	}
	else {
		/* unexpected object type */
		free(cdata->in->check.ids);
		free(cdata->in);
		cdata->in = NULL;
		cdata->rc = 2000;
		cdata->type = EPP_DUMMY;
		return;
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
	cl_purge(cdata->in->check.ids);
	free(cdata->in);
	cdata->in = NULL;
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP info command + list command. List command is non-standard
 * command for listing of registered objects. This makes info command very
 * special since it may contain two different commands. Authinfo tag is
 * ignored in info command.
 *
 * @param doc Parsed XML document.
 * @param xpathCtx XPath context.
 * @param cdata Output of parsing stage.
 */
static void
parse_info(xmlDocPtr doc, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
	/*
	 * catch the "list command" cases at the beginning, then proceed with
	 * info command
	 */
	if (xpath_exists(xpathCtx, "epp:info/contact:list"))
		cdata->type = EPP_LIST_CONTACT;
	else if (xpath_exists(xpathCtx, "epp:info/domain:list"))
		cdata->type = EPP_LIST_DOMAIN;
	else if (xpath_exists(xpathCtx, "epp:info/nsset:list"))
		cdata->type = EPP_LIST_NSSET;
	else {
		/* info command */
		/* allocate necessary structures */
		if ((cdata->in = calloc(1, sizeof (*cdata->in))) == NULL) {
			cdata->rc = 2400;
			cdata->type = EPP_DUMMY;
			return;
		}
		/* get object type - contact, domain or nsset */
		if (xpath_exists(xpathCtx, "epp:info/contact:info"))
		{
			/* object is contact */
			XPATH_REQ1(cdata->in->info.id, doc, xpathCtx, error_i,
					"epp:info/contact:info/contact:id");
			cdata->type = EPP_INFO_CONTACT;
		}
		else if (xpath_exists(xpathCtx, "epp:info/domain:info"))
		{
			/* object is a domain */
			XPATH_REQ1(cdata->in->info.id, doc, xpathCtx, error_i,
					"epp:info/domain:info/domain:name");
			cdata->type = EPP_INFO_DOMAIN;
		}
		else if (xpath_exists(xpathCtx, "epp:info/nsset:info"))
		{
			/* object is a nsset */
			XPATH_REQ1(cdata->in->info.id, doc, xpathCtx, error_i,
					"epp:info/nsset:info/nsset:id");
			cdata->type = EPP_INFO_NSSET;
		}
		else {
			/* unexpected object type for both (info & list) */
			free(cdata->in);
			cdata->in = NULL;
			cdata->rc = 2000;
			cdata->type = EPP_DUMMY;
		}
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
 * Parser of EPP poll command. This is for both poll variants - req and ack.
 * @param doc Parsed XML document.
 * @param xpathCtx XPath context.
 * @param cdata Output of parsing stage.
 */
static void
parse_poll(xmlDocPtr doc, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
	xmlXPathObjectPtr	xpathObj;
	xmlChar	*str;
	xmlNodePtr	node;

	/* get poll type - request or acknoledge */
	if (xpath_exists(xpathCtx, "epp:poll[@op='req']"))
	{
		/* it is request */
		cdata->type = EPP_POLL_REQ;
		return;
	}

	/* it should be acknoledge */
	xpathObj = xmlXPathEvalExpression(BAD_CAST "epp:poll[@op='ack']", xpathCtx);
	if (xpathObj == NULL) {
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	if (xmlXPathNodeSetGetLength(xpathObj->nodesetval) == 0) {
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
	node = xmlXPathNodeSetItem(xpathObj->nodesetval, 0);
	str = xmlGetProp(node, BAD_CAST "msgID");

	/*
	 * msgID attribute is not strictly required by xml schema so we
	 * have to explicitly check if it is there
	 */
	if (str == NULL) {
		struct circ_list	*new_item;
		xmlBufferPtr	buf;
		epp_error	*valerr;

		free(cdata->in);
		cdata->in = NULL;
		cdata->rc = 2003;
		cdata->type = EPP_DUMMY;

		/*
		 * we will politely create error message which says which parameter is
		 * missing.
		 */
		valerr = malloc(sizeof *valerr);
		new_item = malloc(sizeof *new_item);

		/* dump problematic node */
		buf = xmlBufferCreate();
		if (buf == NULL) {
			free(valerr);
			free(new_item);
			xmlXPathFreeObject(xpathObj);
			return;
		}
		if (xmlNodeDump(buf, doc, node, 0, 0) < 0) {
			free(valerr);
			free(new_item);
			xmlBufferFree(buf);
			xmlXPathFreeObject(xpathObj);
			return;
		}
		valerr->value = strdup((char *) buf->content);
		xmlBufferFree(buf);

		/* TODO This should be bilingual */
		valerr->reason = strdup("Required parameter msgID is missing");
		valerr->standalone = 1;

		CL_CONTENT(new_item) = (void *) valerr;
		CL_ADD(cdata->errors, new_item);

		xmlXPathFreeObject(xpathObj);
		return;
	}
	xmlXPathFreeObject(xpathObj);

	/* conversion is safe, if str is not a number, validator catches it */
	cdata->in->poll_ack.msgid = atoi((char *) str);
	xmlFree(str);
	cdata->type = EPP_POLL_ACK;
}

/**
 * Parser of EPP create-domain command.
 * @param doc Parsed XML document.
 * @param xpathCtx XPath context.
 * @param cdata Output of parsing stage.
 */
static void
parse_create_domain(
		xmlDocPtr doc,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	xmlXPathObjectPtr	xpathObj;
	struct circ_list	*item;
	char	*str;

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
	if ((cdata->in->create_domain.ds = malloc(sizeof *item)) == NULL) {
		free(cdata->in->create_domain.admin);
		free(cdata->in);
		cdata->in = NULL;
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	CL_NEW(cdata->in->create_domain.ds);

	/* get the domain data */
	XPATH_REQ1(cdata->in->create_domain.name, doc, xpathCtx, error_cd,
			"domain:name");
	XPATH_REQ1(cdata->in->create_domain.registrant, doc, xpathCtx, error_cd,
			"domain:registrant");
	XPATH_REQ1(cdata->in->create_domain.nsset, doc, xpathCtx, error_cd,
			"domain:nsset");
	XPATH_REQ1(cdata->in->create_domain.authInfo, doc, xpathCtx, error_cd,
			"domain:authInfo/domain:pw");
	/* domain period handling is slightly more difficult */
	XPATH_EVAL(xpathObj, xpathCtx, error_cd, "domain:period");
	if (xmlXPathNodeSetGetLength(xpathObj->nodesetval) == 1) {
		char	*str = (char *) xmlNodeListGetString(doc,
				xmlXPathNodeSetItem(xpathObj->nodesetval, 0)->xmlChildrenNode,
				1);
		assert(str != NULL && *str != '\0');
		cdata->in->create_domain.period = atoi(str);
		xmlFree(str);
		/* correct period value if given in years and not months */
		str = (char *) xmlGetProp(xmlXPathNodeSetItem(xpathObj->nodesetval, 0),
				BAD_CAST "unit");
		assert(str != NULL && *str != '\0');
		if (*str == 'y') cdata->in->create_domain.period *= 12;
		xmlFree(str);
	}
	else cdata->in->create_domain.period = 0;
	xmlXPathFreeObject(xpathObj);
	/* process "unbounded" number of admin contacts */
	XPATH_TAKEN(cdata->in->create_domain.admin, doc, xpathCtx, error_cd,
			"domain:admin");

	/* now look for optional extensions (extension tag is 2 layers upwards) */
	xpathCtx->node = xpathCtx->node->parent->parent;

	/* enumval extension */
	XPATH_TAKE1(str, doc, xpathCtx, error_cd,
			"epp:extension/enumval:create/enumval:valExDate");
	if (*str != '\0')
		cdata->in->create_domain.valExDate = str2timestamp(str);
	free(str);

	/* secDNS extension */
	XPATH_EVAL(xpathObj, xpathCtx, error_cd,
			"epp:extension/secdns:create/secdns:dsData");
	if (xmlXPathNodeSetGetLength(xpathObj->nodesetval) > 0) {
		epp_ds	*ds;
		int	i;

		for (i = 0; i < xmlXPathNodeSetGetLength(xpathObj->nodesetval); i++) {
			/* change relative path prefix */
			xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, i);
			/* allocate necessary structures */
			if ((item = malloc(sizeof *item)) == NULL) goto error_cd;
			if ((ds = calloc(1, sizeof *ds)) == NULL) {
				free(item);
				goto error_cd;
			}
			CL_CONTENT(item) = (void *) ds;
			CL_ADD(cdata->in->create_domain.ds, item);

			/* parse dnssec extensions */
			XPATH_REQ1(str, doc, xpathCtx, error_cd, "secdns:keyTag");
			ds->keytag = atoi(str);
			free(str);
			XPATH_REQ1(str, doc, xpathCtx, error_cd, "secdns:alg");
			ds->alg = atoi(str);
			free(str);
			XPATH_REQ1(str, doc, xpathCtx, error_cd, "secdns:digestType");
			ds->digestType = atoi(str);
			free(str);
			XPATH_REQ1(ds->digest, doc, xpathCtx, error_cd, "secdns:digest");
			XPATH_TAKE1(str, doc, xpathCtx, error_cd, "secdns:maxSigLife");
			ds->digestType = (*str == '\0') ? 0 : atoi(str);
			free(str);
			/*
			 * following fields are optional and are meaningfull only if
			 * all of them are filled in. We don't check it here, xsd takes
			 * (or at least should take) care of this.
			 */
			XPATH_TAKE1(str, doc, xpathCtx, error_cd,
					"secdns:keyData/secdns:flags");
			ds->flags = (*str == '\0') ? -1 : atoi(str);
			free(str);
			XPATH_TAKE1(str, doc, xpathCtx, error_cd,
					"secdns:keyData/secdns:protocol");
			ds->protocol = (*str == '\0') ? -1 : atoi(str);
			free(str);
			XPATH_TAKE1(str, doc, xpathCtx, error_cd,
					"secdns:keyData/secdns:alg");
			ds->key_alg = (*str == '\0') ? -1 : atoi(str);
			free(str);
			XPATH_TAKE1(ds->pubkey, doc, xpathCtx, error_cd,
					"secdns:keyData/secdns:pubKey");
		}
	}
	xmlXPathFreeObject(xpathObj);

	cdata->type = EPP_CREATE_DOMAIN;
	return;

	/*
	 * nasty error's epilog
	 * Used in case of internal critical failure. It is not terribly
	 * effecient but this case should not occure very often.
	 */
error_cd:
	FREENULL(cdata->in->create_domain.name);
	FREENULL(cdata->in->create_domain.registrant);
	FREENULL(cdata->in->create_domain.admin);
	FREENULL(cdata->in->create_domain.nsset);
	FREENULL(cdata->in->create_domain.authInfo);
	CL_FOREACH(cdata->in->create_domain.admin)
		free(CL_CONTENT(cdata->in->create_domain.admin));
	cl_purge(cdata->in->create_domain.admin);
	/* clear the extensions */
	CL_FOREACH(cdata->in->create_domain.ds) {
		FREENULL(((epp_ds *) CL_CONTENT(cdata->in->create_domain.ds))->digest);
		FREENULL(((epp_ds *) CL_CONTENT(cdata->in->create_domain.ds))->pubkey);
		free(CL_CONTENT(cdata->in->create_domain.ds));
	}
	cl_purge(cdata->in->create_domain.ds);

	free(cdata->in);
	cdata->in = NULL;
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Routine converts string to ssn type.
 *
 * @param str String to be compared and categorized.
 * @return If string is not matched, SSN_UNKNOWN is returned.
 */
static epp_ssnType
string2ssntype(const char *str)
{
	if (strcmp("op", str) == 0) return SSN_OP;
	else if (strcmp("rc", str) == 0) return SSN_RC;
	else if (strcmp("ico", str) == 0) return SSN_ICO;
	else if (strcmp("mpsv", str) == 0) return SSN_MPSV;
	else if (strcmp("passport", str) == 0) return SSN_PASSPORT;

	return SSN_UNKNOWN;
}

/**
 * Parser of EPP create-contact command.
 * @param doc Parsed XML document.
 * @param xpathCtx XPath context.
 * @param cdata Output of parsing stage.
 */
static void
parse_create_contact(
		xmlDocPtr doc,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	xmlXPathObjectPtr	xpathObj;

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
	XPATH_REQ1(cdata->in->create_contact.id, doc, xpathCtx, error_cc,
			"contact:id");
	XPATH_REQ1(cdata->in->create_contact.authInfo, doc, xpathCtx, error_cc,
			"contact:authInfo/contact:pw");
	XPATH_TAKE1(cdata->in->create_contact.voice, doc, xpathCtx, error_cc,
			"contact:voice");
	XPATH_TAKE1(cdata->in->create_contact.fax, doc, xpathCtx, error_cc,
			"contact:fax");
	XPATH_REQ1(cdata->in->create_contact.email, doc, xpathCtx, error_cc,
			"contact:email");
	XPATH_TAKE1(cdata->in->create_contact.notify_email, doc, xpathCtx, error_cc,
			"contact:notifyEmail");
	XPATH_TAKE1(cdata->in->create_contact.vat, doc, xpathCtx, error_cc,
			"contact:vat");
	XPATH_EVAL(xpathObj, xpathCtx, error_cc, "contact:ssn");
	if (xmlXPathNodeSetGetLength(xpathObj->nodesetval) == 1) {
		char	*str;

		/* get content of ssn */
		cdata->in->create_contact.ssn = (char *) xmlNodeListGetString(doc,
				xmlXPathNodeSetItem(xpathObj->nodesetval,0)->xmlChildrenNode, 1);
		/* get value of attr type */
		str = (char *) xmlGetProp(xmlXPathNodeSetItem(xpathObj->nodesetval, 0),
				BAD_CAST "type");
		assert(str != NULL);
		cdata->in->create_contact.ssntype = string2ssntype(str);
		free(str);
		/* schema and source code is out of sync if following error occurs */
		assert(cdata->in->create_contact.ssntype != SSN_UNKNOWN);
	}
	else {
		cdata->in->create_contact.ssn = strdup("");
		cdata->in->create_contact.ssntype = SSN_UNKNOWN;
	}
	xmlXPathFreeObject(xpathObj);

	/* disclose info */
	if (xpath_exists(xpathCtx, "contact:disclose[@flag='0']"))
	{
		cdata->in->create_contact.discl->name = xpath_exists(xpathCtx,
				"contact:disclose/contact:name");
		cdata->in->create_contact.discl->org = xpath_exists(xpathCtx,
				"contact:disclose/contact:org");
		cdata->in->create_contact.discl->addr = xpath_exists(xpathCtx,
				"contact:disclose/contact:addr");
		cdata->in->create_contact.discl->voice = xpath_exists(xpathCtx,
				"contact:disclose/contact:voice");
		cdata->in->create_contact.discl->fax = xpath_exists(xpathCtx,
				"contact:disclose/contact:fax");
		cdata->in->create_contact.discl->email = xpath_exists(xpathCtx,
				"contact:disclose/contact:email");
	}
	/* postal info, change relative root */
	XPATH_EVAL(xpathObj, xpathCtx, error_cc, "contact:postalInfo");
	assert(xmlXPathNodeSetGetLength(xpathObj->nodesetval) == 1);
	xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, 0);
	xmlXPathFreeObject(xpathObj);

	XPATH_REQ1(cdata->in->create_contact.postalInfo->name, doc, xpathCtx,
			error_cc, "contact:name");
	XPATH_TAKE1(cdata->in->create_contact.postalInfo->org, doc, xpathCtx,
			error_cc, "contact:org");
	XPATH_EVAL(xpathObj, xpathCtx, error_cc, "contact:addr/contact:street");
	if (xpathObj->nodesetval) {
		int	i, j;
		for (i = 0; i < xmlXPathNodeSetGetLength(xpathObj->nodesetval); i++)
			cdata->in->create_contact.postalInfo->street[i] = (char *)
					xmlNodeListGetString(doc, xmlXPathNodeSetItem(
								xpathObj->nodesetval, i)->xmlChildrenNode, 1);
		/* the rest must be empty strings */
		for (j = i; j < 3; j++)
			cdata->in->create_contact.postalInfo->street[j] = strdup("");
	}
	xmlXPathFreeObject(xpathObj);
	XPATH_REQ1(cdata->in->create_contact.postalInfo->city, doc, xpathCtx,
			error_cc, "contact:addr/contact:city");
	XPATH_TAKE1(cdata->in->create_contact.postalInfo->sp, doc, xpathCtx,
			error_cc, "contact:addr/contact:sp");
	XPATH_TAKE1(cdata->in->create_contact.postalInfo->pc, doc, xpathCtx,
			error_cc, "contact:addr/contact:pc");
	XPATH_REQ1(cdata->in->create_contact.postalInfo->cc, doc, xpathCtx,
			error_cc, "contact:addr/contact:cc");

	cdata->type = EPP_CREATE_CONTACT;
	return;

	/*
	 * nasty error's epilog
	 * Used in case of internal critical failure. It is not terribly
	 * effecient but this case should not occure very often.
	 */
error_cc:
	FREENULL(cdata->in->create_contact.id);
	FREENULL(cdata->in->create_contact.authInfo);
	FREENULL(cdata->in->create_contact.voice);
	FREENULL(cdata->in->create_contact.fax);
	FREENULL(cdata->in->create_contact.email);
	FREENULL(cdata->in->create_contact.notify_email);
	FREENULL(cdata->in->create_contact.vat);
	FREENULL(cdata->in->create_contact.ssn);
	/* postal info */
	FREENULL(cdata->in->create_contact.postalInfo->name);
	FREENULL(cdata->in->create_contact.postalInfo->org);
	FREENULL(cdata->in->create_contact.postalInfo->street[0]);
	FREENULL(cdata->in->create_contact.postalInfo->street[1]);
	FREENULL(cdata->in->create_contact.postalInfo->street[2]);
	FREENULL(cdata->in->create_contact.postalInfo->city);
	FREENULL(cdata->in->create_contact.postalInfo->sp);
	FREENULL(cdata->in->create_contact.postalInfo->pc);
	FREENULL(cdata->in->create_contact.postalInfo->cc);
	free(cdata->in->create_contact.postalInfo);
	/* disclose info */
	free(cdata->in->create_contact.discl);
	free(cdata->in);
	cdata->in = NULL;
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP create-nsset command.
 * @param doc Parsed XML document.
 * @param xpathCtx XPath context.
 * @param cdata Output of parsing stage.
 */
static void
parse_create_nsset(
		xmlDocPtr doc,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	xmlXPathObjectPtr	xpathObj;
	struct circ_list	*item;
	int	j;

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
	XPATH_REQ1(cdata->in->create_nsset.id, doc, xpathCtx, error_cn, "nsset:id");
	XPATH_REQ1(cdata->in->create_nsset.authInfo, doc, xpathCtx, error_cn,
			"nsset:authInfo/nsset:pw");
	/* process "unbounded" number of tech contacts */
	XPATH_TAKEN(cdata->in->create_nsset.tech, doc, xpathCtx, error_cn,
			"nsset:tech");
	/* process multiple ns records which have in turn multiple addresses */
	XPATH_EVAL(xpathObj, xpathCtx, error_cn, "nsset:ns");
	assert(xmlXPathNodeSetGetLength(xpathObj->nodesetval) > 0);
	for (j = 0; j < xmlXPathNodeSetGetLength(xpathObj->nodesetval); j++) {
		epp_ns	*ns = NULL;
		struct circ_list	*item = NULL;

		/* allocate data structures */
		if ((item = malloc(sizeof *item)) == NULL) goto error_cn2;
		CL_NEW(item);
		if ((ns = malloc(sizeof *ns)) == NULL) goto error_cn2;
		if ((ns->addr = malloc(sizeof *(ns->addr))) == NULL) goto error_cn2;
		CL_NEW(ns->addr);
		/* get data */
		xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, j);
		XPATH_REQ1(ns->name, doc, xpathCtx, error_cn2, "nsset:name");
		XPATH_TAKEN(ns->addr, doc, xpathCtx, error_cn2, "nsset:addr");
		/* enqueue ns record */
		CL_CONTENT(item) = ns;
		CL_ADD(cdata->in->create_nsset.ns, item);
		continue;
error_cn2:
		/*
		 * free items which would be otherwise lost in case of jump to
		 * error_cn label
		 */
		free(item);
		free(ns);
		xmlXPathFreeObject(xpathObj);
		goto error_cn;
	}
	xmlXPathFreeObject(xpathObj);

	cdata->type = EPP_CREATE_NSSET;
	return;

	/*
	 * nasty error's epilog
	 * Used in case of internal critical failure. It is not terribly
	 * effecient but this case should not occure very often.
	 */
error_cn:
	FREENULL(cdata->in->create_nsset.id);
	FREENULL(cdata->in->create_nsset.authInfo);
	CL_FOREACH(cdata->in->create_nsset.tech)
		free(CL_CONTENT(cdata->in->create_nsset.tech));
	cl_purge(cdata->in->create_nsset.tech);
	CL_FOREACH(cdata->in->create_nsset.ns) {
		epp_ns	*ns = (epp_ns *) CL_CONTENT(cdata->in->create_nsset.ns);
		FREENULL(ns->name);
		CL_FOREACH(ns->addr) free(CL_CONTENT(ns->addr));
		cl_purge(ns->addr);
		free(ns);
	}
	cl_purge(cdata->in->create_nsset.ns);
	free(cdata->in);
	cdata->in = NULL;
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP create command.
 * @param doc Parsed XML document.
 * @param xpathCtx XPath context.
 * @param cdata Output of parsing stage.
 */
static void
parse_create(
		xmlDocPtr doc,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	xmlXPathObjectPtr	xpathObj;

	/* get object type - contact, domain or nsset */
	XPATH_EVAL(xpathObj, xpathCtx, error_c, "epp:create/contact:create");
	if (xmlXPathNodeSetGetLength(xpathObj->nodesetval) == 1) {
		/* change relative path prefix */
		xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, 0);
		xmlXPathFreeObject(xpathObj);
		parse_create_contact(doc, xpathCtx, cdata);
		return;
	}
	xmlXPathFreeObject(xpathObj);

	XPATH_EVAL(xpathObj, xpathCtx, error_c, "epp:create/domain:create");
	if (xmlXPathNodeSetGetLength(xpathObj->nodesetval) == 1) {
		/* change relative path prefix and backup old one */
		xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, 0);
		xmlXPathFreeObject(xpathObj);
		parse_create_domain(doc, xpathCtx, cdata);
		return;
	}
	xmlXPathFreeObject(xpathObj);

	XPATH_EVAL(xpathObj, xpathCtx, error_c, "epp:create/nsset:create");
	if (xmlXPathNodeSetGetLength(xpathObj->nodesetval) == 1) {
		/* change relative path prefix */
		xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, 0);
		xmlXPathFreeObject(xpathObj);
		parse_create_nsset(doc, xpathCtx, cdata);
		return;
	}
	xmlXPathFreeObject(xpathObj);

	/* unexpected object type */
	cdata->rc = 2000;
	cdata->type = EPP_DUMMY;
	return;

error_c:
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP delete command.
 * @param doc Parsed XML document.
 * @param xpathCtx XPath context.
 * @param cdata Output of parsing stage.
 */
static void
parse_delete(
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

	/* get object type - contact, domain or nsset */
	if (xpath_exists(xpathCtx,"epp:delete/contact:delete"))
	{
		/* object is contact */
		XPATH_REQ1(cdata->in->delete.id, doc, xpathCtx, error_d,
				"epp:delete/contact:delete/contact:id");
		cdata->type = EPP_DELETE_CONTACT;
	}
	else if (xpath_exists(xpathCtx, "epp:delete/domain:delete"))
	{
		/* object is a domain */
		XPATH_REQ1(cdata->in->delete.id, doc, xpathCtx, error_d,
				"epp:delete/domain:delete/domain:name");
		cdata->type = EPP_DELETE_DOMAIN;
	}
	else if (xpath_exists(xpathCtx, "epp:delete/nsset:delete"))
	{
		/* object is a nsset */
		XPATH_REQ1(cdata->in->delete.id, doc, xpathCtx, error_d,
				"epp:delete/nsset:delete/nsset:id");
		cdata->type = EPP_DELETE_NSSET;
	}
	else {
		/* unexpected object type */
		free(cdata->in);
		cdata->in = NULL;
		cdata->rc = 2000;
		cdata->type = EPP_DUMMY;
	}
	return;

error_d:
	/* nasty error's epilog */
	FREENULL(cdata->in->delete.id);
	free(cdata->in);
	cdata->in = NULL;
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP update-domain command.
 * @param doc Parsed XML document.
 * @param xpathCtx XPath context.
 * @param cdata Output of parsing stage.
 */
static void
parse_update_domain(
		xmlDocPtr doc,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	xmlXPathObjectPtr	xpathObj;
	struct circ_list	*item;
	char	*str;

	/* allocate necessary structures */
	if ((cdata->in = calloc(1, sizeof (*cdata->in))) == NULL) {
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	if ((cdata->in->update_domain.add_admin = malloc(sizeof *item)) == NULL) {
		free(cdata->in);
		cdata->in = NULL;
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	CL_NEW(cdata->in->update_domain.add_admin);
	if ((cdata->in->update_domain.rem_admin = malloc(sizeof *item)) == NULL) {
		free(cdata->in->update_domain.add_admin);
		free(cdata->in);
		cdata->in = NULL;
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	CL_NEW(cdata->in->update_domain.rem_admin);
	if ((cdata->in->update_domain.add_status = malloc(sizeof *item)) == NULL) {
		free(cdata->in->update_domain.add_admin);
		free(cdata->in->update_domain.rem_admin);
		free(cdata->in);
		cdata->in = NULL;
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	CL_NEW(cdata->in->update_domain.add_status);
	if ((cdata->in->update_domain.rem_status = malloc(sizeof *item)) == NULL) {
		free(cdata->in->update_domain.add_status);
		free(cdata->in->update_domain.add_admin);
		free(cdata->in->update_domain.rem_admin);
		free(cdata->in);
		cdata->in = NULL;
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	CL_NEW(cdata->in->update_domain.rem_status);
	if ((cdata->in->update_domain.chg_ds = malloc(sizeof *item)) == NULL) {
		free(cdata->in->update_domain.rem_status);
		free(cdata->in->update_domain.add_status);
		free(cdata->in->update_domain.add_admin);
		free(cdata->in->update_domain.rem_admin);
		free(cdata->in);
		cdata->in = NULL;
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	CL_NEW(cdata->in->update_domain.chg_ds);
	if ((cdata->in->update_domain.add_ds = malloc(sizeof *item)) == NULL) {
		free(cdata->in->update_domain.chg_ds);
		free(cdata->in->update_domain.rem_status);
		free(cdata->in->update_domain.add_status);
		free(cdata->in->update_domain.add_admin);
		free(cdata->in->update_domain.rem_admin);
		free(cdata->in);
		cdata->in = NULL;
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	CL_NEW(cdata->in->update_domain.add_ds);
	if ((cdata->in->update_domain.rem_ds = malloc(sizeof *item)) == NULL) {
		free(cdata->in->update_domain.add_ds);
		free(cdata->in->update_domain.chg_ds);
		free(cdata->in->update_domain.rem_status);
		free(cdata->in->update_domain.add_status);
		free(cdata->in->update_domain.add_admin);
		free(cdata->in->update_domain.rem_admin);
		free(cdata->in);
		cdata->in = NULL;
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	CL_NEW(cdata->in->update_domain.rem_ds);

	/* get the update-domain data */
	XPATH_REQ1(cdata->in->update_domain.name, doc, xpathCtx, error_ud,
			"domain:name");
	/* chg data */
	XPATH_TAKE1_UPD(cdata->in->update_domain.registrant, doc, xpathCtx, error_ud,
			"domain:chg/domain:registrant");
	XPATH_TAKE1_UPD(cdata->in->update_domain.nsset, doc, xpathCtx, error_ud,
			"domain:chg/domain:nsset");
	XPATH_TAKE1_UPD(cdata->in->update_domain.authInfo, doc, xpathCtx, error_ud,
			"domain:chg/domain:authInfo/domain:pw");
	/* add & rem data */
	XPATH_TAKEN(cdata->in->update_domain.add_admin, doc, xpathCtx, error_ud,
			"domain:add/domain:admin");
	XPATH_TAKEN(cdata->in->update_domain.rem_admin, doc, xpathCtx, error_ud,
			"domain:rem/domain:admin");
	/* status (attrs) */
	XPATH_TAKEN_ATTR(cdata->in->update_domain.add_status, xpathCtx, error_ud,
			"domain:add/domain:status", "s");
	XPATH_TAKEN_ATTR(cdata->in->update_domain.rem_status, xpathCtx, error_ud,
			"domain:rem/domain:status", "s");

	/* now look for optional extensions (extension tag is 2 layers upwards) */
	xpathCtx->node = xpathCtx->node->parent->parent;

	/* enumval extension */
	XPATH_TAKE1(str, doc, xpathCtx, error_ud,
			"epp:extension/enumval:update/enumval:chg/enumval:valExDate");
	if (*str != '\0')
		cdata->in->update_domain.valExDate = str2timestamp(str);
	free(str);

	/* secDNS extension */
	XPATH_EVAL(xpathObj, xpathCtx, error_ud, "epp:extension/secdns:update");
	if (xmlXPathNodeSetGetLength(xpathObj->nodesetval) > 0) {
		epp_ds	*ds;
		int	i;
		unsigned	*num;

		xmlXPathFreeObject(xpathObj);
		/* rem */
		XPATH_EVAL(xpathObj, xpathCtx, error_ud, "secdns:rem/secdns:keyTag");
		for (i = 0; i < xmlXPathNodeSetGetLength(xpathObj->nodesetval); i++) {
			if ((item = malloc(sizeof *item)) == NULL) goto error_ud;
			if ((num = malloc(sizeof *num)) == NULL) {
				free(item);
				goto error_ud;
			}
			CL_ADD(cdata->in->update_domain.rem_ds, item);
			CL_CONTENT(item) = (void *) num;
			str = (char *) xmlNodeListGetString(doc,
				xmlXPathNodeSetItem(xpathObj->nodesetval, i)->xmlChildrenNode,1);
			*num = atoi(str);
		}
		xmlXPathFreeObject(xpathObj);
		/* add */
		XPATH_EVAL(xpathObj, xpathCtx, error_ud, "secdns:add/secdns:dsData");
		for (i = 0; i < xmlXPathNodeSetGetLength(xpathObj->nodesetval); i++) {
			/* change relative path prefix */
			xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, i);
			/* allocate necessary structures */
			if ((item = malloc(sizeof *item)) == NULL) goto error_ud;
			if ((ds = calloc(1, sizeof *ds)) == NULL) {
				free(item);
				goto error_ud;
			}
			CL_CONTENT(item) = (void *) ds;
			CL_ADD(cdata->in->update_domain.add_ds, item);

			/* parse dnssec extensions */
			XPATH_REQ1(str, doc, xpathCtx, error_ud, "secdns:keyTag");
			ds->keytag = atoi(str);
			free(str);
			XPATH_REQ1(str, doc, xpathCtx, error_ud, "secdns:alg");
			ds->alg = atoi(str);
			free(str);
			XPATH_REQ1(str, doc, xpathCtx, error_ud, "secdns:digestType");
			ds->digestType = atoi(str);
			free(str);
			XPATH_REQ1(ds->digest, doc, xpathCtx, error_ud, "secdns:digest");
			XPATH_TAKE1(str, doc, xpathCtx, error_ud, "secdns:maxSigLife");
			ds->digestType = (*str == '\0') ? 0 : atoi(str);
			free(str);
			/*
			 * following fields are optional and are meaningfull only if
			 * all of them are filled in. We don't check it here, xsd takes
			 * (or at least should take) care of this.
			 */
			XPATH_TAKE1(str, doc, xpathCtx, error_ud,
					"secdns:keyData/secdns:flags");
			ds->flags = (*str == '\0') ? -1 : atoi(str);
			free(str);
			XPATH_TAKE1(str, doc, xpathCtx, error_ud,
					"secdns:keyData/secdns:protocol");
			ds->protocol = (*str == '\0') ? -1 : atoi(str);
			free(str);
			XPATH_TAKE1(str, doc, xpathCtx, error_ud,
					"secdns:keyData/secdns:alg");
			ds->key_alg = (*str == '\0') ? -1 : atoi(str);
			free(str);
			XPATH_TAKE1(ds->pubkey, doc, xpathCtx, error_ud,
					"secdns:keyData/secdns:pubKey");
		}
		/* chg */
		xmlXPathFreeObject(xpathObj);
		XPATH_EVAL(xpathObj, xpathCtx, error_ud, "secdns:chg/secdns:dsData");
		for (i = 0; i < xmlXPathNodeSetGetLength(xpathObj->nodesetval); i++) {
			/* change relative path prefix */
			xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, i);
			/* allocate necessary structures */
			if ((item = malloc(sizeof *item)) == NULL) goto error_ud;
			if ((ds = calloc(1, sizeof *ds)) == NULL) {
				free(item);
				goto error_ud;
			}
			CL_CONTENT(item) = (void *) ds;
			CL_ADD(cdata->in->update_domain.chg_ds, item);

			/* parse dnssec extensions */
			XPATH_REQ1(str, doc, xpathCtx, error_ud, "secdns:keyTag");
			ds->keytag = atoi(str);
			free(str);
			XPATH_REQ1(str, doc, xpathCtx, error_ud, "secdns:alg");
			ds->alg = atoi(str);
			free(str);
			XPATH_REQ1(str, doc, xpathCtx, error_ud, "secdns:digestType");
			ds->digestType = atoi(str);
			free(str);
			XPATH_REQ1(ds->digest, doc, xpathCtx, error_ud, "secdns:digest");
			XPATH_TAKE1(str, doc, xpathCtx, error_ud, "secdns:maxSigLife");
			ds->digestType = (*str == '\0') ? 0 : atoi(str);
			free(str);
			/*
			 * following fields are optional and are meaningfull only if
			 * all of them are filled in. We don't check it here, xsd takes
			 * (or at least should take) care of this.
			 */
			XPATH_TAKE1(str, doc, xpathCtx, error_ud,
					"secdns:keyData/secdns:flags");
			ds->flags = (*str == '\0') ? -1 : atoi(str);
			free(str);
			XPATH_TAKE1(str, doc, xpathCtx, error_ud,
					"secdns:keyData/secdns:protocol");
			ds->protocol = (*str == '\0') ? -1 : atoi(str);
			free(str);
			XPATH_TAKE1(str, doc, xpathCtx, error_ud,
					"secdns:keyData/secdns:alg");
			ds->key_alg = (*str == '\0') ? -1 : atoi(str);
			free(str);
			XPATH_TAKE1(ds->pubkey, doc, xpathCtx, error_ud,
					"secdns:keyData/secdns:pubKey");
		}
	}
	xmlXPathFreeObject(xpathObj);

	cdata->type = EPP_UPDATE_DOMAIN;
	return;

	/*
	 * nasty error's epilog
	 * Used in case of internal critical failure. It is not terribly
	 * effecient but this case should not occure very often.
	 */
error_ud:
	FREENULL(cdata->in->update_domain.name);
	FREENULL(cdata->in->update_domain.registrant);
	FREENULL(cdata->in->update_domain.nsset);
	FREENULL(cdata->in->update_domain.authInfo);
	/* free contact */
	CL_FOREACH(cdata->in->update_domain.add_admin)
		free(CL_CONTENT(cdata->in->update_domain.add_admin));
	cl_purge(cdata->in->update_domain.add_admin);
	CL_FOREACH(cdata->in->update_domain.rem_admin)
		free(CL_CONTENT(cdata->in->update_domain.rem_admin));
	cl_purge(cdata->in->update_domain.rem_admin);
	/* free status */
	CL_FOREACH(cdata->in->update_domain.add_status)
		free(CL_CONTENT(cdata->in->update_domain.add_status));
	cl_purge(cdata->in->update_domain.add_status);
	CL_FOREACH(cdata->in->update_domain.rem_status)
		free(CL_CONTENT(cdata->in->update_domain.rem_status));
	cl_purge(cdata->in->update_domain.rem_status);

	/* clear the extensions */
	CL_FOREACH(cdata->in->update_domain.chg_ds) {
		FREENULL(((epp_ds *)
					CL_CONTENT(cdata->in->update_domain.chg_ds))->digest);
		FREENULL(((epp_ds *)
					CL_CONTENT(cdata->in->update_domain.chg_ds))->pubkey);
		free(CL_CONTENT(cdata->in->update_domain.chg_ds));
	}
	cl_purge(cdata->in->update_domain.chg_ds);
	CL_FOREACH(cdata->in->update_domain.add_ds) {
		FREENULL(((epp_ds *)
					CL_CONTENT(cdata->in->update_domain.add_ds))->digest);
		FREENULL(((epp_ds *)
					CL_CONTENT(cdata->in->update_domain.add_ds))->pubkey);
		free(CL_CONTENT(cdata->in->update_domain.add_ds));
	}
	cl_purge(cdata->in->update_domain.add_ds);
	CL_FOREACH(cdata->in->update_domain.rem_ds)
		free(CL_CONTENT(cdata->in->update_domain.rem_ds));
	cl_purge(cdata->in->update_domain.rem_ds);

	free(cdata->in);
	cdata->in = NULL;
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP update-contact command.
 * @param doc Parsed XML document.
 * @param xpathCtx XPath context.
 * @param cdata Output of parsing stage.
 */
static void
parse_update_contact(
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
	if ((cdata->in->update_contact.add_status = malloc(sizeof *item)) == NULL) {
		free(cdata->in);
		cdata->in = NULL;
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	CL_NEW(cdata->in->update_contact.add_status);
	if ((cdata->in->update_contact.rem_status = malloc(sizeof *item)) == NULL) {
		free(cdata->in->update_contact.add_status);
		free(cdata->in);
		cdata->in = NULL;
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	CL_NEW(cdata->in->update_contact.rem_status);
	if ((cdata->in->update_contact.discl = calloc(1, sizeof
			*(cdata->in->update_contact.discl))) == NULL) {
		free(cdata->in->update_contact.rem_status);
		free(cdata->in->update_contact.add_status);
		free(cdata->in);
		cdata->in = NULL;
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	if ((cdata->in->update_contact.postalInfo = calloc(1, sizeof
			*(cdata->in->update_contact.postalInfo))) == NULL) {
		free(cdata->in->update_contact.discl);
		free(cdata->in->update_contact.rem_status);
		free(cdata->in->update_contact.add_status);
		free(cdata->in);
		cdata->in = NULL;
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}

	/* get the update-contact data */
	/* the most difficult item comes first (ssn) */
	XPATH_TAKE1_UPD(cdata->in->update_contact.ssn, doc, xpathCtx, error_uc,
			"contact:chg/contact:ssn");
	if (*cdata->in->update_contact.ssn == '\0' ||
			*cdata->in->update_contact.ssn == BS_CHAR)
	{
		cdata->in->update_contact.ssntype = SSN_UNKNOWN;
	}
	else {
	/* depending on ssn value we decide what to do with attribute */
		char	*str;

		XPATH_EVAL(xpathObj, xpathCtx, error_uc, "contact:chg/contact:ssn");
		assert(xmlXPathNodeSetGetLength(xpathObj->nodesetval) == 1);

		/* get value of attr type */
		str = (char *) xmlGetProp(xmlXPathNodeSetItem(xpathObj->nodesetval, 0),
				BAD_CAST "type");
		/* attribute must be present in this case */
		if (str == NULL) {
			/* create our custom error */
			struct circ_list	*new_item;
			xmlBufferPtr	buf;
			epp_error	*valerr;

			free(cdata->in->update_contact.add_status);
			free(cdata->in->update_contact.rem_status);
			free(cdata->in->update_contact.discl);
			free(cdata->in->update_contact.postalInfo);
			free(cdata->in);
			cdata->in = NULL;
			cdata->rc = 2003;
			cdata->type = EPP_DUMMY;

			/*
			 * we will politely create error message which says which
			 * parameter is missing.
			 */
			valerr = malloc(sizeof *valerr);
			new_item = malloc(sizeof *new_item);

			/* dump problematic node */
			buf = xmlBufferCreate();
			if (buf == NULL) {
				free(valerr);
				free(new_item);
				xmlXPathFreeObject(xpathObj);
				return;
			}
			if (xmlNodeDump(buf, doc,
						xmlXPathNodeSetItem(xpathObj->nodesetval, 0), 0, 0) < 0)
			{
				free(valerr);
				free(new_item);
				xmlBufferFree(buf);
				xmlXPathFreeObject(xpathObj);
				return;
			}
			valerr->value = strdup((char *) buf->content);
			xmlBufferFree(buf);

			/* TODO This should be bilingual */
			valerr->reason = strdup("Required parameter \"type\" is missing");
			valerr->standalone = 1;

			CL_CONTENT(new_item) = (void *) valerr;
			CL_ADD(cdata->errors, new_item);

			xmlXPathFreeObject(xpathObj);
			return;
		}
		xmlXPathFreeObject(xpathObj);
		cdata->in->update_contact.ssntype = string2ssntype(str);
		free(str);
		/* schema and source code is out of sync if following error occurs */
		assert(cdata->in->update_contact.ssntype != SSN_UNKNOWN);
	}

	XPATH_REQ1(cdata->in->update_contact.id, doc, xpathCtx, error_uc,
			"contact:id");
	/* chg data */
	XPATH_TAKE1_UPD(cdata->in->update_contact.authInfo, doc, xpathCtx, error_uc,
			"contact:chg/contact:authInfo/contact:pw");
	XPATH_TAKE1_UPD(cdata->in->update_contact.voice, doc, xpathCtx, error_uc,
			"contact:chg/contact:voice");
	XPATH_TAKE1_UPD(cdata->in->update_contact.fax, doc, xpathCtx, error_uc,
			"contact:chg/contact:fax");
	XPATH_TAKE1(cdata->in->update_contact.email, doc, xpathCtx, error_uc,
			"contact:chg/contact:email");
	XPATH_TAKE1(cdata->in->update_contact.authInfo, doc, xpathCtx, error_uc,
			"contact:chg/contact:authInfo/contact:pw");
	XPATH_TAKE1_UPD(cdata->in->update_contact.notify_email, doc, xpathCtx,
			error_uc,
			"contact:chg/contact:notifyEmail");
	XPATH_TAKE1_UPD(cdata->in->update_contact.vat, doc, xpathCtx, error_uc,
			"contact:chg/contact:vat");
	/*
	 * there can be just one disclose section, now it depens if with flag
	 * 0 or 1
	 */
	if (xpath_exists(xpathCtx, "contact:chg/contact:disclose[@flag='0']"))
	{
		cdata->in->update_contact.discl->name = xpath_exists(xpathCtx,
				"contact:chg/contact:disclose/contact:name");
		cdata->in->update_contact.discl->org = xpath_exists(xpathCtx,
				"contact:chg/contact:disclose/contact:org");
		cdata->in->update_contact.discl->addr = xpath_exists(xpathCtx,
				"contact:chg/contact:disclose/contact:addr");
		cdata->in->update_contact.discl->voice = xpath_exists(xpathCtx,
				"contact:chg/contact:disclose/contact:voice");
		cdata->in->update_contact.discl->fax = xpath_exists(xpathCtx,
				"contact:chg/contact:disclose/contact:fax");
		cdata->in->update_contact.discl->email = xpath_exists(xpathCtx,
				"contact:chg/contact:disclose/contact:email");
	}
	else if (xpath_exists(xpathCtx, "contact:chg/contact:disclose[@flag='1']"))
	{
		/*
		 * disclose with flag 1 is non-sense (literally to specify attributes
		 * which should be disclosed - handled exceptionally - when server's
		 * default policy is to disclose all, doesn't make any sence.
		 */
		cdata->in->update_contact.discl->name = 0;
		cdata->in->update_contact.discl->org = 0;
		cdata->in->update_contact.discl->addr = 0;
		cdata->in->update_contact.discl->voice = 0;
		cdata->in->update_contact.discl->fax = 0;
		cdata->in->update_contact.discl->email = 0;
	}
	else {
		/* fill discl with value "not updated" -1 */
		cdata->in->update_contact.discl->name = -1;
		cdata->in->update_contact.discl->org = -1;
		cdata->in->update_contact.discl->addr = -1;
		cdata->in->update_contact.discl->voice = -1;
		cdata->in->update_contact.discl->fax = -1;
		cdata->in->update_contact.discl->email = -1;
	}
	/* is there postalInfo section ? */
	if (xpath_exists(xpathCtx,
			"contact:chg/contact:postalInfo"))
	{
		XPATH_TAKE1_UPD(cdata->in->update_contact.postalInfo->name,
				doc, xpathCtx, error_uc,
				"contact:chg/contact:postalInfo/contact:name");
		XPATH_TAKE1_UPD(cdata->in->update_contact.postalInfo->org,
				doc, xpathCtx, error_uc,
				"contact:chg/contact:postalInfo/contact:org");
		/* is there address section? */
		if (xpath_exists(xpathCtx,
				"contact:chg/contact:postalInfo/contact:addr"))
		{
			XPATH_TAKE1_UPD(cdata->in->update_contact.postalInfo->city,
					doc, xpathCtx, error_uc,
					"contact:chg/contact:postalInfo/contact:addr/contact:city");
			XPATH_TAKE1_UPD(cdata->in->update_contact.postalInfo->sp,
					doc, xpathCtx, error_uc,
					"contact:chg/contact:postalInfo/contact:addr/contact:sp");
			XPATH_TAKE1_UPD(cdata->in->update_contact.postalInfo->pc,
					doc, xpathCtx, error_uc,
					"contact:chg/contact:postalInfo/contact:addr/contact:pc");
			XPATH_TAKE1_UPD(cdata->in->update_contact.postalInfo->cc,
					doc, xpathCtx, error_uc,
					"contact:chg/contact:postalInfo/contact:addr/contact:cc");
			XPATH_EVAL(xpathObj, xpathCtx, error_uc,
				"contact:chg/contact:postalInfo/contact:addr/contact:street");
			if (xpathObj->nodesetval) {
				int	i, j;
				for (i = 0;
						i < xmlXPathNodeSetGetLength(xpathObj->nodesetval);
						i++)
					cdata->in->update_contact.postalInfo->street[i] = (char *)
							xmlNodeListGetString(doc, xmlXPathNodeSetItem(
								xpathObj->nodesetval, i)->xmlChildrenNode, 1);
				/* the rest must be "backspace" strings */
				for (j = i; j < 3; j++) {
					char *str = malloc(2);
					str[0] = BS_CHAR;
					str[1] = '\0';
					cdata->in->update_contact.postalInfo->street[j] = str;
				}
			}
			xmlXPathFreeObject(xpathObj);
		}
		else {
			/* fill empty strings in address fields */
			cdata->in->update_contact.postalInfo->street[0] = strdup("");
			cdata->in->update_contact.postalInfo->street[1] = strdup("");
			cdata->in->update_contact.postalInfo->street[2] = strdup("");
			cdata->in->update_contact.postalInfo->city = strdup("");
			cdata->in->update_contact.postalInfo->sp = strdup("");
			cdata->in->update_contact.postalInfo->pc = strdup("");
			cdata->in->update_contact.postalInfo->cc = strdup("");
		}
	}
	else {
		/* fill empty strings in postal info */
		cdata->in->update_contact.postalInfo->name = strdup("");
		cdata->in->update_contact.postalInfo->org = strdup("");
		cdata->in->update_contact.postalInfo->street[0] = strdup("");
		cdata->in->update_contact.postalInfo->street[1] = strdup("");
		cdata->in->update_contact.postalInfo->street[2] = strdup("");
		cdata->in->update_contact.postalInfo->city = strdup("");
		cdata->in->update_contact.postalInfo->sp = strdup("");
		cdata->in->update_contact.postalInfo->pc = strdup("");
		cdata->in->update_contact.postalInfo->cc = strdup("");
	}
	/* add & rem data */
	/* status (attrs) */
	XPATH_TAKEN_ATTR(cdata->in->update_contact.add_status, xpathCtx, error_uc,
			"contact:add/contact:status", "s");
	XPATH_TAKEN_ATTR(cdata->in->update_contact.rem_status, xpathCtx, error_uc,
			"contact:rem/contact:status", "s");

	cdata->type = EPP_UPDATE_CONTACT;
	return;

	/*
	 * nasty error's epilog
	 * Used in case of internal critical failure. It is not terribly
	 * effecient but this case should not occure very often.
	 */
error_uc:
	FREENULL(cdata->in->update_contact.id);
	FREENULL(cdata->in->update_contact.voice);
	FREENULL(cdata->in->update_contact.fax);
	FREENULL(cdata->in->update_contact.email);
	FREENULL(cdata->in->update_contact.authInfo);
	FREENULL(cdata->in->update_contact.notify_email);
	FREENULL(cdata->in->update_contact.vat);
	FREENULL(cdata->in->update_contact.ssn);
	free(cdata->in->update_contact.discl);
	/* postal info */
	FREENULL(cdata->in->update_contact.postalInfo->name);
	FREENULL(cdata->in->update_contact.postalInfo->org);
	FREENULL(cdata->in->update_contact.postalInfo->street[0]);
	FREENULL(cdata->in->update_contact.postalInfo->street[1]);
	FREENULL(cdata->in->update_contact.postalInfo->street[2]);
	FREENULL(cdata->in->update_contact.postalInfo->city);
	FREENULL(cdata->in->update_contact.postalInfo->sp);
	FREENULL(cdata->in->update_contact.postalInfo->pc);
	FREENULL(cdata->in->update_contact.postalInfo->cc);
	free(cdata->in->update_contact.postalInfo);
	/* free status */
	CL_FOREACH(cdata->in->update_contact.add_status)
		free(CL_CONTENT(cdata->in->update_contact.add_status));
	cl_purge(cdata->in->update_contact.add_status);
	CL_FOREACH(cdata->in->update_contact.rem_status)
		free(CL_CONTENT(cdata->in->update_contact.rem_status));
	cl_purge(cdata->in->update_contact.rem_status);
	free(cdata->in);
	cdata->in = NULL;
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP update-nsset command.
 * @param doc Parsed XML document.
 * @param xpathCtx XPath context.
 * @param cdata Output of parsing stage.
 */
static void
parse_update_nsset(
		xmlDocPtr doc,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	struct circ_list	*item;
	xmlNodePtr	node;	/* for saving xpath context */
	xmlXPathObjectPtr	xpathObj;
	int	j;

	/* allocate necessary structures */
	if ((cdata->in = calloc(1, sizeof (*cdata->in))) == NULL) {
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	if ((cdata->in->update_nsset.add_ns = malloc(sizeof *item)) == NULL) {
		free(cdata->in);
		cdata->in = NULL;
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	CL_NEW(cdata->in->update_nsset.add_ns);
	if ((cdata->in->update_nsset.rem_ns = malloc(sizeof *item)) == NULL) {
		free(cdata->in->update_nsset.add_ns);
		free(cdata->in);
		cdata->in = NULL;
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	CL_NEW(cdata->in->update_nsset.rem_ns);
	if ((cdata->in->update_nsset.add_tech = malloc(sizeof *item)) == NULL) {
		free(cdata->in->update_nsset.rem_ns);
		free(cdata->in->update_nsset.add_ns);
		free(cdata->in);
		cdata->in = NULL;
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	CL_NEW(cdata->in->update_nsset.add_tech);
	if ((cdata->in->update_nsset.rem_tech = malloc(sizeof *item)) == NULL) {
		free(cdata->in->update_nsset.add_tech);
		free(cdata->in->update_nsset.rem_ns);
		free(cdata->in->update_nsset.add_ns);
		free(cdata->in);
		cdata->in = NULL;
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	CL_NEW(cdata->in->update_nsset.rem_tech);
	if ((cdata->in->update_nsset.add_status = malloc(sizeof *item)) == NULL) {
		free(cdata->in->update_nsset.rem_tech);
		free(cdata->in->update_nsset.add_tech);
		free(cdata->in->update_nsset.rem_ns);
		free(cdata->in->update_nsset.add_ns);
		free(cdata->in);
		cdata->in = NULL;
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	CL_NEW(cdata->in->update_nsset.add_status);
	if ((cdata->in->update_nsset.rem_status = malloc(sizeof *item)) == NULL) {
		free(cdata->in->update_nsset.add_status);
		free(cdata->in->update_nsset.rem_tech);
		free(cdata->in->update_nsset.add_tech);
		free(cdata->in->update_nsset.rem_ns);
		free(cdata->in->update_nsset.add_ns);
		free(cdata->in);
		cdata->in = NULL;
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	CL_NEW(cdata->in->update_nsset.rem_status);

	/* get the update-nsset data */
	XPATH_REQ1(cdata->in->update_nsset.id, doc, xpathCtx, error_un, "nsset:id");
	/* chg data */
	XPATH_TAKE1_UPD(cdata->in->update_nsset.authInfo, doc, xpathCtx, error_un,
			"nsset:chg/nsset:authInfo/nsset:pw");
	/* add & rem tech */
	XPATH_TAKEN(cdata->in->update_nsset.add_tech, doc, xpathCtx, error_un,
			"nsset:add/nsset:tech");
	XPATH_TAKEN(cdata->in->update_nsset.rem_tech, doc, xpathCtx, error_un,
			"nsset:rem/nsset:tech");
	/* add & rem status */
	XPATH_TAKEN_ATTR(cdata->in->update_nsset.add_status, xpathCtx, error_un,
			"nsset:add/nsset:status", "s");
	XPATH_TAKEN_ATTR(cdata->in->update_nsset.rem_status, xpathCtx, error_un,
			"nsset:rem/nsset:status", "s");
	/* rem ns */
	XPATH_TAKEN(cdata->in->update_nsset.rem_ns, doc, xpathCtx, error_un,
			"nsset:rem/nsset:name");

	/* add ns */
	XPATH_EVAL(xpathObj, xpathCtx, error_un,
			"nsset:add/nsset:ns");
	/* backup current xpath context node */
	node = xpathCtx->node;
	/* memory leaks are possible with this schema but not ussual */
	for (j = 0; j < xmlXPathNodeSetGetLength(xpathObj->nodesetval); j++) {
		epp_ns	*ns;
		struct circ_list	*item;
		/* allocate data structures */
		if ((item = malloc(sizeof *item)) == NULL) {
			xmlXPathFreeObject(xpathObj);
			goto error_un;
		}
		CL_NEW(item);
		if ((ns = malloc(sizeof *ns)) == NULL) {
			free(item);
			xmlXPathFreeObject(xpathObj);
			goto error_un;
		}
		if ((ns->addr = malloc(sizeof *(ns->addr))) == NULL) {
			free(item);
			free(ns);
			xmlXPathFreeObject(xpathObj);
			goto error_un;
		}
		CL_NEW(ns->addr);
		/* get data */
		xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, j);
		XPATH_REQ1(ns->name, doc, xpathCtx, error_un, "nsset:name");
		XPATH_TAKEN(ns->addr, doc, xpathCtx, error_un, "nsset:addr");
		/* enqueue ns record */
		CL_CONTENT(item) = ns;
		CL_ADD(cdata->in->update_nsset.add_ns, item);
	}
	xmlXPathFreeObject(xpathObj);
	/* restore xpath context node */
	node = xpathCtx->node;

	cdata->type = EPP_UPDATE_NSSET;
	return;

	/*
	 * nasty error's epilog
	 * Used in case of internal critical failure. It is not terribly
	 * effecient but this case should not occure very often.
	 */
error_un:
	FREENULL(cdata->in->update_nsset.id);
	FREENULL(cdata->in->update_nsset.authInfo);
	CL_FOREACH(cdata->in->update_nsset.add_tech)
		free(CL_CONTENT(cdata->in->update_nsset.add_tech));
	cl_purge(cdata->in->update_nsset.add_tech);
	CL_FOREACH(cdata->in->update_nsset.rem_tech)
		free(CL_CONTENT(cdata->in->update_nsset.rem_tech));
	cl_purge(cdata->in->update_nsset.rem_tech);
	/* free ns sets */
	CL_FOREACH(cdata->in->update_nsset.add_ns) {
		epp_ns	*ns = (epp_ns *) CL_CONTENT(cdata->in->update_nsset.add_ns);
		FREENULL(ns->name);
		CL_FOREACH(ns->addr) free(CL_CONTENT(ns->addr));
		cl_purge(ns->addr);
		free(ns);
	}
	cl_purge(cdata->in->update_nsset.rem_ns);
	CL_FOREACH(cdata->in->update_nsset.rem_ns) {
		epp_ns	*ns = (epp_ns *) CL_CONTENT(cdata->in->update_nsset.rem_ns);
		FREENULL(ns->name);
		CL_FOREACH(ns->addr) free(CL_CONTENT(ns->addr));
		cl_purge(ns->addr);
		free(ns);
	}
	cl_purge(cdata->in->update_nsset.rem_ns);
	/* free status */
	CL_FOREACH(cdata->in->update_nsset.add_status)
		free(CL_CONTENT(cdata->in->update_nsset.add_status));
	cl_purge(cdata->in->update_nsset.add_status);
	CL_FOREACH(cdata->in->update_nsset.rem_status)
		free(CL_CONTENT(cdata->in->update_nsset.rem_status));
	cl_purge(cdata->in->update_nsset.rem_status);
	free(cdata->in);
	cdata->in = NULL;
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}


/**
 * Parser of EPP update command.
 * @param doc Parsed XML document.
 * @param xpathCtx XPath context.
 * @param cdata Output of parsing stage.
 */
static void
parse_update(
		xmlDocPtr doc,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	xmlXPathObjectPtr	xpathObj;

	/* get object type - contact, domain or nsset */
	XPATH_EVAL(xpathObj, xpathCtx, error_u,
			"epp:update/contact:update");
	if (xmlXPathNodeSetGetLength(xpathObj->nodesetval) == 0) {
		xmlXPathFreeObject(xpathObj);
		XPATH_EVAL(xpathObj, xpathCtx, error_u,
				"epp:update/domain:update");
		if (xmlXPathNodeSetGetLength(xpathObj->nodesetval) == 0) {
			xmlXPathFreeObject(xpathObj);
			XPATH_EVAL(xpathObj, xpathCtx, error_u,
					"epp:update/nsset:update");
			if (xmlXPathNodeSetGetLength(xpathObj->nodesetval) == 0) {
				/* unexpected object type */
				xmlXPathFreeObject(xpathObj);
				cdata->in = NULL;
				cdata->rc = 2000;
				cdata->type = EPP_DUMMY;
				return;
			}
			/* object is a nsset */
			else {
				/* change relative path prefix */
				xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, 0);
				parse_update_nsset(doc, xpathCtx, cdata);
			}
		}
		/* object is a domain */
		else {
			/* change relative path prefix */
			xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, 0);
			parse_update_domain(doc, xpathCtx, cdata);
		}
	}
	/* object is contact */
	else {
		/* change relative path prefix */
		xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, 0);
		parse_update_contact(doc, xpathCtx, cdata);
	}
	xmlXPathFreeObject(xpathObj);
	return;

error_u:
	cdata->in = NULL;
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP renew command.
 * @param doc Parsed XML document.
 * @param xpathCtx XPath context.
 * @param cdata Output of parsing stage.
 */
static void
parse_renew(
		xmlDocPtr doc,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	xmlXPathObjectPtr	xpathObj;
	char	*str;

	/* allocate necessary structures */
	if ((cdata->in = calloc(1, sizeof (*cdata->in))) == NULL) {
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	/* get renew data */
	XPATH_REQ1(cdata->in->renew.name, doc, xpathCtx, error_r,
		"epp:renew/domain:renew/domain:name");
	XPATH_REQ1(str, doc, xpathCtx, error_r,
		"epp:renew/domain:renew/domain:curExpDate");
	cdata->in->renew.exDate = str2timestamp(str);
	free(str);
	/* domain period handling is slightly more difficult */
	XPATH_EVAL(xpathObj, xpathCtx, error_r,
			"epp:renew/domain:renew/domain:period");
	if (xmlXPathNodeSetGetLength(xpathObj->nodesetval) == 1) {
		str = (char *) xmlNodeListGetString(doc, xmlXPathNodeSetItem(
					xpathObj->nodesetval, 0)->xmlChildrenNode, 1);
		assert(str != NULL && *str != '\0');
		cdata->in->renew.period = atoi(str);
		free(str);
		/* correct period value if given in years and not months */
		str = (char *) xmlGetProp(
				xmlXPathNodeSetItem(xpathObj->nodesetval, 0),
				BAD_CAST "unit");
		assert(str != NULL);
		if (*str == 'y') cdata->in->renew.period *= 12;
		free(str);
	}
	/*
	 * value 0 means that the period was not given and default value
	 * should be used instead
	 */
	else cdata->in->renew.period = 0;

	xmlXPathFreeObject(xpathObj);

	/* enumval extension */
	XPATH_TAKE1(str, doc, xpathCtx, error_r,
			"epp:extension/enumval:renew/enumval:valExDate");
	if (*str != '\0') {
		cdata->in->renew.valExDate = str2timestamp(str);
	}
	free(str);

	cdata->type = EPP_RENEW_DOMAIN;
	return;

error_r:
	/* nasty error's epilog */
	FREENULL(cdata->in->renew.name);
	free(cdata->in);
	cdata->in = NULL;
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP transfer command.
 * @param doc Parsed XML document.
 * @param xpathCtx XPath context.
 * @param cdata Output of parsing stage.
 */
static void
parse_transfer(
		xmlDocPtr doc,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	xmlXPathObjectPtr	xpathObj;

	/* allocate necessary structures */
	if ((cdata->in = calloc(1, sizeof (*cdata->in))) == NULL) {
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}

	/*
	 * we process only transfer requests (not approves, cancels, queries, ..)
	 * though all transfer commands are valid according to xml schemas
	 * because we don't want to be incompatible with epp-1.0 schema.
	 * If there is another command than "transfer request" we return
	 * 2102 "Unimplemented option" response.
	 */

	/* get object type - domain, contact or nsset */
	XPATH_EVAL(xpathObj, xpathCtx, error_t,
			"epp:transfer[@op='request']/domain:transfer");
	if (xmlXPathNodeSetGetLength(xpathObj->nodesetval) == 0) {
		xmlXPathFreeObject(xpathObj);
		XPATH_EVAL(xpathObj, xpathCtx, error_t,
				"epp:transfer[@op='request']/nsset:transfer");
		if (xmlXPathNodeSetGetLength(xpathObj->nodesetval) == 0) {
			xmlXPathFreeObject(xpathObj);
			XPATH_EVAL(xpathObj, xpathCtx, error_t,
					"epp:transfer[@op='request']/contact:transfer");
			if (xmlXPathNodeSetGetLength(xpathObj->nodesetval) == 0) {
				/*
				 * Transfer not implemented for object or bad transfer option.
				 * Generate error message.
				 */
				struct circ_list	*new_item;
				xmlBufferPtr	buf;
				xmlNodePtr	node;
				epp_error	*valerr;

				xmlXPathFreeObject(xpathObj);
				free(cdata->in);
				cdata->in = NULL;
				cdata->rc = 2102;
				cdata->type = EPP_DUMMY;

				valerr = malloc(sizeof *valerr);
				new_item = malloc(sizeof *new_item);

				/* dump problematic node */
				buf = xmlBufferCreate();
				if (buf == NULL) {
					free(valerr);
					free(new_item);
					return;
				}
				XPATH_EVAL(xpathObj, xpathCtx, error_t, "epp:transfer");
				node = xmlXPathNodeSetItem(xpathObj->nodesetval, 0);
				if (xmlNodeDump(buf, doc, node, 0, 0) < 0) {
					free(valerr);
					free(new_item);
					xmlBufferFree(buf);
					xmlXPathFreeObject(xpathObj);
					return;
				}
				xmlXPathFreeObject(xpathObj);
				valerr->value = strdup((char *) buf->content);
				xmlBufferFree(buf);

				/* TODO This should be bilingual */
				valerr->reason =
					strdup("Unimplemented op value or bad object type");
				valerr->standalone = 1;

				CL_CONTENT(new_item) = (void *) valerr;
				CL_ADD(cdata->errors, new_item);
				return;
			}
			else {
				/* object is a contact */
				xmlXPathFreeObject(xpathObj);
				XPATH_REQ1(cdata->in->transfer.id, doc, xpathCtx, error_t,
						"epp:transfer/contact:transfer/contact:id");
				XPATH_TAKE1(cdata->in->transfer.authInfo, doc, xpathCtx,
					error_t,
					"epp:transfer/contact:transfer/contact:authInfo/contact:pw");
				cdata->type = EPP_TRANSFER_CONTACT;
			}
		}
		else {
			/* object is a nsset */
			xmlXPathFreeObject(xpathObj);
			XPATH_REQ1(cdata->in->transfer.id, doc, xpathCtx, error_t,
					"epp:transfer/nsset:transfer/nsset:id");
			XPATH_TAKE1(cdata->in->transfer.authInfo, doc, xpathCtx,
					error_t,
					"epp:transfer/nsset:transfer/nsset:authInfo/nsset:pw");
			cdata->type = EPP_TRANSFER_NSSET;
		}
	}
	else {
		/* object is a domain */
		xmlXPathFreeObject(xpathObj);
		XPATH_REQ1(cdata->in->transfer.id, doc, xpathCtx, error_t,
				"epp:transfer/domain:transfer/domain:name");
		XPATH_TAKE1(cdata->in->transfer.authInfo, doc, xpathCtx, error_t,
				"epp:transfer/domain:transfer/domain:authInfo/domain:pw");
		cdata->type = EPP_TRANSFER_DOMAIN;
	}
	return;

error_t:
	/* nasty error's epilog */
	FREENULL(cdata->in->transfer.id);
	FREENULL(cdata->in->transfer.authInfo);
	free(cdata->in);
	cdata->in = NULL;
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

parser_status
epp_parse_command(
		int session,
		void *schema,
		const char *request,
		unsigned bytes,
		epp_command_data *cdata,
		unsigned long long *timestart,
		unsigned long long *timeend)
{
	xmlDocPtr	doc;
	xmlXPathContextPtr	xpathCtx;
	xmlXPathObjectPtr	xpathObj;
	xmlNodeSetPtr	nodeset;
	epp_red_command_type	cmd;
	valid_status	val_ret;
	struct timeval	tv; /* for meassuring of time spent in parser */

	/* get current time with microsecond resulution */
	*timestart = 0;
	*timeend = 0;
	timerclear(&tv);
	if (gettimeofday(&tv, NULL) == 0)
		*timestart = tv.tv_sec * 1000000 + tv.tv_usec;

	/* check input parameters */
	assert(request != NULL);
	assert(bytes != 0);

	/* parse xml request */
	doc = xmlParseMemory(request, bytes);
	if (doc == NULL) {
		return PARSER_NOT_XML;
	}

	/*
	 * create validation error callback and initialize list which is used
	 * for error cumulation.
	 */
	if ((cdata->errors = malloc(sizeof (*cdata->errors))) == NULL) {
		xmlFreeDoc(doc);
		return PARSER_EINTERNAL;
	}
	CL_NEW(cdata->errors);

	/* save input xml document */
	cdata->xml_in = malloc(bytes + 1);
	if (request != NULL) {
		memcpy(cdata->xml_in, request, bytes);
		/* the result is not null terminated yet */
		cdata->xml_in[bytes] = '\0';
	}
	else cdata->xml_in = strdup("");

	/* validate the doc */
	val_ret = validate_doc((xmlSchemaPtr) schema, doc, cdata->errors);

	if (val_ret == VAL_ESCHEMA || val_ret == VAL_EINTERNAL) {
		/* free error messages if there are any */
		CL_FOREACH(cdata->errors) {
			epp_error	*e = (epp_error *) CL_CONTENT(cdata->errors);
			free(e->value);
			free(e->reason);
			free(e);
		}
		cl_purge(cdata->errors);
		free(cdata->xml_in);
		xmlFreeDoc(doc);
		return (val_ret == VAL_ESCHEMA) ? PARSER_ESCHEMA : PARSER_EINTERNAL;
	}
	else if (val_ret == VAL_NOT_VALID) {
		/*
		 * validation error consequence: response identifing the problem is sent
		 * to client, the connection persists.
		 */
		/* TODO set rc value more thorougly */
		cdata->clTRID = strdup(""); /* must be set becauseof corba */
		cdata->rc = 2001;
		cdata->type = EPP_DUMMY;
		xmlFreeDoc(doc);
		return PARSER_NOT_VALID;
	}
	/* ... VAL_OK */

	/* create XPath context */
	xpathCtx = xmlXPathNewContext(doc);
	if (xpathCtx == NULL) {
		free(cdata->errors);
		free(cdata->xml_in);
		xmlFreeDoc(doc);
		return PARSER_EINTERNAL;
	}

	/*
	 * register namespaces and their prefixes in XPath context
	 * Error handling is same for all xmlXPathRegisterNs calls.
	 */
	if (xmlXPathRegisterNs(xpathCtx, BAD_CAST "epp", BAD_CAST NS_EPP) ||
		xmlXPathRegisterNs(xpathCtx, BAD_CAST "eppcom", BAD_CAST NS_EPPCOM) ||
		xmlXPathRegisterNs(xpathCtx, BAD_CAST "contact", BAD_CAST NS_CONTACT) ||
		xmlXPathRegisterNs(xpathCtx, BAD_CAST "domain", BAD_CAST NS_DOMAIN) ||
		xmlXPathRegisterNs(xpathCtx, BAD_CAST "nsset", BAD_CAST NS_NSSET) ||
		xmlXPathRegisterNs(xpathCtx, BAD_CAST "secdns", BAD_CAST NS_SECDNS) ||
		xmlXPathRegisterNs(xpathCtx, BAD_CAST "enumval", BAD_CAST NS_ENUMVAL))
	{
		xmlXPathFreeContext(xpathCtx);
		free(cdata->errors);
		free(cdata->xml_in);
		xmlFreeDoc(doc);
		return PARSER_EINTERNAL;
	}

	/* if it is a <hello> frame, we will send greeting and return */
	xpathObj = xmlXPathEvalExpression(BAD_CAST "/epp:epp/epp:hello", xpathCtx);
	if (xpathObj == NULL) {
		xmlXPathFreeContext(xpathCtx);
		free(cdata->errors);
		free(cdata->xml_in);
		xmlFreeDoc(doc);
		return PARSER_EINTERNAL;
	}
	if (xmlXPathNodeSetGetLength(xpathObj->nodesetval) == 1) {
		xmlXPathFreeObject(xpathObj);
		xmlXPathFreeContext(xpathCtx);
		free(cdata->errors);
		free(cdata->xml_in);
		xmlFreeDoc(doc);
		return PARSER_HELLO;
	}
	xmlXPathFreeObject(xpathObj);

	/* is it a command? */
	xpathObj = xmlXPathEvalExpression(BAD_CAST "/epp:epp/epp:command", xpathCtx);
	if (xpathObj == NULL) {
		xmlXPathFreeContext(xpathCtx);
		free(cdata->errors);
		free(cdata->xml_in);
		xmlFreeDoc(doc);
		return PARSER_EINTERNAL;
	}
	if (xmlXPathNodeSetGetLength(xpathObj->nodesetval) == 0) {
		/*
		 * not all documents which are valid are commands (e.g. greeting,
		 * response, extension). EPP standard does not describe any error
		 * which should be returned in that case. There for we will silently
		 * close connection in that case.
		 */
		xmlXPathFreeObject(xpathObj);
		xmlXPathFreeContext(xpathCtx);
		free(cdata->errors);
		free(cdata->xml_in);
		xmlFreeDoc(doc);
		return PARSER_NOT_COMMAND;
	}
	/* set current node for relative path expressions */
	xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, 0);
	xmlXPathFreeObject(xpathObj);

	/* it is a command, get clTRID if there is any */
	xpathObj = xmlXPathEvalExpression(BAD_CAST "epp:clTRID", xpathCtx);
	if (xpathObj == NULL) {
		xmlXPathFreeContext(xpathCtx);
		free(cdata->errors);
		free(cdata->xml_in);
		xmlFreeDoc(doc);
		return PARSER_EINTERNAL;
	}
	nodeset = xpathObj->nodesetval;
	if (xmlXPathNodeSetGetLength(xpathObj->nodesetval) == 1)
		cdata->clTRID = (char *) xmlNodeListGetString(doc, xmlXPathNodeSetItem(
					xpathObj->nodesetval, 0)->xmlChildrenNode, 1);
	else
		/* we cannot leave clTRID NULL becauseof corba */
		cdata->clTRID = (char *) xmlStrdup(BAD_CAST "");
	xmlXPathFreeObject(xpathObj);

	/*
	 * command recognition part
	 * XXX We shouldn't do any assumtions about order of nodes in
	 * nodeset, currently we do :(
	 */
	xpathObj = xmlXPathEvalExpression(BAD_CAST "*", xpathCtx);
	if (xpathObj == NULL) {
		xmlFree(cdata->clTRID);
		xmlXPathFreeContext(xpathCtx);
		free(cdata->errors);
		free(cdata->xml_in);
		xmlFreeDoc(doc);
		return PARSER_EINTERNAL;
	}
	assert(xmlXPathNodeSetGetLength(xpathObj->nodesetval) > 0);

	/* command lookup through hash table .. huraaa :) */
	cmd = cmd_hash_lookup( (char *)
			xmlXPathNodeSetItem(xpathObj->nodesetval, 0)->name);
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
			return PARSER_CMD_OTHER;
		}
	}
	else {
		if (session != 0) {
			cdata->type = EPP_DUMMY;
			cdata->rc = 2002;
			xmlXPathFreeContext(xpathCtx);
			xmlFreeDoc(doc);
			return PARSER_CMD_OTHER;
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
			parse_delete(doc, xpathCtx, cdata);
			break;
		case EPP_RED_RENEW:
			parse_renew(doc, xpathCtx, cdata);
			break;
		case EPP_RED_UPDATE:
			parse_update(doc, xpathCtx, cdata);
			break;
		case EPP_RED_TRANSFER:
			parse_transfer(doc, xpathCtx, cdata);
			break;
		case EPP_RED_UNKNOWN_CMD:
		default:
			cdata->rc = 2000;
			cdata->type = EPP_DUMMY;
			break;
	}

	xmlXPathFreeContext(xpathCtx);
	xmlFreeDoc(doc);
	/* xmlMemoryDump(); - never showed anything :-/ */

	if (cdata->type == EPP_LOGIN) return PARSER_CMD_LOGIN;
	if (cdata->type == EPP_LOGOUT) return PARSER_CMD_LOGOUT;

	/* get end time */
	timerclear(&tv);
	if (gettimeofday(&tv, NULL) == 0)
		*timeend = tv.tv_sec * 1000000 + tv.tv_usec;

	return PARSER_CMD_OTHER;
}

void epp_command_data_cleanup(epp_command_data *cdata)
{
	assert(cdata != NULL);
	assert(cdata->clTRID != NULL);
	assert(cdata->xml_in != NULL);
	free(cdata->clTRID);
	free(cdata->xml_in);
	/* free error messages if there are any */
	CL_FOREACH(cdata->errors) {
		epp_error	*e = (epp_error *) CL_CONTENT(cdata->errors);
		free(e->value);
		free(e->reason);
		free(e);
	}
	cl_purge(cdata->errors);
	/*
	 * corba function might not be called and therefore svTRID might be
	 * still NULL (msg and xml_out too)
	 */
	FREENULL(cdata->svTRID);
	FREENULL(cdata->msg);

	switch (cdata->type) {
		case EPP_LOGIN:
			assert(cdata->in != NULL);
			assert(cdata->out == NULL); /* login has no output parameters */
			free(cdata->in->login.clID);
			free(cdata->in->login.pw);
			free(cdata->in->login.newPW);
			/* destroy objuri list */
			CL_RESET(cdata->in->login.objuri);
			CL_FOREACH(cdata->in->login.objuri)
				free(CL_CONTENT(cdata->in->login.objuri));
			cl_purge(cdata->in->login.objuri);
			/* destroy exturi list */
			CL_RESET(cdata->in->login.exturi);
			CL_FOREACH(cdata->in->login.exturi)
				free(CL_CONTENT(cdata->in->login.exturi));
			cl_purge(cdata->in->login.exturi);
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
			cl_purge(cdata->in->check.ids);
			/* destroy avails */
			if (cdata->out != NULL) {
				CL_RESET(cdata->out->check.avails);
				CL_FOREACH(cdata->out->check.avails) {
					epp_avail	*avail = CL_CONTENT(cdata->out->check.avails);
					assert(avail->reason != NULL);
					free(avail->reason);
					free(avail);
				}
				/* there is no content to be freed for bools */
				cl_purge(cdata->out->check.avails);
			}
			break;
		case EPP_INFO_CONTACT:
			assert(cdata->in != NULL);
			free(cdata->in->info.id);
			if (cdata->out != NULL) {
				epp_postalInfo	*pi;
				epp_discl	*discl;

				free(cdata->out->info_contact.roid);
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
				/* status */
				CL_RESET(cdata->out->info_contact.status);
				CL_FOREACH(cdata->out->info_contact.status)
					free(CL_CONTENT(cdata->out->info_contact.status));
				cl_purge(cdata->out->info_contact.status);
				/* postal info */
				pi = cdata->out->info_contact.postalInfo;
				assert(pi != NULL);
				free(pi->name);
				free(pi->org);
				free(pi->street[0]);
				free(pi->street[1]);
				free(pi->street[2]);
				free(pi->city);
				free(pi->sp);
				free(pi->pc);
				free(pi->cc);
				free(pi);
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
				free(cdata->out->info_domain.registrant);
				free(cdata->out->info_domain.nsset);
				free(cdata->out->info_domain.clID);
				free(cdata->out->info_domain.crID);
				free(cdata->out->info_domain.upID);
				free(cdata->out->info_domain.authInfo);
				/* status */
				CL_RESET(cdata->out->info_domain.status);
				CL_FOREACH(cdata->out->info_domain.status)
					free(CL_CONTENT(cdata->out->info_domain.status));
				cl_purge(cdata->out->info_domain.status);
				/* admin contacts */
				CL_RESET(cdata->out->info_domain.admin);
				CL_FOREACH(cdata->out->info_domain.admin)
					free(CL_CONTENT(cdata->out->info_domain.admin));
				cl_purge(cdata->out->info_domain.admin);
				/* clear extensions */
				CL_FOREACH(cdata->out->info_domain.ds) {
					FREENULL(((epp_ds *)
								CL_CONTENT(cdata->out->info_domain.ds))->digest);
					FREENULL(((epp_ds *)
								CL_CONTENT(cdata->out->info_domain.ds))->pubkey);
					free(CL_CONTENT(cdata->out->info_domain.ds));
				}
				cl_purge(cdata->out->info_domain.ds);
			}
			break;
		case EPP_INFO_NSSET:
			assert(cdata->in != NULL);
			free(cdata->in->info.id);
			if (cdata->out != NULL) {
				free(cdata->out->info_nsset.roid);
				free(cdata->out->info_nsset.clID);
				free(cdata->out->info_nsset.crID);
				free(cdata->out->info_nsset.upID);
				free(cdata->out->info_nsset.authInfo);
				/* ns */
				CL_RESET(cdata->out->info_nsset.ns);
				CL_FOREACH(cdata->out->info_nsset.ns) {
					epp_ns	*ns = (epp_ns *)
						CL_CONTENT(cdata->out->info_nsset.ns);
					free(ns->name);
					/* addr */
					CL_RESET(ns->addr);
					CL_FOREACH(ns->addr) free(CL_CONTENT(ns->addr));
					cl_purge(ns->addr);
					free(CL_CONTENT(cdata->out->info_nsset.ns));
				}
				cl_purge(cdata->out->info_nsset.ns);
				/* tech */
				CL_RESET(cdata->out->info_nsset.tech);
				CL_FOREACH(cdata->out->info_nsset.tech)
					free(CL_CONTENT(cdata->out->info_nsset.tech));
				cl_purge(cdata->out->info_nsset.tech);
				/* status */
				CL_RESET(cdata->out->info_nsset.status);
				CL_FOREACH(cdata->out->info_nsset.status)
					free(CL_CONTENT(cdata->out->info_nsset.status));
				cl_purge(cdata->out->info_nsset.status);
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
			cl_purge(cdata->in->create_domain.admin);
			/* clear the extensions */
			assert(cdata->in->create_domain.ds != NULL);
			CL_FOREACH(cdata->in->create_domain.ds) {
				epp_ds	*ds = (epp_ds *) CL_CONTENT(cdata->in->create_domain.ds);
				FREENULL(ds->digest);
				FREENULL(ds->pubkey);
				free(ds);
			}
			cl_purge(cdata->in->create_domain.ds);
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
				free(pi->street[0]);
				free(pi->street[1]);
				free(pi->street[2]);
				free(pi->city);
				free(pi->sp);
				free(pi->pc);
				free(pi->cc);
				free(pi);
			}
			assert(cdata->in->create_contact.discl != NULL);
			free(cdata->in->create_contact.discl);
			break;
		case EPP_CREATE_NSSET:
			assert(cdata->in != NULL);
			free(cdata->in->create_nsset.id);
			free(cdata->in->create_nsset.authInfo);
			CL_RESET(cdata->in->create_nsset.tech);
			CL_FOREACH(cdata->in->create_nsset.tech)
				free(CL_CONTENT(cdata->in->create_nsset.tech));
			cl_purge(cdata->in->create_nsset.tech);
			CL_FOREACH(cdata->in->create_nsset.ns) {
				epp_ns	*ns = (epp_ns *) CL_CONTENT(cdata->in->create_nsset.ns);
				free(ns->name);
				CL_FOREACH(ns->addr) free(CL_CONTENT(ns->addr));
				cl_purge(ns->addr);
				free(ns);
			}
			cl_purge(cdata->in->create_nsset.ns);
			break;
		case EPP_DELETE_DOMAIN:
		case EPP_DELETE_CONTACT:
		case EPP_DELETE_NSSET:
			assert(cdata->in != NULL);
			assert(cdata->out == NULL);
			free(cdata->in->delete.id);
			break;
		case EPP_RENEW_DOMAIN:
			assert(cdata->in != NULL);
			free(cdata->in->renew.name);
			break;
		case EPP_UPDATE_DOMAIN:
			assert(cdata->in != NULL);
			assert(cdata->out == NULL);
			free(cdata->in->update_domain.name);
			free(cdata->in->update_domain.registrant);
			free(cdata->in->update_domain.nsset);
			free(cdata->in->update_domain.authInfo);
			/* rem & add admin */
			CL_RESET(cdata->in->update_domain.add_admin);
			CL_FOREACH(cdata->in->update_domain.add_admin)
				free(CL_CONTENT(cdata->in->update_domain.add_admin));
			cl_purge(cdata->in->update_domain.add_admin);
			CL_RESET(cdata->in->update_domain.rem_admin);
			CL_FOREACH(cdata->in->update_domain.rem_admin)
				free(CL_CONTENT(cdata->in->update_domain.rem_admin));
			cl_purge(cdata->in->update_domain.rem_admin);
			/* rem & add status */
			CL_RESET(cdata->in->update_domain.add_status);
			CL_FOREACH(cdata->in->update_domain.add_status)
				free(CL_CONTENT(cdata->in->update_domain.add_status));
			cl_purge(cdata->in->update_domain.add_status);
			CL_RESET(cdata->in->update_domain.rem_status);
			CL_FOREACH(cdata->in->update_domain.rem_status)
				free(CL_CONTENT(cdata->in->update_domain.rem_status));
			cl_purge(cdata->in->update_domain.rem_status);
			/* clear the extensions */
			assert(cdata->in->update_domain.chg_ds != NULL);
			assert(cdata->in->update_domain.add_ds != NULL);
			assert(cdata->in->update_domain.rem_ds != NULL);
			CL_FOREACH(cdata->in->update_domain.chg_ds) {
				FREENULL(((epp_ds *)
						CL_CONTENT(cdata->in->update_domain.chg_ds))->digest);
				FREENULL(((epp_ds *)
						CL_CONTENT(cdata->in->update_domain.chg_ds))->pubkey);
				free(CL_CONTENT(cdata->in->update_domain.chg_ds));
			}
			cl_purge(cdata->in->update_domain.chg_ds);
			CL_FOREACH(cdata->in->update_domain.add_ds) {
				FREENULL(((epp_ds *)
						CL_CONTENT(cdata->in->update_domain.add_ds))->digest);
				FREENULL(((epp_ds *)
						CL_CONTENT(cdata->in->update_domain.add_ds))->pubkey);
				free(CL_CONTENT(cdata->in->update_domain.add_ds));
			}
			cl_purge(cdata->in->update_domain.add_ds);
			CL_FOREACH(cdata->in->update_domain.rem_ds)
				free(CL_CONTENT(cdata->in->update_domain.rem_ds));
			cl_purge(cdata->in->update_domain.rem_ds);
			break;
		case EPP_UPDATE_CONTACT:
			assert(cdata->in != NULL);
			assert(cdata->out == NULL);
			free(cdata->in->update_contact.id);
			free(cdata->in->update_contact.voice);
			free(cdata->in->update_contact.fax);
			free(cdata->in->update_contact.email);
			free(cdata->in->update_contact.authInfo);
			free(cdata->in->update_contact.notify_email);
			free(cdata->in->update_contact.vat);
			free(cdata->in->update_contact.ssn);
			assert(cdata->in->update_contact.postalInfo != NULL);
			{
				epp_postalInfo	*pi = cdata->in->update_contact.postalInfo;
				free(pi->name);
				free(pi->org);
				free(pi->street[0]);
				free(pi->street[1]);
				free(pi->street[2]);
				free(pi->city);
				free(pi->sp);
				free(pi->pc);
				free(pi->cc);
				free(pi);
			}
			/* discl might be NULL if not updated */
			assert(cdata->in->update_contact.discl != NULL);
			free(cdata->in->update_contact.discl);
			/* rem & add status */
			CL_RESET(cdata->in->update_contact.add_status);
			CL_FOREACH(cdata->in->update_contact.add_status)
				free(CL_CONTENT(cdata->in->update_contact.add_status));
			cl_purge(cdata->in->update_contact.add_status);
			CL_RESET(cdata->in->update_contact.rem_status);
			CL_FOREACH(cdata->in->update_contact.rem_status)
				free(CL_CONTENT(cdata->in->update_contact.rem_status));
			cl_purge(cdata->in->update_contact.rem_status);
			break;
		case EPP_UPDATE_NSSET:
			assert(cdata->in != NULL);
			assert(cdata->out == NULL);
			free(cdata->in->update_nsset.id);
			free(cdata->in->update_nsset.authInfo);
			/* add ns */
			CL_FOREACH(cdata->in->update_nsset.add_ns) {
				epp_ns	*ns = (epp_ns *)
					CL_CONTENT(cdata->in->update_nsset.add_ns);
				free(ns->name);
				CL_FOREACH(ns->addr) free(CL_CONTENT(ns->addr));
				cl_purge(ns->addr);
				free(ns);
			}
			cl_purge(cdata->in->update_nsset.add_ns);
			/* rem ns */
			CL_RESET(cdata->in->update_nsset.rem_ns);
			CL_FOREACH(cdata->in->update_nsset.rem_ns)
				free(CL_CONTENT(cdata->in->update_nsset.rem_ns));
			cl_purge(cdata->in->update_nsset.rem_ns);
			/* rem & add tech */
			CL_RESET(cdata->in->update_nsset.add_tech);
			CL_FOREACH(cdata->in->update_nsset.add_tech)
				free(CL_CONTENT(cdata->in->update_nsset.add_tech));
			cl_purge(cdata->in->update_nsset.add_tech);
			CL_RESET(cdata->in->update_nsset.rem_tech);
			CL_FOREACH(cdata->in->update_nsset.rem_tech)
				free(CL_CONTENT(cdata->in->update_nsset.rem_tech));
			cl_purge(cdata->in->update_nsset.rem_tech);
			/* rem & add status */
			CL_RESET(cdata->in->update_nsset.add_status);
			CL_FOREACH(cdata->in->update_nsset.add_status)
				free(CL_CONTENT(cdata->in->update_nsset.add_status));
			cl_purge(cdata->in->update_nsset.add_status);
			CL_RESET(cdata->in->update_nsset.rem_status);
			CL_FOREACH(cdata->in->update_nsset.rem_status)
				free(CL_CONTENT(cdata->in->update_nsset.rem_status));
			cl_purge(cdata->in->update_nsset.rem_status);
			break;
		case EPP_LIST_CONTACT:
		case EPP_LIST_DOMAIN:
		case EPP_LIST_NSSET:
			assert(cdata->in == NULL);
			if (cdata->out != NULL) {
				CL_RESET(cdata->out->list.handles);
				CL_FOREACH(cdata->out->list.handles);
					free(CL_CONTENT(cdata->out->list.handles));
				cl_purge(cdata->out->list.handles);
			}
			break;
		case EPP_TRANSFER_NSSET:
		case EPP_TRANSFER_DOMAIN:
		case EPP_TRANSFER_CONTACT:
			assert(cdata->in != NULL);
			free(cdata->in->transfer.id);
			free(cdata->in->transfer.authInfo);
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
			assert(cdata->in == NULL);
			assert(cdata->out == NULL);
			break;
		default:
			assert(1 == 2);
			break;
	}
	/* same for all */
	if (cdata->in != NULL) free(cdata->in);
	if (cdata->out != NULL) free(cdata->out);
}

