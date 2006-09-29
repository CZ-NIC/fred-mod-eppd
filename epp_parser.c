/*
 * @file epp_parser.c
 *
 * Component for parsing EPP requests in form of xml documents.
 * The product is a data structure which contains data from xml document.
 * This file also contains routine which handles deallocation of this
 * structure. Currently the component is based on libxml library.
 */

#include <string.h>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define BS_CHAR	8	/**< Backspace ASCII code. */
/**
 * Size of hash table used for hashing command names. The size is tradeof
 * between size of hash table and lookup speed, it should be less than 255
 * since hash value is unsigned char.
 */
#define HASH_SIZE_CMD	30

/**
 * Get content of text node.
 * You have to copy the string in returned pointer if you want to manipulate
 * with string, you have to make yout own copy.
 */
#define TEXT_CONTENT(_xpathObj, _i)	((char *) ((xmlXPathNodeSetItem((_xpathObj)->nodesetval, (_i))->xmlChildrenNode)->content))

/**
 * Fast check for return value of xpath utility functions.
 * If failure occurs (_test is false) then we jump to _label.
 */
#define XCHK(_test, _label)	if (!(_test)) goto _label

/**
 * This function returns given attribute value of specific node.
 * You have to make your own copy if you want to edit the returned string.
 *
 * @param xpathObj XPath object.
 * @param i Number of node in node set.
 * @param name Name of attribute.
 * @return Pointer to attribute's value.
 */
static char *
get_attr(xmlXPathObjectPtr xpathObj, int i, const char *name)
{
	xmlAttrPtr	prop;
	xmlNodePtr	node;

	node = xmlXPathNodeSetItem(xpathObj->nodesetval, i);
	prop = node->properties;
	while (prop != NULL) {
		if (xmlStrEqual(prop->name, name)) {
			return (char *) prop->children->content;
		}
		prop = prop->next;
	}
	return NULL;
}

/**
 * @defgroup xpathgroup Functions for convenient usage of xpath
 * queries.
 * @{
 */

/**
 * Sometimes we want to know only if the element is there or not.
 * If error occures we return 0, which means: object is not there
 * (I hope that it doesn't do much damage).
 *
 * @param ctx XPath context.
 * @param expr XPath expression.
 * @return 1 if the element described by expr is there, otherwise 0.
 */
static int
xpath_exists(xmlXPathContextPtr ctx, const char *expr)
{
		int ret;

		xmlXPathObjectPtr obj = xmlXPathEvalExpression(BAD_CAST expr, ctx);
		if (obj == NULL) return 0;
		ret = xmlXPathNodeSetGetLength(obj->nodesetval);
		xmlXPathFreeObject(obj);
		return ret ? 1:0;
}

/**
 * A content of element described by xpath expression is returned.
 * The element must be only one. If req is set, the element is required to
 * exist, otherwise assert aborts the program and if assert are inactive, NULL
 * is returned. If the element is not required
 * to exist and it is not there, empty string is returned. In case of internal
 * error, NULL value is returned.
 *
 * @param pool Memory pool to allocate memory from.
 * @param ctx  XPath context pointer.
 * @param expr XPath expression which describes a xml node.
 * @param req  1 if element is required to exist, 0 if not.
 * @return String with content of xml element allocated from pool.
 */
static char *
xpath_get1(void *pool, xmlXPathContextPtr ctx, const char *expr, int req)
{
	xmlXPathObjectPtr obj;
	char	*res;
	
	obj = xmlXPathEvalExpression(BAD_CAST expr, ctx);
	if (obj == NULL)
		return NULL;
	if (xmlXPathNodeSetGetLength(obj->nodesetval) != 1) {
		xmlXPathFreeObject(obj);
		if (req) {
			assert(xmlXPathNodeSetGetLength(obj->nodesetval) == 1);
			return NULL;
		}
		else
			return epp_strdup(pool, "");
	}
	res = TEXT_CONTENT(obj, 0);
	/*
	 * the value might be NULL in special circumstances, it is equivalent
	 * to empty content of element, so we will copy empty string to result.
	 */
	if (res == NULL)
		res = epp_strdup(pool, "");
	else
		res = epp_strdup(pool, res);

	xmlXPathFreeObject(obj);
	return res;
}

/**
 * A content of element described by xpath expression is returned as in
 * xpath_get1(), but additionaly if element exists and is empty, string
 * containing one character "backspace" is returned. This is used in
 * processing of update request to distinguish between element which is
 * not updated and element which is erased (Note that we cannot use NULL
 * value because CORBA doesn't like it).
 *
 * @param pool Memory pool to allocate memory from.
 * @param ctx  XPath context pointer.
 * @param expr XPath expression which describes a xml node.
 * @return String with content of xml element allocated from pool.
 */
static char *
xpath_get1_upd(void *pool, xmlXPathContextPtr ctx, const char *expr)
{
	xmlXPathObjectPtr obj;
	char	*res;
	
	obj = xmlXPathEvalExpression(BAD_CAST expr, ctx);
	if (obj == NULL)
		return NULL;
	if (xmlXPathNodeSetGetLength(obj->nodesetval) != 1)
		return epp_strdup(pool, "");
	res = TEXT_CONTENT(obj, 0);
	/*
	 * the value might be NULL in special circumstances, it is equivalent
	 * to empty content of element, so we will copy empty string to result.
	 */
	if (res == NULL || *res == '\0') {
		if ((res = epp_malloc(pool, 2)) == NULL) {
			xmlXPathFreeObject(obj);
			return NULL;
		}
		res[0] = BS_CHAR;                             \
		res[1] = '\0';                                \
	}
	else
		res = epp_strdup(pool, res);

	xmlXPathFreeObject(obj);
	return res;
}

/**
 * Into list is put the content of elements described by xpath expression.
 * There may be more elements matching xpath expression, their content is
 * copied in a list.
 *
 * @param pool Memory pool to allocate memory from.
 * @param list Allocated list where the list items will be added.
 * @param ctx  XPath context pointer.
 * @param expr XPath expression which describes a xml node.
 * @return If succesfull 1, in case of failure 0.
 */
static int
xpath_getn(
		void *pool,
		struct circ_list *list,
		xmlXPathContextPtr ctx,
		const char *expr)
{
	int	i;
	struct circ_list	*item;
	xmlXPathObjectPtr obj;
	
	obj = xmlXPathEvalExpression(BAD_CAST expr, ctx);
	if (obj == NULL)
		return 0;
	for (i = 0; i < xmlXPathNodeSetGetLength(obj->nodesetval); i++) {
		item = (struct circ_list *) epp_malloc(pool, sizeof *item);
		if (item == NULL) {
			xmlXPathFreeObject(obj);
			return 0;
		}
		CL_CONTENT(item) = (void *) epp_strdup(pool, TEXT_CONTENT(obj, i));
		if (CL_CONTENT(item) == NULL) {
			CL_CONTENT(item) = epp_strdup(pool, "");
			if (CL_CONTENT(item) == NULL) {
				xmlXPathFreeObject(obj);
				return 0;
			}
		}
		CL_ADD(list, item);
	}
	xmlXPathFreeObject(obj);
	return 1;
}

/**
 * A value of attribute of node described by xpath expression is returned.
 * The resulting node must be only one. If req is set, the node is required to
 * exist, otherwise assert aborts the program and if asserts are inactive, NULL
 * is returned. If the element is not required to exist and it is not there,
 * empty string is returned. In case of internal error, NULL value is returned.
 *
 * @param pool Memory pool to allocate memory from.
 * @param ctx  XPath context pointer.
 * @param expr XPath expression which describes a xml node.
 * @param attr Name of attribute.
 * @param req  1 if element is required to exist, 0 if not.
 * @return String with content of xml element allocated from pool.
 */
static char *
xpath_get_attr(
		void *pool,
		xmlXPathContextPtr ctx,
		const char *expr,
		const char *attr,
		int req)
{
	xmlXPathObjectPtr obj;
	char	*str;

	obj = xmlXPathEvalExpression(BAD_CAST expr, ctx);
	if (obj == NULL)
		return NULL;
	if (xmlXPathNodeSetGetLength(obj->nodesetval) != 1) {
		xmlXPathFreeObject(obj);
		if (req) {
			assert(xmlXPathNodeSetGetLength(obj->nodesetval) == 1);
			return NULL;
		}
		else
			return epp_strdup(pool, "");
	}
	str = get_attr(obj, 0, attr);
	/*
	 * the value might be NULL in special circumstances, it is equivalent
	 * to empty content of element, so we will copy empty string to result.
	 */
	if (str == NULL)
		str = epp_strdup(pool, "");
	else
		str = epp_strdup(pool, str);

	xmlXPathFreeObject(obj);
	return str;
}

/**
 * Into list are put the values of attributes of elements described by xpath
 * expression. There may be more elements matching xpath expression, their
 * content is copied in a list.
 *
 * @param pool Memory pool to allocate memory from.
 * @param list Allocated list where the list items will be added.
 * @param ctx  XPath context pointer.
 * @param expr XPath expression which describes a xml node.
 * @return If succesfull 1, in case of failure 0.
 */
static int
xpath_getn_attrs(
		void *pool,
		struct circ_list *list,
		xmlXPathContextPtr ctx,
		const char *expr,
		const char *attr)
{
	int	i;
	char	*str;
	struct circ_list	*item;
	xmlXPathObjectPtr obj;
	
	obj = xmlXPathEvalExpression(BAD_CAST expr, ctx);
	if (obj == NULL)
		return 0;
	for (i = 0; i < xmlXPathNodeSetGetLength(obj->nodesetval); i++) {
		item = (struct circ_list *) epp_malloc(pool, sizeof *item);
		if (item == NULL) {
			xmlXPathFreeObject(obj);
			return 0;
		}
		str = get_attr(obj, i, attr);
		if (str == NULL) {
			str = epp_strdup(pool, "");
			if (str == NULL) {
				xmlXPathFreeObject(obj);
				return 0;
			}
		}
		else {
			str = epp_strdup(pool, str);
			if (str == NULL) {
				xmlXPathFreeObject(obj);
				return 0;
			}
		}

		CL_CONTENT(item) = (void *) str;
		CL_ADD(list, item);
	}
	xmlXPathFreeObject(obj);
	return 1;
}

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
 * Parser of EPP login command.
 * @param pool Pool for memory allocations.
 * @param xpathCtx XPath context.
 * @param cdata Output of parsing stage.
 */
static void
parse_login(
		void *pool,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	char	*str;
	struct circ_list	*item;

	/* allocate necessary structures */
	if (!(cdata->in = epp_calloc(pool, sizeof (*cdata->in)))
		|| !(cdata->in->login.objuri = epp_malloc(pool, sizeof *item))
		|| !(cdata->in->login.exturi = epp_malloc(pool, sizeof *item)))
	{
		goto error;
	}
	CL_NEW(cdata->in->login.objuri);
	CL_NEW(cdata->in->login.exturi);

	/* check if language matches */
	XCHK(str = xpath_get1(pool, xpathCtx, "epp:login/epp:options/epp:lang", 1),
			error);
	if (xmlStrEqual((xmlChar *) str, BAD_CAST "en"))
		cdata->in->login.lang = LANG_EN;
	else if (xmlStrEqual((xmlChar *) str, BAD_CAST "cs"))
		cdata->in->login.lang = LANG_CS;
	else {
		cdata->type = EPP_DUMMY;
		cdata->rc = 2102;
		return;
	}

	/* check if EPP version matches */
	XCHK(str = xpath_get1(pool, xpathCtx, "epp:login/epp:options/epp:version", 1)
			,error);
	if (!xmlStrEqual((xmlChar *) str, BAD_CAST "1.0")) {
		cdata->type = EPP_DUMMY;
		cdata->rc = 2100;
		return;
	}

	/* ok, checking done. now get input parameters for corba function call */
	XCHK(cdata->in->login.clID = xpath_get1(pool, xpathCtx,
				"epp:login/epp:clID", 1), error);
	XCHK(cdata->in->login.pw = xpath_get1(pool, xpathCtx,
				"epp:login/epp:pw", 1), error);
	XCHK(cdata->in->login.newPW = xpath_get1(pool, xpathCtx,
				"epp:login/epp:newPW", 0), error);
	XCHK(xpath_getn(pool, cdata->in->login.objuri, xpathCtx,
			"epp:login/epp:svcs/epp:objURI"), error);
	XCHK(xpath_getn(pool, cdata->in->login.exturi, xpathCtx,
			"epp:login/epp:svcs/epp:extURI"), error);

	cdata->type = EPP_LOGIN;
	return;

error:
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP check command.
 * @param pool Pool for memory allocations.
 * @param xpathCtx XPath context.
 * @param cdata Output of parsing stage.
 */
static void
parse_check(
		void *pool,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	struct circ_list	*item;

	/* allocate necessary structures */
	if (!(cdata->in = epp_calloc(pool, sizeof (*cdata->in)))
		|| !(cdata->in->check.ids = epp_malloc(pool, sizeof *item)))
	{
		goto error;
	}
	CL_NEW(cdata->in->check.ids);

	/* get object type - contact, domain or nsset */
	if (xpath_exists(xpathCtx, "epp:check/contact:check"))
	{
		/* object is contact */
		XCHK(xpath_getn(pool, cdata->in->check.ids, xpathCtx,
				"epp:check/contact:check/contact:id"), error);
		cdata->type = EPP_CHECK_CONTACT;
	}
	else if (xpath_exists(xpathCtx, "epp:check/domain:check"))
	{
		/* object is a domain */
		XCHK(xpath_getn(pool, cdata->in->check.ids, xpathCtx,
				"epp:check/domain:check/domain:name"), error);
		cdata->type = EPP_CHECK_DOMAIN;
	}
	else if (xpath_exists(xpathCtx, "epp:check/nsset:check"))
	{
		/* object is a nsset */
		XCHK(xpath_getn(pool, cdata->in->check.ids, xpathCtx,
				"epp:check/nsset:check/nsset:id"), error);
		cdata->type = EPP_CHECK_NSSET;
	}
	else {
		/* unexpected object type */
		cdata->rc = 2000;
		cdata->type = EPP_DUMMY;
	}

	return;

error:
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP info command + list command. List command is a non-standard
 * command for listing of registered objects. This makes info command very
 * special since it may contain two different commands. Authinfo tag is
 * ignored in info command.
 *
 * @param pool Pool for memory allocations.
 * @param xpathCtx XPath context.
 * @param cdata Output of parsing stage.
 */
static void
parse_info(
		void *pool,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	/*
	 * catch the "list command" at the beginning, then proceed with
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
		if (!(cdata->in = epp_calloc(pool, sizeof (*cdata->in)))) {
			goto error;
		}
		/* get object type - contact, domain or nsset */
		if (xpath_exists(xpathCtx, "epp:info/contact:info"))
		{
			/* object is contact */
			XCHK(cdata->in->info.id = xpath_get1(pool, xpathCtx,
					"epp:info/contact:info/contact:id", 1), error);
			cdata->type = EPP_INFO_CONTACT;
		}
		else if (xpath_exists(xpathCtx, "epp:info/domain:info"))
		{
			/* object is a domain */
			XCHK(cdata->in->info.id = xpath_get1(pool, xpathCtx,
					"epp:info/domain:info/domain:name", 1), error);
			cdata->type = EPP_INFO_DOMAIN;
		}
		else if (xpath_exists(xpathCtx, "epp:info/nsset:info"))
		{
			/* object is a nsset */
			XCHK(cdata->in->info.id = xpath_get1(pool, xpathCtx,
					"epp:info/nsset:info/nsset:id", 1), error);
			cdata->type = EPP_INFO_NSSET;
		}
		else {
			/* unexpected object type for both (info & list) */
			cdata->rc = 2000;
			cdata->type = EPP_DUMMY;
		}
	}
	return;

error:
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP poll command. This is for both poll variants - req and ack.
 *
 * @param pool Pool for memory allocations.
 * @param doc Parsed XML document.
 * @param xpathCtx XPath context.
 * @param cdata Output of parsing stage.
 */
static void
parse_poll(
		void *pool,
		xmlDocPtr doc,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	xmlXPathObjectPtr	xpathObj;
	xmlNodePtr	node;
	char	*str;

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
	if (!(cdata->in = epp_calloc(pool, sizeof (*cdata->in)))) {
		xmlXPathFreeObject(xpathObj);
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	/* get value of attr msgID */
	node = xmlXPathNodeSetItem(xpathObj->nodesetval, 0);
	str = get_attr(xpathObj, 0, "msgID");

	/*
	 * msgID attribute is not strictly required by xml schema so we
	 * have to explicitly check if it is there
	 */
	if (str == NULL) {
		struct circ_list	*new_item;
		xmlBufferPtr	buf;
		epp_error	*valerr;

		cdata->rc = 2003;
		cdata->type = EPP_DUMMY;

		/*
		 * we will politely create error message which says which parameter is
		 * missing.
		 */
		valerr = epp_malloc(pool, sizeof *valerr);
		new_item = epp_malloc(pool, sizeof *new_item);

		/* dump problematic node */
		buf = xmlBufferCreate();
		if (buf == NULL) {
			xmlXPathFreeObject(xpathObj);
			return;
		}
		if (xmlNodeDump(buf, doc, node, 0, 0) < 0) {
			xmlBufferFree(buf);
			xmlXPathFreeObject(xpathObj);
			return;
		}
		valerr->value = epp_strdup(pool, (char *) buf->content);
		xmlBufferFree(buf);

		/* TODO This should be bilingual */
		valerr->reason = epp_strdup(pool, "Required parameter msgID is missing");
		valerr->standalone = 1;

		CL_CONTENT(new_item) = (void *) valerr;
		CL_ADD(cdata->errors, new_item);

		xmlXPathFreeObject(xpathObj);
		return;
	}

	/* conversion is safe, if str is not a number, validator catches it */
	cdata->in->poll_ack.msgid = atoi(str);
	xmlXPathFreeObject(xpathObj);
	cdata->type = EPP_POLL_ACK;
}

/**
 * Parser of EPP create-domain command.
 * @param pool Pool for memory allocations.
 * @param xpathCtx XPath context.
 * @param cdata Output of parsing stage.
 */
static void
parse_create_domain(
		void *pool,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	struct circ_list	*item;
	char	*str;

	/* allocate necessary structures */
	if (!(cdata->in = epp_calloc(pool, sizeof (*cdata->in)))
		|| !(cdata->in->create_domain.admin = epp_malloc(pool, sizeof *item))
		|| !(cdata->in->create_domain.ds = epp_malloc(pool, sizeof *item)))
	{
		goto error;
	}
	CL_NEW(cdata->in->create_domain.admin);
	CL_NEW(cdata->in->create_domain.ds);

	/* get the domain data */
	XCHK(cdata->in->create_domain.name = xpath_get1(pool, xpathCtx,
			"domain:name", 1), error);
	XCHK(cdata->in->create_domain.registrant = xpath_get1(pool, xpathCtx,
			"domain:registrant", 1), error);
	XCHK(cdata->in->create_domain.nsset = xpath_get1(pool, xpathCtx,
			"domain:nsset", 0), error);
	XCHK(cdata->in->create_domain.authInfo = xpath_get1(pool, xpathCtx,
			"domain:authInfo/domain:pw", 0), error);
	/* domain period handling is slightly more difficult */
	XCHK(str = xpath_get1(pool, xpathCtx, "domain:period", 0), error);
	if (*str != '\0') {
		cdata->in->create_domain.period = atoi(str);
		/* correct period value if given in years and not months */
		XCHK(str = xpath_get_attr(pool, xpathCtx, "domain:period", "unit", 1),
				error);
		if (*str == 'y') cdata->in->create_domain.period *= 12;
	}
	else
		/*
		 * value 0 means that the period was not given and default value
		 * should be used instead
		 */
		cdata->in->create_domain.period = 0;
	/* process "unbounded" number of admin contacts */
	XCHK(xpath_getn(pool, cdata->in->create_domain.admin, xpathCtx,
			"domain:admin"), error);

	/* now look for optional extensions (extension tag is 2 layers upwards) */
	xpathCtx->node = xpathCtx->node->parent->parent;
	/* enumval extension */
	XCHK(cdata->in->create_domain.valExDate = xpath_get1(pool, xpathCtx,
			"epp:extension/enumval:create/enumval:valExDate", 0), error);
#ifdef SECDNS_ENABLED
	/* secDNS extension */
	XCHK(xpathObj = xmlXPathEvalExpression(BAD_CAST
			"epp:extension/secdns:create/secdns:dsData", xpathCtx), error);
	if (xmlXPathNodeSetGetLength(xpathObj->nodesetval) > 0) {
		epp_ds	*ds;
		int	i;

		/* XXX possible memory leak - if error occurs xpathObj is not released */
		for (i = 0; i < xmlXPathNodeSetGetLength(xpathObj->nodesetval); i++) {
			/* change relative path prefix */
			xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, i);
			/* allocate necessary structures */
			if (!(item = epp_malloc(pool, sizeof *item))
				|| (!(ds = epp_calloc(pool, sizeof *ds))))
				goto error;
			/* parse dnssec extensions */
			XCHK(str = xpath_get1(pool, xpathCtx, "secdns:keyTag", 1), error);
			ds->keytag = atoi(str);
			XCHK(str = xpath_get1(pool, xpathCtx, "secdns:alg", 1), error);
			ds->alg = atoi(str);
			XCHK(str = xpath_get1(pool, xpathCtx, "secdns:digestType", 1),error);
			ds->digestType = atoi(str);
			XCHK(ds->digest = xpath_get1(pool, xpathCtx, "secdns:digest", 1),
					error);
			XCHK(str = xpath_get1(pool, xpathCtx, "secdns:maxSigLife", 0),error);
			ds->digestType = (*str == '\0') ? 0 : atoi(str);
			/*
			 * following fields are optional and are meaningfull only if
			 * all of them are filled in. We don't check it here, xsd takes
			 * care of this.
			 */
			XCHK(str = xpath_get1(pool, xpathCtx,
						"secdns:keyData/secdns:flags", 0), error);
			ds->flags = (*str == '\0') ? -1 : atoi(str);
			XCHK(str = xpath_get1(pool, xpathCtx,
					"secdns:keyData/secdns:protocol", 0), error);
			ds->protocol = (*str == '\0') ? -1 : atoi(str);
			XCHK(str = xpath_get1(pool, xpathCtx,
					"secdns:keyData/secdns:alg", 0), error);
			ds->key_alg = (*str == '\0') ? -1 : atoi(str);
			XCHK(ds->pubkey = xpath_get1(pool, xpathCtx,
					"secdns:keyData/secdns:pubKey", 0), error);
			/* enqueue new item */
			CL_CONTENT(item) = (void *) ds;
			CL_ADD(cdata->in->create_domain.ds, item);

		}
	}
	xmlXPathFreeObject(xpathObj);
#endif /* SECDNS_ENABLED */

	cdata->type = EPP_CREATE_DOMAIN;
	return;

error:
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
 * @param pool Pool for memory allocations.
 * @param xpathCtx XPath context.
 * @param cdata Output of parsing stage.
 */
static void
parse_create_contact(
		void *pool,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	xmlXPathObjectPtr	xpathObj;

	/* allocate necessary structures */
	if (!(cdata->in = epp_calloc(pool, sizeof (*cdata->in)))
		|| !(cdata->in->create_contact.postalInfo = epp_calloc(pool,
				sizeof (*cdata->in->create_contact.postalInfo)))
		|| !(cdata->in->create_contact.discl = epp_calloc(pool,
				sizeof (*cdata->in->create_contact.discl))))
	{
		goto error;
	}
	/* get the contact data */
	XCHK(cdata->in->create_contact.id = xpath_get1(pool, xpathCtx,
			"contact:id", 1), error);
	XCHK(cdata->in->create_contact.authInfo = xpath_get1(pool, xpathCtx,
			"contact:authInfo/contact:pw", 0), error);
	XCHK(cdata->in->create_contact.voice = xpath_get1(pool, xpathCtx,
			"contact:voice", 0), error);
	XCHK(cdata->in->create_contact.fax = xpath_get1(pool, xpathCtx,
			"contact:fax", 0), error);
	XCHK(cdata->in->create_contact.email = xpath_get1(pool, xpathCtx,
			"contact:email", 1), error);
	XCHK(cdata->in->create_contact.notify_email = xpath_get1(pool, xpathCtx,
			"contact:notifyEmail", 0), error);
	XCHK(cdata->in->create_contact.vat = xpath_get1(pool, xpathCtx,
			"contact:vat", 0), error);
	XCHK(cdata->in->create_contact.ssn = xpath_get1(pool, xpathCtx,
			"contact:ssn", 0), error);
	cdata->in->create_contact.ssntype = SSN_UNKNOWN;
	if (*cdata->in->create_contact.ssn != '\0') {
		char	*str;

		XCHK(str = xpath_get_attr(pool, xpathCtx, "contact:ssn", "type", 1),
				error);
		cdata->in->create_contact.ssntype = string2ssntype(str);
		/* schema and source code is out of sync if following error occurs */
		assert(cdata->in->create_contact.ssntype != SSN_UNKNOWN);
	}
	/*
	 * disclose flags - we don't interpret anyhow disclose flags, we just
	 * send the values to CR and CR decides in conjuction with default
	 * server policy what to do
	 */
	if (xpath_exists(xpathCtx, "contact:disclose[@flag='0']"))
		cdata->in->create_contact.discl->flag = 0;
	else if (xpath_exists(xpathCtx, "contact:disclose[@flag='1']"))
		cdata->in->create_contact.discl->flag = 1;
	else
		cdata->in->create_contact.discl->flag = -1;
	if (cdata->in->create_contact.discl->flag != -1) {
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
	XCHK(xpathObj = xmlXPathEvalExpression(BAD_CAST "contact:postalInfo",
				xpathCtx), error);
	xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, 0);
	xmlXPathFreeObject(xpathObj);

	XCHK(cdata->in->create_contact.postalInfo->name = xpath_get1(pool, xpathCtx,
			"contact:name", 1), error);
	XCHK(cdata->in->create_contact.postalInfo->org = xpath_get1(pool, xpathCtx,
			"contact:org", 0), error);
	XCHK(xpathObj = xmlXPathEvalExpression(BAD_CAST
				"contact:addr/contact:street", xpathCtx), error);
	if (xpathObj->nodesetval) {
		int	i, j;
		for (i = 0; i < xmlXPathNodeSetGetLength(xpathObj->nodesetval); i++) {
			cdata->in->create_contact.postalInfo->street[i] =
					epp_strdup(pool, TEXT_CONTENT(xpathObj, i));
			if (cdata->in->create_contact.postalInfo->street[i] == NULL) {
				xmlXPathFreeObject(xpathObj);
				goto error;
			}
		}
		/* the rest must be empty strings */
		for (j = i; j < 3; j++) {
			cdata->in->create_contact.postalInfo->street[j] =
					epp_strdup(pool, "");
			if (cdata->in->create_contact.postalInfo->street[j] == NULL) {
				xmlXPathFreeObject(xpathObj);
				goto error;
			}
		}
	}
	xmlXPathFreeObject(xpathObj);
	XCHK(cdata->in->create_contact.postalInfo->city = xpath_get1(pool, xpathCtx,
			"contact:addr/contact:city", 1), error);
	XCHK(cdata->in->create_contact.postalInfo->sp = xpath_get1(pool, xpathCtx,
			"contact:addr/contact:sp", 0), error);
	XCHK(cdata->in->create_contact.postalInfo->pc = xpath_get1(pool, xpathCtx,
			"contact:addr/contact:pc", 0), error);
	XCHK(cdata->in->create_contact.postalInfo->cc = xpath_get1(pool, xpathCtx,
			"contact:addr/contact:cc", 1), error);

	cdata->type = EPP_CREATE_CONTACT;
	return;

error:
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP create-nsset command.
 * @param pool Pool for memory allocations.
 * @param xpathCtx XPath context.
 * @param cdata Output of parsing stage.
 */
static void
parse_create_nsset(
		void *pool,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	xmlXPathObjectPtr	xpathObj;
	struct circ_list	*item;
	int	j;

	/* allocate necessary structures */
	if (!(cdata->in = epp_calloc(pool, sizeof (*cdata->in)))
		|| !(cdata->in->create_nsset.tech = epp_malloc(pool, sizeof *item))
		|| !(cdata->in->create_nsset.ns = epp_malloc(pool, sizeof *item)))
	{
		goto error;
	}
	CL_NEW(cdata->in->create_nsset.tech);
	CL_NEW(cdata->in->create_nsset.ns);

	/* get the domain data */
	XCHK(cdata->in->create_nsset.id = xpath_get1(pool, xpathCtx,
			"nsset:id", 1), error);
	XCHK(cdata->in->create_nsset.authInfo = xpath_get1(pool, xpathCtx,
			"nsset:authInfo/nsset:pw", 0), error);
	/* process "unbounded" number of tech contacts */
	XCHK(xpath_getn(pool, cdata->in->create_nsset.tech, xpathCtx,
			"nsset:tech"), error);
	/* process multiple ns records which have in turn multiple addresses */
	XCHK(xpathObj = xmlXPathEvalExpression(BAD_CAST "nsset:ns", xpathCtx),error);
	assert(xmlXPathNodeSetGetLength(xpathObj->nodesetval) > 0);
	for (j = 0; j < xmlXPathNodeSetGetLength(xpathObj->nodesetval); j++) {
		epp_ns	*ns;
		struct circ_list	*item;

		/* allocate data structures */
		if (!(item = epp_malloc(pool, sizeof *item))
			|| !(ns = epp_malloc(pool, sizeof *ns))
			|| !(ns->addr = epp_malloc(pool, sizeof *(ns->addr))))
		{
			xmlXPathFreeObject(xpathObj);
			goto error;
		}
		CL_NEW(item);
		CL_NEW(ns->addr);
		/* get data */
		xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, j);
		XCHK(ns->name = xpath_get1(pool, xpathCtx, "nsset:name", 1), error);
		XCHK(xpath_getn(pool, ns->addr, xpathCtx, "nsset:addr"), error);
		/* enqueue ns record */
		CL_CONTENT(item) = ns;
		CL_ADD(cdata->in->create_nsset.ns, item);
	}
	xmlXPathFreeObject(xpathObj);

	cdata->type = EPP_CREATE_NSSET;
	return;

error:
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP create command.
 * @param pool Pool for memory allocations.
 * @param xpathCtx XPath context.
 * @param cdata Output of parsing stage.
 */
static void
parse_create(
		void *pool,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	xmlXPathObjectPtr	xpathObj;

	/* get object type - contact, domain or nsset */
	XCHK(xpathObj = xmlXPathEvalExpression(BAD_CAST
				"epp:create/contact:create", xpathCtx), error);
	if (xmlXPathNodeSetGetLength(xpathObj->nodesetval) == 1) {
		/* change relative path prefix */
		xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, 0);
		xmlXPathFreeObject(xpathObj);
		parse_create_contact(pool, xpathCtx, cdata);
		return;
	}
	xmlXPathFreeObject(xpathObj);

	XCHK(xpathObj = xmlXPathEvalExpression(BAD_CAST
				"epp:create/domain:create", xpathCtx), error);
	if (xmlXPathNodeSetGetLength(xpathObj->nodesetval) == 1) {
		/* change relative path prefix and backup old one */
		xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, 0);
		xmlXPathFreeObject(xpathObj);
		parse_create_domain(pool, xpathCtx, cdata);
		return;
	}
	xmlXPathFreeObject(xpathObj);

	XCHK(xpathObj = xmlXPathEvalExpression(BAD_CAST
				"epp:create/nsset:create", xpathCtx), error);
	if (xmlXPathNodeSetGetLength(xpathObj->nodesetval) == 1) {
		/* change relative path prefix */
		xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, 0);
		xmlXPathFreeObject(xpathObj);
		parse_create_nsset(pool, xpathCtx, cdata);
		return;
	}
	xmlXPathFreeObject(xpathObj);

	/* unexpected object type */
	cdata->rc = 2000;
	cdata->type = EPP_DUMMY;
	return;

error:
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP delete command.
 * @param pool Pool for memory allocations.
 * @param xpathCtx XPath context.
 * @param cdata Output of parsing stage.
 */
static void
parse_delete(
		void *pool,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	/* allocate necessary structures */
	if ((cdata->in = epp_calloc(pool, sizeof (*cdata->in))) == NULL) {
		goto error;
	}

	/* get object type - contact, domain or nsset */
	if (xpath_exists(xpathCtx, "epp:delete/contact:delete"))
	{
		/* object is contact */
		XCHK(cdata->in->delete.id = xpath_get1(pool, xpathCtx,
				"epp:delete/contact:delete/contact:id", 1), error);
		cdata->type = EPP_DELETE_CONTACT;
	}
	else if (xpath_exists(xpathCtx, "epp:delete/domain:delete"))
	{
		/* object is a domain */
		XCHK(cdata->in->delete.id = xpath_get1(pool, xpathCtx,
				"epp:delete/domain:delete/domain:name", 1), error);
		cdata->type = EPP_DELETE_DOMAIN;
	}
	else if (xpath_exists(xpathCtx, "epp:delete/nsset:delete"))
	{
		/* object is a nsset */
		XCHK(cdata->in->delete.id = xpath_get1(pool, xpathCtx,
				"epp:delete/nsset:delete/nsset:id", 1), error);
		cdata->type = EPP_DELETE_NSSET;
	}
	else {
		/* unexpected object type */
		cdata->rc = 2000;
		cdata->type = EPP_DUMMY;
	}
	return;

error:
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP renew command.
 * @param pool Pool for memory allocations.
 * @param xpathCtx XPath context.
 * @param cdata Output of parsing stage.
 */
static void
parse_renew(
		void *pool,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	char	*str;

	/* allocate necessary structures */
	if (!(cdata->in = epp_calloc(pool, sizeof (*cdata->in)))) {
		goto error;
	}
	/* get renew data */
	XCHK(cdata->in->renew.name = xpath_get1(pool, xpathCtx,
			"epp:renew/domain:renew/domain:name", 1), error);
	XCHK(cdata->in->renew.exDate = xpath_get1(pool, xpathCtx,
			"epp:renew/domain:renew/domain:curExpDate", 1), error);
	/* domain period handling is slightly more difficult */
	XCHK(str = xpath_get1(pool, xpathCtx,
			"epp:renew/domain:renew/domain:period", 0), error);
	if (*str != '\0') {
		cdata->in->create_domain.period = atoi(str);
		/* correct period value if given in years and not months */
		XCHK(str = xpath_get_attr(pool, xpathCtx,
				"epp:renew/domain:renew/domain:period", "unit", 1), error);
		if (*str == 'y') cdata->in->create_domain.period *= 12;
	}
	else
		/*
		 * value 0 means that the period was not given and default value
		 * should be used instead
		 */
		cdata->in->renew.period = 0;

	/* enumval extension */
	XCHK(cdata->in->renew.valExDate = xpath_get1(pool, xpathCtx,
			"epp:extension/enumval:renew/enumval:valExDate", 0), error);

	cdata->type = EPP_RENEW_DOMAIN;
	return;

error:
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP update-domain command.
 * @param pool Pool for memory allocations.
 * @param xpathCtx XPath context.
 * @param cdata Output of parsing stage.
 */
static void
parse_update_domain(
		void *pool,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	struct circ_list	*item;

	/* allocate necessary structures */
	if (!(cdata->in = epp_calloc(pool, sizeof (*cdata->in)))
		|| !(cdata->in->update_domain.add_admin = epp_malloc(pool, sizeof *item))
		|| !(cdata->in->update_domain.rem_admin = epp_malloc(pool, sizeof *item))
		|| !(cdata->in->update_domain.add_status= epp_malloc(pool, sizeof *item))
		|| !(cdata->in->update_domain.rem_status= epp_malloc(pool, sizeof *item))
		|| !(cdata->in->update_domain.chg_ds = epp_malloc(pool, sizeof *item))
		|| !(cdata->in->update_domain.add_ds = epp_malloc(pool, sizeof *item))
		|| !(cdata->in->update_domain.rem_ds = epp_malloc(pool, sizeof *item)))
	{
		goto error;
	}
	CL_NEW(cdata->in->update_domain.add_admin);
	CL_NEW(cdata->in->update_domain.rem_admin);
	CL_NEW(cdata->in->update_domain.add_status);
	CL_NEW(cdata->in->update_domain.rem_status);
	CL_NEW(cdata->in->update_domain.chg_ds);
	CL_NEW(cdata->in->update_domain.add_ds);
	CL_NEW(cdata->in->update_domain.rem_ds);

	/* get the update-domain data */
	XCHK(cdata->in->update_domain.name = xpath_get1(pool, xpathCtx,
			"domain:name", 1), error);
	/* chg data */
	XCHK(cdata->in->update_domain.registrant = xpath_get1_upd(pool, xpathCtx,
			"domain:chg/domain:registrant"), error);
	XCHK(cdata->in->update_domain.nsset = xpath_get1_upd(pool, xpathCtx,
			"domain:chg/domain:nsset"), error);
	XCHK(cdata->in->update_domain.authInfo = xpath_get1_upd(pool, xpathCtx,
			"domain:chg/domain:authInfo/domain:pw"), error);
	/* add & rem data */
	XCHK(xpath_getn(pool, cdata->in->update_domain.add_admin, xpathCtx,
			"domain:add/domain:admin"), error);
	XCHK(xpath_getn(pool, cdata->in->update_domain.rem_admin, xpathCtx,
			"domain:rem/domain:admin"), error);
	/* status (attrs) */
	XCHK(xpath_getn_attrs(pool, cdata->in->update_domain.add_status, xpathCtx,
			"domain:add/domain:status", "s"), error);
	XCHK(xpath_getn_attrs(pool, cdata->in->update_domain.rem_status, xpathCtx,
			"domain:rem/domain:status", "s"), error);

	/* now look for optional extensions (extension tag is 2 layers upwards) */
	xpathCtx->node = xpathCtx->node->parent->parent;
	/* enumval extension */
	XCHK(cdata->in->update_domain.valExDate = xpath_get1(pool, xpathCtx,
			"epp:extension/enumval:update/enumval:chg/enumval:valExDate", 0),
			error);
#ifdef SECDNS_ENABLE
	/* secDNS extension */
	XPATH_EVAL(xpathObj, xpathCtx, error_ud, "epp:extension/secdns:update");
	if (xmlXPathNodeSetGetLength(xpathObj->nodesetval) > 0) {
		epp_ds	*ds;
		int	i;
		unsigned	*num;

		xmlXPathFreeObject(xpathObj);
		/* rem */
#error "It is a terible error to enable SECDNS before code correction!"
		XPATH_EVAL(xpathObj, xpathCtx, error_ud, "secdns:rem/secdns:keyTag");
		for (i = 0; i < xmlXPathNodeSetGetLength(xpathObj->nodesetval); i++) {
			if (!(item = epp_malloc(pool, sizeof *item))
				|| !(num = epp_malloc(pool, sizeof *num)))
			{
				goto error;
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
#endif /* SECDNS_ENABLE */

	cdata->type = EPP_UPDATE_DOMAIN;
	return;

error:
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP update-contact command.
 * @param pool Pool for memory allocations.
 * @param doc Parsed XML document.
 * @param xpathCtx XPath context.
 * @param cdata Output of parsing stage.
 */
static void
parse_update_contact(
		void *pool,
		xmlDocPtr doc,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	xmlXPathObjectPtr	xpathObj;
	struct circ_list	*item;
	int	is_pi; /* is there postalInfo section */
	int is_addr; /* is there address section */

	/* allocate necessary structures */
	if (!(cdata->in = epp_calloc(pool, sizeof (*cdata->in)))
		|| !(cdata->in->update_contact.add_status =
			epp_malloc(pool, sizeof *item))
		|| !(cdata->in->update_contact.rem_status =
			epp_malloc(pool, sizeof *item))
		|| !(cdata->in->update_contact.discl =
			epp_calloc(pool, sizeof *(cdata->in->update_contact.discl)))
		|| !(cdata->in->update_contact.postalInfo =
			epp_calloc(pool, sizeof *(cdata->in->update_contact.postalInfo))))
	{
		goto error;
	}
	CL_NEW(cdata->in->update_contact.add_status);
	CL_NEW(cdata->in->update_contact.rem_status);

	/* get the update-contact data */
	/* the most difficult item comes first (ssn) */
	XCHK(cdata->in->update_contact.ssn = xpath_get1_upd(pool, xpathCtx,
			"contact:chg/contact:ssn"), error);
	cdata->in->update_contact.ssntype = SSN_UNKNOWN;
	if (*cdata->in->create_contact.ssn != '\0' ||
			*cdata->in->create_contact.ssn != BS_CHAR) {
		char	*str;

		XCHK(str = xpath_get_attr(pool, xpathCtx, "contact:chg/contact:ssn",
				"type", 1), error);
		if (*str != '\0') {
			cdata->in->create_contact.ssntype = string2ssntype(str);
			/* schema and source code is out of sync if following error occurs */
			assert(cdata->in->create_contact.ssntype != SSN_UNKNOWN);
		}
		else {
			/* create our custom error */
			struct circ_list	*new_item;
			xmlBufferPtr	buf;
			epp_error	*valerr;

			/*
			 * we will politely create error message which says which
			 * parameter is missing.
			 */
			if (!(valerr = epp_malloc(pool, sizeof *valerr))
				|| !(new_item = epp_malloc(pool, sizeof *new_item)))
			{
				goto error;
			}

			/* dump problematic node */
			buf = xmlBufferCreate();
			if (buf == NULL)
				goto error;
			XCHK(xpathObj = xmlXPathEvalExpression(BAD_CAST
						"contact:chg/contact:ssn", xpathCtx), error);
			if (xmlNodeDump(buf, doc,
						xmlXPathNodeSetItem(xpathObj->nodesetval, 0), 0, 0) < 0)
			{
				xmlBufferFree(buf);
				xmlXPathFreeObject(xpathObj);
				goto error;
			}
			xmlXPathFreeObject(xpathObj);
			valerr->value = epp_strdup(pool, (char *) buf->content);
			xmlBufferFree(buf);

			/* TODO This should be bilingual */
			valerr->reason = epp_strdup(pool,
					"Required parameter \"type\" is missing");
			valerr->standalone = 1;

			CL_CONTENT(new_item) = (void *) valerr;
			CL_ADD(cdata->errors, new_item);

			cdata->rc = 2003;
			cdata->type = EPP_DUMMY;
			return;
		}
	}

	XCHK(cdata->in->update_contact.id = xpath_get1(pool, xpathCtx,
				"contact:id", 1), error);
	/* chg data */
	XCHK(cdata->in->update_contact.authInfo = xpath_get1_upd(pool, xpathCtx,
			"contact:chg/contact:authInfo/contact:pw"), error);
	XCHK(cdata->in->update_contact.voice = xpath_get1_upd(pool, xpathCtx,
			"contact:chg/contact:voice"), error);
	XCHK(cdata->in->update_contact.fax = xpath_get1_upd(pool, xpathCtx,
			"contact:chg/contact:fax"), error);
	XCHK(cdata->in->update_contact.email = xpath_get1(pool, xpathCtx,
			"contact:chg/contact:email", 0), error);
	XCHK(cdata->in->update_contact.notify_email = xpath_get1_upd(pool, xpathCtx,
			"contact:chg/contact:notifyEmail"), error);
	XCHK(cdata->in->update_contact.vat = xpath_get1_upd(pool, xpathCtx,
			"contact:chg/contact:vat"), error);
	/*
	 * there can be just one disclose section, now it depens if the flag is
	 * 0 or 1
	 */
	if (xpath_exists(xpathCtx, "contact:chg/contact:disclose[@flag='0']"))
		cdata->in->update_contact.discl->flag = 0;
	else if (xpath_exists(xpathCtx, "contact:chg/contact:disclose[@flag='1']"))
		cdata->in->update_contact.discl->flag = 1;
	else
		cdata->in->update_contact.discl->flag = -1;

	if (cdata->in->update_contact.discl->flag != -1) {
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
	/* is there postalInfo section ? */
	is_pi = xpath_exists(xpathCtx, "contact:chg/contact:postalInfo");
	if (is_pi) {
		/* is there address section? */
		is_addr = xpath_exists(xpathCtx,
				"contact:chg/contact:postalInfo/contact:addr");
	}
	XCHK(cdata->in->update_contact.postalInfo->name = (is_pi) ?
			xpath_get1_upd(pool, xpathCtx,
				"contact:chg/contact:postalInfo/contact:name"):
			epp_strdup(pool, ""), error);
	XCHK(cdata->in->update_contact.postalInfo->org = (is_pi) ?
			xpath_get1_upd(pool, xpathCtx,
				"contact:chg/contact:postalInfo/contact:org"):
			epp_strdup(pool, ""), error);
	XCHK(cdata->in->update_contact.postalInfo->city = (is_addr) ?
			xpath_get1_upd(pool, xpathCtx,
				"contact:chg/contact:postalInfo/contact:addr/contact:city"):
			epp_strdup(pool, ""), error);
	XCHK(cdata->in->update_contact.postalInfo->sp = (is_addr) ?
			xpath_get1_upd(pool, xpathCtx,
				"contact:chg/contact:postalInfo/contact:addr/contact:sp"):
			epp_strdup(pool, ""), error);
	XCHK(cdata->in->update_contact.postalInfo->pc = (is_addr) ?
			xpath_get1_upd(pool, xpathCtx,
				"contact:chg/contact:postalInfo/contact:addr/contact:pc"):
			epp_strdup(pool, ""), error);
	XCHK(cdata->in->update_contact.postalInfo->cc = (is_addr) ?
			xpath_get1_upd(pool, xpathCtx,
				"contact:chg/contact:postalInfo/contact:addr/contact:cc"):
			epp_strdup(pool, ""), error);
	if (is_addr) {
		XCHK(xpathObj = xmlXPathEvalExpression(BAD_CAST
				"contact:chg/contact:postalInfo/contact:addr/contact:street",
				xpathCtx), error);
		if (xpathObj->nodesetval) {
			int	i, j;
			char	*str;

			for (i = 0; i < xmlXPathNodeSetGetLength(xpathObj->nodesetval); i++)
			{
				cdata->in->update_contact.postalInfo->street[i] =
						epp_strdup(pool, TEXT_CONTENT(xpathObj, i));
				if (cdata->in->create_contact.postalInfo->street[i] == NULL) {
					xmlXPathFreeObject(xpathObj);
					goto error;
				}
			}
			/* the rest must be "backspace" strings */
			for (j = i; j < 3; j++) {
				str = epp_malloc(pool, 2);
				if (str == NULL) {
					xmlXPathFreeObject(xpathObj);
					goto error;
				}
				str[0] = BS_CHAR;
				str[1] = '\0';
				cdata->in->update_contact.postalInfo->street[j] = str;
			}
		}
		xmlXPathFreeObject(xpathObj);
	}
	else {
		/* fill empty strings in address fields */
		XCHK(cdata->in->update_contact.postalInfo->street[0] =
				epp_strdup(pool, ""), error);
		XCHK(cdata->in->update_contact.postalInfo->street[1] =
				epp_strdup(pool, ""), error);
		XCHK(cdata->in->update_contact.postalInfo->street[2] =
				epp_strdup(pool, ""), error);
	}
	/* add & rem data */
	/* status (attrs) */
	XCHK(xpath_getn_attrs(pool, cdata->in->update_contact.add_status, xpathCtx,
			"contact:add/contact:status", "s"), error);
	XCHK(xpath_getn_attrs(pool, cdata->in->update_contact.rem_status, xpathCtx,
			"contact:rem/contact:status", "s"), error);

	cdata->type = EPP_UPDATE_CONTACT;
	return;

error:
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP update-nsset command.
 * @param pool Pool for memory allocations.
 * @param xpathCtx XPath context.
 * @param cdata Output of parsing stage.
 */
static void
parse_update_nsset(
		void *pool,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	struct circ_list	*item;
	xmlXPathObjectPtr	xpathObj;
	int	j;

	/* allocate necessary structures */
	if (!(cdata->in = epp_calloc(pool, sizeof (*cdata->in)))
		|| !(cdata->in->update_nsset.add_ns = epp_malloc(pool, sizeof *item))
		|| !(cdata->in->update_nsset.rem_ns = epp_malloc(pool, sizeof *item))
		|| !(cdata->in->update_nsset.add_tech = epp_malloc(pool, sizeof *item))
		|| !(cdata->in->update_nsset.rem_tech = epp_malloc(pool, sizeof *item))
		|| !(cdata->in->update_nsset.add_status = epp_malloc(pool, sizeof *item))
		|| !(cdata->in->update_nsset.rem_status = epp_malloc(pool,sizeof *item)))
	{
		goto error;
	}
	CL_NEW(cdata->in->update_nsset.rem_ns);
	CL_NEW(cdata->in->update_nsset.add_tech);
	CL_NEW(cdata->in->update_nsset.rem_tech);
	CL_NEW(cdata->in->update_nsset.add_status);
	CL_NEW(cdata->in->update_nsset.add_ns);
	CL_NEW(cdata->in->update_nsset.rem_status);

	/* get the update-nsset data */
	XCHK(cdata->in->update_nsset.id = xpath_get1(pool, xpathCtx,
			"nsset:id", 1), error);
	/* chg data */
	XCHK(cdata->in->update_nsset.authInfo = xpath_get1_upd(pool, xpathCtx,
			"nsset:chg/nsset:authInfo/nsset:pw"), error);
	/* add & rem tech */
	XCHK(xpath_getn(pool, cdata->in->update_nsset.add_tech, xpathCtx,
			"nsset:add/nsset:tech"), error);
	XCHK(xpath_getn(pool, cdata->in->update_nsset.rem_tech, xpathCtx,
			"nsset:rem/nsset:tech"), error);
	/* add & rem status */
	XCHK(xpath_getn_attrs(pool, cdata->in->update_nsset.add_status, xpathCtx,
			"nsset:add/nsset:status", "s"), error);
	XCHK(xpath_getn_attrs(pool, cdata->in->update_nsset.rem_status, xpathCtx,
			"nsset:rem/nsset:status", "s"), error);
	/* rem ns */
	XCHK(xpath_getn(pool, cdata->in->update_nsset.rem_ns, xpathCtx,
			"nsset:rem/nsset:name"), error);

	/* add ns */
	XCHK(xpathObj = xmlXPathEvalExpression(BAD_CAST "nsset:add/nsset:ns",
			xpathCtx), error);
	/* memory leaks are possible with this schema but not ussual */
	for (j = 0; j < xmlXPathNodeSetGetLength(xpathObj->nodesetval); j++) {
		epp_ns	*ns;
		struct circ_list	*item;

		/* allocate data structures */
		if (!(item = epp_malloc(pool, sizeof *item))
			|| !(ns = epp_malloc(pool, sizeof *ns))
			|| !(ns->addr = epp_malloc(pool, sizeof *(ns->addr))))
		{
			xmlXPathFreeObject(xpathObj);
			goto error;
		}
		CL_NEW(item);
		CL_NEW(ns->addr);
		/* get data */
		xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, j);
		if ((ns->name = xpath_get1(pool, xpathCtx, "nsset:name", 1)) == NULL
			|| xpath_getn(pool, ns->addr, xpathCtx, "nsset:addr") == 0)
		{
			xmlXPathFreeObject(xpathObj);
			goto error;
		}
		/* enqueue ns record */
		CL_CONTENT(item) = ns;
		CL_ADD(cdata->in->update_nsset.add_ns, item);
	}
	xmlXPathFreeObject(xpathObj);

	cdata->type = EPP_UPDATE_NSSET;
	return;

error:
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}


/**
 * Parser of EPP update command.
 * @param pool Pool for memory allocations.
 * @param doc Parsed XML document.
 * @param xpathCtx XPath context.
 * @param cdata Output of parsing stage.
 */
static void
parse_update(
		void *pool,
		xmlDocPtr doc,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	xmlXPathObjectPtr	xpathObj;

	/* get object type - contact, domain or nsset */
	XCHK(xpathObj = xmlXPathEvalExpression(BAD_CAST "epp:update/contact:update",
				xpathCtx), error);
	/* if object is contact */
	if (xmlXPathNodeSetGetLength(xpathObj->nodesetval) == 1) {
		/* change relative path prefix */
		xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, 0);
		xmlXPathFreeObject(xpathObj);
		parse_update_contact(pool, doc, xpathCtx, cdata);
		return;
	}
	xmlXPathFreeObject(xpathObj);
	XCHK(xpathObj = xmlXPathEvalExpression(BAD_CAST "epp:update/domain:update",
				xpathCtx), error);
	if (xmlXPathNodeSetGetLength(xpathObj->nodesetval) == 1) {
		/* change relative path prefix */
		xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, 0);
		xmlXPathFreeObject(xpathObj);
		parse_update_domain(pool, xpathCtx, cdata);
		return;
	}
	xmlXPathFreeObject(xpathObj);
	XCHK(xpathObj = xmlXPathEvalExpression(BAD_CAST "epp:update/nsset:update",
				xpathCtx), error);
	if (xmlXPathNodeSetGetLength(xpathObj->nodesetval) == 1) {
		/* change relative path prefix */
		xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, 0);
		xmlXPathFreeObject(xpathObj);
		parse_update_nsset(pool, xpathCtx, cdata);
		return;
	}
	xmlXPathFreeObject(xpathObj);

	/* unexpected object type */
	cdata->rc = 2000;
	cdata->type = EPP_DUMMY;
	return;

error:
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP transfer command.
 * @param pool Pool for memory allocations.
 * @param doc Parsed XML document.
 * @param xpathCtx XPath context.
 * @param cdata Output of parsing stage.
 */
static void
parse_transfer(
		void *pool,
		xmlDocPtr doc,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	xmlXPathObjectPtr	xpathObj;

	/* allocate necessary structures */
	if ((cdata->in = epp_calloc(pool, sizeof (*cdata->in))) == NULL) {
		goto error;
	}

	/*
	 * we process only transfer requests (not approves, cancels, queries, ..)
	 * though all transfer commands are valid according to xml schemas
	 * because we don't want to be incompatible with epp-1.0 schema.
	 * If there is another command than "transfer request" we return
	 * 2102 "Unimplemented option" response.
	 */
	if (!xpath_exists(xpathCtx, "epp:transfer[@op='request']")) {
		/*
		 * Generate error message.
		 */
		struct circ_list	*new_item;
		xmlBufferPtr	buf;
		xmlNodePtr	node;
		epp_error	*valerr;

		if (!(valerr = epp_malloc(pool, sizeof *valerr))
			|| !(new_item = epp_malloc(pool, sizeof *new_item)))
		{
			goto error;
		}

		/* dump problematic node */
		buf = xmlBufferCreate();
		if (buf == NULL) {
			goto error;
		}
		XCHK(xpathObj = xmlXPathEvalExpression(BAD_CAST "epp:transfer",
					xpathCtx), error);
		node = xmlXPathNodeSetItem(xpathObj->nodesetval, 0);
		xmlXPathFreeObject(xpathObj);
		if (xmlNodeDump(buf, doc, node, 0, 0) < 0) {
			xmlBufferFree(buf);
			goto error;
		}
		valerr->value = epp_strdup(pool, (char *) buf->content);
		xmlBufferFree(buf);

		/* TODO This should be bilingual */
		valerr->reason =
			epp_strdup(pool, "Unimplemented op value or bad object type");
		valerr->standalone = 1;
		/* enqueue item */
		CL_CONTENT(new_item) = (void *) valerr;
		CL_ADD(cdata->errors, new_item);

		cdata->rc = 2102;
		cdata->type = EPP_DUMMY;
		return;
	}
	/* get object type - domain, contact or nsset */
	if (xpath_exists(xpathCtx, "epp:transfer[@op='request']/domain:transfer"))
	{
		/* object is a domain */
		XCHK(cdata->in->transfer.id = xpath_get1(pool, xpathCtx,
				"epp:transfer/domain:transfer/domain:name", 1), error);
		XCHK(cdata->in->transfer.authInfo = xpath_get1(pool, xpathCtx,
				"epp:transfer/domain:transfer/domain:authInfo/domain:pw", 0),
				error);
		cdata->type = EPP_TRANSFER_DOMAIN;
		return;
	}
	if (xpath_exists(xpathCtx, "epp:transfer[@op='request']/nsset:transfer"))
	{
		/* object is a nsset */
		XCHK(cdata->in->transfer.id = xpath_get1(pool, xpathCtx,
				"epp:transfer/nsset:transfer/nsset:id", 1), error);
		XCHK(cdata->in->transfer.authInfo = xpath_get1(pool, xpathCtx,
				"epp:transfer/nsset:transfer/nsset:authInfo/nsset:pw", 0),
				error);
		cdata->type = EPP_TRANSFER_NSSET;
		return;
	}
	if (xpath_exists(xpathCtx, "epp:transfer[@op='request']/contact:transfer"))
	{
		/* object is a contact */
		XCHK(cdata->in->transfer.id = xpath_get1(pool, xpathCtx,
				"epp:transfer/contact:transfer/contact:id", 1), error);
		XCHK(cdata->in->transfer.authInfo = xpath_get1(pool, xpathCtx,
				"epp:transfer/contact:transfer/contact:authInfo/contact:pw", 0),
				error);
		cdata->type = EPP_TRANSFER_CONTACT;
		return;
	}

	/* unexpected object type */
	cdata->rc = 2000;
	cdata->type = EPP_DUMMY;
	return;

error:
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

parser_status
epp_parse_command(
		void *pool,
		int session,
		void *schema,
		const char *request,
		unsigned bytes,
		epp_command_data **cdata_arg)
{
	xmlDocPtr	doc;
	xmlXPathContextPtr	xpathCtx;
	xmlXPathObjectPtr	xpathObj;
	epp_red_command_type	cmd;
	valid_status	val_ret;
	epp_command_data	*cdata;

	/* check input parameters */
	assert(pool != NULL);
	assert(request != NULL);
	assert(bytes != 0);

	/* parse xml request */
	doc = xmlParseMemory(request, bytes);
	if (doc == NULL) {
		return PARSER_NOT_XML;
	}

	/* allocate cdata structure */
	*cdata_arg = (epp_command_data *) epp_calloc(pool, sizeof *cdata);
	cdata = *cdata_arg;

	/*
	 * create validation error callback and initialize list which is used
	 * for error cumulation.
	 */
	cdata->errors = epp_malloc(pool, sizeof (*cdata->errors));
	if (cdata->errors == NULL) {
		xmlFreeDoc(doc);
		return PARSER_EINTERNAL;
	}
	CL_NEW(cdata->errors);

	/*
	 * Save input xml document (we cannot use strdup since it is not sure the
	 * request is NULL terminated).
	 */
	cdata->xml_in = epp_malloc(pool, bytes + 1);
	if (cdata->xml_in == NULL) {
		xmlFreeDoc(doc);
		return PARSER_EINTERNAL;
	}
	memcpy(cdata->xml_in, request, bytes);
	cdata->xml_in[bytes] = '\0';

	/* validate the doc */
	val_ret = validate_doc(pool, (xmlSchemaPtr) schema, doc, cdata->errors);

	if (val_ret == VAL_ESCHEMA || val_ret == VAL_EINTERNAL) {
		xmlFreeDoc(doc);
		return (val_ret == VAL_ESCHEMA) ? PARSER_ESCHEMA : PARSER_EINTERNAL;
	}
	else if (val_ret == VAL_NOT_VALID) {
		/*
		 * validation error consequence: response identifing a problem is sent
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
		xmlFreeDoc(doc);
		return PARSER_EINTERNAL;
	}

	/*
	 * register namespaces and their prefixes in XPath context
	 * Error handling is same for all xmlXPathRegisterNs calls.
	 */
	if (xmlXPathRegisterNs(xpathCtx, BAD_CAST "epp", BAD_CAST NS_EPP) ||
		xmlXPathRegisterNs(xpathCtx, BAD_CAST "contact", BAD_CAST NS_CONTACT) ||
		xmlXPathRegisterNs(xpathCtx, BAD_CAST "domain", BAD_CAST NS_DOMAIN) ||
		xmlXPathRegisterNs(xpathCtx, BAD_CAST "nsset", BAD_CAST NS_NSSET) ||
#ifdef SECDNS_ENABLE
		xmlXPathRegisterNs(xpathCtx, BAD_CAST "secdns", BAD_CAST NS_SECDNS) ||
#endif
		xmlXPathRegisterNs(xpathCtx, BAD_CAST "enumval", BAD_CAST NS_ENUMVAL))
	{
		xmlXPathFreeContext(xpathCtx);
		xmlFreeDoc(doc);
		return PARSER_EINTERNAL;
	}

	/* if it is a <hello> frame, we will send greeting and return */
	if (xpath_exists(xpathCtx, "/epp:epp/epp:hello")) {
		xmlXPathFreeContext(xpathCtx);
		xmlFreeDoc(doc);
		return PARSER_HELLO;
	}

	/* is it a command? */
	if (!xpath_exists(xpathCtx, "/epp:epp/epp:command")) {
		/*
		 * not all documents which are valid are commands (e.g. greeting,
		 * response, extension). EPP standard does not describe any error
		 * which should be returned in that case. Therefore we will silently
		 * close connection in that case.
		 */
		xmlXPathFreeContext(xpathCtx);
		xmlFreeDoc(doc);
		return PARSER_NOT_COMMAND;
	}
	/* set current node for relative path expressions */
	xpathObj = xmlXPathEvalExpression(BAD_CAST "/epp:epp/epp:command", xpathCtx);
	if (xpathObj == NULL) {
		xmlXPathFreeObject(xpathObj);
		xmlXPathFreeContext(xpathCtx);
		xmlFreeDoc(doc);
		return PARSER_EINTERNAL;
	}
	assert(xmlXPathNodeSetGetLength(xpathObj->nodesetval) == 1);
	xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, 0);
	xmlXPathFreeObject(xpathObj);

	/* it is a command, get clTRID if there is any */
	if ((cdata->clTRID = xpath_get1(pool, xpathCtx, "epp:clTRID", 0)) == NULL)
	{
		xmlXPathFreeContext(xpathCtx);
		xmlFreeDoc(doc);
		return PARSER_EINTERNAL;
	}

	/*
	 * command recognition part
	 * XXX We shouldn't do any assumtions about order of nodes in
	 * nodeset, currently we do :(
	 */
	xpathObj = xmlXPathEvalExpression(BAD_CAST "*", xpathCtx);
	if (xpathObj == NULL) {
		xmlXPathFreeContext(xpathCtx);
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
			parse_login(pool, xpathCtx, cdata);
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
			parse_check(pool, xpathCtx, cdata);
			break;
		case EPP_RED_INFO:
			parse_info(pool, xpathCtx, cdata);
			break;
		case EPP_RED_POLL:
			parse_poll(pool, doc, xpathCtx, cdata);
			break;
		case EPP_RED_CREATE:
			parse_create(pool, xpathCtx, cdata);
			break;
		case EPP_RED_DELETE:
			parse_delete(pool, xpathCtx, cdata);
			break;
		case EPP_RED_RENEW:
			parse_renew(pool, xpathCtx, cdata);
			break;
		case EPP_RED_UPDATE:
			parse_update(pool, doc, xpathCtx, cdata);
			break;
		case EPP_RED_TRANSFER:
			parse_transfer(pool, doc, xpathCtx, cdata);
			break;
		case EPP_RED_UNKNOWN_CMD:
		default:
			cdata->rc = 2000;
			cdata->type = EPP_DUMMY;
			break;
	}

	xmlXPathFreeContext(xpathCtx);
	xmlFreeDoc(doc);

	if (cdata->type == EPP_LOGIN) return PARSER_CMD_LOGIN;
	if (cdata->type == EPP_LOGOUT) return PARSER_CMD_LOGOUT;

	return PARSER_CMD_OTHER;
}

/* vim: set ts=4 sw=4: */
