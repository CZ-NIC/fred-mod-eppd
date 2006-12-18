/**
 * @file epp_parser.c
 *
 * Component for parsing EPP requests in form of xml documents.
 *
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

/**
 * Size of hash table used for hashing command names. The size is tradeof
 * between size of hash table and lookup speed, it should be less than 255
 * since hash value is unsigned char.
 */
#define HASH_SIZE_CMD	30

/**
 * @defgroup xerrors Error codes which signal the cause of an error and
 * macros which make working with error values easier.
 * @{
 */
#define XERR_OK       0 /**< OK status. */
#define XERR_LIBXML   1 /**< Error in function from libxml library. */
#define XERR_ALLOC    2 /**< Memory allocation failed. */
#define XERR_CONSTR   3 /**< Constraints given by caller were not fulfilled. */

/**
 * Macro checks given variable for an error, if the variable has error
 * status, a flow of a program is redirected to given label.
 */
#define CHK_XERR(_var, _label)	if ((_var) != XERR_OK) goto _label

/**
 * Macro checks given variable for an error, if the variable has error
 * status, a flow of a program is redirected to given label.
 */
#define RESET_XERR(_var)	((_var) = XERR_OK)
/**
 * @}
 */


/**
 * Get text content of an element.
 *
 * You have to copy the string from returned pointer if you want to manipulate
 * with string. Note that if element is empty (e.g. <example></example> the
 * child of this element is not empty string but NULL. This makes macro a bit
 * more complicated.
 */
#define TEXT_CONTENT(_xpathObj, _i)	\
	((char *) ((xmlXPathNodeSetItem((_xpathObj)->nodesetval, (_i))->xmlChildrenNode) ? (xmlXPathNodeSetItem((_xpathObj)->nodesetval, (_i))->xmlChildrenNode)->content : NULL))

/**
 * This function returns specified attribute value of given node.
 * You have to make your own copy if you want to edit the returned string.
 *
 * @param node     XPath object.
 * @param name     Name of attribute.
 * @return         Pointer to attribute's value.
 */
static char *
get_attr(xmlNodePtr node, const char *name)
{
	xmlAttrPtr	prop;

	assert(node != NULL);

	prop = node->properties;
	while (prop != NULL) {
		if (xmlStrEqual(prop->name, BAD_CAST name)) {
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
 * Function changes relative root of xpath context to node described
 * by xpath expression.
 *
 * @param ctx    XPath context.
 * @param expr   XPath expression.
 * @param index  Index of node if there are more nodes matching xpath
 *               expression, if index is out of range, NULL is returned.
 * @param xerr   Error status of function (must be set to ok upon calling
 *               the function).
 * @return       The old relative root, which was substituted by new one; or
 *               NULL in case of change failure (new node was not found).
 */
static xmlNodePtr
xpath_chroot(xmlXPathContextPtr ctx, const char *expr, int index, int *xerr)
{
	xmlXPathObjectPtr obj;
	xmlNodePtr	oldNode;

	obj = xmlXPathEvalExpression(BAD_CAST expr, ctx);
	if (obj == NULL) {
		*xerr = XERR_LIBXML;
		return NULL;
	}
	if (xmlXPathNodeSetGetLength(obj->nodesetval) < index + 1) {
		xmlXPathFreeObject(obj);
		*xerr = XERR_CONSTR;
		return NULL;
	}
	/* exchange the nodes */
	oldNode   = ctx->node;
	ctx->node = xmlXPathNodeSetItem(obj->nodesetval, index);
	xmlXPathFreeObject(obj);

	return oldNode;
}

/**
 * Sometimes we want to know how many elements satisfying xpath expression
 * are there or just to know if there is any or not.
 *
 * @param ctx    XPath context.
 * @param expr   XPath expression.
 * @param xerr   Error status of function (must be set to ok upon calling
 *               the function).
 * @return       Count of elements which satisfy xpath expression.
 */
static int
xpath_count(xmlXPathContextPtr ctx, const char *expr, int *xerr)
{
	xmlXPathObjectPtr obj;
	int count;

	obj = xmlXPathEvalExpression(BAD_CAST expr, ctx);
	if (obj == NULL) {
		*xerr = XERR_LIBXML;
		return 0;
	}
	count = xmlXPathNodeSetGetLength(obj->nodesetval);
	xmlXPathFreeObject(obj);

	return count;
}

/**
 * A content of element described by xpath expression is returned.
 *
 * The element must be only one. If req is set, the element is required to
 * exist, otherwise error in xerr is returned. If the element is not required
 * to exist and it is not there, NULL is returned. In case of internal
 * error, xerr is set to appropriate value.
 *
 * @param pool   Memory pool to allocate memory from.
 * @param ctx    XPath context pointer.
 * @param expr   XPath expression which describes a xml node.
 * @param req    1 if element is required to exist, 0 if not.
 * @param xerr   Error status of function (must be set to ok upon calling
 *               the function).
 * @return       String with content of xml element allocated from pool.
 */
static char *
xpath_get1(void *pool,
		xmlXPathContextPtr ctx,
		const char *expr,
		int req,
		int *xerr)
{
	xmlXPathObjectPtr obj;
	char	*res;

	obj = xmlXPathEvalExpression(BAD_CAST expr, ctx);
	if (obj == NULL) {
		*xerr = XERR_CONSTR;
		return NULL;
	}

	/* look what we got */
	if (xmlXPathNodeSetGetLength(obj->nodesetval) == 0) {
		xmlXPathFreeObject(obj);
		if (req) {
			*xerr = XERR_CONSTR;
		}
		return NULL;
	}
	else if (xmlXPathNodeSetGetLength(obj->nodesetval) > 1) {
		xmlXPathFreeObject(obj);
		*xerr = XERR_CONSTR;
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
 * List is filled by content of elements described by xpath expression
 * (There may be more elements matching xpath expression).
 *
 * @param pool   Memory pool to allocate memory from.
 * @param list   Head of empty list where the found items will be added.
 * @param ctx    XPath context pointer.
 * @param expr   XPath expression which describes a xml node.
 * @param xerr   Error status of function (must be set to ok upon calling
 *               the function).
 * @return If succesfull 1, in case of failure 0.
 */
static void
xpath_getn(void *pool,
		qhead *list,
		xmlXPathContextPtr ctx,
		const char *expr,
		int *xerr)
{
	int	i;
	xmlXPathObjectPtr obj;

	obj = xmlXPathEvalExpression(BAD_CAST expr, ctx);
	if (obj == NULL) {
		*xerr = XERR_LIBXML;
		return;
	}

	/* iterate through selected items */
	for (i = 0; i < xmlXPathNodeSetGetLength(obj->nodesetval); i++) {
		char	*value;

		if (TEXT_CONTENT(obj, i) == NULL)
			continue;

		value = epp_strdup(pool, TEXT_CONTENT(obj, i));
		if (value == NULL) {
			xmlXPathFreeObject(obj);
			*xerr = XERR_ALLOC;
			return;
		}
		if (q_add(pool, list, value)) {
			xmlXPathFreeObject(obj);
			*xerr = XERR_ALLOC;
			return;
		}
	}

	xmlXPathFreeObject(obj);
	return;
}

/**
 * A value of attribute of node described by xpath expression is returned.
 *
 * The resulting node must be only one. If req is set, the node is required to
 * exist and xerr is set to error status if it is not so. If the element is
 * not required to exist and it is not there, NULL is returned. If the element
 * exists but attribute doesn't, NULL is returned. In case of
 * internal error, xerr is set to appropriate error status.
 *
 * @param pool   Memory pool to allocate memory from.
 * @param ctx    XPath context pointer.
 * @param expr   XPath expression which describes a xml node.
 * @param attr   Name of attribute.
 * @param req    1 if element is required to exist, 0 if not.
 * @param xerr   Error status of function (must be set to ok upon calling
 *               the function).
 * @return       String with content of xml element allocated from pool.
 */
static char *
xpath_get_attr(void *pool,
		xmlXPathContextPtr ctx,
		const char *expr,
		const char *attr,
		int req,
		int *xerr)
{
	xmlXPathObjectPtr obj;
	char	*str, *attr_val;

	obj = xmlXPathEvalExpression(BAD_CAST expr, ctx);
	if (obj == NULL) {
		*xerr = XERR_LIBXML;
		return NULL;
	}

	/* look what we got */
	if (xmlXPathNodeSetGetLength(obj->nodesetval) == 0) {
		xmlXPathFreeObject(obj);
		if (req) {
			*xerr = XERR_CONSTR;
		}
		return NULL;
	}
	else if (xmlXPathNodeSetGetLength(obj->nodesetval) > 1) {
		xmlXPathFreeObject(obj);
		*xerr = XERR_CONSTR;
		return NULL;
	}

	str = get_attr(xmlXPathNodeSetItem(obj->nodesetval, 0), attr);
	if (str == NULL)
		attr_val = NULL;
	else
		attr_val = epp_strdup(pool, str);

	xmlXPathFreeObject(obj);
	return attr_val;
}
/**
 * @}
 */

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
	cmd_hash_item    *next;	/**< Next item in hash table. */
	char             *key;  /**< Hash key (command name). */
	epp_command_type  val;  /**< Hash value (command type). */
};

/**
 * Hash table of epp commands used for fast command lookup.
 *
 * Once the table is initialized, it is read-only. There for it is thread-safe
 * eventhough it is declared as static and not protected by a lock.
 */
static cmd_hash_item *hash_cmd[HASH_SIZE_CMD];

/**
 * Function for hashing of command name.
 *
 * Function makes xor of first 4 bytes of command name, which is sufficient
 * since first 4 letters are unique for all EPP commands. It is both simple
 * and fast. We assume that command names are at least 4 bytes long and that
 * there are no 2 command with the same first four letters - that's true for
 * EPP commands.
 *
 * @param key   Command name.
 * @return      Hash value.
 */
static unsigned char
get_cmd_hash(const char *key)
{
	int	i;
	unsigned char	hash = 0;

	/* return code has 4 digits */
	for (i = 0; i < 4; i++) hash ^= key[i];
	return hash % HASH_SIZE_CMD;
}

/**
 * Function inserts command in hash table.
 *
 * @param key   Input key for hash algorithm
 * @param type  Command type associated with given key
 * @return      0 in case of success, 1 in case of failure (Theese non-standard
 *              return values are due to the way of their processing in
 *              epp_parser_init()).
 */
static char
cmd_hash_insert(const char *key, epp_command_type type)
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
 *
 * @param key   Command name.
 * @return      Command type, if command is not found in hash table, value
 *              EPP_UNKNOWN_CMD is returned.
 */
static epp_command_type
cmd_hash_lookup(const char *key)
{
	cmd_hash_item	*hi;

	/* iterate through hash chain */
	for (hi = hash_cmd[get_cmd_hash(key)]; hi != NULL; hi = hi->next) {
		if (!strncmp(hi->key, key, 4))
			break;
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
	int	 i;

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
	if (spctx == NULL)
		return NULL;
	schema = xmlSchemaParse(spctx);
	xmlSchemaFreeParserCtxt(spctx);
	/*
	 * schema might be corrupted though it is unlikely, in that case
	 * schema has NULL value
	 */
	return (void *) schema;
}

void epp_parser_init_cleanup(void *schema)
{
	xmlSchemaFree((xmlSchemaPtr) schema);
	cmd_hash_clean();
	xmlCleanupParser();
}

/**
 * Create and enqueue new error item of specified type.
 *
 * @param pool     Pool for memory allocations.
 * @param errors   Error list where new error should be enqueued.
 * @param errspec  Specific code of an error.
 * @return         0 in case of success otherwise 1.
 */
static int
new_error_item(void *pool, qhead *errors, epp_errorspec errspec)
{
	epp_error	*valerr;

	valerr = epp_malloc(pool, sizeof *valerr);
	if (valerr == NULL)
		return 1;

	valerr->value  = NULL; /* will be filled by XML generator */
	valerr->reason = NULL; /* will be filled by CR */
	valerr->spec = errspec;

	if (q_add(pool, errors, valerr))
		return 1;
	return 0;
}

/**
 * Parser of EPP login command.
 *
 * @param pool      Pool for memory allocations.
 * @param xpathCtx  XPath context.
 * @param cdata     Output of parsing stage.
 */
static void
parse_login(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
	epps_login *login;
	char	*str;
	int	xerr;

	RESET_XERR(xerr); /* clear value of errno */

	/* allocate necessary structures */
	if ((cdata->data = epp_calloc(pool, sizeof *login)) == NULL)
		goto error;
	login = cdata->data;

	/* check if language matches */
	str = xpath_get1(pool, xpathCtx, "epp:options/epp:lang", 1, &xerr);
	CHK_XERR(xerr, error);
	if (xmlStrEqual((xmlChar *) str, BAD_CAST "en")) {
		login->lang = LANG_EN;
	}
	else if (xmlStrEqual((xmlChar *) str, BAD_CAST "cs")) {
		login->lang = LANG_CS;
	}
	else {
		cdata->type = EPP_DUMMY;
		cdata->rc = 2102;
		return;
	}

	/* check if EPP version matches */
	str = xpath_get1(pool, xpathCtx, "epp:options/epp:version", 1, &xerr);
	CHK_XERR(xerr, error);
	if (!xmlStrEqual((xmlChar *) str, BAD_CAST "1.0")) {
		cdata->type = EPP_DUMMY;
		cdata->rc = 2100;
		return;
	}

	/* ok, checking done. now get input parameters for corba function call */
	login->clID = xpath_get1(pool, xpathCtx, "epp:clID", 1, &xerr);
	CHK_XERR(xerr, error);
	login->pw = xpath_get1(pool, xpathCtx, "epp:pw", 1, &xerr);
	CHK_XERR(xerr, error);
	login->newPW = xpath_get1(pool, xpathCtx, "epp:newPW", 0, &xerr);
	CHK_XERR(xerr, error);
	xpath_getn(pool, &login->objuri, xpathCtx, "epp:svcs/epp:objURI", &xerr);
	CHK_XERR(xerr, error);
	xpath_getn(pool, &login->exturi, xpathCtx, "epp:svcs/epp:extURI", &xerr);
	CHK_XERR(xerr, error);

	cdata->type = EPP_LOGIN;
	return;

error:
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP check command.
 *
 * @param pool      Pool for memory allocations.
 * @param xpathCtx  XPath context.
 * @param cdata     Output of parsing stage.
 */
static void
parse_check(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
	epps_check *check;
	int	xerr;

	RESET_XERR(xerr); /* clear value of errno */

	/* allocate necessary structures */
	if ((cdata->data = epp_calloc(pool, sizeof *check)) == NULL)
		goto error;
	check = cdata->data;

	xpath_chroot(xpathCtx, "contact:check", 0, &xerr);
	if (xerr == XERR_OK) {
		xpath_getn(pool, &check->ids, xpathCtx, "contact:id", &xerr);
		CHK_XERR(xerr, error);
		cdata->type = EPP_CHECK_CONTACT;
		return;
	}
	else if (xerr != XERR_CONSTR)
		goto error;
	RESET_XERR(xerr); /* clear value of errno */

	xpath_chroot(xpathCtx, "domain:check", 0, &xerr);
	if (xerr == XERR_OK) {
		xpath_getn(pool, &check->ids, xpathCtx, "domain:name", &xerr);
		CHK_XERR(xerr, error);
		cdata->type = EPP_CHECK_DOMAIN;
		return;
	}
	else if (xerr != XERR_CONSTR)
		goto error;
	RESET_XERR(xerr); /* clear value of errno */

	xpath_chroot(xpathCtx, "nsset:check", 0, &xerr);
	if (xerr == XERR_OK) {
		xpath_getn(pool, &check->ids, xpathCtx, "nsset:id", &xerr);
		CHK_XERR(xerr, error);
		cdata->type = EPP_CHECK_NSSET;
		return;
	}
	else if (xerr != XERR_CONSTR)
		goto error;
	RESET_XERR(xerr); /* clear value of errno */

	/* unexpected object type (should not happen) */
	cdata->rc = 2000;
	cdata->type = EPP_DUMMY;
	return;

error:
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP info command + list command.
 *
 * List command is a non-standard command for listing of registered objects.
 * This makes info command very special since it may contain two different
 * commands. Authinfo tag is ignored in info command.
 *
 * @param pool      Pool for memory allocations.
 * @param xpathCtx  XPath context.
 * @param cdata     Output of parsing stage.
 */
static void
parse_info(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
	int	xerr, exists;

	RESET_XERR(xerr); /* clear value of errno */

	/*
	 * catch the "list command" at the beginning, then proceed with
	 * info command
	 */
	exists = xpath_count(xpathCtx, "contact:list", &xerr);
	CHK_XERR(xerr, error);
	if (exists) {
		epps_list	*list;

		if ((cdata->data = epp_calloc(pool, sizeof *list)) == NULL)
			goto error;
		list = cdata->data;

		cdata->type = EPP_LIST_CONTACT;
		return;
	}
	exists = xpath_count(xpathCtx, "domain:list", &xerr);
	CHK_XERR(xerr, error);
	if (exists) {
		epps_list	*list;

		if ((cdata->data = epp_calloc(pool, sizeof *list)) == NULL)
			goto error;
		list = cdata->data;

		cdata->type = EPP_LIST_DOMAIN;
		return;
	}
	exists = xpath_count(xpathCtx, "nsset:list", &xerr);
	CHK_XERR(xerr, error);
	if (exists) {
		epps_list	*list;

		if ((cdata->data = epp_calloc(pool, sizeof *list)) == NULL)
			goto error;
		list = cdata->data;

		cdata->type = EPP_LIST_NSSET;
		return;
	}

	/* info commands */

	xpath_chroot(xpathCtx, "contact:info", 0, &xerr);
	if (xerr == XERR_OK) {
		epps_info_contact	*info_contact;

		if ((cdata->data = epp_calloc(pool, sizeof *info_contact)) == NULL)
			goto error;
		info_contact = cdata->data;

		info_contact->id = xpath_get1(pool, xpathCtx, "contact:id", 1,
				&xerr);
		CHK_XERR(xerr, error);
		cdata->type = EPP_INFO_CONTACT;
		return;
	}
	else if (xerr != XERR_CONSTR) goto error;
	RESET_XERR(xerr); /* clear value of errno */

	xpath_chroot(xpathCtx, "domain:info", 0, &xerr);
	if (xerr == XERR_OK) {
		epps_info_domain	*info_domain;

		if ((cdata->data = epp_calloc(pool, sizeof *info_domain)) == NULL)
			goto error;
		info_domain = cdata->data;

		info_domain->name = xpath_get1(pool, xpathCtx, "domain:name", 1,
				&xerr);
		CHK_XERR(xerr, error);
		cdata->type = EPP_INFO_DOMAIN;
		return;
	}
	else if (xerr != XERR_CONSTR) goto error;
	RESET_XERR(xerr); /* clear value of errno */

	xpath_chroot(xpathCtx, "nsset:info", 0, &xerr);
	if (xerr == XERR_OK) {
		epps_info_nsset	*info_nsset;

		if ((cdata->data = epp_calloc(pool, sizeof *info_nsset)) == NULL)
			goto error;
		info_nsset = cdata->data;

		info_nsset->id = xpath_get1(pool, xpathCtx, "nsset:id",1, &xerr);
		CHK_XERR(xerr, error);
		cdata->type = EPP_INFO_NSSET;
		return;
	}
	else if (xerr != XERR_CONSTR) goto error;
	RESET_XERR(xerr); /* clear value of errno */

	/* unexpected object type for both (info & list) */
	cdata->rc = 2000;
	cdata->type = EPP_DUMMY;
	return;

error:
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP poll command. This is for both poll variants - req and ack.
 *
 * @param pool      Pool for memory allocations.
 * @param xpathCtx  XPath context.
 * @param cdata     Output of parsing stage.
 */
static void
parse_poll(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
	const char	*op, *str;

	/* get poll type - request or acknoledge */
	op = get_attr(xpathCtx->node, "op");
	assert(op != NULL);
	if (!strcmp(op, "req")) {
		epps_poll_req	*poll_req;

		/* it is request */
		if ((cdata->data = epp_calloc(pool, sizeof *poll_req)) == NULL)
			goto error;
		cdata->type = EPP_POLL_REQ;
		return;
	}

	/* it has to be acknowledge */
	assert(!strcmp(op, "ack"));

	/* get value of attr msgID */
	str = get_attr(xpathCtx->node, "msgID");

	/*
	 * msgID attribute is not strictly required by xml schema so we
	 * have to explicitly check if it is there
	 */
	if (str == NULL) {
		if (new_error_item(pool, &cdata->errors,
					errspec_poll_msgID_missing))
			goto error;
		cdata->rc = 2003;
		cdata->type = EPP_DUMMY;
	}
	else {
		epps_poll_ack	*poll_ack;

		if ((cdata->data = epp_calloc(pool, sizeof *poll_ack)) == NULL)
			goto error;
		poll_ack = cdata->data;

		poll_ack->msgid = epp_strdup(pool, str);
		cdata->type = EPP_POLL_ACK;
	}
	return;

error:
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
	return;
}

/**
 * Parser of EPP create-domain command.
 *
 * @param pool      Pool for memory allocations.
 * @param xpathCtx  XPath context.
 * @param cdata     Output of parsing stage.
 */
static void
parse_create_domain(void *pool,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	epps_create_domain	*create_domain;
	char	*str;
	int	xerr;

	RESET_XERR(xerr); /* clear value of errno */

	/* allocate necessary structures */
	if ((cdata->data = epp_calloc(pool, sizeof *create_domain)) == NULL)
		goto error;
	create_domain = cdata->data;

	/* get the domain data */
	create_domain->name = xpath_get1(pool, xpathCtx, "domain:name",1, &xerr);
	CHK_XERR(xerr, error);
	create_domain->registrant = xpath_get1(pool, xpathCtx,
			"domain:registrant", 1, &xerr);
	CHK_XERR(xerr, error);
	create_domain->nsset = xpath_get1(pool, xpathCtx,
			"domain:nsset", 0, &xerr);
	CHK_XERR(xerr, error);
	create_domain->authInfo = xpath_get1(pool, xpathCtx,
			"domain:authInfo", 0, &xerr);
	CHK_XERR(xerr, error);
	/* process "unbounded" number of admin contacts */
	xpath_getn(pool, &create_domain->admin, xpathCtx, "domain:admin", &xerr);
	CHK_XERR(xerr, error);
	/* domain period handling is slightly more difficult */
	str = xpath_get1(pool, xpathCtx, "domain:period[@unit='y']", 0, &xerr);
	CHK_XERR(xerr, error);
	create_domain->unit = TIMEUNIT_YEAR;
	if (str == NULL) {
		str = xpath_get1(pool, xpathCtx, "domain:period[@unit='m']",
				0, &xerr);
		CHK_XERR(xerr, error);
		create_domain->unit = TIMEUNIT_MONTH;
	}
	if (str != NULL)
		create_domain->period = atoi(str);
	else {
		/*
		 * value 0 means that the period was not given and default value
		 * should be used instead
		 */
		create_domain->period = 0;
	}

	cdata->type = EPP_CREATE_DOMAIN;
	return;

error:
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Routine converts string to ident type.
 *
 * @param str String to be compared and categorized.
 * @return If string is not matched, ident_UNKNOWN is returned.
 */
static epp_identType
string2identtype(const char *str)
{
	if (strcmp("op", str) == 0) return ident_OP;
	else if (strcmp("rc", str) == 0) return ident_RC;
	else if (strcmp("ico", str) == 0) return ident_ICO;
	else if (strcmp("mpsv", str) == 0) return ident_MPSV;
	else if (strcmp("passport", str) == 0) return ident_PASSPORT;

	return ident_UNKNOWN;
}

/**
 * Parser of EPP create-contact command.
 *
 * @param pool Pool for memory allocations.
 * @param xpathCtx XPath context.
 * @param cdata Output of parsing stage.
 */
static void
parse_create_contact(void *pool,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	epps_create_contact	*create_contact;
	int	xerr;

	RESET_XERR(xerr); /* clear value of errno */

	/* allocate necessary structures */
	if ((cdata->data = epp_calloc(pool, sizeof *create_contact)) == NULL)
		goto error;
	create_contact = cdata->data;

	/* get the contact data */
	create_contact->id = xpath_get1(pool, xpathCtx, "contact:id", 1, &xerr);
	CHK_XERR(xerr, error);
	create_contact->authInfo = xpath_get1(pool, xpathCtx,
			"contact:authInfo", 0, &xerr);
	CHK_XERR(xerr, error);
	create_contact->voice = xpath_get1(pool, xpathCtx,
			"contact:voice", 0, &xerr);
	CHK_XERR(xerr, error);
	create_contact->fax = xpath_get1(pool, xpathCtx, "contact:fax",0, &xerr);
	CHK_XERR(xerr, error);
	create_contact->email = xpath_get1(pool, xpathCtx,
			"contact:email", 1, &xerr);
	CHK_XERR(xerr, error);
	create_contact->notify_email = xpath_get1(pool, xpathCtx,
			"contact:notifyEmail", 0, &xerr);
	CHK_XERR(xerr, error);
	create_contact->vat = xpath_get1(pool, xpathCtx, "contact:vat",0, &xerr);
	CHK_XERR(xerr, error);
	create_contact->ident = xpath_get1(pool, xpathCtx, "contact:ident",0, &xerr);
	CHK_XERR(xerr, error);
	create_contact->identtype = ident_UNKNOWN;
	if (create_contact->ident != NULL) {
		char	*str;

		str = xpath_get_attr(pool, xpathCtx,
				"contact:ident", "type", 1, &xerr);
		CHK_XERR(xerr, error);
		create_contact->identtype = string2identtype(str);
		/*
		 * schema and source code are out of sync if following error
		 * occurs
		 */
		assert(create_contact->identtype != ident_UNKNOWN);
	}
	/* XXX Hack for obsolete "ssn" tag - to be removed in future */
	if (create_contact->ident == NULL) {
		create_contact->ident = xpath_get1(pool, xpathCtx,
				"contact:ssn", 0, &xerr);
		CHK_XERR(xerr, error);
		create_contact->identtype = ident_UNKNOWN;
		if (create_contact->ident != NULL) {
			char	*str;

			str = xpath_get_attr(pool, xpathCtx,
					"contact:ssn", "type", 1, &xerr);
			CHK_XERR(xerr, error);
			create_contact->identtype = string2identtype(str);
			/*
			 * schema and source code is out of sync if following
			 * assert does not hold
			 */
			assert(create_contact->identtype != ident_UNKNOWN);
		}
	}
	/*
	 * disclose flags - we don't interpret anyhow disclose flags, we just
	 * send the values to CR and CR decides in conjuction with default
	 * server policy what to do
	 */
	xpath_chroot(xpathCtx, "contact:disclose", 0, &xerr);
	if (xerr == XERR_LIBXML) {
		goto error;
	}
	else if (xerr == XERR_OK) {
		char	*str;

		str = get_attr(xpathCtx->node, "flag");
		assert(str != NULL);
		if (*str == '0') {
			create_contact->discl.flag = 0;
		}
		else {
			create_contact->discl.flag = 1;
		}
		create_contact->discl.name = xpath_count(xpathCtx,
				"contact:name", &xerr);
		CHK_XERR(xerr, error);
		create_contact->discl.org = xpath_count(xpathCtx,
				"contact:org", &xerr);
		CHK_XERR(xerr, error);
		create_contact->discl.addr = xpath_count(xpathCtx,
				"contact:addr", &xerr);
		CHK_XERR(xerr, error);
		create_contact->discl.voice = xpath_count(xpathCtx,
				"contact:voice", &xerr);
		CHK_XERR(xerr, error);
		create_contact->discl.fax = xpath_count(xpathCtx,
				"contact:fax", &xerr);
		CHK_XERR(xerr, error);
		create_contact->discl.email = xpath_count(xpathCtx,
				"contact:email", &xerr);
		CHK_XERR(xerr, error);
		xpathCtx->node = xpathCtx->node->parent;
	}
	else {
		create_contact->discl.flag = -1;
		RESET_XERR(xerr); /* clear value of errno */
	}
	/* postal info, change relative root */
	xpath_chroot(xpathCtx, "contact:postalInfo", 0, &xerr);
	CHK_XERR(xerr, error);

	create_contact->pi.name = xpath_get1(pool, xpathCtx,
			"contact:name", 1, &xerr);
	CHK_XERR(xerr, error);
	create_contact->pi.org = xpath_get1(pool, xpathCtx,
			"contact:org", 0, &xerr);
	CHK_XERR(xerr, error);
	/* address, change relative root */
	xpath_chroot(xpathCtx, "contact:addr", 0, &xerr);
	CHK_XERR(xerr, error);
	xpath_getn(pool, &create_contact->pi.streets, xpathCtx,
			"contact:street", &xerr);
	CHK_XERR(xerr, error);
	create_contact->pi.city = xpath_get1(pool, xpathCtx,
			"contact:city", 1, &xerr);
	CHK_XERR(xerr, error);
	create_contact->pi.sp = xpath_get1(pool, xpathCtx,
			"contact:sp", 0, &xerr);
	CHK_XERR(xerr, error);
	create_contact->pi.pc = xpath_get1(pool, xpathCtx,
			"contact:pc", 0, &xerr);
	CHK_XERR(xerr, error);
	create_contact->pi.cc = xpath_get1(pool, xpathCtx,
			"contact:cc", 1, &xerr);
	CHK_XERR(xerr, error);

	cdata->type = EPP_CREATE_CONTACT;
	return;

error:
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP create-nsset command.
 *
 * @param pool      Pool for memory allocations.
 * @param xpathCtx  XPath context.
 * @param cdata     Output of parsing stage.
 */
static void
parse_create_nsset(void *pool,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	epps_create_nsset	*create_nsset;
	xmlXPathObjectPtr	 xpathObj;
	int	j, xerr;

	RESET_XERR(xerr); /* clear value of errno */

	/* allocate necessary structures */
	if ((cdata->data = epp_calloc(pool, sizeof *create_nsset)) == NULL)
		goto error;
	create_nsset = cdata->data;

	/* get the nsset data */
	create_nsset->id = xpath_get1(pool, xpathCtx, "nsset:id", 1, &xerr);
	CHK_XERR(xerr, error);
	create_nsset->authInfo = xpath_get1(pool, xpathCtx,
			"nsset:authInfo", 0, &xerr);
	CHK_XERR(xerr, error);
	/* process "unbounded" number of tech contacts */
	xpath_getn(pool, &create_nsset->tech, xpathCtx, "nsset:tech", &xerr);
	CHK_XERR(xerr, error);
	/* process multiple ns records which have in turn multiple addresses */
	xpathObj = xmlXPathEvalExpression(BAD_CAST "nsset:ns", xpathCtx);
	if (xpathObj == NULL)
		goto error;

	for (j = 0; j < xmlXPathNodeSetGetLength(xpathObj->nodesetval); j++) {
		epp_ns	*ns;

		/* allocate data structures */
		if ((ns = epp_calloc(pool, sizeof *ns)) == NULL)
		{
			xmlXPathFreeObject(xpathObj);
			goto error;
		}
		/* get data */
		xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, j);
		ns->name = xpath_get1(pool, xpathCtx, "nsset:name", 1, &xerr);
		CHK_XERR(xerr, error);
		xpath_getn(pool, &ns->addr, xpathCtx, "nsset:addr", &xerr);
		CHK_XERR(xerr, error);
		/* enqueue ns record */
		if (q_add(pool, &create_nsset->ns, ns))
		{
			xmlXPathFreeObject(xpathObj);
			goto error;
		}
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
 *
 * @param pool      Pool for memory allocations.
 * @param xpathCtx  XPath context.
 * @param cdata     Output of parsing stage.
 */
static void
parse_create(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
	int	xerr;

	RESET_XERR(xerr); /* clear value of errno */

	/* get object type by trying to change relative root */
	xpath_chroot(xpathCtx, "contact:create", 0, &xerr);
	if (xerr == XERR_OK) {
		parse_create_contact(pool, xpathCtx, cdata);
		return;
	}
	else if (xerr != XERR_CONSTR) goto error;
	RESET_XERR(xerr); /* clear value of errno */

	xpath_chroot(xpathCtx, "domain:create", 0, &xerr);
	if (xerr == XERR_OK) {
		parse_create_domain(pool, xpathCtx, cdata);
		return;
	}
	else if (xerr != XERR_CONSTR) goto error;
	RESET_XERR(xerr); /* clear value of errno */

	xpath_chroot(xpathCtx, "nsset:create", 0, &xerr);
	if (xerr == XERR_OK) {
		parse_create_nsset(pool, xpathCtx, cdata);
		return;
	}
	else if (xerr != XERR_CONSTR) goto error;
	RESET_XERR(xerr); /* clear value of errno */

	/* unexpected object type (should not happen) */
	cdata->rc = 2000;
	cdata->type = EPP_DUMMY;
	return;

error:
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP delete command.
 *
 * @param pool      Pool for memory allocations.
 * @param xpathCtx  XPath context.
 * @param cdata     Output of parsing stage.
 */
static void
parse_delete(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
	epps_delete	*delete;
	int	xerr;

	RESET_XERR(xerr); /* clear value of errno */

	/* allocate necessary structures */
	if ((cdata->data = epp_calloc(pool, sizeof *delete)) == NULL)
		goto error;
	delete = cdata->data;

	/* get object type - contact, domain or nsset */
	xpath_chroot(xpathCtx, "contact:delete", 0, &xerr);
	if (xerr == XERR_OK) {
		/* object is contact */
		delete->id = xpath_get1(pool, xpathCtx, "contact:id", 1, &xerr);
		CHK_XERR(xerr, error);
		cdata->type = EPP_DELETE_CONTACT;
		return;
	}
	else if (xerr != XERR_CONSTR) goto error;
	RESET_XERR(xerr); /* clear value of errno */

	xpath_chroot(xpathCtx, "domain:delete", 0, &xerr);
	if (xerr == XERR_OK) {
		/* object is domain */
		delete->id = xpath_get1(pool, xpathCtx, "domain:name", 1, &xerr);
		CHK_XERR(xerr, error);
		cdata->type = EPP_DELETE_DOMAIN;
		return;
	}
	else if (xerr != XERR_CONSTR) goto error;
	RESET_XERR(xerr); /* clear value of errno */

	xpath_chroot(xpathCtx, "nsset:delete", 0, &xerr);
	if (xerr == XERR_OK) {
		/* object is nsset */
		delete->id = xpath_get1(pool, xpathCtx, "nsset:id", 1, &xerr);
		CHK_XERR(xerr, error);
		cdata->type = EPP_DELETE_NSSET;
		return;
	}
	else if (xerr != XERR_CONSTR) goto error;
	RESET_XERR(xerr); /* clear value of errno */

	/* unexpected object type (should not happen) */
	cdata->rc = 2000;
	cdata->type = EPP_DUMMY;
	return;

error:
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP renew command.
 *
 * @param pool      Pool for memory allocations.
 * @param xpathCtx  XPath context.
 * @param cdata     Output of parsing stage.
 */
static void
parse_renew(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
	epps_renew	*renew;
	char	*str;
	int	xerr;

	RESET_XERR(xerr); /* clear value of errno */

	/* allocate necessary structures */
	if ((cdata->data = epp_calloc(pool, sizeof *renew)) == NULL) {
		goto error;
	}
	renew = cdata->data;

	/* get renew data */
	xpath_chroot(xpathCtx, "domain:renew", 0, &xerr);
	CHK_XERR(xerr, error);
	renew->name = xpath_get1(pool, xpathCtx, "domain:name", 1, &xerr);
	CHK_XERR(xerr, error);
	renew->curExDate = xpath_get1(pool, xpathCtx,
			"domain:curExpDate", 1, &xerr);
	CHK_XERR(xerr, error);
	/* domain period handling is slightly more difficult */
	str = xpath_get1(pool, xpathCtx, "domain:period[@unit='y']", 0, &xerr);
	CHK_XERR(xerr, error);
	renew->unit = TIMEUNIT_YEAR;
	if (str == NULL) {
		/* correct period value if given in years and not months */
		str = xpath_get1(pool, xpathCtx, "domain:period[@unit='m']", 0,
				&xerr);
		CHK_XERR(xerr, error);
		renew->unit = TIMEUNIT_MONTH;
	}
	if (str != NULL)
		renew->period = atoi(str);
	else {
		/*
		 * value 0 means that the period was not given and default value
		 * should be used instead
		 */
		renew->period = 0;
	}

	cdata->type = EPP_RENEW_DOMAIN;
	return;

error:
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP update-domain command.
 *
 * @param pool      Pool for memory allocations.
 * @param xpathCtx  XPath context.
 * @param cdata     Output of parsing stage.
 */
static void
parse_update_domain(void *pool,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	epps_update_domain	*update_domain;
	int	xerr;

	RESET_XERR(xerr); /* clear value of errno */

	/* allocate necessary structures */
	if ((cdata->data = epp_calloc(pool, sizeof *update_domain)) == NULL)
		goto error;
	update_domain = cdata->data;

	/* get the update-domain data */
	update_domain->name = xpath_get1(pool, xpathCtx, "domain:name",1, &xerr);
	CHK_XERR(xerr, error);
	/* chg data */
	xpath_chroot(xpathCtx, "domain:chg", 0, &xerr);
	if (xerr == XERR_OK) {
		update_domain->registrant = xpath_get1(pool, xpathCtx,
				"domain:registrant", 0, &xerr);
		CHK_XERR(xerr, error);
		update_domain->nsset = xpath_get1(pool, xpathCtx,
				"domain:nsset", 0, &xerr);
		CHK_XERR(xerr, error);
		update_domain->authInfo = xpath_get1(pool, xpathCtx,
				"domain:authInfo", 0, &xerr);
		CHK_XERR(xerr, error);
		xpathCtx->node = xpathCtx->node->parent;
	}
	else if (xerr == XERR_LIBXML)
		goto error;
	else
		RESET_XERR(xerr); /* clear value of errno */

	/* add data */
	xpath_chroot(xpathCtx, "domain:add", 0, &xerr);
	if (xerr == XERR_OK) {
		xpath_getn(pool, &update_domain->add_admin, xpathCtx,
				"domain:admin", &xerr);
		CHK_XERR(xerr, error);
		xpathCtx->node = xpathCtx->node->parent;
	}
	else if (xerr == XERR_LIBXML)
		goto error;
	else
		RESET_XERR(xerr); /* clear value of errno */

	/* rem data */
	xpath_chroot(xpathCtx, "domain:rem", 0, &xerr);
	if (xerr == XERR_OK) {
		xpath_getn(pool, &update_domain->add_admin, xpathCtx,
				"domain:admin", &xerr);
		CHK_XERR(xerr, error);
		xpathCtx->node = xpathCtx->node->parent;
	}
	else if (xerr == XERR_LIBXML)
		goto error;
	else
		RESET_XERR(xerr); /* clear value of errno */

	cdata->type = EPP_UPDATE_DOMAIN;
	return;

error:
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP update-contact command.
 *
 * @param pool      Pool for memory allocations.
 * @param xpathCtx  XPath context.
 * @param cdata     Output of parsing stage.
 */
static void
parse_update_contact(void *pool,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	epps_update_contact	*update_contact;
	int	xerr;

	RESET_XERR(xerr); /* clear value of errno */

	/* allocate necessary structures */
	if ((cdata->data = epp_calloc(pool, sizeof *update_contact)) == NULL)
		goto error;
	update_contact = cdata->data;

	/* get the update-contact data */
	update_contact->id = xpath_get1(pool, xpathCtx, "contact:id", 1, &xerr);
	CHK_XERR(xerr, error);

	/* chg data */
	xpath_chroot(xpathCtx, "contact:chg", 0, &xerr);
	if (xerr == XERR_LIBXML)
		goto error;
	else if (xerr == XERR_CONSTR) {
		/* there is nothing more to parse */
		cdata->type = EPP_UPDATE_CONTACT;
		return;
	}

	/* the most difficult item comes first (ident) */
	update_contact->ident = xpath_get1(pool, xpathCtx,
			"contact:ident", 0, &xerr);
	CHK_XERR(xerr, error);
	update_contact->identtype = ident_UNKNOWN;
	if (update_contact->ident != NULL) {
		char	*str;

		str = xpath_get_attr(pool, xpathCtx,
				"contact:ident", "type", 1, &xerr);
		CHK_XERR(xerr, error);
		/*
		 * attribute type might not be present, we have to explicitly
		 * check it
		 */
		if (str == NULL) {
			if (new_error_item(pool, &cdata->errors,
					errspec_contact_identtype_missing))
				goto error;

			cdata->rc = 2003;
			cdata->type = EPP_DUMMY;
			return;
		}

		update_contact->identtype = string2identtype(str);
		/*
		 * schema and source code is out of sync if following
		 * assert does not hold
		 */
		assert(update_contact->identtype != ident_UNKNOWN);
	}
	/* XXX Hack for obsolete "ssn" tag - to be removed in future */
	if (update_contact->ident == NULL) {
		update_contact->ident = xpath_get1(pool, xpathCtx,
				"contact:ssn", 0, &xerr);
		CHK_XERR(xerr, error);
		update_contact->identtype = ident_UNKNOWN;
		if (update_contact->ident != NULL) {
			char	*str;

			str = xpath_get_attr(pool, xpathCtx,
					"contact:ssn", "type", 1, &xerr);
			CHK_XERR(xerr, error);
			/*
			 * attribute type might not be present, we have to explicitly
			 * check it
			 */
			if (str == NULL) {
				if (new_error_item(pool, &cdata->errors,
						errspec_contact_identtype_missing))
					goto error;

				cdata->rc = 2003;
				cdata->type = EPP_DUMMY;
				return;
			}

			update_contact->identtype = string2identtype(str);
			/*
			 * schema and source code is out of sync if following
			 * assert does not hold
			 */
			assert(update_contact->identtype != ident_UNKNOWN);
		}
	}
	update_contact->authInfo = xpath_get1(pool, xpathCtx,
			"contact:authInfo", 0, &xerr);
	CHK_XERR(xerr, error);
	update_contact->voice = xpath_get1(pool, xpathCtx,
			"contact:voice", 0, &xerr);
	CHK_XERR(xerr, error);
	update_contact->fax = xpath_get1(pool, xpathCtx, "contact:fax",0, &xerr);
	CHK_XERR(xerr, error);
	update_contact->email = xpath_get1(pool, xpathCtx,
			"contact:email", 0, &xerr);
	CHK_XERR(xerr, error);
	update_contact->notify_email = xpath_get1(pool, xpathCtx,
			"contact:notifyEmail", 0, &xerr);
	CHK_XERR(xerr, error);
	update_contact->vat = xpath_get1(pool, xpathCtx, "contact:vat",0, &xerr);
	CHK_XERR(xerr, error);
	/*
	 * there can be just one disclose section, now it depens if the flag is
	 * 0 or 1
	 */
	xpath_chroot(xpathCtx, "contact:disclose", 0, &xerr);
	if (xerr == XERR_LIBXML) {
		goto error;
	}
	else if (xerr == XERR_OK) {
		char	*str;

		str = get_attr(xpathCtx->node, "flag");
		assert(str != NULL);
		if (*str == '0') {
			update_contact->discl.flag = 0;
		}
		else {
			update_contact->discl.flag = 1;
		}
		update_contact->discl.name = xpath_count(xpathCtx,
				"contact:name", &xerr);
		CHK_XERR(xerr, error);
		update_contact->discl.org = xpath_count(xpathCtx,
				"contact:org", &xerr);
		CHK_XERR(xerr, error);
		update_contact->discl.addr = xpath_count(xpathCtx,
				"contact:addr", &xerr);
		CHK_XERR(xerr, error);
		update_contact->discl.voice = xpath_count(xpathCtx,
				"contact:voice", &xerr);
		CHK_XERR(xerr, error);
		update_contact->discl.fax = xpath_count(xpathCtx,
				"contact:fax", &xerr);
		CHK_XERR(xerr, error);
		update_contact->discl.email = xpath_count(xpathCtx,
				"contact:email", &xerr);
		CHK_XERR(xerr, error);
		xpathCtx->node = xpathCtx->node->parent;
	}
	else {
		update_contact->discl.flag = -1;
		RESET_XERR(xerr); /* clear value of errno */
	}
	/* postal info, change relative root */
	xpath_chroot(xpathCtx, "contact:postalInfo", 0, &xerr);
	if (xerr == XERR_LIBXML) goto error;
	else if (xerr == XERR_OK) {
		update_contact->pi = epp_calloc(pool, sizeof *(update_contact->pi));
		if (update_contact->pi == NULL)
			goto error;

		update_contact->pi->name = xpath_get1(pool, xpathCtx,
				"contact:name", 0, &xerr);
		CHK_XERR(xerr, error);
		update_contact->pi->org = xpath_get1(pool, xpathCtx,
				"contact:org", 0, &xerr);
		CHK_XERR(xerr, error);

		/* address, change relative root */
		xpath_chroot(xpathCtx, "contact:addr", 0, &xerr);
		if (xerr == XERR_LIBXML) goto error;
		else if (xerr == XERR_OK) {
			update_contact->pi->city = xpath_get1(pool, xpathCtx,
						"contact:city", 0, &xerr);
			CHK_XERR(xerr, error);
			update_contact->pi->sp = xpath_get1(pool, xpathCtx,
						"contact:sp", 0, &xerr);
			CHK_XERR(xerr, error);
			update_contact->pi->pc = xpath_get1(pool, xpathCtx,
						"contact:pc", 0, &xerr);
			CHK_XERR(xerr, error);
			update_contact->pi->cc = xpath_get1(pool, xpathCtx,
						"contact:cc", 0, &xerr);
			CHK_XERR(xerr, error);

			xpath_getn(pool, &update_contact->pi->streets, xpathCtx,
					"contact:street", &xerr);
			CHK_XERR(xerr, error);
		}
		else RESET_XERR(xerr); /* clear value of errno */
	}
	else RESET_XERR(xerr); /* clear value of errno */

	cdata->type = EPP_UPDATE_CONTACT;
	return;

error:
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP update-nsset command.
 *
 * @param pool      Pool for memory allocations.
 * @param xpathCtx  XPath context.
 * @param cdata     Output of parsing stage.
 */
static void
parse_update_nsset(void *pool,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	epps_update_nsset	*update_nsset;
	xmlXPathObjectPtr	xpathObj;
	int	j, xerr;

	RESET_XERR(xerr); /* clear value of errno */

	/* allocate necessary structures */
	if ((cdata->data = epp_calloc(pool, sizeof *update_nsset)) == NULL)
		goto error;
	update_nsset = cdata->data;

	/* get the update-nsset data */
	update_nsset->id = xpath_get1(pool, xpathCtx, "nsset:id", 1, &xerr);
	CHK_XERR(xerr, error);
	/* chg data */
	update_nsset->authInfo = xpath_get1(pool, xpathCtx,
			"nsset:chg/nsset:authInfo", 0, &xerr);
	CHK_XERR(xerr, error);
	/* rem data */
	xpath_chroot(xpathCtx, "nsset:rem", 0, &xerr);
	if (xerr == XERR_LIBXML)
		goto error;
	else if (xerr == XERR_OK) {
		xpath_getn(pool, &update_nsset->rem_tech, xpathCtx,
				"nsset:tech", &xerr);
		CHK_XERR(xerr, error);
		xpath_getn(pool, &update_nsset->rem_ns, xpathCtx,
				"nsset:name", &xerr);
		CHK_XERR(xerr, error);
		xpathCtx->node = xpathCtx->node->parent;
	}
	else
		RESET_XERR(xerr); /* clear value of errno */
	/* add data */
	xpath_chroot(xpathCtx, "nsset:add", 0, &xerr);
	if (xerr == XERR_LIBXML)
		goto error;
	else if (xerr == XERR_OK) {
		xpath_getn(pool, &update_nsset->add_tech, xpathCtx,
				"nsset:tech", &xerr);
		CHK_XERR(xerr, error);
		/* add ns */
		xpathObj = xmlXPathEvalExpression(BAD_CAST "nsset:ns", xpathCtx);
		if (xpathObj == NULL)
			goto error;

		/* process all nameservers */
		for (j = 0; j < xmlXPathNodeSetGetLength(xpathObj->nodesetval);
				j++)
		{
			epp_ns	*ns;

			/* allocate and initialize data structures */
			if ((ns = epp_calloc(pool, sizeof *ns)) == NULL) {
				xmlXPathFreeObject(xpathObj);
				goto error;
			}

			/* get data */
			xpathCtx->node =
				xmlXPathNodeSetItem(xpathObj->nodesetval, j);
			ns->name = xpath_get1(pool, xpathCtx,
					"nsset:name", 1, &xerr);
			if (xerr != XERR_OK) {
				xmlXPathFreeObject(xpathObj);
				goto error;
			}
			xpath_getn(pool, &ns->addr, xpathCtx, "nsset:addr",
					&xerr);
			if (xerr != XERR_OK) {
				xmlXPathFreeObject(xpathObj);
				goto error;
			}
			/* enqueue ns record */
			if (q_add(pool, &update_nsset->add_ns, ns)) {
				xmlXPathFreeObject(xpathObj);
				goto error;
			}
		}
		xmlXPathFreeObject(xpathObj);
	}
	else RESET_XERR(xerr); /* clear value of errno */

	cdata->type = EPP_UPDATE_NSSET;
	return;

error:
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP update command.
 *
 * @param pool      Pool for memory allocations.
 * @param xpathCtx  XPath context.
 * @param cdata     Output of parsing stage.
 */
static void
parse_update(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
	int	xerr;

	RESET_XERR(xerr); /* clear value of errno */

	/* change relative root and get object type btw */
	xpath_chroot(xpathCtx, "contact:update", 0, &xerr);
	if (xerr == XERR_OK) {
		parse_update_contact(pool, xpathCtx, cdata);
		return;
	}
	else if (xerr == XERR_LIBXML)
		goto error;
	else
		RESET_XERR(xerr);

	xpath_chroot(xpathCtx, "domain:update", 0, &xerr);
	if (xerr == XERR_OK) {
		parse_update_domain(pool, xpathCtx, cdata);
		return;
	}
	else if (xerr == XERR_LIBXML)
		goto error;
	else
		RESET_XERR(xerr);

	xpath_chroot(xpathCtx, "nsset:update", 0, &xerr);
	if (xerr == XERR_OK) {
		parse_update_nsset(pool, xpathCtx, cdata);
		return;
	}
	else if (xerr == XERR_LIBXML)
		goto error;
	else
		RESET_XERR(xerr);

	/* unexpected object type (should not happen) */
	cdata->rc = 2000;
	cdata->type = EPP_DUMMY;
	return;

error:
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP transfer command.
 *
 * @param pool      Pool for memory allocations.
 * @param xpathCtx  XPath context.
 * @param cdata     Output of parsing stage.
 */
static void
parse_transfer(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
	epps_transfer	*transfer;
	int	 xerr;
	char	*str;

	/* allocate necessary structures */
	if ((cdata->data = epp_calloc(pool, sizeof *transfer)) == NULL) {
		goto error;
	}
	transfer = cdata->data;

	str = get_attr(xpathCtx->node, "op");
	assert(str != NULL);
	/*
	 * we process only transfer requests (not approves, cancels, queries, ..)
	 * though all transfer commands are valid according to xml schemas
	 * because we don't want to be incompatible with epp-1.0 standard.
	 * If there is another command than "transfer request" we return
	 * 2102 "Unimplemented option" response.
	 */
	if (strcmp(str, "request")) {
		if (new_error_item(pool, &cdata->errors, errspec_transfer_op))
			goto error;

		cdata->rc = 2102;
		cdata->type = EPP_DUMMY;
		return;
	}

	RESET_XERR(xerr); /* clear value of errno */

	/* get object type - domain, contact or nsset */
	xpath_chroot(xpathCtx, "domain:transfer", 0, &xerr);
	if (xerr == XERR_OK) {
		transfer->id = xpath_get1(pool, xpathCtx, "domain:name", 1, &xerr);
		CHK_XERR(xerr, error);
		transfer->authInfo = xpath_get1(pool, xpathCtx,
				"domain:authInfo", 0, &xerr);
		CHK_XERR(xerr, error);
		cdata->type = EPP_TRANSFER_DOMAIN;
		return;
	}
	else if (xerr == XERR_LIBXML)
		goto error;
	else
		RESET_XERR(xerr);

	xpath_chroot(xpathCtx, "contact:transfer", 0, &xerr);
	if (xerr == XERR_OK) {
		transfer->id = xpath_get1(pool, xpathCtx, "contact:id",1, &xerr);
		CHK_XERR(xerr, error);
		transfer->authInfo = xpath_get1(pool, xpathCtx,
				"contact:authInfo", 0, &xerr);
		CHK_XERR(xerr, error);
		cdata->type = EPP_TRANSFER_CONTACT;
		return;
	}
	else if (xerr == XERR_LIBXML)
		goto error;
	else
		RESET_XERR(xerr);

	xpath_chroot(xpathCtx, "nsset:transfer", 0, &xerr);
	if (xerr == XERR_OK) {
		transfer->id = xpath_get1(pool, xpathCtx, "nsset:id", 1, &xerr);
		CHK_XERR(xerr, error);
		transfer->authInfo = xpath_get1(pool, xpathCtx,
				"nsset:authInfo", 0, &xerr);
		CHK_XERR(xerr, error);
		cdata->type = EPP_TRANSFER_NSSET;
		return;
	}
	else if (xerr == XERR_LIBXML)
		goto error;
	else
		RESET_XERR(xerr);

	/* unexpected object type (should not happen) */
	cdata->rc = 2000;
	cdata->type = EPP_DUMMY;
	return;

error:
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of command sendAuthInfo.
 *
 * @param pool Pool to allocate memory from.
 * @param xpathCtx Xpath context.
 * @param cdata Parsed data.
 */
static void
parse_sendAuthInfo(void *pool,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	epps_sendAuthInfo	*sendAuthInfo;
	int	xerr;

	cdata->data = epp_calloc(pool, sizeof *sendAuthInfo);
	if (cdata->data == NULL) {
		cdata->rc = 2400;
		cdata->type = EPP_DUMMY;
		return;
	}
	sendAuthInfo = cdata->data;

	/* get object type - domain, contact or nsset */
	RESET_XERR(xerr); /* clear value of errno */
	xpath_chroot(xpathCtx, "domain:sendAuthInfo", 0, &xerr);
	if (xerr == XERR_OK) {
		sendAuthInfo->id = xpath_get1(pool, xpathCtx,
				"domain:name", 1, &xerr);
		CHK_XERR(xerr, error);
		cdata->type = EPP_SENDAUTHINFO_DOMAIN;
		return;
	}
	else if (xerr == XERR_LIBXML)
		goto error;
	else
		RESET_XERR(xerr);

	xpath_chroot(xpathCtx, "contact:sendAuthInfo", 0, &xerr);
	if (xerr == XERR_OK) {
		sendAuthInfo->id = xpath_get1(pool, xpathCtx,
				"contact:id", 1, &xerr);
		CHK_XERR(xerr, error);
		cdata->type = EPP_SENDAUTHINFO_CONTACT;
		return;
	}
	else if (xerr == XERR_LIBXML)
		goto error;
	else
		RESET_XERR(xerr);

	xpath_chroot(xpathCtx, "nsset:sendAuthInfo", 0, &xerr);
	if (xerr == XERR_OK) {
		sendAuthInfo->id = xpath_get1(pool, xpathCtx,
				"nsset:id", 1, &xerr);
		CHK_XERR(xerr, error);
		cdata->type = EPP_SENDAUTHINFO_NSSET;
		return;
	}
	else if (xerr == XERR_LIBXML)
		goto error;
	else
		RESET_XERR(xerr);

	/* unexpected object type (should not happen) */
	cdata->rc = 2000;
	cdata->type = EPP_DUMMY;
	return;

error:
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of enumval extension in context of create domain command.
 *
 * @param pool      Pool for memory allocations.
 * @param xpathCtx  XPath context.
 * @param cdata     Output of parsing stage.
 */
static void
parse_ext_enumval_create(void *pool,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	epps_create_domain	*create_domain;
	epp_ext_item	*ext_item;
	int	 xerr;

	/* assure we are being called in corect context */
	if (cdata->type != EPP_CREATE_DOMAIN) {
		cdata->rc = 2002;
		cdata->type = EPP_DUMMY;
		return;
	}

	if ((ext_item = epp_calloc(pool, sizeof *ext_item)) == NULL)
		goto error;

	create_domain = cdata->data;

	RESET_XERR(xerr); /* clear value of errno */
	ext_item->extType = EPP_EXT_ENUMVAL;
	ext_item->ext.ext_enumval = xpath_get1(pool, xpathCtx,
			"enumval:valExDate", 1, &xerr);
	if (q_add(pool, &create_domain->extensions, ext_item))
		goto error;

	return;
error:
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of enumval extension in context of update domain command.
 *
 * @param pool      Pool for memory allocations.
 * @param xpathCtx  XPath context.
 * @param cdata     Output of parsing stage.
 */
static void
parse_ext_enumval_update(void *pool,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	epps_update_domain	*update_domain;
	epp_ext_item	*ext_item;
	int	 xerr;

	/* assure we are being called in corect context */
	if (cdata->type != EPP_UPDATE_DOMAIN) {
		cdata->rc = 2002;
		cdata->type = EPP_DUMMY;
		return;
	}

	if ((ext_item = epp_calloc(pool, sizeof *ext_item)) == NULL)
		goto error;

	update_domain = cdata->data;

	RESET_XERR(xerr); /* clear value of errno */
	ext_item->extType = EPP_EXT_ENUMVAL;
	ext_item->ext.ext_enumval = xpath_get1(pool, xpathCtx,
			"enumval:chg/enumval:valExDate", 1, &xerr);
	if (q_add(pool, &update_domain->extensions, ext_item))
		goto error;
	return;

error:
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

/**
 * Parser of enumval extension in context of renew domain command.
 *
 * @param pool      Pool for memory allocations.
 * @param xpathCtx  XPath context.
 * @param cdata     Output of parsing stage.
 */
static void
parse_ext_enumval_renew(void *pool,
		xmlXPathContextPtr xpathCtx,
		epp_command_data *cdata)
{
	epps_renew	*renew;
	epp_ext_item	*ext_item;
	int	 xerr;

	/* assure we are being called in corect context */
	if (cdata->type != EPP_RENEW_DOMAIN) {
		cdata->rc = 2002;
		cdata->type = EPP_DUMMY;
		return;
	}

	if ((ext_item = epp_calloc(pool, sizeof *ext_item)) == NULL)
		goto error;

	renew = cdata->data;

	RESET_XERR(xerr); /* clear value of errno */
	ext_item->extType = EPP_EXT_ENUMVAL;
	ext_item->ext.ext_enumval = xpath_get1(pool, xpathCtx,
			"enumval:valExDate", 1, &xerr);
	if (q_add(pool, &renew->extensions, ext_item))
		goto error;
	return;

error:
	cdata->rc = 2400;
	cdata->type = EPP_DUMMY;
}

static parser_status
parse_command(void *pool,
		int session,
		epp_command_data *cdata,
		xmlXPathContextPtr xpathCtx)
{
	epp_red_command_type	 cmd;
	xmlXPathObjectPtr	 xpathObj;
	xmlNodePtr	 node;
	int	 xerr;

	/* backup relative root for later processing of clTRID and extensions */
	node = xpathCtx->node;

	/*
	 * command recognition part
	 */
	xpathObj = xmlXPathEvalExpression(BAD_CAST "epp:*[position()=1]",
			xpathCtx);
	if (xpathObj == NULL)
		return PARSER_EINTERNAL;

	assert(xmlXPathNodeSetGetLength(xpathObj->nodesetval) == 1);

	/* command lookup through hash table .. huraaa :) */
	cmd = cmd_hash_lookup( (char *)
			xmlXPathNodeSetItem(xpathObj->nodesetval, 0)->name);
	/* change relative root to command's node */
	xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, 0);
	xmlXPathFreeObject(xpathObj);

	/*
	 * Do validity checking for following cases:
	 * 	- the user is not logged in and attempts to issue a command
	 * 	- the user is already logged in and issues another login
	 */
	if ((cmd != EPP_RED_LOGIN && session == 0) ||
		(cmd == EPP_RED_LOGIN && session != 0))
	{
		cdata->type = EPP_DUMMY;
		cdata->rc = 2002;
		return PARSER_CMD_OTHER;
	}

	switch (cmd) {
		case EPP_RED_LOGIN:
			parse_login(pool, xpathCtx, cdata);
			break;
		case EPP_RED_LOGOUT:
			/*
			 * logout is so simple that we don't use dedicated
			 * parsing function
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
			parse_poll(pool, xpathCtx, cdata);
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
			parse_update(pool, xpathCtx, cdata);
			break;
		case EPP_RED_TRANSFER:
			parse_transfer(pool, xpathCtx, cdata);
			break;
		case EPP_RED_UNKNOWN_CMD:
		default:
			cdata->rc = 2000; /* "Unknown command" */
			cdata->type = EPP_DUMMY;
			break;
	}

	/* parse command extensions only if error did not occur */
	if (cdata->type != EPP_DUMMY) {
		int	i;

		/* restore relative root */
		xpathCtx->node = node;

		xpathObj = xmlXPathEvalExpression(BAD_CAST "epp:extension/*",
				xpathCtx);
		if (xpathObj == NULL) {
			return PARSER_EINTERNAL;
		}
		/* iterate through extensions */
		for (i = 0; i < xmlXPathNodeSetGetLength(xpathObj->nodesetval);
				i++)
		{
			const char	*ext_name;
			const char	*ext_ns;
			xmlNodePtr	 ext_node;

			ext_node = xmlXPathNodeSetItem(xpathObj->nodesetval, i);
			xpathCtx->node = ext_node;
			ext_ns   = (ext_node->ns) ?
				(char *) ext_node->ns->href : NULL;
			if (ext_ns == NULL)
				continue;
			if (!strcmp(ext_ns, NS_ENUMVAL)) {
				ext_name = (char *) ext_node->name;
				if (!strcmp(ext_name, "create"))
					parse_ext_enumval_create(pool, xpathCtx,
							cdata);
				else if (!strcmp(ext_name, "update"))
					parse_ext_enumval_update(pool, xpathCtx,
							cdata);
				else if (!strcmp(ext_name, "renew"))
					parse_ext_enumval_renew(pool, xpathCtx,
							cdata);
				else {
					/* unknown enumval command */
					cdata->rc = 2000; /* "Unknown command" */
					cdata->type = EPP_DUMMY;
					break;
				}
			}
			else {
				/* unknown extension */
				cdata->rc = 2000; /* "Unknown command" */
				cdata->type = EPP_DUMMY;
				break;
			}
		}
		xmlXPathFreeObject(xpathObj);
	}

	/* restore relative root */
	xpathCtx->node = node;

	RESET_XERR(xerr); /* clear value of errno */
	cdata->clTRID = xpath_get1(pool, xpathCtx, "epp:clTRID", 0, &xerr);
	if (xerr != XERR_OK) {
		return PARSER_EINTERNAL;
	}

	/* return code corection */
	if (cdata->type == EPP_LOGIN)
		return PARSER_CMD_LOGIN;
	else if (cdata->type == EPP_LOGOUT)
		return PARSER_CMD_LOGOUT;

	return PARSER_CMD_OTHER;
}

static parser_status
parse_extension(void *pool,
		epp_command_data *cdata,
		xmlXPathContextPtr xpathCtx)
{
	xmlNodePtr	 node;
	int	 xerr;
	const char	*elemname;

	RESET_XERR(xerr); /* clear value of errno */
	xpath_chroot(xpathCtx, "fred:extcommand", 0, &xerr);
	if (xerr == XERR_LIBXML) {
		return PARSER_EINTERNAL;
	}
	else if (xerr == XERR_CONSTR) {
		/* unknown extension */
		cdata->rc = 2000; /* "Unknown command" */
		cdata->type = EPP_DUMMY;
		return PARSER_CMD_OTHER;
	}

	/* backup relative root for later processing of clTRID */
	node = xpathCtx->node;

	/*
	 * command recognition part
	 */
	xpath_chroot(xpathCtx, "fred:*[position()=1]", 0, &xerr);
	if (xerr == XERR_LIBXML) {
		return PARSER_EINTERNAL;
	}
	assert(xerr == XERR_OK);

	elemname = (char *) xpathCtx->node->name;

	switch (elemname[0]) {
		case 's':
			/* It is sendAuthInfo */
			if (!strcmp(elemname, "sendAuthInfo")) {
				parse_sendAuthInfo(pool, xpathCtx, cdata);
				break;
			}
			/* fall-through if not matched */
		case 'c':
			/* It is cashInfo */
			if (!strcmp(elemname, "creditInfo")) {
				cdata->data = epp_calloc(pool,
						sizeof (epps_creditInfo));
				if (cdata->data == NULL) {
					cdata->rc = 2400;
					cdata->type = EPP_DUMMY;
					return PARSER_CMD_OTHER;
				}
				cdata->type = EPP_CREDITINFO;
				break;
			}
			/* fall-through if not matched */
		default:
			cdata->rc = 2000; /* "Unknown command" */
			cdata->type = EPP_DUMMY;
			break;
	}

	/* restore relative root */
	xpathCtx->node = node;

	cdata->clTRID = xpath_get1(pool, xpathCtx, "fred:clTRID", 0, &xerr);
	if (xerr != XERR_OK) {
		return PARSER_EINTERNAL;
	}

	return PARSER_CMD_OTHER;
}

parser_status
epp_parse_command(void *pool,
		int session,
		void *schema,
		const char *request,
		unsigned bytes,
		epp_command_data **cdata_arg)
{
	xmlXPathContextPtr	 xpathCtx;
	xmlXPathObjectPtr	 xpathObj;
	epp_command_data	*cdata;
	xmlDocPtr	 doc;
	valid_status	 val_ret;
	parser_status	 ret;
	const char	*elemname;

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
	if (*cdata_arg == NULL) {
		xmlFreeDoc(doc);
		return PARSER_EINTERNAL;
	}
	cdata = *cdata_arg;

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
	val_ret = validate_doc(pool, (xmlSchemaPtr) schema, doc, &cdata->errors);

	if (val_ret == VAL_ESCHEMA || val_ret == VAL_EINTERNAL) {
		xmlFreeDoc(doc);
		return (val_ret == VAL_ESCHEMA) ?
			PARSER_ESCHEMA : PARSER_EINTERNAL;
	}
	else if (val_ret == VAL_NOT_VALID) {
		xmlFreeDoc(doc);
		/*
		 * validation error consequence: response identifing a problem
		 * (libxml message) is sent back to client, the connection
		 * persists.
		 */
		cdata->rc = 2001;
		cdata->type = EPP_DUMMY;
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
		xmlXPathRegisterNs(xpathCtx, BAD_CAST "contact",
			BAD_CAST NS_CONTACT) ||
		xmlXPathRegisterNs(xpathCtx, BAD_CAST "domain",
			BAD_CAST NS_DOMAIN) ||
		xmlXPathRegisterNs(xpathCtx, BAD_CAST "nsset",
			BAD_CAST NS_NSSET) ||
		xmlXPathRegisterNs(xpathCtx, BAD_CAST "fred",
			BAD_CAST NS_FRED) ||
#ifdef SECDNS_ENABLE
#error "It is a terible error to enable SECDNS before code correction!"
		xmlXPathRegisterNs(xpathCtx, BAD_CAST "secdns",
			BAD_CAST NS_SECDNS) ||
#endif
		xmlXPathRegisterNs(xpathCtx, BAD_CAST "enumval",
			BAD_CAST NS_ENUMVAL))
	{
		xmlXPathFreeContext(xpathCtx);
		xmlFreeDoc(doc);
		return PARSER_EINTERNAL;
	}

	xpathObj = xmlXPathEvalExpression(BAD_CAST "/epp:epp/epp:*", xpathCtx);
	if (xpathObj == NULL) {
		xmlXPathFreeContext(xpathCtx);
		xmlFreeDoc(doc);
		return PARSER_EINTERNAL;
	}
	assert(xmlXPathNodeSetGetLength(xpathObj->nodesetval) == 1);
	xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, 0);
	xmlXPathFreeObject(xpathObj);
	elemname = (char *) xpathCtx->node->name;

	/*
	 * See what we have. <hello>, <command>, <extension> are admittable.
	 * NOTE: Recognition is optimized, we exploit the difference in first
	 * letter of valid elements.
	 */
	switch (elemname[0]) {
		case 'h':
			/* It is a <hello> element. */
			if (!strcmp(elemname, "hello")) {
				ret = PARSER_HELLO;
				break;
			}
			/* fall through if not matched */
		case 'c':
			/* It is a <command> element. */
			if (!strcmp(elemname, "command")) {
				ret = parse_command(pool, session, cdata,
						xpathCtx);
				break;
			}
			/* fall through if not matched */
		case 'e':
			/* It is an <extension> element. */
			if (!strcmp(elemname, "extension")) {
				if (session == 0) {
					cdata->type = EPP_DUMMY;
					cdata->rc = 2002;
					ret = PARSER_CMD_OTHER;
				}
				else {
					ret = parse_extension(pool, cdata,
							xpathCtx);
				}
				break;
			}
			/* fall through if not matched */
		default:
			/*
			 * not all documents which are valid are commands
			 * (e.g. greeting and response). EPP standard does
			 * not describe any error which should be returned in
			 * that case. Therefore we will silently close
			 * connection in that case.
			 */
			ret = PARSER_NOT_COMMAND;
			break;
	}

	xmlXPathFreeContext(xpathCtx);
	xmlFreeDoc(doc);
	return ret;
}

/* vim: set ts=8 sw=8: */
