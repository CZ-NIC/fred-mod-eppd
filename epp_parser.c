/*
 * Copyright (C) 2006-2022  CZ.NIC, z. s. p. o.
 *
 * This file is part of FRED.
 *
 * FRED is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * FRED is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRED.  If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * @file epp_parser.c
 *
 * Component for parsing EPP requests in form of xml documents.
 *
 * The product is a data structure which contains data from xml document.
 * This file also contains routine which handles deallocation of this
 * structure. Currently the component is based on libxml library.
 */

#include "epp_common.h"
#include "epp_parser.h"
#include "epp_xmlcommon.h"
#include "xml-in-out-log.h"

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <apr.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/xmlschemas.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/**
 * Size of hash table used for hashing command names. The size is tradeof
 * between size of hash table and lookup speed, it should be less than 255
 * since hash value is unsigned char.
 */
#define HASH_SIZE_CMD 30

/**
 * Encoding for input xml in epp_command_data
 * structure
 */
#define XML_IN_ENC "UTF-8"

/**
 * @defgroup xerrors Error codes which signal the cause of an error and
 * macros which make working with error values easier.
 * @{
 */
#define XERR_OK 0 /**< OK status. */
#define XERR_LIBXML 1 /**< Error in function from libxml library. */
#define XERR_ALLOC 2 /**< Memory allocation failed. */
#define XERR_CONSTR 3 /**< Constraints given by caller were not fulfilled. */

/**
 * Macro checks given variable for an error, if the variable has error
 * status, a flow of a program is redirected to given label.
 */
#define CHK_XERR(_var, _label)                                                                     \
    if ((_var) != XERR_OK)                                                                         \
    goto _label

/**
 * Macro checks given variable for an error, if the variable has error
 * status, a flow of a program is redirected to given label.
 */
#define RESET_XERR(_var) ((_var) = XERR_OK)
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
#define TEXT_CONTENT(_xpathObj, _i)                                                                \
    (                                                                                              \
            (char*)((xmlXPathNodeSetItem((_xpathObj)->nodesetval, (_i))->xmlChildrenNode)          \
                            ? (xmlXPathNodeSetItem((_xpathObj)->nodesetval, (_i))                  \
                                       ->xmlChildrenNode)                                          \
                                      ->content                                                    \
                            : NULL))

int read_epp_dnskey(void *pool, xmlXPathContextPtr xpathCtx, epp_dnskey *key);

/**
 * This function returns specified attribute value of given node.
 * You have to make your own copy if you want to edit the returned string.
 *
 * @param node     XPath object.
 * @param name     Name of attribute.
 * @return         Pointer to attribute's value.
 */
static char *get_attr(xmlNodePtr node, const char *name)
{
    xmlAttrPtr prop;

    assert(node != NULL);

    prop = node->properties;
    while (prop != NULL)
    {
        if (xmlStrEqual(prop->name, BAD_CAST name))
        {
            return (char *)prop->children->content;
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
static xmlNodePtr xpath_chroot(xmlXPathContextPtr ctx, const char *expr, int index, int *xerr)
{
    xmlXPathObjectPtr obj;
    xmlNodePtr oldNode;

    obj = xmlXPathEvalExpression(BAD_CAST expr, ctx);
    if (obj == NULL)
    {
        *xerr = XERR_LIBXML;
        return NULL;
    }
    if (xmlXPathNodeSetGetLength(obj->nodesetval) < index + 1)
    {
        xmlXPathFreeObject(obj);
        *xerr = XERR_CONSTR;
        return NULL;
    }
    /* exchange the nodes */
    oldNode = ctx->node;
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
static int xpath_count(xmlXPathContextPtr ctx, const char *expr, int *xerr)
{
    xmlXPathObjectPtr obj;
    int count;

    obj = xmlXPathEvalExpression(BAD_CAST expr, ctx);
    if (obj == NULL)
    {
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
static char *xpath_get1(void *pool, xmlXPathContextPtr ctx, const char *expr, int req, int *xerr)
{
    xmlXPathObjectPtr obj;
    char *res;

    obj = xmlXPathEvalExpression(BAD_CAST expr, ctx);
    if (obj == NULL)
    {
        *xerr = XERR_LIBXML;
        return NULL;
    }

    /* look what we got */
    if (xmlXPathNodeSetGetLength(obj->nodesetval) == 0)
    {
        xmlXPathFreeObject(obj);
        if (req)
        {
            *xerr = XERR_CONSTR;
        }
        return NULL;
    }
    else if (xmlXPathNodeSetGetLength(obj->nodesetval) > 1)
    {
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
static void xpath_getn(void *pool, qhead *list, xmlXPathContextPtr ctx, const char *expr, int *xerr)
{
    int i;
    xmlXPathObjectPtr obj;

    obj = xmlXPathEvalExpression(BAD_CAST expr, ctx);
    if (obj == NULL)
    {
        *xerr = XERR_LIBXML;
        return;
    }

    /* iterate through selected items */
    for (i = 0; i < xmlXPathNodeSetGetLength(obj->nodesetval); i++)
    {
        char *value;

        if (TEXT_CONTENT(obj, i) == NULL)
            continue;

        value = epp_strdup(pool, TEXT_CONTENT(obj, i));
        if (value == NULL)
        {
            xmlXPathFreeObject(obj);
            *xerr = XERR_ALLOC;
            return;
        }
        if (q_add(pool, list, value))
        {
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
static char *xpath_get_attr(
        void *pool, xmlXPathContextPtr ctx, const char *expr, const char *attr, int req, int *xerr)
{
    xmlXPathObjectPtr obj;
    char *str, *attr_val;

    obj = xmlXPathEvalExpression(BAD_CAST expr, ctx);
    if (obj == NULL)
    {
        *xerr = XERR_LIBXML;
        return NULL;
    }

    /* look what we got */
    if (xmlXPathNodeSetGetLength(obj->nodesetval) == 0)
    {
        xmlXPathFreeObject(obj);
        if (req)
        {
            *xerr = XERR_CONSTR;
        }
        return NULL;
    }
    else if (xmlXPathNodeSetGetLength(obj->nodesetval) > 1)
    {
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
 * Parse a boolean value entered either
 * as a number or as a string (true/false)
 *
 * @param str  	string to be parsed
 *
 * @returns  	0 or 1
 */
int parse_boolean(char *str)
{
    // this could be also treated as an error
    if (*str == '\0')
        return 0;

    switch (tolower(*str))
    {
        case '0':
        case 'f':
            return 0;
        case '1':
        case 't':
            return 1;

        default:
            // also can be an error, lets just return 0
            return 0;
    }
}

/**
 * @}
 */

typedef struct cmd_hash_item_t cmd_hash_item;

/**
 * Item of command hash table used for fast command recognition.
 */
struct cmd_hash_item_t
{
    cmd_hash_item *next; /**< Next item in hash table. */
    char *key; /**< Hash key (command name). */
    epp_command_type val; /**< Hash value (command type). */
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
static unsigned char get_cmd_hash(const char *key)
{
    int i;
    unsigned char hash = 0;

    /* return code has 4 digits */
    for (i = 0; i < 4; i++)
        hash ^= key[i];
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
static char cmd_hash_insert(const char *key, epp_command_type type)
{
    cmd_hash_item *hi;
    int index;

    assert(key != NULL);
    assert(strlen(key) >= 4);

    /* allocate and initialize new item */
    if ((hi = malloc(sizeof *hi)) == NULL)
        return 1;
    hi->val = type;
    if ((hi->key = strdup(key)) == NULL)
    {
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
static epp_command_type cmd_hash_lookup(const char *key)
{
    cmd_hash_item *hi;

    /* iterate through hash chain */
    for (hi = hash_cmd[get_cmd_hash(key)]; hi != NULL; hi = hi->next)
    {
        if (!strncmp(hi->key, key, 4))
            break;
    }
    /* did we find anything? */
    if (hi)
        return hi->val;
    /* command is not there */
    return EPP_UNKNOWN_CMD;
}

/**
 * Function releases all items in command hash table.
 */
static void cmd_hash_clean(void)
{
    cmd_hash_item *tmp;
    int i;

    /* step through all hash table indexes */
    for (i = 0; i < HASH_SIZE_CMD; i++)
    {
        /* free one hash chain */
        while (hash_cmd[i])
        {
            tmp = hash_cmd[i]->next;
            free(hash_cmd[i]->key);
            free(hash_cmd[i]);
            hash_cmd[i] = tmp;
        }
    }
}

void *epp_parser_init(const char *url_schema)
{
    xmlSchemaPtr schema; /* parsed schema */
    xmlSchemaParserCtxtPtr spctx; /* schema parser's context */
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
    if (rc)
    {
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
    return (void *)schema;
}

void epp_parser_init_cleanup(void *schema)
{
    xmlSchemaFree((xmlSchemaPtr)schema);
    cmd_hash_clean();
    xmlCleanupParser();
}

void epp_parser_request_cleanup(void *cdata_arg)
{
    epp_command_data* const cdata = (epp_command_data*)cdata_arg;

    /* be carefull when freeing - any of pointers might be NULL */
    if (cdata != NULL)
    {
        if (cdata->xpath_ctx != NULL)
        {
            xmlXPathFreeContext((xmlXPathContextPtr)cdata->xpath_ctx);
        }
        if (cdata->parsed_doc != NULL)
        {
            xmlFreeDoc((xmlDocPtr)cdata->parsed_doc);
        }
    }
}

/**
 * Create and enqueue new error item of specified type.
 *
 * @param pool     Pool for memory allocations.
 * @param errors   Error list where new error should be enqueued.
 * @param errspec  Specific code of an error.
 * @return         0 in case of success otherwise 1.
 */
static int new_error_item(void *pool, qhead *errors, epp_errorspec errspec)
{
    epp_error *valerr;

    valerr = epp_malloc(pool, sizeof *valerr);
    if (valerr == NULL)
        return 1;

    valerr->value = NULL; /* will be filled by XML generator */
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
static void parse_login(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
    epps_login *login;
    char *str;
    int xerr;

    RESET_XERR(xerr); /* clear value of errno */

    /* allocate necessary structures */
    if ((cdata->data = epp_calloc(pool, sizeof *login)) == NULL)
        goto error;
    login = cdata->data;

    /* check if language matches */
    str = xpath_get1(pool, xpathCtx, "epp:options/epp:lang", 1, &xerr);
    CHK_XERR(xerr, error);
    if (xmlStrEqual((xmlChar *)str, BAD_CAST "en"))
    {
        login->lang = LANG_EN;
    }
    else if (xmlStrEqual((xmlChar *)str, BAD_CAST "cs"))
    {
        login->lang = LANG_CS;
    }
    else
    {
        cdata->type = EPP_DUMMY;
        cdata->rc = 2102;
        return;
    }

    /* check if EPP version matches */
    str = xpath_get1(pool, xpathCtx, "epp:options/epp:version", 1, &xerr);
    CHK_XERR(xerr, error);
    if (!xmlStrEqual((xmlChar *)str, BAD_CAST "1.0"))
    {
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
static void parse_check(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
    epps_check *check;
    int xerr;

    RESET_XERR(xerr); /* clear value of errno */

    /* allocate necessary structures */
    if ((cdata->data = epp_calloc(pool, sizeof *check)) == NULL)
        goto error;
    check = cdata->data;

    xpath_chroot(xpathCtx, "contact:check", 0, &xerr);
    if (xerr == XERR_OK)
    {
        xpath_getn(pool, &check->ids, xpathCtx, "contact:id", &xerr);
        CHK_XERR(xerr, error);
        cdata->type = EPP_CHECK_CONTACT;
        return;
    }
    else if (xerr != XERR_CONSTR)
        goto error;
    RESET_XERR(xerr); /* clear value of errno */

    xpath_chroot(xpathCtx, "domain:check", 0, &xerr);
    if (xerr == XERR_OK)
    {
        xpath_getn(pool, &check->ids, xpathCtx, "domain:name", &xerr);
        CHK_XERR(xerr, error);
        cdata->type = EPP_CHECK_DOMAIN;
        return;
    }
    else if (xerr != XERR_CONSTR)
        goto error;
    RESET_XERR(xerr); /* clear value of errno */

    xpath_chroot(xpathCtx, "nsset:check", 0, &xerr);
    if (xerr == XERR_OK)
    {
        xpath_getn(pool, &check->ids, xpathCtx, "nsset:id", &xerr);
        CHK_XERR(xerr, error);
        cdata->type = EPP_CHECK_NSSET;
        return;
    }
    else if (xerr != XERR_CONSTR)
        goto error;
    RESET_XERR(xerr); /* clear value of errno */

    xpath_chroot(xpathCtx, "keyset:check", 0, &xerr);
    if (xerr == XERR_OK)
    {
        xpath_getn(pool, &check->ids, xpathCtx, "keyset:id", &xerr);
        CHK_XERR(xerr, error);
        cdata->type = EPP_CHECK_KEYSET;
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
static void parse_info(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
    int xerr, exists;

    RESET_XERR(xerr); /* clear value of errno */

    /*
     * catch the "list command" at the beginning, then proceed with
     * info command
     */
    exists = xpath_count(xpathCtx, "contact:list", &xerr);
    CHK_XERR(xerr, error);
    if (exists)
    {
        if ((cdata->data = epp_calloc(pool, sizeof(epps_list))) == NULL)
            goto error;
        cdata->type = EPP_LIST_CONTACT;
        return;
    }
    exists = xpath_count(xpathCtx, "domain:list", &xerr);
    CHK_XERR(xerr, error);
    if (exists)
    {
        if ((cdata->data = epp_calloc(pool, sizeof(epps_list))) == NULL)
            goto error;
        cdata->type = EPP_LIST_DOMAIN;
        return;
    }
    exists = xpath_count(xpathCtx, "nsset:list", &xerr);
    CHK_XERR(xerr, error);
    if (exists)
    {
        if ((cdata->data = epp_calloc(pool, sizeof(epps_list))) == NULL)
            goto error;
        cdata->type = EPP_LIST_NSSET;
        return;
    }
    exists = xpath_count(xpathCtx, "keyset:list", &xerr);
    CHK_XERR(xerr, error);
    if (exists)
    {
        if ((cdata->data = epp_calloc(pool, sizeof(epps_list))) == NULL)
            goto error;
        cdata->type = EPP_LIST_KEYSET;
        return;
    }

    /* info commands */

    xpath_chroot(xpathCtx, "contact:info", 0, &xerr);
    if (xerr == XERR_OK)
    {
        epps_info_contact *info_contact;

        if ((cdata->data = epp_calloc(pool, sizeof *info_contact)) == NULL)
            goto error;
        info_contact = cdata->data;

        info_contact->id = xpath_get1(pool, xpathCtx, "contact:id", 1, &xerr);
        CHK_XERR(xerr, error);
        info_contact->authInfo = xpath_get1(pool, xpathCtx, "contact:authInfo", 0, &xerr);
        CHK_XERR(xerr, error);
        cdata->type = EPP_INFO_CONTACT;
        return;
    }
    else if (xerr != XERR_CONSTR)
        goto error;
    RESET_XERR(xerr); /* clear value of errno */

    xpath_chroot(xpathCtx, "domain:info", 0, &xerr);
    if (xerr == XERR_OK)
    {
        epps_info_domain *info_domain;

        if ((cdata->data = epp_calloc(pool, sizeof *info_domain)) == NULL)
            goto error;
        info_domain = cdata->data;

        info_domain->name = xpath_get1(pool, xpathCtx, "domain:name", 1, &xerr);
        CHK_XERR(xerr, error);
        info_domain->authInfo = xpath_get1(pool, xpathCtx, "domain:authInfo", 0, &xerr);
        CHK_XERR(xerr, error);
        cdata->type = EPP_INFO_DOMAIN;
        return;
    }
    else if (xerr != XERR_CONSTR)
        goto error;
    RESET_XERR(xerr); /* clear value of errno */

    xpath_chroot(xpathCtx, "nsset:info", 0, &xerr);
    if (xerr == XERR_OK)
    {
        epps_info_nsset *info_nsset;

        if ((cdata->data = epp_calloc(pool, sizeof *info_nsset)) == NULL)
            goto error;
        info_nsset = cdata->data;

        info_nsset->id = xpath_get1(pool, xpathCtx, "nsset:id", 1, &xerr);
        CHK_XERR(xerr, error);
        info_nsset->authInfo = xpath_get1(pool, xpathCtx, "nsset:authInfo", 0, &xerr);
        CHK_XERR(xerr, error);
        cdata->type = EPP_INFO_NSSET;
        return;
    }
    else if (xerr != XERR_CONSTR)
        goto error;
    RESET_XERR(xerr); /* clear value of errno */

    xpath_chroot(xpathCtx, "keyset:info", 0, &xerr);
    if (xerr == XERR_OK)
    {
        epps_info_keyset *info_keyset;

        if ((cdata->data = epp_calloc(pool, sizeof *info_keyset)) == NULL)
            goto error;
        info_keyset = cdata->data;

        info_keyset->id = xpath_get1(pool, xpathCtx, "keyset:id", 1, &xerr);
        CHK_XERR(xerr, error);
        info_keyset->authInfo = xpath_get1(pool, xpathCtx, "keyset:authInfo", 0, &xerr);
        CHK_XERR(xerr, error);
        cdata->type = EPP_INFO_KEYSET;
        return;
    }
    else if (xerr != XERR_CONSTR)
        goto error;
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
static void parse_poll(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
    const char *op, *str;

    /* get poll type - request or acknoledge */
    op = get_attr(xpathCtx->node, "op");
    assert(op != NULL);
    if (!strcmp(op, "req"))
    {
        epps_poll_req *poll_req;

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
    if (str == NULL)
    {
        if (new_error_item(pool, &cdata->errors, errspec_poll_msgID_missing))
            goto error;
        cdata->rc = 2003;
        cdata->type = EPP_DUMMY;
    }
    else
    {
        epps_poll_ack *poll_ack;

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
static void parse_create_domain(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
    epps_create_domain *create_domain;
    char *str;
    int xerr;

    RESET_XERR(xerr); /* clear value of errno */

    /* allocate necessary structures */
    if ((cdata->data = epp_calloc(pool, sizeof *create_domain)) == NULL)
        goto error;
    create_domain = cdata->data;

    /* get the domain data */
    create_domain->name = xpath_get1(pool, xpathCtx, "domain:name", 1, &xerr);
    CHK_XERR(xerr, error);
    create_domain->registrant = xpath_get1(pool, xpathCtx, "domain:registrant", 1, &xerr);
    CHK_XERR(xerr, error);
    create_domain->nsset = xpath_get1(pool, xpathCtx, "domain:nsset", 0, &xerr);
    CHK_XERR(xerr, error);
    create_domain->keyset = xpath_get1(pool, xpathCtx, "domain:keyset", 0, &xerr);
    CHK_XERR(xerr, error);
    create_domain->authInfo = xpath_get1(pool, xpathCtx, "domain:authInfo", 0, &xerr);
    CHK_XERR(xerr, error);
    /* process "unbounded" number of admin contacts */
    xpath_getn(pool, &create_domain->admin, xpathCtx, "domain:admin", &xerr);
    CHK_XERR(xerr, error);
    /* domain period handling is slightly more difficult */
    str = xpath_get1(pool, xpathCtx, "domain:period[@unit='y']", 0, &xerr);
    CHK_XERR(xerr, error);
    create_domain->unit = TIMEUNIT_YEAR;
    if (str == NULL)
    {
        str = xpath_get1(pool, xpathCtx, "domain:period[@unit='m']", 0, &xerr);
        CHK_XERR(xerr, error);
        create_domain->unit = TIMEUNIT_MONTH;
    }
    if (str != NULL)
        create_domain->period = atoi(str);
    else
    {
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
static epp_identType string2identtype(const char *str)
{
    assert(str != NULL);
    if (strcmp(str, "op") == 0)
    {
        return ident_OP;
    }
    if (strcmp(str, "passport") == 0)
    {
        return ident_PASSPORT;
    }
    if (strcmp(str, "mpsv") == 0)
    {
        return ident_MPSV;
    }
    if (strcmp(str, "ico") == 0)
    {
        return ident_ICO;
    }
    if (strcmp(str, "birthday") == 0)
    {
        return ident_BIRTHDAY;
    }
    return ident_UNKNOWN;
}

/**
 * Parser of EPP create-contact command.
 *
 * @param pool Pool for memory allocations.
 * @param xpathCtx XPath context.
 * @param cdata Output of parsing stage.
 */
static void parse_create_contact(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
    epps_create_contact *create_contact;
    int xerr;

    RESET_XERR(xerr); /* clear value of errno */

    /* allocate necessary structures */
    if ((cdata->data = epp_calloc(pool, sizeof *create_contact)) == NULL)
    {
        goto error;
    }
    create_contact = cdata->data;

    /* get the contact data */
    create_contact->id = xpath_get1(pool, xpathCtx, "contact:id", 1, &xerr);
    CHK_XERR(xerr, error);
    create_contact->authInfo = xpath_get1(pool, xpathCtx, "contact:authInfo", 0, &xerr);
    CHK_XERR(xerr, error);
    create_contact->voice = xpath_get1(pool, xpathCtx, "contact:voice", 0, &xerr);
    CHK_XERR(xerr, error);
    create_contact->fax = xpath_get1(pool, xpathCtx, "contact:fax", 0, &xerr);
    CHK_XERR(xerr, error);
    create_contact->email = xpath_get1(pool, xpathCtx, "contact:email", 1, &xerr);
    CHK_XERR(xerr, error);
    create_contact->notify_email = xpath_get1(pool, xpathCtx, "contact:notifyEmail", 0, &xerr);
    CHK_XERR(xerr, error);
    create_contact->vat = xpath_get1(pool, xpathCtx, "contact:vat", 0, &xerr);
    CHK_XERR(xerr, error);
    create_contact->ident = xpath_get1(pool, xpathCtx, "contact:ident", 0, &xerr);
    CHK_XERR(xerr, error);
    create_contact->identtype = ident_UNKNOWN;
    if (create_contact->ident != NULL)
    {
        const char* const str = xpath_get_attr(pool, xpathCtx, "contact:ident", "type", 1, &xerr);
        CHK_XERR(xerr, error);
        create_contact->identtype = string2identtype(str);
        /*
         * schema and source code are out of sync if following error occurs
         */
        assert(create_contact->identtype != ident_UNKNOWN);
    }
    xpath_chroot(xpathCtx, "contact:disclose", 0, &xerr);
    if (xerr == XERR_LIBXML)
    {
        goto error;
    }

    epp_PrivacyPolicy default_privacy_policy;
    switch (cdata->xml_schema.data_collection_policy_access)
    {
        case dcpa_all:
            default_privacy_policy = public_data;
            break;
        case dcpa_none:
            default_privacy_policy = private_data;
            break;
        default:
            goto error;
    }
    const epp_controlled_privacy_data_mask available_disclose_elements =
            cdata->xml_schema.contact_create_available_disclose_elements;
    if (xerr == XERR_OK)
    {
        const char* const str = get_attr(xpathCtx->node, "flag");
        assert(str != NULL);

        const epp_PrivacyPolicy element_presents = *str == '0' ? private_data : public_data;
        const epp_PrivacyPolicy element_absents = default_privacy_policy;
        if (available_disclose_elements.name)
        {
            create_contact->discl.name = 0 < xpath_count(xpathCtx, "contact:name", &xerr) ? element_presents
                                                                                          : element_absents;
            CHK_XERR(xerr, error);
        }
        else
        {
            create_contact->discl.name = unused_privacy_policy;
        }
        if (available_disclose_elements.organization)
        {
            create_contact->discl.organization = 0 < xpath_count(xpathCtx, "contact:org", &xerr) ? element_presents
                                                                                                 : element_absents;
            CHK_XERR(xerr, error);
        }
        else
        {
            create_contact->discl.organization = unused_privacy_policy;
        }
        if (available_disclose_elements.address)
        {
            create_contact->discl.address = 0 < xpath_count(xpathCtx, "contact:addr", &xerr) ? element_presents
                                                                                             : element_absents;
            CHK_XERR(xerr, error);
        }
        else
        {
            create_contact->discl.address = unused_privacy_policy;
        }
        if (available_disclose_elements.telephone)
        {
            create_contact->discl.telephone = 0 < xpath_count(xpathCtx, "contact:voice", &xerr) ? element_presents
                                                                                                : element_absents;
            CHK_XERR(xerr, error);
        }
        else
        {
            create_contact->discl.telephone = unused_privacy_policy;
        }
        if (available_disclose_elements.fax)
        {
            create_contact->discl.fax = 0 < xpath_count(xpathCtx, "contact:fax", &xerr) ? element_presents
                                                                                        : element_absents;
            CHK_XERR(xerr, error);
        }
        else
        {
            create_contact->discl.fax = unused_privacy_policy;
        }
        if (available_disclose_elements.email)
        {
            create_contact->discl.email = 0 < xpath_count(xpathCtx, "contact:email", &xerr) ? element_presents
                                                                                            : element_absents;
            CHK_XERR(xerr, error);
        }
        else
        {
            create_contact->discl.email = unused_privacy_policy;
        }
        if (available_disclose_elements.vat)
        {
            create_contact->discl.vat = 0 < xpath_count(xpathCtx, "contact:vat", &xerr) ? element_presents
                                                                                        : element_absents;
            CHK_XERR(xerr, error);
        }
        else
        {
            create_contact->discl.vat = unused_privacy_policy;
        }
        if (available_disclose_elements.ident)
        {
            create_contact->discl.ident = 0 < xpath_count(xpathCtx, "contact:ident", &xerr) ? element_presents
                                                                                            : element_absents;
            CHK_XERR(xerr, error);
        }
        else
        {
            create_contact->discl.ident = unused_privacy_policy;
        }
        if (available_disclose_elements.notify_email)
        {
            create_contact->discl.notify_email = 0 < xpath_count(xpathCtx, "contact:notifyEmail", &xerr) ? element_presents
                                                                                                         : element_absents;
            CHK_XERR(xerr, error);
        }
        else
        {
            create_contact->discl.notify_email = unused_privacy_policy;
        }
        xpathCtx->node = xpathCtx->node->parent;
    }
    else
    {
        create_contact->discl.name = available_disclose_elements.name ? default_privacy_policy : unused_privacy_policy;
        create_contact->discl.organization = available_disclose_elements.organization ? default_privacy_policy : unused_privacy_policy;
        create_contact->discl.address = available_disclose_elements.address ? default_privacy_policy : unused_privacy_policy;
        create_contact->discl.telephone = available_disclose_elements.telephone ? default_privacy_policy : unused_privacy_policy;
        create_contact->discl.fax = available_disclose_elements.fax ? default_privacy_policy : unused_privacy_policy;
        create_contact->discl.email = available_disclose_elements.email ? default_privacy_policy : unused_privacy_policy;
        create_contact->discl.vat = available_disclose_elements.vat ? default_privacy_policy : unused_privacy_policy;
        create_contact->discl.ident = available_disclose_elements.ident ? default_privacy_policy : unused_privacy_policy;
        create_contact->discl.notify_email = available_disclose_elements.notify_email ? default_privacy_policy : unused_privacy_policy;
        RESET_XERR(xerr); /* clear value of errno */
    }
    /* postal info, change relative root */
    xpath_chroot(xpathCtx, "contact:postalInfo", 0, &xerr);
    CHK_XERR(xerr, error);

    create_contact->pi.name = xpath_get1(pool, xpathCtx, "contact:name", 1, &xerr);
    CHK_XERR(xerr, error);
    create_contact->pi.org = xpath_get1(pool, xpathCtx, "contact:org", 0, &xerr);
    CHK_XERR(xerr, error);
    /* address, change relative root */
    xpath_chroot(xpathCtx, "contact:addr", 0, &xerr);
    CHK_XERR(xerr, error);
    xpath_getn(pool, &create_contact->pi.streets, xpathCtx, "contact:street", &xerr);
    CHK_XERR(xerr, error);
    create_contact->pi.city = xpath_get1(pool, xpathCtx, "contact:city", 1, &xerr);
    CHK_XERR(xerr, error);
    create_contact->pi.sp = xpath_get1(pool, xpathCtx, "contact:sp", 0, &xerr);
    CHK_XERR(xerr, error);
    create_contact->pi.pc = xpath_get1(pool, xpathCtx, "contact:pc", 1, &xerr);
    CHK_XERR(xerr, error);
    create_contact->pi.cc = xpath_get1(pool, xpathCtx, "contact:cc", 1, &xerr);
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
static void parse_create_nsset(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
    epps_create_nsset *create_nsset;
    xmlXPathObjectPtr xpathObj;
    char *level;
    int j, xerr;

    RESET_XERR(xerr); /* clear value of errno */

    /* allocate necessary structures */
    if ((cdata->data = epp_calloc(pool, sizeof *create_nsset)) == NULL)
        goto error;
    create_nsset = cdata->data;

    /* get the nsset data */
    create_nsset->id = xpath_get1(pool, xpathCtx, "nsset:id", 1, &xerr);
    CHK_XERR(xerr, error);
    create_nsset->authInfo = xpath_get1(pool, xpathCtx, "nsset:authInfo", 0, &xerr);
    CHK_XERR(xerr, error);
    level = xpath_get1(pool, xpathCtx, "nsset:reportlevel", 0, &xerr);
    CHK_XERR(xerr, error);
    if (level != NULL)
        create_nsset->level = atoi(level);
    else
        create_nsset->level = -1;
    /* process "unbounded" number of tech contacts */
    xpath_getn(pool, &create_nsset->tech, xpathCtx, "nsset:tech", &xerr);
    CHK_XERR(xerr, error);
    /* process multiple ns records which have in turn multiple addresses */
    xpathObj = xmlXPathEvalExpression(BAD_CAST "nsset:ns", xpathCtx);
    if (xpathObj == NULL)
        goto error;

    for (j = 0; j < xmlXPathNodeSetGetLength(xpathObj->nodesetval); j++)
    {
        epp_ns *ns;

        /* allocate data structures */
        if ((ns = epp_calloc(pool, sizeof *ns)) == NULL)
        {
            goto err_free;
        }
        /* get data */
        xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, j);
        ns->name = xpath_get1(pool, xpathCtx, "nsset:name", 1, &xerr);
        CHK_XERR(xerr, err_free);
        xpath_getn(pool, &ns->addr, xpathCtx, "nsset:addr", &xerr);
        CHK_XERR(xerr, err_free);
        /* enqueue ns record */
        if (q_add(pool, &create_nsset->ns, ns))
        {
            goto err_free;
        }
    }
    xmlXPathFreeObject(xpathObj);

    cdata->type = EPP_CREATE_NSSET;
    return;

err_free:
    xmlXPathFreeObject(xpathObj);
error:
    cdata->rc = 2400;
    cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP create-keyset command.
 *
 * @param pool      Pool for memory allocations.
 * @param xpathCtx  XPath context.
 * @param cdata     Output of parsing stage.
 */
static void parse_create_keyset(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
    epps_create_keyset *create_keyset;
    xmlXPathObjectPtr xpathObj;
    xmlNodePtr par_node;
    int j, xerr;

    RESET_XERR(xerr); /* clear value of errno */

    /* allocate necessary structures */
    if ((cdata->data = epp_calloc(pool, sizeof *create_keyset)) == NULL)
        goto error;
    create_keyset = cdata->data;

    /* save the root node */
    par_node = xpathCtx->node;

    /* get the nsset data */
    create_keyset->id = xpath_get1(pool, xpathCtx, "keyset:id", 1, &xerr);
    CHK_XERR(xerr, error);
    create_keyset->authInfo = xpath_get1(pool, xpathCtx, "keyset:authInfo", 0, &xerr);
    CHK_XERR(xerr, error);
    /* process "unbounded" number of tech contacts */
    xpath_getn(pool, &create_keyset->tech, xpathCtx, "keyset:tech", &xerr);
    CHK_XERR(xerr, error);
    /* process multiple DNSKEY reocrds */
    xpathObj = xmlXPathEvalExpression(BAD_CAST "keyset:dnskey", xpathCtx);
    if (xpathObj == NULL)
        goto error;

    for (j = 0; j < xmlXPathNodeSetGetLength(xpathObj->nodesetval); j++)
    {
        epp_dnskey *key;

        /* allocate data structures */
        if ((key = epp_calloc(pool, sizeof(epp_dnskey))) == NULL)
        {
            xmlXPathFreeObject(xpathObj);
            goto error;
        }
        /* get data */
        xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, j);

        if (read_epp_dnskey(pool, xpathCtx, key) == 0)
        {
            xmlXPathFreeObject(xpathObj);
            goto error;
        }

        /* enqueue ds record */
        if (q_add(pool, &create_keyset->keys, key))
        {
            xmlXPathFreeObject(xpathObj);
            goto error;
        }
    }
    xmlXPathFreeObject(xpathObj);
    xpathCtx->node = par_node;

    cdata->type = EPP_CREATE_KEYSET;
    return;

error:
    cdata->rc = 2400;
    cdata->type = EPP_DUMMY;
}

/**
 * Read DNSKEY information from xml into epp_dnskey structure
 *
 * @param pool 		Pool for allocating memory
 * @param xpathCtx 	XML parsing context
 * @param key		DNSKEY structure filled with data
 * @returns 		1 on success, 0 on failure (goto error in other functions
 */
int read_epp_dnskey(void *pool, xmlXPathContextPtr xpathCtx, epp_dnskey *key)
{
    char *str;
    int xerr;

    RESET_XERR(xerr);

    str = xpath_get1(pool, xpathCtx, "keyset:flags", 1, &xerr);
    CHK_XERR(xerr, error);
    key->flags = (unsigned short)atoi(str);

    str = xpath_get1(pool, xpathCtx, "keyset:protocol", 1, &xerr);
    CHK_XERR(xerr, error);
    key->protocol = (unsigned char)atoi(str);

    str = xpath_get1(pool, xpathCtx, "keyset:alg", 1, &xerr);
    CHK_XERR(xerr, error);
    key->alg = (unsigned char)atoi(str);

    key->public_key = xpath_get1(pool, xpathCtx, "keyset:pubKey", 1, &xerr);
    CHK_XERR(xerr, error);

    return 1;
error:
    return 0;
}


/**
 * Parser of EPP create command.
 *
 * @param pool      Pool for memory allocations.
 * @param xpathCtx  XPath context.
 * @param cdata     Output of parsing stage.
 */
static void parse_create(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
    int xerr;

    RESET_XERR(xerr); /* clear value of errno */

    /* get object type by trying to change relative root */
    xpath_chroot(xpathCtx, "contact:create", 0, &xerr);
    if (xerr == XERR_OK)
    {
        parse_create_contact(pool, xpathCtx, cdata);
        return;
    }
    else if (xerr != XERR_CONSTR)
        goto error;
    RESET_XERR(xerr); /* clear value of errno */

    xpath_chroot(xpathCtx, "domain:create", 0, &xerr);
    if (xerr == XERR_OK)
    {
        parse_create_domain(pool, xpathCtx, cdata);
        return;
    }
    else if (xerr != XERR_CONSTR)
        goto error;
    RESET_XERR(xerr); /* clear value of errno */

    xpath_chroot(xpathCtx, "nsset:create", 0, &xerr);
    if (xerr == XERR_OK)
    {
        parse_create_nsset(pool, xpathCtx, cdata);
        return;
    }
    else if (xerr != XERR_CONSTR)
        goto error;
    RESET_XERR(xerr); /* clear value of errno */

    xpath_chroot(xpathCtx, "keyset:create", 0, &xerr);
    if (xerr == XERR_OK)
    {
        parse_create_keyset(pool, xpathCtx, cdata);
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
 * Parser of EPP delete command.
 *
 * @param pool      Pool for memory allocations.
 * @param xpathCtx  XPath context.
 * @param cdata     Output of parsing stage.
 */
static void parse_delete(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
    epps_delete *delete;
    int xerr;

    RESET_XERR(xerr); /* clear value of errno */

    /* allocate necessary structures */
    if ((cdata->data = epp_calloc(pool, sizeof *delete)) == NULL)
        goto error;
    delete = cdata->data;

    /* get object type - contact, domain or nsset */
    xpath_chroot(xpathCtx, "contact:delete", 0, &xerr);
    if (xerr == XERR_OK)
    {
        /* object is contact */
        delete->id = xpath_get1(pool, xpathCtx, "contact:id", 1, &xerr);
        CHK_XERR(xerr, error);
        cdata->type = EPP_DELETE_CONTACT;
        return;
    }
    else if (xerr != XERR_CONSTR)
        goto error;
    RESET_XERR(xerr); /* clear value of errno */

    xpath_chroot(xpathCtx, "domain:delete", 0, &xerr);
    if (xerr == XERR_OK)
    {
        /* object is domain */
        delete->id = xpath_get1(pool, xpathCtx, "domain:name", 1, &xerr);
        CHK_XERR(xerr, error);
        cdata->type = EPP_DELETE_DOMAIN;
        return;
    }
    else if (xerr != XERR_CONSTR)
        goto error;
    RESET_XERR(xerr); /* clear value of errno */

    xpath_chroot(xpathCtx, "nsset:delete", 0, &xerr);
    if (xerr == XERR_OK)
    {
        /* object is nsset */
        delete->id = xpath_get1(pool, xpathCtx, "nsset:id", 1, &xerr);
        CHK_XERR(xerr, error);
        cdata->type = EPP_DELETE_NSSET;
        return;
    }
    else if (xerr != XERR_CONSTR)
        goto error;
    RESET_XERR(xerr); /* clear value of errno */

    xpath_chroot(xpathCtx, "keyset:delete", 0, &xerr);
    if (xerr == XERR_OK)
    {
        /* object is nsset */
        delete->id = xpath_get1(pool, xpathCtx, "keyset:id", 1, &xerr);
        CHK_XERR(xerr, error);
        cdata->type = EPP_DELETE_KEYSET;
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
 * Parser of EPP renew command.
 *
 * @param pool      Pool for memory allocations.
 * @param xpathCtx  XPath context.
 * @param cdata     Output of parsing stage.
 */
static void parse_renew(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
    epps_renew *renew;
    char *str;
    int xerr;

    RESET_XERR(xerr); /* clear value of errno */

    /* allocate necessary structures */
    if ((cdata->data = epp_calloc(pool, sizeof *renew)) == NULL)
    {
        goto error;
    }
    renew = cdata->data;

    /* get renew data */
    xpath_chroot(xpathCtx, "domain:renew", 0, &xerr);
    CHK_XERR(xerr, error);
    renew->name = xpath_get1(pool, xpathCtx, "domain:name", 1, &xerr);
    CHK_XERR(xerr, error);
    renew->curExDate = xpath_get1(pool, xpathCtx, "domain:curExpDate", 1, &xerr);
    CHK_XERR(xerr, error);
    /* domain period handling is slightly more difficult */
    str = xpath_get1(pool, xpathCtx, "domain:period[@unit='y']", 0, &xerr);
    CHK_XERR(xerr, error);
    renew->unit = TIMEUNIT_YEAR;
    if (str == NULL)
    {
        /* correct period value if given in years and not months */
        str = xpath_get1(pool, xpathCtx, "domain:period[@unit='m']", 0, &xerr);
        CHK_XERR(xerr, error);
        renew->unit = TIMEUNIT_MONTH;
    }
    if (str != NULL)
        renew->period = atoi(str);
    else
    {
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
static void parse_update_domain(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
    epps_update_domain *update_domain;
    int xerr;

    RESET_XERR(xerr); /* clear value of errno */

    /* allocate necessary structures */
    if ((cdata->data = epp_calloc(pool, sizeof *update_domain)) == NULL)
        goto error;
    update_domain = cdata->data;

    /* get the update-domain data */
    update_domain->name = xpath_get1(pool, xpathCtx, "domain:name", 1, &xerr);
    CHK_XERR(xerr, error);
    /* chg data */
    xpath_chroot(xpathCtx, "domain:chg", 0, &xerr);
    if (xerr == XERR_OK)
    {
        update_domain->registrant = xpath_get1(pool, xpathCtx, "domain:registrant", 0, &xerr);
        CHK_XERR(xerr, error);
        update_domain->nsset = xpath_get1(pool, xpathCtx, "domain:nsset", 0, &xerr);
        CHK_XERR(xerr, error);
        update_domain->keyset = xpath_get1(pool, xpathCtx, "domain:keyset", 0, &xerr);
        CHK_XERR(xerr, error);

        update_domain->authInfo = xpath_get1(pool, xpathCtx, "domain:authInfo", 0, &xerr);
        CHK_XERR(xerr, error);
        xpathCtx->node = xpathCtx->node->parent;
    }
    else if (xerr == XERR_LIBXML)
        goto error;
    else
        RESET_XERR(xerr); /* clear value of errno */

    /* add data */
    xpath_chroot(xpathCtx, "domain:add", 0, &xerr);
    if (xerr == XERR_OK)
    {
        xpath_getn(pool, &update_domain->add_admin, xpathCtx, "domain:admin", &xerr);
        CHK_XERR(xerr, error);
        xpathCtx->node = xpathCtx->node->parent;
    }
    else if (xerr == XERR_LIBXML)
        goto error;
    else
        RESET_XERR(xerr); /* clear value of errno */

    /* rem data */
    xpath_chroot(xpathCtx, "domain:rem", 0, &xerr);
    if (xerr == XERR_OK)
    {
        xpath_getn(pool, &update_domain->rem_admin, xpathCtx, "domain:admin", &xerr);
        CHK_XERR(xerr, error);
        xpath_getn(pool, &update_domain->rem_tmpcontact, xpathCtx, "domain:tempcontact", &xerr);
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
static void parse_update_contact(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
    epps_update_contact *update_contact;
    int xerr;

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
    {
        goto error;
    }
    if (xerr == XERR_CONSTR)
    {
        /* there is nothing more to parse */
        cdata->type = EPP_UPDATE_CONTACT;
        update_contact->discl_update = 0;
        return;
    }

    /* the most difficult item comes first (ident) */
    update_contact->ident = xpath_get1(pool, xpathCtx, "contact:ident", 0, &xerr);
    CHK_XERR(xerr, error);
    update_contact->identtype = ident_UNKNOWN;
    if (update_contact->ident != NULL)
    {
        char *str;

        str = xpath_get_attr(pool, xpathCtx, "contact:ident", "type", 1, &xerr);
        CHK_XERR(xerr, error);
        /* if ident is non-empty, type attribute must be present */
        if ((*update_contact->ident != '\0') && (str == NULL))
        {
            if (new_error_item(pool, &cdata->errors, errspec_contact_identtype_missing))
            {
                goto error;
            }
            cdata->rc = 2003;
            cdata->type = EPP_DUMMY;
            return;
        }
        if (str != NULL)
        {
            update_contact->identtype = string2identtype(str);
            /*
             * schema and source code is out of sync if following
             * assert does not hold
             */
            assert(update_contact->identtype != ident_UNKNOWN);
        }
    }
    update_contact->authInfo = xpath_get1(pool, xpathCtx, "contact:authInfo", 0, &xerr);
    CHK_XERR(xerr, error);
    update_contact->voice = xpath_get1(pool, xpathCtx, "contact:voice", 0, &xerr);
    CHK_XERR(xerr, error);
    update_contact->fax = xpath_get1(pool, xpathCtx, "contact:fax", 0, &xerr);
    CHK_XERR(xerr, error);
    update_contact->email = xpath_get1(pool, xpathCtx, "contact:email", 0, &xerr);
    CHK_XERR(xerr, error);
    update_contact->notify_email = xpath_get1(pool, xpathCtx, "contact:notifyEmail", 0, &xerr);
    CHK_XERR(xerr, error);
    update_contact->vat = xpath_get1(pool, xpathCtx, "contact:vat", 0, &xerr);
    CHK_XERR(xerr, error);
    /*
     * there can be just one disclose section, now it depens if the flag is
     * 0 or 1
     */
    xpath_chroot(xpathCtx, "contact:disclose", 0, &xerr);
    if (xerr == XERR_LIBXML)
    {
        goto error;
    }
    if (xerr == XERR_OK)
    {
        epp_PrivacyPolicy default_privacy_policy;
        switch (cdata->xml_schema.data_collection_policy_access)
        {
            case dcpa_all:
                default_privacy_policy = public_data;
                break;
            case dcpa_none:
                default_privacy_policy = private_data;
                break;
            default:
                goto error;
        }
        const char *const str = get_attr(xpathCtx->node, "flag");
        assert(str != NULL);
        const epp_PrivacyPolicy element_presents = *str == '0' ? private_data : public_data;
        const epp_PrivacyPolicy element_absents = default_privacy_policy;
        const epp_controlled_privacy_data_mask available_disclose_elements =
                cdata->xml_schema.contact_update_available_disclose_elements;
        update_contact->discl_update = 1;
        if (available_disclose_elements.name)
        {
            update_contact->discl.name = 0 < xpath_count(xpathCtx, "contact:name", &xerr) ? element_presents
                                                                                          : element_absents;
            CHK_XERR(xerr, error);
        }
        else
        {
            update_contact->discl.name = unused_privacy_policy;
        }
        if (available_disclose_elements.organization)
        {
            update_contact->discl.organization = 0 < xpath_count(xpathCtx, "contact:org", &xerr) ? element_presents
                                                                                                 : element_absents;
            CHK_XERR(xerr, error);
        }
        else
        {
            update_contact->discl.organization = unused_privacy_policy;
        }
        if (available_disclose_elements.address)
        {
            update_contact->discl.address = 0 < xpath_count(xpathCtx, "contact:addr", &xerr) ? element_presents
                                                                                             : element_absents;
            CHK_XERR(xerr, error);
        }
        else
        {
            update_contact->discl.address = unused_privacy_policy;
        }
        if (available_disclose_elements.telephone)
        {
            update_contact->discl.telephone = 0 < xpath_count(xpathCtx, "contact:voice", &xerr) ? element_presents
                                                                                                : element_absents;
            CHK_XERR(xerr, error);
        }
        else
        {
            update_contact->discl.telephone = unused_privacy_policy;
        }
        if (available_disclose_elements.fax)
        {
            update_contact->discl.fax = 0 < xpath_count(xpathCtx, "contact:fax", &xerr) ? element_presents
                                                                                        : element_absents;
            CHK_XERR(xerr, error);
        }
        else
        {
            update_contact->discl.fax = unused_privacy_policy;
        }
        if (available_disclose_elements.email)
        {
            update_contact->discl.email = 0 < xpath_count(xpathCtx, "contact:email", &xerr) ? element_presents
                                                                                            : element_absents;
            CHK_XERR(xerr, error);
        }
        else
        {
            update_contact->discl.email = unused_privacy_policy;
        }
        if (available_disclose_elements.vat)
        {
            update_contact->discl.vat = 0 < xpath_count(xpathCtx, "contact:vat", &xerr) ? element_presents
                                                                                        : element_absents;
            CHK_XERR(xerr, error);
        }
        else
        {
            update_contact->discl.vat = unused_privacy_policy;
        }
        if (available_disclose_elements.ident)
        {
            update_contact->discl.ident = 0 < xpath_count(xpathCtx, "contact:ident", &xerr) ? element_presents
                                                                                            : element_absents;
            CHK_XERR(xerr, error);
        }
        else
        {
            update_contact->discl.ident = unused_privacy_policy;
        }
        if (available_disclose_elements.notify_email)
        {
            update_contact->discl.notify_email = 0 < xpath_count(xpathCtx, "contact:notifyEmail", &xerr) ? element_presents
                                                                                                         : element_absents;
            CHK_XERR(xerr, error);
        }
        else
        {
            update_contact->discl.notify_email = unused_privacy_policy;
        }
        xpathCtx->node = xpathCtx->node->parent;
    }
    else
    {
        update_contact->discl_update = 0;
        RESET_XERR(xerr); /* clear value of errno */
    }
    /* postal info, change relative root */
    xpath_chroot(xpathCtx, "contact:postalInfo", 0, &xerr);
    if (xerr == XERR_LIBXML)
    {
        goto error;
    }
    if (xerr == XERR_OK)
    {
        update_contact->pi = epp_calloc(pool, sizeof *(update_contact->pi));
        if (update_contact->pi == NULL)
        {
            goto error;
        }
        update_contact->pi->name = xpath_get1(pool, xpathCtx, "contact:name", 0, &xerr);
        CHK_XERR(xerr, error);
        update_contact->pi->org = xpath_get1(pool, xpathCtx, "contact:org", 0, &xerr);
        CHK_XERR(xerr, error);

        /* address, change relative root */
        xpath_chroot(xpathCtx, "contact:addr", 0, &xerr);
        if (xerr == XERR_LIBXML)
        {
            goto error;
        }
        if (xerr == XERR_OK)
        {
            update_contact->pi->city = xpath_get1(pool, xpathCtx, "contact:city", 0, &xerr);
            CHK_XERR(xerr, error);
            update_contact->pi->sp = xpath_get1(pool, xpathCtx, "contact:sp", 0, &xerr);
            CHK_XERR(xerr, error);
            update_contact->pi->pc = xpath_get1(pool, xpathCtx, "contact:pc", 0, &xerr);
            CHK_XERR(xerr, error);
            update_contact->pi->cc = xpath_get1(pool, xpathCtx, "contact:cc", 0, &xerr);
            CHK_XERR(xerr, error);

            xpath_getn(pool, &update_contact->pi->streets, xpathCtx, "contact:street", &xerr);
            CHK_XERR(xerr, error);
        }
        else
        {
            RESET_XERR(xerr); /* clear value of errno */
        }
    }
    else
    {
        RESET_XERR(xerr); /* clear value of errno */
    }

    cdata->type = EPP_UPDATE_CONTACT;
    return;

error:
    cdata->rc = 2400;
    cdata->type = EPP_DUMMY;
}

/**
 * Parser of EPP update-keyset command.
 *
 * @param pool      Pool for memory allocations.
 * @param xpathCtx  XPath context.
 * @param cdata     Output of parsing stage.
 */
static void parse_update_keyset(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
    epps_update_keyset *update_keyset;
    xmlXPathObjectPtr xpathObj;
    xmlNodePtr par_node, root_node;
    int j, xerr;

    RESET_XERR(xerr); /* clear value of errno */

    /* allocate necessary structures */
    if ((cdata->data = epp_calloc(pool, sizeof *update_keyset)) == NULL)
        goto error;
    update_keyset = cdata->data;

    /* get the update-keyset data */
    update_keyset->id = xpath_get1(pool, xpathCtx, "keyset:id", 1, &xerr);
    CHK_XERR(xerr, error);
    /* chg data */
    update_keyset->authInfo = xpath_get1(pool, xpathCtx, "keyset:chg/keyset:authInfo", 0, &xerr);
    CHK_XERR(xerr, error);

    /* rem data */
    root_node = xpath_chroot(xpathCtx, "keyset:rem", 0, &xerr);

    if (xerr == XERR_LIBXML)
        goto error;
    else if (xerr == XERR_OK)
    {
        par_node = xpathCtx->node;

        /*
        xpath_getn(pool, &update_keyset->rem_tech, xpathCtx,
                "keyset:tech", &xerr);
        CHK_XERR(xerr, error);
        xpath_getn(pool, &update_keyset->rem_ds, xpathCtx,
                "keyset:name", &xerr);
        CHK_XERR(xerr, error);
        xpathCtx->node = xpathCtx->node->parent;
        */
        xpath_getn(pool, &update_keyset->rem_tech, xpathCtx, "keyset:tech", &xerr);
        CHK_XERR(xerr, error);
        /* rem DNSKEY records */
        xpathObj = xmlXPathEvalExpression(BAD_CAST "keyset:dnskey", xpathCtx);
        if (xpathObj == NULL)
            goto error;

        for (j = 0; j < xmlXPathNodeSetGetLength(xpathObj->nodesetval); j++)
        {
            epp_dnskey *key;

            /* allocate and initialize data structures */
            if ((key = epp_calloc(pool, sizeof(epp_dnskey))) == NULL)
            {
                xmlXPathFreeObject(xpathObj);
                goto error;
            }

            /* get data */
            xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, j);

            if (read_epp_dnskey(pool, xpathCtx, key) == 0)
            {
                xmlXPathFreeObject(xpathObj);
                goto error;
            }

            /* enqueue dnskey record */
            if (q_add(pool, &update_keyset->rem_dnskey, key))
            {
                xmlXPathFreeObject(xpathObj);
                goto error;
            }
        }
        xmlXPathFreeObject(xpathObj);

        xpathCtx->node = par_node;
    }
    else
    {
        RESET_XERR(xerr); /* clear value of errno */
    }


    /* go back to the root node */
    if (root_node != NULL)
        xpathCtx->node = root_node;

    /* add data */
    xpath_chroot(xpathCtx, "keyset:add", 0, &xerr);
    if (xerr == XERR_LIBXML)
        goto error;
    else if (xerr == XERR_OK)
    {
        par_node = xpathCtx->node;

        xpath_getn(pool, &update_keyset->add_tech, xpathCtx, "keyset:tech", &xerr);
        CHK_XERR(xerr, error);
        /* add DNSKEY record */
        xpathObj = xmlXPathEvalExpression(BAD_CAST "keyset:dnskey", xpathCtx);
        if (xpathObj == NULL)
            goto error;

        for (j = 0; j < xmlXPathNodeSetGetLength(xpathObj->nodesetval); j++)
        {
            epp_dnskey *key;

            /* allocate and initialize data structures */
            if ((key = epp_calloc(pool, sizeof(epp_dnskey))) == NULL)
            {
                xmlXPathFreeObject(xpathObj);
                goto error;
            }

            /* get data */
            xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, j);

            if (read_epp_dnskey(pool, xpathCtx, key) == 0)
            {
                xmlXPathFreeObject(xpathObj);
                goto error;
            }

            /* enqueue dnskey record */
            if (q_add(pool, &update_keyset->add_dnskey, key))
            {
                xmlXPathFreeObject(xpathObj);
                goto error;
            }
        }
        xmlXPathFreeObject(xpathObj);
    }
    else
    {
        RESET_XERR(xerr); /* clear value of errno */
    }

    cdata->type = EPP_UPDATE_KEYSET;
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
static void parse_update_nsset(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
    epps_update_nsset *update_nsset;
    xmlXPathObjectPtr xpathObj;
    int j, xerr;
    char *level;

    RESET_XERR(xerr); /* clear value of errno */

    /* allocate necessary structures */
    if ((cdata->data = epp_calloc(pool, sizeof *update_nsset)) == NULL)
        goto error;
    update_nsset = cdata->data;

    /* get the update-nsset data */
    update_nsset->id = xpath_get1(pool, xpathCtx, "nsset:id", 1, &xerr);
    CHK_XERR(xerr, error);
    /* chg data */
    update_nsset->authInfo = xpath_get1(pool, xpathCtx, "nsset:chg/nsset:authInfo", 0, &xerr);
    CHK_XERR(xerr, error);
    level = xpath_get1(pool, xpathCtx, "nsset:chg/nsset:reportlevel", 0, &xerr);
    CHK_XERR(xerr, error);
    if (level != NULL)
        update_nsset->level = atoi(level);
    else
        update_nsset->level = -1;
    /* rem data */
    xpath_chroot(xpathCtx, "nsset:rem", 0, &xerr);
    if (xerr == XERR_LIBXML)
        goto error;
    else if (xerr == XERR_OK)
    {
        xpath_getn(pool, &update_nsset->rem_tech, xpathCtx, "nsset:tech", &xerr);
        CHK_XERR(xerr, error);
        xpath_getn(pool, &update_nsset->rem_ns, xpathCtx, "nsset:name", &xerr);
        CHK_XERR(xerr, error);
        xpathCtx->node = xpathCtx->node->parent;
    }
    else
        RESET_XERR(xerr); /* clear value of errno */
    /* add data */
    xpath_chroot(xpathCtx, "nsset:add", 0, &xerr);
    if (xerr == XERR_LIBXML)
        goto error;
    else if (xerr == XERR_OK)
    {
        xpath_getn(pool, &update_nsset->add_tech, xpathCtx, "nsset:tech", &xerr);
        CHK_XERR(xerr, error);
        /* add ns */
        xpathObj = xmlXPathEvalExpression(BAD_CAST "nsset:ns", xpathCtx);
        if (xpathObj == NULL)
            goto error;

        /* process all nameservers */
        for (j = 0; j < xmlXPathNodeSetGetLength(xpathObj->nodesetval); j++)
        {
            epp_ns *ns;

            /* allocate and initialize data structures */
            if ((ns = epp_calloc(pool, sizeof *ns)) == NULL)
            {
                xmlXPathFreeObject(xpathObj);
                goto error;
            }

            /* get data */
            xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, j);
            ns->name = xpath_get1(pool, xpathCtx, "nsset:name", 1, &xerr);
            if (xerr != XERR_OK)
            {
                xmlXPathFreeObject(xpathObj);
                goto error;
            }
            xpath_getn(pool, &ns->addr, xpathCtx, "nsset:addr", &xerr);
            if (xerr != XERR_OK)
            {
                xmlXPathFreeObject(xpathObj);
                goto error;
            }
            /* enqueue ns record */
            if (q_add(pool, &update_nsset->add_ns, ns))
            {
                xmlXPathFreeObject(xpathObj);
                goto error;
            }
        }
        xmlXPathFreeObject(xpathObj);
    }
    else
        RESET_XERR(xerr); /* clear value of errno */

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
static void parse_update(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
    int xerr;

    RESET_XERR(xerr); /* clear value of errno */

    /* change relative root and get object type btw */
    xpath_chroot(xpathCtx, "contact:update", 0, &xerr);
    if (xerr == XERR_OK)
    {
        parse_update_contact(pool, xpathCtx, cdata);
        return;
    }
    else if (xerr == XERR_LIBXML)
        goto error;
    else
        RESET_XERR(xerr);

    xpath_chroot(xpathCtx, "domain:update", 0, &xerr);
    if (xerr == XERR_OK)
    {
        parse_update_domain(pool, xpathCtx, cdata);
        return;
    }
    else if (xerr == XERR_LIBXML)
        goto error;
    else
        RESET_XERR(xerr);

    xpath_chroot(xpathCtx, "nsset:update", 0, &xerr);
    if (xerr == XERR_OK)
    {
        parse_update_nsset(pool, xpathCtx, cdata);
        return;
    }
    else if (xerr == XERR_LIBXML)
        goto error;
    else
        RESET_XERR(xerr);

    xpath_chroot(xpathCtx, "keyset:update", 0, &xerr);
    if (xerr == XERR_OK)
    {
        parse_update_keyset(pool, xpathCtx, cdata);
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
static void parse_transfer(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
    epps_transfer *transfer;
    int xerr;
    char *str;

    /* allocate necessary structures */
    if ((cdata->data = epp_calloc(pool, sizeof *transfer)) == NULL)
    {
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
    if (strcmp(str, "request"))
    {
        if (new_error_item(pool, &cdata->errors, errspec_transfer_op))
            goto error;

        cdata->rc = 2102;
        cdata->type = EPP_DUMMY;
        return;
    }

    RESET_XERR(xerr); /* clear value of errno */

    /* get object type - domain, contact, nsset or keyset */
    xpath_chroot(xpathCtx, "domain:transfer", 0, &xerr);
    if (xerr == XERR_OK)
    {
        transfer->id = xpath_get1(pool, xpathCtx, "domain:name", 1, &xerr);
        CHK_XERR(xerr, error);
        transfer->authInfo = xpath_get1(pool, xpathCtx, "domain:authInfo", 0, &xerr);
        CHK_XERR(xerr, error);
        cdata->type = EPP_TRANSFER_DOMAIN;
        return;
    }
    else if (xerr == XERR_LIBXML)
        goto error;
    else
        RESET_XERR(xerr);

    xpath_chroot(xpathCtx, "contact:transfer", 0, &xerr);
    if (xerr == XERR_OK)
    {
        transfer->id = xpath_get1(pool, xpathCtx, "contact:id", 1, &xerr);
        CHK_XERR(xerr, error);
        transfer->authInfo = xpath_get1(pool, xpathCtx, "contact:authInfo", 0, &xerr);
        CHK_XERR(xerr, error);
        cdata->type = EPP_TRANSFER_CONTACT;
        return;
    }
    else if (xerr == XERR_LIBXML)
        goto error;
    else
        RESET_XERR(xerr);

    xpath_chroot(xpathCtx, "nsset:transfer", 0, &xerr);
    if (xerr == XERR_OK)
    {
        transfer->id = xpath_get1(pool, xpathCtx, "nsset:id", 1, &xerr);
        CHK_XERR(xerr, error);
        transfer->authInfo = xpath_get1(pool, xpathCtx, "nsset:authInfo", 0, &xerr);
        CHK_XERR(xerr, error);
        cdata->type = EPP_TRANSFER_NSSET;
        return;
    }
    else if (xerr == XERR_LIBXML)
        goto error;
    else
        RESET_XERR(xerr);

    xpath_chroot(xpathCtx, "keyset:transfer", 0, &xerr);
    if (xerr == XERR_OK)
    {
        transfer->id = xpath_get1(pool, xpathCtx, "keyset:id", 1, &xerr);
        CHK_XERR(xerr, error);
        transfer->authInfo = xpath_get1(pool, xpathCtx, "keyset:authInfo", 0, &xerr);
        CHK_XERR(xerr, error);
        cdata->type = EPP_TRANSFER_KEYSET;
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
static void parse_sendAuthInfo(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
    epps_sendAuthInfo *sendAuthInfo;
    int xerr;

    cdata->data = epp_calloc(pool, sizeof *sendAuthInfo);
    if (cdata->data == NULL)
    {
        cdata->rc = 2400;
        cdata->type = EPP_DUMMY;
        return;
    }
    sendAuthInfo = cdata->data;

    /* get object type - domain, contact or nsset */
    RESET_XERR(xerr); /* clear value of errno */
    xpath_chroot(xpathCtx, "domain:sendAuthInfo", 0, &xerr);
    if (xerr == XERR_OK)
    {
        sendAuthInfo->id = xpath_get1(pool, xpathCtx, "domain:name", 1, &xerr);
        CHK_XERR(xerr, error);
        cdata->type = EPP_SENDAUTHINFO_DOMAIN;
        return;
    }
    else if (xerr == XERR_LIBXML)
        goto error;
    else
        RESET_XERR(xerr);

    xpath_chroot(xpathCtx, "contact:sendAuthInfo", 0, &xerr);
    if (xerr == XERR_OK)
    {
        sendAuthInfo->id = xpath_get1(pool, xpathCtx, "contact:id", 1, &xerr);
        CHK_XERR(xerr, error);
        cdata->type = EPP_SENDAUTHINFO_CONTACT;
        return;
    }
    else if (xerr == XERR_LIBXML)
        goto error;
    else
        RESET_XERR(xerr);

    xpath_chroot(xpathCtx, "nsset:sendAuthInfo", 0, &xerr);
    if (xerr == XERR_OK)
    {
        sendAuthInfo->id = xpath_get1(pool, xpathCtx, "nsset:id", 1, &xerr);
        CHK_XERR(xerr, error);
        cdata->type = EPP_SENDAUTHINFO_NSSET;
        return;
    }
    else if (xerr == XERR_LIBXML)
        goto error;
    else
        RESET_XERR(xerr);

    xpath_chroot(xpathCtx, "keyset:sendAuthInfo", 0, &xerr);
    if (xerr == XERR_OK)
    {
        sendAuthInfo->id = xpath_get1(pool, xpathCtx, "keyset:id", 1, &xerr);
        CHK_XERR(xerr, error);
        cdata->type = EPP_SENDAUTHINFO_KEYSET;
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
 * Parametrized parser of commands domainsByNsset, domainsByContact,
 * nssetsByContact and nssetsByNs.
 *
 * @param pool     Pool to allocate memory from.
 * @param xpathCtx Xpath context.
 * @param cdata    Parsed data.
 * @param key      Key used for search (for domain and ns it is name, otherwise
 *                 it is id).
 */
static void
parse_infoKey(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata, const char *key)
{
    epps_info *info;
    int xerr;

    cdata->data = epp_calloc(pool, sizeof(epps_info));
    if (cdata->data == NULL)
    {
        cdata->rc = 2400;
        cdata->type = EPP_DUMMY;
        return;
    }
    info = cdata->data;

    RESET_XERR(xerr); /* clear value of errno */
    info->handle = xpath_get1(pool, xpathCtx, key, 1, &xerr);
    CHK_XERR(xerr, error);
    return;

error:
    cdata->rc = 2400;
    cdata->type = EPP_DUMMY;
}

/**
 * Parser of command test.
 *
 * @param pool Pool to allocate memory from.
 * @param xpathCtx Xpath context.
 * @param cdata Parsed data.
 */
static void parse_test(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
    epps_test *test;
    char *level;
    int xerr;

    cdata->data = epp_calloc(pool, sizeof *test);
    if (cdata->data == NULL)
    {
        cdata->rc = 2400;
        cdata->type = EPP_DUMMY;
        return;
    }
    test = cdata->data;

    RESET_XERR(xerr); /* clear value of errno */
    xpath_chroot(xpathCtx, "nsset:test", 0, &xerr);
    if (xerr == XERR_LIBXML)
    {
        goto error;
    }
    else if (xerr != XERR_OK)
    {
        /* unexpected object type */
        cdata->rc = 2000;
        cdata->type = EPP_DUMMY;
        return;
    }

    test->id = xpath_get1(pool, xpathCtx, "nsset:id", 1, &xerr);
    CHK_XERR(xerr, error);
    xpath_getn(pool, &test->names, xpathCtx, "nsset:name", &xerr);
    CHK_XERR(xerr, error);
    level = xpath_get1(pool, xpathCtx, "nsset:level", 0, &xerr);
    CHK_XERR(xerr, error);
    if (level != NULL)
        test->level = atoi(level);
    else
        test->level = -1;
    cdata->type = EPP_TEST_NSSET;
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
parse_ext_enumval_create(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
    epps_create_domain *create_domain;
    epp_ext_item *ext_item;
    int xerr;
    char *str;

    /* assure we are being called in corect context */
    if (cdata->type != EPP_CREATE_DOMAIN)
    {
        cdata->rc = 2002;
        cdata->type = EPP_DUMMY;
        return;
    }

    if ((ext_item = epp_calloc(pool, sizeof *ext_item)) == NULL)
        goto error;

    create_domain = cdata->data;

    RESET_XERR(xerr); /* clear value of errno */
    ext_item->extType = EPP_EXT_ENUMVAL;
    ext_item->ext.ext_enum.ext_enumval = xpath_get1(pool, xpathCtx, "enumval:valExDate", 0, &xerr);

    CHK_XERR(xerr, error);
    str = xpath_get1(pool, xpathCtx, "enumval:publish", 0, &xerr);

    if (str == NULL)
    {
        ext_item->ext.ext_enum.publish = -1;
    }
    else
    {
        ext_item->ext.ext_enum.publish = parse_boolean(str);
    }

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
parse_ext_enumval_update(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
    epps_update_domain *update_domain;
    epp_ext_item *ext_item;
    int xerr;
    char *str;

    /* assure we are being called in corect context */
    if (cdata->type != EPP_UPDATE_DOMAIN)
    {
        cdata->rc = 2002;
        cdata->type = EPP_DUMMY;
        return;
    }

    if ((ext_item = epp_calloc(pool, sizeof *ext_item)) == NULL)
        goto error;

    update_domain = cdata->data;

    RESET_XERR(xerr); /* clear value of errno */
    ext_item->extType = EPP_EXT_ENUMVAL;
    ext_item->ext.ext_enum.ext_enumval =
            xpath_get1(pool, xpathCtx, "enumval:chg/enumval:valExDate", 0, &xerr);
    CHK_XERR(xerr, error);

    str = xpath_get1(pool, xpathCtx, "enumval:chg/enumval:publish", 0, &xerr);
    if (str == NULL)
    {
        ext_item->ext.ext_enum.publish = -1;
    }
    else
    {
        ext_item->ext.ext_enum.publish = parse_boolean(str);
    }

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
parse_ext_enumval_renew(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
    epps_renew *renew;
    epp_ext_item *ext_item;
    int xerr;
    char *str;

    /* assure we are being called in corect context */
    if (cdata->type != EPP_RENEW_DOMAIN)
    {
        cdata->rc = 2002;
        cdata->type = EPP_DUMMY;
        return;
    }

    if ((ext_item = epp_calloc(pool, sizeof *ext_item)) == NULL)
        goto error;

    renew = cdata->data;

    RESET_XERR(xerr); /* clear value of errno */
    ext_item->extType = EPP_EXT_ENUMVAL;
    ext_item->ext.ext_enum.ext_enumval = xpath_get1(pool, xpathCtx, "enumval:valExDate", 0, &xerr);
    CHK_XERR(xerr, error);

    str = xpath_get1(pool, xpathCtx, "enumval:publish", 0, &xerr);
    if (str == NULL)
    {
        ext_item->ext.ext_enum.publish = -1;
    }
    else
    {
        ext_item->ext.ext_enum.publish = parse_boolean(str);
    }

    if (!q_add(pool, &renew->extensions, ext_item))
    {
        return;
    }
error:
    cdata->rc = 2400;
    cdata->type = EPP_DUMMY;
}

/**
 * Parser of extraaddr extension in context of create contact command.
 *
 * @param pool      Pool for memory allocations.
 * @param xpathCtx  XPath context.
 * @param cdata     Output of parsing stage.
 */
static void
parse_ext_extraaddr_create(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
    epps_create_contact *create_contact = cdata->data;
    int xerr = -1;

    /* assure we are being called in corect context */
    if (cdata->type != EPP_CREATE_CONTACT)
    {
        cdata->rc = 2002;
        cdata->type = EPP_DUMMY;
        return;
    }

    RESET_XERR(xerr);

    epp_ext_item *ext_item = epp_calloc(pool, sizeof *ext_item);
    if (ext_item == NULL)
    {
        goto error;
    }
    ext_item->extType = EPP_EXT_MAILING_ADDR;

    xpath_chroot(xpathCtx, "//extra-addr:create/extra-addr:mailing/extra-addr:addr", 0, &xerr);
    if (xerr == XERR_LIBXML)
    {
        goto error;
    }
    if (xerr != XERR_OK)
    {
        /* unexpected object type or missing node */
        cdata->rc = 2000;
        cdata->type = EPP_DUMMY;
        return;
    }
    ext_item->ext.ext_mailing_addr.command = mailing_addr_set;
    ext_item->ext.ext_mailing_addr.data.set.Street1 =
            xpath_get1(pool, xpathCtx, "extra-addr:street[1]", 0, &xerr);
    CHK_XERR(xerr, error);
    ext_item->ext.ext_mailing_addr.data.set.Street2 =
            xpath_get1(pool, xpathCtx, "extra-addr:street[2]", 0, &xerr);
    CHK_XERR(xerr, error);
    ext_item->ext.ext_mailing_addr.data.set.Street3 =
            xpath_get1(pool, xpathCtx, "extra-addr:street[3]", 0, &xerr);
    CHK_XERR(xerr, error);
    ext_item->ext.ext_mailing_addr.data.set.City =
            xpath_get1(pool, xpathCtx, "extra-addr:city", 0, &xerr);
    CHK_XERR(xerr, error);
    ext_item->ext.ext_mailing_addr.data.set.PostalCode =
            xpath_get1(pool, xpathCtx, "extra-addr:pc", 0, &xerr);
    CHK_XERR(xerr, error);
    ext_item->ext.ext_mailing_addr.data.set.StateOrProvince =
            xpath_get1(pool, xpathCtx, "extra-addr:sp", 0, &xerr);
    CHK_XERR(xerr, error);
    ext_item->ext.ext_mailing_addr.data.set.CountryCode =
            xpath_get1(pool, xpathCtx, "extra-addr:cc", 0, &xerr);
    CHK_XERR(xerr, error);

    if (!q_add(pool, &create_contact->extensions, ext_item))
    {
        return;
    }

error:
    cdata->rc = 2400;
    cdata->type = EPP_DUMMY;
}

/**
 * Parser of extraaddr extension in context of update contact command.
 *
 * @param pool      Pool for memory allocations.
 * @param xpathCtx  XPath context.
 * @param cdata     Output of parsing stage.
 */
static void
parse_ext_extraaddr_update(void *pool, xmlXPathContextPtr xpathCtx, epp_command_data *cdata)
{
    epps_update_contact *update_contact = cdata->data;

    /* assure we are being called in corect context */
    if (cdata->type != EPP_UPDATE_CONTACT)
    {
        cdata->rc = 2002;
        cdata->type = EPP_DUMMY;
        return;
    }

    epp_ext_item *ext_item = epp_calloc(pool, sizeof *ext_item);
    int xerr = -1;
    if (ext_item == NULL)
    {
        goto error;
    }

    RESET_XERR(xerr);

    xpath_chroot(xpathCtx, "//extra-addr:update", 0, &xerr);
    if (xerr == XERR_LIBXML)
    {
        goto error;
    }
    if (xerr != XERR_OK)
    {
        /* unexpected object type or missing node */
        cdata->rc = 2000;
        cdata->type = EPP_DUMMY;
        return;
    }
    CHK_XERR(xerr, error);

    ext_item->extType = EPP_EXT_MAILING_ADDR;
    if (xpath_get1(pool, xpathCtx, "extra-addr:rem/extra-addr:mailing", 0, &xerr) != NULL)
    {
        ext_item->ext.ext_mailing_addr.command = mailing_addr_remove;
    }
    else if (
            xpath_get1(
                    pool,
                    xpathCtx,
                    "extra-addr:set/extra-addr:mailing/extra-addr:addr",
                    0,
                    &xerr) != NULL)
    {
        ext_item->ext.ext_mailing_addr.command = mailing_addr_set;

        xpath_chroot(
                xpathCtx,
                "//extra-addr:update/extra-addr:set/extra-addr:mailing/extra-addr:addr",
                0,
                &xerr);
        if (xerr == XERR_LIBXML)
        {
            goto error;
        }
        if (xerr != XERR_OK)
        {
            /* unexpected object type or missing node */
            cdata->rc = 2000;
            cdata->type = EPP_DUMMY;
            return;
        }
        CHK_XERR(xerr, error);

        ext_item->ext.ext_mailing_addr.data.set.Street1 =
                xpath_get1(pool, xpathCtx, "extra-addr:street[1]", 0, &xerr);
        CHK_XERR(xerr, error);
        ext_item->ext.ext_mailing_addr.data.set.Street2 =
                xpath_get1(pool, xpathCtx, "extra-addr:street[2]", 0, &xerr);
        CHK_XERR(xerr, error);
        ext_item->ext.ext_mailing_addr.data.set.Street3 =
                xpath_get1(pool, xpathCtx, "extra-addr:street[3]", 0, &xerr);
        CHK_XERR(xerr, error);
        ext_item->ext.ext_mailing_addr.data.set.City =
                xpath_get1(pool, xpathCtx, "extra-addr:city", 0, &xerr);
        CHK_XERR(xerr, error);
        ext_item->ext.ext_mailing_addr.data.set.PostalCode =
                xpath_get1(pool, xpathCtx, "extra-addr:pc", 0, &xerr);
        CHK_XERR(xerr, error);
        ext_item->ext.ext_mailing_addr.data.set.StateOrProvince =
                xpath_get1(pool, xpathCtx, "extra-addr:sp", 0, &xerr);
        CHK_XERR(xerr, error);
        ext_item->ext.ext_mailing_addr.data.set.CountryCode =
                xpath_get1(pool, xpathCtx, "extra-addr:cc", 0, &xerr);
        CHK_XERR(xerr, error);
    }
    else
    {
        /* unexpected extraaddr command */
        cdata->rc = 2000;
        cdata->type = EPP_DUMMY;
        return;
    }

    if (!q_add(pool, &update_contact->extensions, ext_item))
    {
        return;
    }
error:
    cdata->rc = 2400;
    cdata->type = EPP_DUMMY;
}


/**
 * Generic parser of EPP command section.
 *
 * From this function are further called dedicated parser handlers for
 * individual commands.
 *
 * @param pool       Memory pool.
 * @param loggedin   True if user is logged in.
 * @param cdata      Command data.
 * @param cmd		 Command type - output parameter
 * @param xpathCtx   XPath context.
 * @return           Status.
 */
static parser_status parse_command(
        void *pool, int loggedin, epp_command_data *cdata, epp_red_command_type *cmd,
        xmlXPathContextPtr xpathCtx)
{
    xmlXPathObjectPtr xpathObj;
    xmlNodePtr node;
    int xerr;
    int i;

    /* backup relative root for later processing of clTRID and extensions */
    node = xpathCtx->node;

    /*
     * command recognition part
     */
    xpathObj = xmlXPathEvalExpression(BAD_CAST "epp:*[position()=1]", xpathCtx);
    if (xpathObj == NULL)
        return PARSER_EINTERNAL;

    assert(xmlXPathNodeSetGetLength(xpathObj->nodesetval) == 1);

    /* command lookup through hash table .. huraaa :) */
    *cmd = cmd_hash_lookup((char *)xmlXPathNodeSetItem(xpathObj->nodesetval, 0)->name);
    /* change relative root to command's node */
    xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, 0);
    xmlXPathFreeObject(xpathObj);

    /*
     * Do validity checking for following cases:
     * 	- the user is not logged in and attempts to issue a command
     * 	- the user is already logged in and issues another login
     */
    if ((*cmd != EPP_RED_LOGIN && !loggedin) || (*cmd == EPP_RED_LOGIN && loggedin))
    {
        cdata->type = EPP_DUMMY;
        cdata->rc = 2002;
        return PARSER_CMD_OTHER;
    }

    switch (*cmd)
    {
        case EPP_RED_LOGIN:
            parse_login(pool, xpathCtx, cdata);
            break;
        case EPP_RED_LOGOUT:
            /*
             * logout is so simple that we don't use dedicated
             * parsing function
             */
            cdata->type = EPP_LOGOUT;
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
    if (cdata->type != EPP_DUMMY)
    {
        /* restore relative root */
        xpathCtx->node = node;

        xpathObj = xmlXPathEvalExpression(BAD_CAST "epp:extension/*", xpathCtx);
        if (xpathObj == NULL)
        {
            return PARSER_EINTERNAL;
        }
        /* iterate through extensions */
        for (i = 0; i < xmlXPathNodeSetGetLength(xpathObj->nodesetval); ++i)
        {
            const xmlNodePtr ext_node = xmlXPathNodeSetItem(xpathObj->nodesetval, i);
            xpathCtx->node = ext_node;
            const char *const ext_ns = (ext_node->ns) ? (char *)ext_node->ns->href : NULL;
            if (ext_ns == NULL)
            {
                continue;
            }
            if (!strcmp(ext_ns, NS_ENUMVAL))
            {
                const char *const ext_name = (char *)ext_node->name;
                if (!strcmp(ext_name, "create"))
                {
                    parse_ext_enumval_create(pool, xpathCtx, cdata);
                }
                else if (!strcmp(ext_name, "update"))
                {
                    parse_ext_enumval_update(pool, xpathCtx, cdata);
                }
                else if (!strcmp(ext_name, "renew"))
                {
                    parse_ext_enumval_renew(pool, xpathCtx, cdata);
                }
                else
                {
                    /* unknown enumval command */
                    cdata->rc = 2000; /* "Unknown command" */
                    cdata->type = EPP_DUMMY;
                    break;
                }
            }
            else if (!strcmp(ext_ns, NS_EXTRAADDR))
            {
                const char *const ext_name = (char *)ext_node->name;

                /* restore relative root */
                xpathCtx->node = node;

                if (!strcmp(ext_name, "create"))
                {
                    parse_ext_extraaddr_create(pool, xpathCtx, cdata);
                }
                else if (!strcmp(ext_name, "update"))
                {
                    parse_ext_extraaddr_update(pool, xpathCtx, cdata);
                }
                else
                {
                    /* unknown extraaddr command */
                    cdata->rc = 2000; /* "Unknown command" */
                    cdata->type = EPP_DUMMY;
                    break;
                }
            }
            else
            {
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
    if (xerr != XERR_OK)
    {
        return PARSER_EINTERNAL;
    }

    /* return code corection */
    switch (cdata->type)
    {
        case EPP_LOGIN:
            return PARSER_CMD_LOGIN;
        case EPP_LOGOUT:
            return PARSER_CMD_LOGOUT;
        default:
            return PARSER_CMD_OTHER;
    }
}

/**
 * Generic parser of EPP extension section.
 *
 * From this function are further called dedicated parser handlers for
 * individual extensions.
 *
 * @param pool       Memory pool.
 * @param cdata      Command data.
 * @param xpathCtx   XPath context.
 * @return           Status.
 */
static parser_status
parse_extension(void *pool, epp_command_data *cdata, xmlXPathContextPtr xpathCtx)
{
    xmlNodePtr node;
    int xerr, matched;
    const char *elemname;

    RESET_XERR(xerr); /* clear value of errno */
    xpath_chroot(xpathCtx, "fred:extcommand", 0, &xerr);
    if (xerr == XERR_LIBXML)
    {
        return PARSER_EINTERNAL;
    }
    else if (xerr == XERR_CONSTR)
    {
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
    if (xerr == XERR_LIBXML)
    {
        return PARSER_EINTERNAL;
    }
    assert(xerr == XERR_OK);

    elemname = (char *)xpathCtx->node->name;
    matched = 0;

    switch (elemname[0])
    {
        case 's':
            /* It is sendAuthInfo */
            if (!strcmp(elemname, "sendAuthInfo"))
            {
                matched = 1;
                parse_sendAuthInfo(pool, xpathCtx, cdata);
            }
            break;
        case 't':
            /* It is test */
            if (!strcmp(elemname, "test"))
            {
                matched = 1;
                parse_test(pool, xpathCtx, cdata);
            }
            break;
        case 'c':
            /* It is cashInfo */
            if (!strcmp(elemname, "creditInfo"))
            {
                matched = 1;
                cdata->data = epp_calloc(pool, sizeof(epps_creditInfo));
                if (cdata->data == NULL)
                {
                    cdata->rc = 2400;
                    cdata->type = EPP_DUMMY;
                    return PARSER_CMD_OTHER;
                }
                cdata->type = EPP_CREDITINFO;
            }
            break;
        case 'l':
        {

            /* It is listDomains,listContacts,listNssets,listKeysets */
            if (!strcmp(elemname, "listDomains"))
            {
                cdata->type = EPP_INFO_LIST_DOMAINS;
                matched = 1;
            }
            else if (!strcmp(elemname, "listContacts"))
            {
                cdata->type = EPP_INFO_LIST_CONTACTS;
                matched = 1;
            }
            else if (!strcmp(elemname, "listNssets"))
            {
                cdata->type = EPP_INFO_LIST_NSSETS;
                matched = 1;
            }
            else if (!strcmp(elemname, "listKeysets"))
            {
                cdata->type = EPP_INFO_LIST_KEYSETS;
                matched = 1;
            }


            /* allocate I/O structure if matched */
            if (matched)
            {
                cdata->data = epp_calloc(pool, sizeof(epps_info));
                if (cdata->data == NULL)
                {
                    cdata->rc = 2400;
                    cdata->type = EPP_DUMMY;
                    return PARSER_CMD_OTHER;
                }
            }
            break;
        }
        case 'd':
        {
            if (!strcmp(elemname, "domainsByNsset"))
            {
                matched = 1;
                cdata->type = EPP_INFO_DOMAINS_BY_NSSET;
                parse_infoKey(pool, xpathCtx, cdata, "fred:id");
            }
            if (!strcmp(elemname, "domainsByContact"))
            {
                matched = 1;
                cdata->type = EPP_INFO_DOMAINS_BY_CONTACT;
                parse_infoKey(pool, xpathCtx, cdata, "fred:id");
            }
            if (!strcmp(elemname, "domainsByKeyset"))
            {
                matched = 1;
                cdata->type = EPP_INFO_DOMAINS_BY_KEYSET;
                parse_infoKey(pool, xpathCtx, cdata, "fred:id");
            }
            break;
        }
        case 'n':
        {
            if (!strcmp(elemname, "nssetsByContact"))
            {
                matched = 1;
                cdata->type = EPP_INFO_NSSETS_BY_CONTACT;
                parse_infoKey(pool, xpathCtx, cdata, "fred:id");
            }
            if (!strcmp(elemname, "nssetsByNs"))
            {
                matched = 1;
                cdata->type = EPP_INFO_NSSETS_BY_NS;
                parse_infoKey(pool, xpathCtx, cdata, "fred:name");
            }
            break;
        }
        case 'g':
        {
            if (!strcmp(elemname, "getResults"))
            {
                matched = 1;
                cdata->type = EPP_INFO_GET_RESULTS;
                cdata->data = epp_calloc(pool, sizeof(epps_list));
                if (cdata->data == NULL)
                {
                    cdata->rc = 2400;
                    cdata->type = EPP_DUMMY;
                    return PARSER_CMD_OTHER;
                }
            }
            break;
        }
        case 'k':
        {
            if (!strcmp(elemname, "keysetsByContact"))
            {
                matched = 1;
                cdata->type = EPP_INFO_KEYSETS_BY_CONTACT;
                parse_infoKey(pool, xpathCtx, cdata, "fred:id");
            }
            break;
        }
        default:
            break;
    }
    if (!matched)
    {
        cdata->rc = 2000; /* "Unknown command" */
        cdata->type = EPP_DUMMY;
    }

    /* restore relative root */
    xpathCtx->node = node;

    cdata->clTRID = xpath_get1(pool, xpathCtx, "fred:clTRID", 0, &xerr);
    if (xerr != XERR_OK)
    {
        return PARSER_EINTERNAL;
    }

    return PARSER_CMD_OTHER;
}

parser_status epp_parse_command(
        epp_context *epp_ctx, int loggedin, void *schema, const char *request, unsigned bytes,
        epp_command_data **cdata_arg, const eppd_server_xml_conf *xml_schema, epp_red_command_type *cmd_type)
{
    xmlXPathContextPtr xpathCtx;
    xmlXPathObjectPtr xpathObj;
    xmlChar *dumpedXML;
    int dumpLength;
    valid_status val_ret;

    const char *elemname;

    /* check input parameters */
    assert(epp_ctx != NULL);
    assert(request != NULL);
    assert(bytes != 0);
    assert(cdata_arg != NULL);
    assert(xml_schema != NULL);

    /* allocate cdata structure */
    *cdata_arg = (epp_command_data*)epp_calloc(epp_ctx->pool, sizeof **cdata_arg);
    if (*cdata_arg == NULL)
    {
        return PARSER_EINTERNAL;
    }
    epp_command_data* const cdata = *cdata_arg;
    cdata->xml_schema = *xml_schema;
    /* ... from now the management of cdata structure and all its items
     * is done at higher level -> we don't have to care about release
     * of resources which are part of cdata. */

    /* parse xml request */
    cdata->parsed_doc = xmlParseMemory(request, bytes);
    if (cdata->parsed_doc == NULL)
    {
        return PARSER_NOT_XML;
    }
    /* Save input xml document */
    xmlDocDumpMemoryEnc(cdata->parsed_doc, &dumpedXML, &dumpLength, XML_IN_ENC);
    if (dumpedXML == NULL || dumpLength <= 0)
    {
        return PARSER_EINTERNAL;
    }
    /*
     * we cannot use strdup since it is not sure the request is NULL
     * terminated
     */
    cdata->xml_in = epp_malloc(epp_ctx->pool, dumpLength + 1);
    if (cdata->xml_in == NULL)
    {
        return PARSER_EINTERNAL;
    }
    memcpy(cdata->xml_in, dumpedXML, dumpLength);
    cdata->xml_in[dumpLength] = '\0';
    xmlFree(dumpedXML);

    xml_in_out_log(epp_ctx,
           "Request content dumped in %s encoding:" APR_EOL_STR "%s",
           XML_IN_ENC,
           cdata->xml_in);

    /* validate the doc */
    val_ret = validate_doc(
            epp_ctx->pool, (xmlSchemaPtr)schema, (xmlDocPtr)cdata->parsed_doc, &cdata->errors);

    if (val_ret == VAL_ESCHEMA || val_ret == VAL_EINTERNAL)
    {
        return (val_ret == VAL_ESCHEMA) ? PARSER_ESCHEMA : PARSER_EINTERNAL;
    }
    if (val_ret == VAL_NOT_VALID)
    {
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
    cdata->xpath_ctx = xpathCtx = xmlXPathNewContext((xmlDocPtr)cdata->parsed_doc);
    if (cdata->xpath_ctx == NULL)
    {
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
        xmlXPathRegisterNs(xpathCtx, BAD_CAST "keyset", BAD_CAST NS_KEYSET) ||
        xmlXPathRegisterNs(xpathCtx, BAD_CAST "fred", BAD_CAST NS_FRED) ||
#ifdef SECDNS_ENABLE
#error "It is a terible error to enable SECDNS before code correction!"
        xmlXPathRegisterNs(xpathCtx, BAD_CAST "secdns", BAD_CAST NS_SECDNS) ||
#endif
        xmlXPathRegisterNs(xpathCtx, BAD_CAST "enumval", BAD_CAST NS_ENUMVAL) ||
        xmlXPathRegisterNs(xpathCtx, BAD_CAST "extra-addr", BAD_CAST NS_EXTRAADDR))
    {
        return PARSER_EINTERNAL;
    }

    xpathObj = xmlXPathEvalExpression(BAD_CAST "/epp:epp/epp:*", xpathCtx);
    if (xpathObj == NULL)
    {
        return PARSER_EINTERNAL;
    }
    assert(xmlXPathNodeSetGetLength(xpathObj->nodesetval) == 1);
    xpathCtx->node = xmlXPathNodeSetItem(xpathObj->nodesetval, 0);
    xmlXPathFreeObject(xpathObj);
    elemname = (char *)xpathCtx->node->name;

    if (strcmp(elemname, "hello") == 0)
    {
        return PARSER_HELLO;
    }
    if (strcmp(elemname, "command") == 0)
    {
        return parse_command(epp_ctx->pool, loggedin, cdata, cmd_type, xpathCtx);
    }
    if (strcmp(elemname, "extension") == 0)
    {
        *cmd_type = EPP_RED_EXTCMD;
        if (!loggedin)
        {
            cdata->type = EPP_DUMMY;
            cdata->rc = 2002;
            return PARSER_CMD_OTHER;
        }
        return parse_extension(epp_ctx->pool, cdata, xpathCtx);
    }
    return PARSER_NOT_COMMAND;
}

/* vim: set ts=8 sw=8: */
