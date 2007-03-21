/*
 * @file epp_xmlcommon.c
 *
 * This file gathers definitions of functions used by both libxml components
 * (parser and generator).
 *
 * Currently the components share only routine for xml document validation.
 */

#include <string.h>
#include <assert.h>

#include <libxml/tree.h>
#include <libxml/xmlerror.h>
#include <libxml/xmlschemas.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include "epp_common.h"
#include "epp_xmlcommon.h"

/**
 * This struct gathers context parameters used by error handler of libxml's
 * validator.
 */
typedef struct {
	void	*pool;      /**< Pool to allocate memory from. */
	qhead	*err_list;  /**< List of encountered errors. */
	xmlDocPtr doc;      /**< XML document. */
}valerr_ctx;

/**
 * This is a callback for validator errors.
 *
 * Purpose is to cumulate all encountered errors in a list, which is further
 * processed after the validation is done. If any malloc inside this routine
 * fails, the error is silently dropped and is not queued in the list of
 * errors. That makes algorithm a bit less complicated.
 *
 * @param ctx     Hook's context pointer.
 * @param error   Specification of encountered error.
 */
static void
validerr_callback(void *ctx, xmlErrorPtr error)
{
	/* used to get content of problematic xml tag */
	xmlBufferPtr	buf;
	int	len;
	/* used for new list item creation */
	epp_error	*valerr;
	/* get context parameters */
	qhead	*error_list = ((valerr_ctx *) ctx)->err_list;
	xmlDocPtr	doc = ((valerr_ctx *) ctx)->doc;
	void	*pool = ((valerr_ctx *) ctx)->pool;

	/* in case of allocation failure simply don't log the error and exit */
	if ((valerr = epp_malloc(pool, sizeof *valerr)) == NULL) return;

	/*
	 * xmlError has quite a lot of fields, we are interested only in 3
	 * of them: code, message, node.
	 */

	/*
	 * XXX error code should be further examined in order to get
	 * more detailed error
	 * valerr->code = error->code;
	 */

	/*
	 * get error message (we don't use strdup because we have to
	 * truncate trailing newline)
	 */
	len = strlen(error->message);
	valerr->reason = (char *) epp_malloc(pool, len);
	if (valerr->reason == NULL)
		return;
	strncpy(valerr->reason, error->message, --len); /*truncate trailing \n */
	(valerr->reason)[len] = '\0';

	/* XXX this needs to be done better way */
	/*
	 * recognized errors:
	 *    unknown command (2000)
	 *    required parameter missing (2003)
	 *    Parameter value range error (2004)
	 *    Parameter value syntax error (2005)
	 *    Unimplemented extension (2103)
	 *    ???Unimplemented command (2101)???
	 *    ???Unimplemented option (2102)???
	 * all other errors are reported as:
	 *    command syntax error (2001)
	 */

	/* get content of problematic tag */
	buf = xmlBufferCreate();
	if (buf == NULL)
		return;
	if (xmlNodeDump(buf, doc, (xmlNodePtr) error->node, 0, 0) < 0) {
		xmlBufferFree(buf);
		return;
	}
	valerr->value = epp_strdup(pool, (char *) buf->content);
	xmlBufferFree(buf);
	if (valerr->value == NULL)
		return;
	valerr->spec = errspec_not_valid; /* surrounding tags are included */

	/* enqueue new error item */
	q_add(pool, error_list, valerr);
}

valid_status
validate_doc(void *pool, xmlSchemaPtr schema, xmlDocPtr doc, qhead *err_list)
{
	xmlSchemaValidCtxtPtr	svctx; /* schema validator context */
	valerr_ctx	ctx;    /* context used for validator's error hook */
	int	rc;             /* return code from xmllib's validator */

	svctx = xmlSchemaNewValidCtxt(schema);
	if (svctx == NULL) {
		return VAL_EINTERNAL;
	}
	/* initialize error hook's context */
	ctx.err_list = err_list;
	ctx.doc      = doc;
	ctx.pool     = pool;
	xmlSchemaSetValidStructuredErrors(svctx, validerr_callback, &ctx);
	/* validate request against schema */
	rc = xmlSchemaValidateDoc(svctx, doc);
	if (rc < 0) {	/* -1 is validator's internal error */
		xmlSchemaFreeValidCtxt(svctx);
		return VAL_EINTERNAL;
	}
	if (rc > 0) {	/* the doc does not validate */
		xmlSchemaFreeValidCtxt(svctx);
		return VAL_NOT_VALID;
	}
	xmlSchemaFreeValidCtxt(svctx);

	return VAL_OK;
}

char *
epp_getSubtree(void *pool,
		epp_command_data *cdata,
		const char *xpath_expr,
		int position)
{
	char	*subtree;
	xmlBufferPtr	 buf;
	xmlDocPtr	 doc;
	xmlXPathObjectPtr	 xpath_obj;
	xmlXPathContextPtr	 xpath_ctx;

	doc = (xmlDocPtr) cdata->parsed_doc;
	xpath_ctx = (xmlXPathContextPtr) cdata->xpath_ctx;

	xpath_obj = xmlXPathEvalExpression(BAD_CAST xpath_expr, xpath_ctx);
	if (xpath_obj == NULL)
		return NULL;
	/* correct position for non-list elements */
	if (position == 0) position++;
	if (xmlXPathNodeSetGetLength(xpath_obj->nodesetval) < position) {
		xmlXPathFreeObject(xpath_obj);
		/* return empty string if the node is not there */
		return epp_strdup(pool, "");
	}

	/* get content of problematic tag */
	buf = xmlBufferCreate();
	if (buf == NULL)
		return NULL;
	if (xmlNodeDump(buf, doc, xmlXPathNodeSetItem(xpath_obj->nodesetval,
					position - 1),
				0, 0) < 0)
	{
		xmlXPathFreeObject(xpath_obj);
		xmlBufferFree(buf);
		return NULL;
	}
	subtree = epp_strdup(pool, (char *) buf->content);
	xmlXPathFreeObject(xpath_obj);
	xmlBufferFree(buf);
	return subtree;
}

/* vim: set ts=8 sw=8: */
