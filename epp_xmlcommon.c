/*
 * @file epp_xmlcommon.c
 *
 * This file gathers definitions of functions used by both libxml components
 * (parser and generator). Currently the components share only routine for
 * xml document validation.
 */

#include <string.h>
#include <assert.h>

#include <libxml/tree.h>
#include <libxml/xmlerror.h>
#include <libxml/xmlschemas.h>

#include "epp_common.h"
#include "epp_xmlcommon.h"

/**
 * This struct gathers context parameters used by error handler of libxml's
 * validator.
 */
typedef struct {
	struct circ_list	*err_list;	/**< List of encountered errors. */
	xmlDocPtr	doc;	/**< XML document. */
}valerr_ctx;

/**
 * This is a callback for validator errors. Purpose is to cumulate
 * all encountered errors in a list, which is further processed after
 * the validation is done.
 *
 * @param ctx Hook's context pointer.
 * @param error Specification of encountered error.
 */
static void
validerr_callback(void *ctx, xmlErrorPtr error)
{
	/* used to get content of problematic xml tag */
	xmlNodePtr	node;
	xmlBufferPtr	buf;
	int	len;
	/* used for new list item creation */
	struct circ_list	*new_item;
	epp_error	*valerr;
	/* get context parameters */
	struct circ_list	*error_list = ((valerr_ctx *) ctx)->err_list;
	xmlDocPtr	doc = ((valerr_ctx *) ctx)->doc;

	/* in case of allocation failure simply don't log the error and exit */
	if ((valerr = malloc(sizeof *valerr)) == NULL) return;
	if ((new_item = malloc(sizeof *new_item)) == NULL) {
		free(valerr);
		return;
	}

	/*
	 * xmlError has quite a lot of fields, we are interested only in 3
	 * of them: code, message, node.
	 */

	/*
	 * XXX error code should be further examined in order to get
	 * more detailed error
	 * valerr->code = error->code;
	 */

	/* get error message */
	len = strlen(error->message);
	if ((valerr->reason = malloc(len)) == NULL) {
		free(valerr);
		free(new_item);
		return;
	}
	strncpy(valerr->reason, error->message, --len); /* truncate trailing \n */
	(valerr->reason)[len] = '\0';
	node = (xmlNodePtr) error->node;
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
		valerr->value = strdup("unknown");
	else {
		if (xmlNodeDump(buf, doc, node, 0, 0) < 0)
			valerr->value = strdup("unknown");
		else {
			valerr->value = strdup((char *) buf->content);
		}
		xmlBufferFree(buf);
	}
	valerr->standalone = 1;	/* the surrounding tag is included */

	/* enqueue new error item */
	CL_CONTENT(new_item) = (void *) valerr;
	CL_ADD(error_list, new_item);
}

valid_status
validate_doc(const char *url_schema, xmlDocPtr doc, struct circ_list *err_list)
{
	xmlSchemaParserCtxtPtr	spctx;	/* schema parser context */
	xmlSchemaValidCtxtPtr	svctx;	/* schema validator context */
	xmlSchemaPtr	schema; /* schema against which are validated requests */
	valerr_ctx	ctx;	/* context used for validator's error hook */
	int	rc;	/* return code from xmllib's validator */

	/* parse epp schema */
	spctx = xmlSchemaNewParserCtxt(url_schema);
	if (spctx == NULL) return VAL_EINTERNAL;
	schema = xmlSchemaParse(spctx);
	xmlSchemaFreeParserCtxt(spctx);
	/* schemas might be corrupted though it is unlikely */
	if (schema == NULL) return VAL_ESCHEMA;

	svctx = xmlSchemaNewValidCtxt(schema);
	if (svctx == NULL) {
		xmlSchemaFree(schema);
		return VAL_EINTERNAL;
	}
	/* initialize error hook's context */
	ctx.err_list = err_list;
	ctx.doc = doc;
	xmlSchemaSetValidStructuredErrors(svctx, validerr_callback, &ctx);
	/* validate request against schema */
	rc = xmlSchemaValidateDoc(svctx, doc);
	if (rc < 0) {	/* -1 is validator's internal error */
		xmlSchemaFreeValidCtxt(svctx);
		xmlSchemaFree(schema);
		return VAL_EINTERNAL;
	}
	if (rc > 0) {	/* the doc does not validate */
		xmlSchemaFreeValidCtxt(svctx);
		xmlSchemaFree(schema);
		return VAL_NOT_VALID;
	}
	xmlSchemaFreeValidCtxt(svctx);
	xmlSchemaFree(schema);

	assert(CL_EMPTY(err_list));
	return VAL_OK;
}

