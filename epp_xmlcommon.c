/*
 * Copyright statement
 */

#include <string.h>
#include <assert.h>

#include <libxml/tree.h>
#include <libxml/xmlerror.h>
#include <libxml/xmlschemas.h>

#include "epp_common.h"
#include "epp_xmlcommon.h"

/**
 * This struct gathers context parameters to validator error handler
 */
typedef struct {
	struct circ_list	*err_list;
	xmlDocPtr	doc;
}valerr_ctx;

/**
 * This is a callback for xml validator errors. Purpose is to cumulate
 * all encountered errors in a list, which is further processed after
 * the validation is done.
 */
static void
validerr_callback(void *ctx, xmlErrorPtr error)
{
	struct circ_list	*new_item;
	epp_error	*valerr;
	xmlNodePtr	node;
	int	len;
	xmlBufferPtr	buf;
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
	 * XXX error code must be further examined in order to get
	 * more detailed error
	 * valerr->code = error->code;
	 */
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
	valerr->standalone = 1;

	CL_CONTENT(new_item) = (void *) valerr;
	CL_ADD(error_list, new_item);
}

valid_status
validate_doc(const char *url_schema, xmlDocPtr doc, struct circ_list *err_list)
{
	xmlSchemaParserCtxtPtr	spctx;	/* schema parser context */
	xmlSchemaValidCtxtPtr	svctx;	/* schema validator context */
	xmlSchemaPtr	schema; /* schema against which are validated requests */
	valerr_ctx	ctx;
	int	rc;

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

