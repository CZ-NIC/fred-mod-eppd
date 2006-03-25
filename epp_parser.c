/*
 * Copyright statement
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>

#include "epp_parser.h"

/**
 * epp connection context struct used to store information associated
 * with connection between subsequent calls to request parser.
 */
typedef struct {
	char *user;
} epp_connection_ctx;

void *epp_parser_init(void)
{
	epp_connection_ctx *ctx;

	xmlInitParser();

	if ((ctx = malloc(sizeof (*ctx))) == NULL) return NULL;
	ctx->user = NULL;
	return (void *) ctx;
}

void epp_parser_cleanup(void *conn_ctx)
{
	xmlCleanupParser();

	epp_connection_ctx *ctx = (epp_connection_ctx *) conn_ctx;

	free(ctx);
}

void epp_parser_cleanup_parms_out(epp_parser_parms_out *parms_out)
{
	if (parms_out->response) free(parms_out->response);
	if (parms_out->err) free(parms_out->err);
	if (parms_out->info) free(parms_out->info);
}

static void log(epp_parser_parms_out *parms, epp_parser_loglevel severity,
		const char *msg)
{
	epp_parser_log *temp;

	/* is it first log in chain? */
	if (parms->head == NULL) {
		parms->head = malloc(sizeof *(parms->head));
		if (parms->head == NULL) return;
		parms->head->next = NULL;
		parms->head->severity = severity;
		parms->head->msg = strndup(msg, 300);
		parms->last = parms->head;
		return;
	}

	assert(last->next == NULL);

	temp = parms->last;
	parms->last = malloc(sizeof *(parms->last));
	if (parms->last == NULL) return;
	parms->last->next = NULL;
	parms->last->severity = severity;
	parms->last->msg = strndup(msg, 300);
	parms->temp->next = parms->last;
}

void epp_parser_process_request(void *conn_ctx, char *request,
		epp_parser_parms_out *parms_out)
{
	/* XML stuff */
	xmlDocPtr	doc;
	/* session stuff */
	epp_connection_ctx *ctx = (epp_connection_ctx *) conn_ctx;

	assert(request != NULL);

	/* parse request */
	doc = xmlParseMemory(request, strlen(request));
	if (doc == NULL) {
		log(parms_out, EPP_LOG_ERROR, "Request is not valid XML");
		return;
	}

	/* return errors from parser if any */

	/* validate request */

	/* return errors from validator if any */

	/* select and invoke command handler */

	xmlFreeDoc(doc);
	xmlMemoryDump();

	/* pass struct parms_out as it is to mod_eppd */
}
