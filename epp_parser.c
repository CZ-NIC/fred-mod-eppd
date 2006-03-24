/*
 * Copyright statement
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

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

	if ((ctx = malloc(sizeof (*ctx))) == NULL) return NULL;
	ctx->user = NULL;
	return (void *) ctx;
}

void epp_parser_cleanup_ctx(void *conn_ctx)
{
	epp_connection_ctx *ctx = (epp_connection_ctx *) conn_ctx;

	free(ctx);
}

void epp_parser_cleanup_parms_out(epp_parser_parms_out *parms_out)
{
	if (parms_out->response) free(parms_out->response);
	if (parms_out->err) free(parms_out->err);
	if (parms_out->info) free(parms_out->info);
}

void epp_parser_process_request(
		void *conn_ctx,
		char *request,
		epp_parser_parms_out *parms_out)
{
	epp_connection_ctx *ctx = (epp_connection_ctx *) conn_ctx;
	parms_out->response = NULL;
	parms_out->err = NULL;
	parms_out->status = EPP_DEFAULT_STAT;


	assert(request != NULL);

	parms_out->err = strdup("Request is empty, nothing to be done");

	/* parse request */

	/* return errors from parser if any */

	/* validate request */

	/* return errors from validator if any */

	/* select and invoke command handler */

	/* return struct parms_out as it is to mod_eppd */

}
