/**
 * EPP parser is in fact translator. Input is unparsed string from mod_eppd
 * and outputs are function calls to corba client, who performs actual CORBA
 * function calls. This header file specifies interface between mod_eppd and
 * epp parser.
 */

#ifndef EPP_PARSER_H
#define EPP_PARSER_H

/**
 * EPP status values (part of mod_eppd - xml_epp interface).
 */
typedef enum {
	EPP_DEFAULT_STAT,
	EPP_CLOSE_CONN
} epp_status_t;

/**
 * This structure gathers output parameters of epp_parser_process_request.
 * eppd_mod takes case of structure as such and parser takes manages the items
 * inside the struct
 */
typedef struct {
	char *response;
	char *err;
	char *info;
	epp_status_t status;
} epp_parser_parms_out;

/**
 * This creates and returns context of epp connection, which is used
 * when handling subsequent requests.
 * @ret Connection context
 */
void *epp_parser_init(void);

/**
 * Parses request and gets response.
 * @par	Connection context
 * @par Request to be processed
 * @par Response ready to be sent
 * @par Error message to be written in apache log
 * @ret Status
 */
void epp_parser_process_request(
		void *conn_ctx,
		char *request,
		epp_parser_parms_out *parms_out);

/**
 * Since mod_eppd doesn't know anything about connection context structure,
 * at the end of connection is called this routine, to do necessary cleanup.
 * @par Connection context
 */
void epp_parser_cleanup_ctx(void *conn_ctx);

/**
 * epp_parser_parms_out is allocated by mod_eppd but management of items inside
 * the structure is task of parser. This routine cleans up the struct.
 * @par retval Structure to clean up
 */
void epp_parser_cleanup_parms_out(epp_parser_parms_out *parms_out);

#endif /* EPP_PARSER_H */

/* vi:set ts=4 sw=4: */
