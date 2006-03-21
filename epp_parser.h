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
	EPP_CLOSE_CONN
} epp_status_t;

/**
 * This creates and returns context of epp connection, which is used
 * when handling subsequent requests.
 * @ret Connection context
 */
epp_conn_ctx *epp_parser_init(void);

/**
 * Parses request and gets response.
 * @par	Connection context
 * @par Request to be processed
 * @par Response ready to be sent
 * @ret Status
 */
epp_status_t epp_parser_process_request(void *conn_ctx, char *request, char *response);

/**
 * Since mod_eppd doesn't know anything about connection context structure,
 * at the end of connection is called this routine, to do necessary cleanup.
 * @par Connection context
 */
void epp_parser_cleanup(void *conn_ctx);

#endif /* EPP_PARSER_H */
