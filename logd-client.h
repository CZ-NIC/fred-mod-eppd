
#include "epp_common.h"
#include "epp-client.h"
#include "epp_parser.h"


#define LOG_INTERNAL_ERROR   0
#define LOG_SUCCESS 1

/* logd-client.c */


int log_epp_response(epp_context *epp_ctx, service_Logger *log_service, qhead *valerr, const char *response, const epp_command_data *cdata,  ccReg_TID session_id, ccReg_TID log_entry_id);

ccReg_TID log_epp_command(epp_context *epp_ctx, service_Logger *service, char *remote_ip, char *request, epp_command_data *cdata, epp_red_command_type cmdtype, ccReg_TID sessionid);


int epp_log_CreateSession(epp_context *epp_ctx, service_Logger service, const char *user_name, ccReg_TID user_id, ccReg_TID * const log_session_id, char *errmsg);
int epp_log_CloseSession(epp_context *epp_ctx, service_Logger service, ccReg_TID log_session_id, char *errmsg);

