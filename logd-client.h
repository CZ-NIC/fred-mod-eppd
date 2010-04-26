
#include "epp_common.h"
#include "epp-client.h"
#include "epp_parser.h"


#define LOG_REQ_NOT_SAVED   0

/* logd-client.c */


int log_epp_response(service_Logger *log_service, qhead *valerr, const char *response,
        const epp_command_data *cdata,  ccReg_TID session_id, ccReg_TID log_entry_id);

ccReg_TID log_epp_command(service_Logger *service, char *remote_ip, char *request, epp_command_data *cdata, epp_red_command_type cmdtype, ccReg_TID sessionid);

int epp_log_CreateSession(service_Logger service, const char *name, epp_lang lang, ccReg_TID * const log_session_id, char *errmsg);
int epp_log_CloseSession(service_Logger service, ccReg_TID log_session_id, char *errmsg);
