
#include "epp_common.h"
#include "epp-client.h"
#include "epp_parser.h"


#define LOG_REQ_NOT_SAVED   0

/* logd-client.c */


int log_epp_response(service_Logger *log_service, int stat, qhead *valerr, const char *response,
        const epp_command_data *cdata,  int session_id, ccReg_TID log_entry_id);

ccReg_TID log_epp_command(service_Logger *service, char *remote_ip, char *request, epp_command_data *cdata, epp_red_command_type cmdtype, int sessionid);

