/*
 * Copyright (C) 2010-2018  CZ.NIC, z. s. p. o.
 *
 * This file is part of FRED.
 *
 * FRED is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * FRED is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRED.  If not, see <https://www.gnu.org/licenses/>.
 */
#include "epp-client.h"
#include "epp_common.h"
#include "epp_parser.h"

typedef struct epp_log_operation_result
{
    int success;
} epp_log_operation_result;


epp_log_operation_result log_epp_response(
        epp_context *epp_ctx, service_Logger *log_service, qhead *valerr, const char *response,
        const epp_command_data *cdata, ccReg_TID session_id, ccReg_TID log_entry_id);

ccReg_TID log_epp_command(
        epp_context *epp_ctx, service_Logger *service, char *remote_ip, char *request,
        epp_command_data *cdata, epp_red_command_type cmdtype, ccReg_TID sessionid);


int epp_log_CreateSession(
        epp_context *epp_ctx, service_Logger service, const char *user_name, ccReg_TID user_id,
        ccReg_TID *const log_session_id, char *errmsg);

int epp_log_CloseSession(
        epp_context *epp_ctx, service_Logger service, ccReg_TID log_session_id, char *errmsg);
