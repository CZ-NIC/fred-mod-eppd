/*
 * Copyright (C) 2018  CZ.NIC, z. s. p. o.
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
#ifndef MOD_EPPD_H_7115510E8D7B41C572B1134BE7BB0E23//date "+%s"|md5sum|tr "[a-f]" "[A-F]"
#define MOD_EPPD_H_7115510E8D7B41C572B1134BE7BB0E23

#include "epp_common.h"

#include <http_core.h>
#include <apr_file_io.h>

/**
 * Configuration structure of eppd module.
 */
typedef struct
{
    int epp_enabled; /**< Decides whether mod_eppd is enabled for host.*/
    const char *servername; /**< Epp server name used in <greeting> frame. */
    const char *ns_loc; /**< Location of CORBA nameservice. */
    char *object; /**< Name under which the object is known. */
    const char *logger_object; /**< Name of fred-logd object */
    int logd_mandatory; /**< Whether fred-logd failure is fatal to EPP */
    void *schema; /**< URL of EPP schema (use just path). */
    int valid_resp; /**< Validate response before sending it to client.*/
    const char *epplog; /**< Epp log filename. */
    apr_file_t *epplogfp; /**< File descriptor of epp log file. */
    epp_loglevel loglevel; /**< Epp log level. */
    const char *xml_in_out_log_filename; /**< XML in/out log filename. */
    apr_file_t *xml_in_out_log_file; /**< File handle of XML in/out log file. */
    int defer_err; /**< Time value for deferring error response. */
    eppd_server_xml_conf xml_schema; /**< Entities enabled in xml schemas. */
} eppd_server_conf;

/**
 * eppd_module declaration.
 */
extern module AP_MODULE_DECLARE_DATA eppd_module;

#endif//MOD_EPPD_H_7115510E8D7B41C572B1134BE7BB0E23
