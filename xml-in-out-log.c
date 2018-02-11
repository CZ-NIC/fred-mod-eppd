/*
 * Copyright (C) 2018  CZ.NIC, z.s.p.o.
 *
 * This file is part of FRED.
 *
 * FRED is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 *
 * FRED is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRED.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "xml-in-out-log.h"
#include "xml-in-out-log-details.h"
#include "mod_eppd.h"

#include <http_core.h>
#include <http_config.h>
#include <http_log.h>
#include <apr_strings.h>
#include <apr_time.h>
#include <apr_file_io.h>
#include <apr_global_mutex.h>

#include <stdarg.h>
#include <unistd.h>

void xml_in_out_log(epp_context *epp_ctx, const char *fmt, ...)
{
    if (epp_ctx == NULL)
    {
        return;
    }
    conn_rec *const conn = epp_ctx->conn;
    if (conn == NULL)
    {
        return;
    }
    eppd_server_conf *const sc = (eppd_server_conf *)ap_get_module_config(conn->base_server->module_config, &eppd_module);
    if ((sc == NULL) ||
        (sc->xml_in_out_log_file == NULL))
    {
        return;
    }

    apr_pool_t *const pool = epp_ctx->pool;

    va_list ap;
    va_start(ap, fmt);
    const char *const text = apr_pvsprintf(pool, fmt, ap);
    va_end(ap);

    /* get remote host's ip address - is not critical if it is not known */
    const char *const rhost = ap_get_remote_host(conn, NULL, REMOTE_NOLOOKUP, NULL);

    /* get timestamp */
    apr_time_exp_t t;
    apr_time_exp_lt(&t, apr_time_now());
    const char *const timefmt = apr_psprintf(pool, "[%%Y/%%m/%%d %%H:%%M:%%S.%06d %%z]", t.tm_usec);
    apr_size_t len;
    char timestr[80];
    apr_strftime(timestr, &len, sizeof(timestr), timefmt, &t);

    /* make up the whole log record */
    const char *const logline = apr_psprintf(
            pool,
            "%s %s (process:%" APR_PID_T_FMT ") "
            "[sessionID %d] %s" APR_EOL_STR,
            timestr,
            rhost != NULL ? rhost : "UNKNOWN-HOST",
            getpid(),
            epp_ctx->session,
            text);

    apr_status_t rv = apr_global_mutex_lock(xml_in_out_log_mutex);
    if (rv != APR_SUCCESS)
    {
        ap_log_cerror(
                APLOG_MARK, APLOG_ERR, rv, conn, "apr_global_mutex_lock(xml_in_out_log_mutex) failed");
    }

    const apr_size_t nbytes = strlen(logline);
    apr_size_t wbytes = nbytes;
    rv = apr_file_write(sc->xml_in_out_log_file, logline, &wbytes);
    if (rv != APR_SUCCESS)
    {
        ap_log_cerror(
                APLOG_MARK, APLOG_ERR, rv, conn, "apr_file_write() failed");
    }
    else if (wbytes != nbytes)
    {
        ap_log_cerror(
                APLOG_MARK,
                APLOG_NOTICE,
                rv,
                conn,
                "apr_file_write() wrote %" APR_SIZE_T_FMT " bytes "
                "instead of %" APR_SIZE_T_FMT, wbytes, nbytes);
    }

    rv = apr_global_mutex_unlock(xml_in_out_log_mutex);
    if (rv != APR_SUCCESS)
    {
        ap_log_cerror(
                APLOG_MARK, APLOG_ERR, rv, conn, "apr_global_mutex_unlock(xml_in_out_log_mutex) failed");
    }
}
