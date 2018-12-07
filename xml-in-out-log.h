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
#ifndef XML_IN_OUT_LOG_H_9646CA383C65E16365E6E528EA911193//date "+%s"|md5sum|tr "[a-f]" "[A-F]"
#define XML_IN_OUT_LOG_H_9646CA383C65E16365E6E528EA911193

#include "epp_common.h"

/**
 * Write a log message into xml in/out log file.
 *
 * @param epp_ctx EPP context structure (connection, pool and session id).
 * @param fmt     Printf-style format string.
 */
extern void xml_in_out_log(epp_context *epp_ctx, const char *fmt, ...);

#endif//XML_IN_OUT_LOG_H_9646CA383C65E16365E6E528EA911193
