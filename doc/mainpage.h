/*
 * Copyright (C) 2006-2018  CZ.NIC, z. s. p. o.
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
/**
 * @file mainpage.h
 *
 * This file contains only the main page of doxygen documentation.
 */

/**
 * @mainpage package mod_eppd
 *
 * WARNING! This documentation is slightly obsolete and needs to be updated.
 * However it is still usefull source of information.
 *
 * @section overview Overview
 *
 * Purpose of this package is to translate incomming requests in form of
 * a XML to CORBA request, which are further processed by central register.
 * And also the way back - translate CORBA responses of central register
 * to XML responses to client. The protocol used to communicate with client
 * is EPP (Extensible provisioning protocol). The interface to central
 * register is defined by IDL file.
 *
 * \image html mod_eppd.png
 *
 * Apache connection handler is used to process EPP connection and
 * subsequent EPP requests. Incomming and outgoing requests are filtered
 * through mod_ssl, which handles SSL encryption of communication channel.
 * mod_eppd.c is interfacing with apache and the central component of
 * the whole module. A request goes through following stages:
 * 
 *     - At first it is read.
 *     - It is processed by XML parser.
 *     - Data are sent to central register and answer is received from central register.
 *     - Answer is generated in form of XML.
 *     - Answer is sent off.
 *     .
 *
 * Parsing, CORBA communication and generating of response is not done
 * by mod_eppd.c itself, but rather by epp_parser.c, epp-client.c and
 * epp_gen.c. These are components which help to mod_eppd.c to get work done.
 * epp_parser.c and epp_gen.c use libxml2 library to process and generate XML.
 * epp-client.c uses ORBit2 library, implementation of CORBA protocol, in
 * order to communicate with central register.
 *
 * @section config Module's configuration
 *
 * List of configuration directives recognized by mod_eppd:
 * 
 *   name: EPPprotocol
 *   - value:        On, Off
 *   - default:      Off
 *   - context:      global config, virtual host
 *   - description:
 *         Activates epp module.  This means that any
 *         data comming from network connection on ip address of virtual host
 *         are assummed to be epp requests.
 *   .
 * 
 *   name: EPPobject
 *   - value:        alias
 *   - default:      EPP
 *   - context:      global config, virtual host
 *   - description:
 *         Alias under which is exported corba object reference from mod_corba
 *         module.
 *   .
 * 
 *   name: EPPschema
 *   - value:        path
 *   - default:      none
 *   - context:      global config, virtual host
 *   - description:
 *         A location of xsd file (xml schema) describing EPP protocol. It is
 *         used for validation of incomming and possibly outcomming messages.
 *   .
 * 
 *   name: EPPservername
 *   - value:        quoted string
 *   - default:      none
 *   - context:      global config, virtual host
 *   - description:
 *         Name of the server used in EPP greeting frame.
 *   .
 * 
 *   name: EPPlog
 *   - value:        path
 *   - default:      none
 *   - context:      global config, virtual host
 *   - description:
 *         Log file of mod_eppd. It is not an error not to set log file,
 *         in that case all messages will be logged to apache's error log.
 *         This log file is espesially neat when tracing XML documents
 *         exchanged between client and server. In that case epp log level
 *         must be set to debug.
 *   .
 * 
 *   name: EPPloglevel
 *   - value:        fatal, error, warning, info, debug
 *   - default:      info
 *   - context:      global config, virtual host
 *   - description:
 *         EPP log verbosity.
 *   .
 * 
 *   name: EPPvalidResponse
 *   - value:        On, Off
 *   - default:      Off
 *   - context:      global config, virtual host
 *   - description:
 *         Whether to validate responses from the mod_eppd. The line is dropped
 *         in log file if response does not validate, but otherwise the response
 *         proceeds as normaly. This is very handy for verifing good operation
 *         of the server. On the other hand it will notably slow down server.
 *   .
 *
 *   name: EPPdeferErrors
 *   - value:        positive integer (<=10000)
 *   - default:      0
 *   - context:      global config, virtual host
 *   - description:
 *         Value represents time in msec that will be used to defer all error
 *         responses from Central Registry (all response codes > 2000).
 *   .
 *
 * File httpd-epp.conf is example of mod_eppd's configuration.
 *
 * @section make Building and installing the module
 *
 * Module comes with configure script, which should hide differences
 * among Fedora, Gentoo, Debian and Ubuntu linux distributions. Other
 * distribution let alone UNIX-like operating systems where not tested.
 * The following parameters in addition to standard ones are recognized
 * by the configure script:
 *
 *     - --with-profiling       Enable simple profiling support.
 *     - --with-idl             Location of IDL file.
 *     - --with-schema          Location of epp xmlschema.
 *     .
 * Following options doesn't have to be ussualy specified since tools'
 * location is automatically found by configure in most cases:
 *
 *     - --with-apr-config      Location of apr-config tool.
 *     - --with-apxs            Location of apxs tool.
 *     - --with-orbit-idl       Location of ORBit IDL compiler.
 *     - --with-pkg-config      Location of pkg-config tool.
 *     - --with-doc             Location of doxygen if you want to generate documentation.
 *     .
 *
 * The installation directories are not taken into account. The installation
 * directories are given by apxs tool.
 *
 * The module is installed by the traditional way: ./configure && make && make
 * install. The module is installed in directory where other apache modules
 * reside. Together with module are installed xmlschema files in subdirectory
 * "schemas" in apache configuration directory.
 *
 * @section trouble Troubleshooting
 *
 * The best friend is mod_eppd's log file.
 * In case of serious error the message is written to stderr instead of the
 * log, so you will find it in apache's error log. If you can't still localize
 * the problem, module comes with test program "epp_test". This binary is easy
 * to debug in gdb and in 99% of cases are the bugs from mod_eppd reproducible
 * by this simplified binary. If you decided to use gdb, don't forget to
 * configure mod_eppd with CFLAGS='-g -O0'.
 *
 * It is possible to run epp_test in two modes: interactive and batch mode.
 * In batch mode you specify XML files to be processed on command line. They
 * will be processed in the same order as they are written on command line.
 * Interactive mode will give you a prompt, where you specify a command
 * and then another prompt to specify name of file when command was 'file'
 * and XML document when command was 'custom'. If you want to exit from
 * program, use command 'exit'.
 *
 * @section memory Memory management
 *
 * Apache introduces memory pools, which should minimize danger of memory
 * leaks. Of course libraries which we use (libxml and ORBit) are not
 * aware of these pools and they allocate memory by traditional malloc.
 * But everywhere where it is possible, we try to use apache pools for
 * allocations. Apache header files are not included directly in theese
 * files but rather mod_eppd.c exports wrappers for memory allocations
 * to be used in other files. For each request is created dedicated pool,
 * which is destroyed when the request is processed.
 *
 */
