/**
 * @file mainpage.h
 *
 * This file contains only the main page of doxygen documentation.
 */

/**
 * @mainpage package mod_eppd
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
 * subsequent EPP requests. Incomming and outcomming requests are filtered
 * through mod_ssl, which handles SSL encryption of communication channel.
 * mod_eppd.c is interfacing with apache and the central component of
 * the whole module. A request goes through following stages:
 * 
 *     - At first it is read.
 *     - It is processed by XML parser.
 *     - Data are send and answer is received to/from central register.
 *     - Answer in form of XML is generated.
 *     - Answer is sent off.
 *     .
 *
 * Parsing resp. CORBA communication resp. generating of response is not done
 * by mod_eppd.c itself, but rather by epp_parser.c resp. epp-client.c resp.
 * epp_gen.c. These are components which help to mod_eppd.c to get work done.
 * epp_parser.c uses libxml2 library to process XML, epp_gen.c as well.
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
 *         Activates epp module.
 *   .
 * 
 *   name: EPPnameservice
 *   - value:        host[:port]
 *   - default:      localhost
 *   - context:      global config, virtual host
 *   - description:
 *         A location of CORBA nameservice where the module asks for EPP object.
 *         Obtained reference is used for lifetime of process so it is best
 *         to restart the apache when you change the object on other side.
 *   .
 * 
 *   name: EPPobject
 *   - value:        token
 *   - default:      EPP
 *   - context:      global config, virtual host
 *   - description:
 *         Name under which is the EPP object known to CORBA nameservice.
 *   .
 * 
 *   name: EPPschema
 *   - value:        path
 *   - default:      none
 *   - context:      global config, virtual host
 *   - description:
 *         A location of xsd file (xml schema) describing EPP protocol. It is
 *         used for validation of incomming and outcomming messages.
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
 *   .
 * 
 *   name: EPPloglevel
 *   - value:        fatal, error, warning, info, debug
 *   - default:      info
 *   - context:      global config, virtual host
 *   - description:
 *         Log verbosity.
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
 *         of the server. On the other hand it will slow down server quite a
 *         bit.
 *   .
 * 
 * Example configuration suited for production might look like this:
 *
 @verbatim
 #
 # mod_eppd virtual host
 #
 Listen 700      # EPP port, assigned by IANA
 LoadModule eppd_module modules/mod_eppd.so
 <VirtualHost 192.168.2.1:700>
   EPPprotocol       On
   EPPnameservice    "nameservice-host.cz"
   EPPobject         "EPP"
   EPPschema         "/etc/apache2/schemas/all-1.0.xsd"
   EPPservername     "EPP production server"
   EPPlog            "/var/log/apache2/epp.log"
   EPPloglevel       error
   EPPvalidResponse  Off
 
   SSLEngine on
   SSLCipherSuite ALL:!ADH:!EXPORT56:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP
   SSLCertificateFile    /etc/apache2/server.crt
   SSLCertificateKeyFile /etc/apache2/server.key
   SSLVerifyClient       require
   SSLCACertificateFile  /etc/apache2/certs/server.crt
 </VirtualHost>
 @endverbatim
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
 * which is destroyed when the request is answered.
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
 * location is automatically found by configure:
 *
 *     - --with-apr-config      Location of apr-config tool.
 *     - --with-apu-config      Location of apu-config tool.
 *     - --with-apxs            Location of apxs tool.
 *     - --with-orbit-idl       Location of ORBit IDL compiler.
 *     - --with-pkg-config      Location of pkg-config tool.
 *     - --with-pkg-config      Location of pkg-config tool.
 *     - --with-pkg-config      Location of doxygen tool.
 *     .
 *
 * The module is built by the traditional way: ./configure && make && make
 * install. The module is installed in directory where reside other apache
 * modules. Together with module are installed xmlschema files in subdirectory
 * "schemas" in apache configuration directory.
 *
 * @section trouble Troubleshooting
 *
 * The best friend is mod_eppd's log (the one configured in apache's config).
 * In case of serious error the message is written to stderr instead of the
 * log, so you will find it in apache's error log. If you can't still localize
 * the problem, module comes with test program "test". This binary is easy
 * to debug in gdb and in 99% of cases are the bugs from mod_eppd reproducible
 * by this binary.
 *
 */
