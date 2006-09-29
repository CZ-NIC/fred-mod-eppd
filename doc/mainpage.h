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
 * 
 *   name: EPPnameservice
 *   - value:        host[:port]
 *   - default:      localhost
 *   - context:      global config, virtual host
 *   - description:
 *         A location of CORBA nameservice where the module asks for EPP object.
 *         Obtained reference is used for lifetime of process so it is best
 *         to restart the apache when you change the object on other side.
 * 
 *   name: EPPobject
 *   - value:        token
 *   - default:      EPP
 *   - context:      global config, virtual host
 *   - description:
 *         Name under which is the EPP object known to CORBA nameservice.
 * 
 *   name: EPPschema
 *   - value:        path
 *   - default:      none
 *   - context:      global config, virtual host
 *   - description:
 *         A location of xsd file (xml schema) describing EPP protocol. It is
 *         used for validation of incomming and outcomming messages.
 * 
 *   name: EPPservername
 *   - value:        quoted string
 *   - default:      none
 *   - context:      global config, virtual host
 *   - description:
 *         Name of the server used in EPP greeting frame.
 * 
 *   name: EPPlog
 *   - value:        path
 *   - default:      none
 *   - context:      global config, virtual host
 *   - description:
 *         Log file of mod_eppd. It is not an error not to set log file,
 *         in that case all messages will be logged to apache's error log.
 * 
 *   name: EPPloglevel
 *   - value:        fatal, error, warning, info, debug
 *   - default:      info
 *   - context:      global config, virtual host
 *   - description:
 *         Log verbosity.
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
 */
