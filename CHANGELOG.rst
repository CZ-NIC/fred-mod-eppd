ChangeLog
=========

2022-09-14 (2.22.0)
-------------------

* Add optional ``authinfo`` parameter to epp info domain/nsset/keyset methods


2021-10-27 (2.21.1)
-------------------

* Fix rpm build


2021-04-30 (2.21.0)
-------------------

* Add optional authinfo parameter to info contact method
* Rename changelog to CHANGELOG.rst to match all FRED projects


2019-10-20 (2.20.1)
-------------------

* Update spec file for F31 and Centos/RHEL 8
* Gitlab CI


2019-03-18 (2.20.0)
-------------------

* CMake fixes
* Autotools removal
* License GNU GPLv3+


2018-08-16 (2.19.0)
-------------------

* Disclose flags policy configuration
* Fix - according to configuration generate extra-addr extension uri to greeting


2018-04-20 (2.18.0)
-------------------

* Quick fix to change default disclose policy to hide (will be revisited)
* Add impl. for update contact poll message


2018-02-14 (2.17.0)
-------------------

* Separate configurable log file for epp (xml) requests and responses


2018-01-08 Michal Strnad (2.16.0)
---------------------------------

* Hide registrars plaintext passwords


2017-09-12 (2.15.0)
-------------------

* Add contact extension to support additional addreses (mailing address implemented)


2016-09-12 Jan Zima, Zuzana Ansorgova (2.14.2)
----------------------------------------------

* Build fix (gcc 6.1.1)
* Configuration documentation


2016-03-21 Jaromir Talir (2.14.1)
---------------------------------

* Fix rpm build


2014-06-12 Jan Korous (2.14.0)
------------------------------

* build adapted to idl changes (separation of common types)


2013-11-11 Jan Zima (2.13.0)
----------------------------

* fix epp poll req/ack commands - overflow of count values


2013-04-02 Jiri Sadek (2.12.0)
------------------------------

* appropriate impl. changes for update object poll messages
* allow compilation with both apache 2.2 and 2.4


2012-11-21 Jiri Sadek, Juraj Vicenik (2.11.0)
---------------------------------------------

* schema changes (see standalone ChangeLog)


2012-09-06 Juraj Vicenik (2.10.0)
---------------------------------

* logger - removed output flag from properties interface
* low credit poll message - credit and creditlimit are now passed as strings


2012-05-11 Juraj Vicenik (2.9.0)
--------------------------------

* fix - %llu format string in epp log
* schema changes (see standalone ChangeLog)


2012-04-27 Jiri Sadek, Juraj Vicenik (2.8.0)
--------------------------------------------

* epp action removed from fred


2011-10-17 Jiri Sadek, Juraj Vicenik (2.7.0)
--------------------------------------------

* credit amount in credit info command is now passed as string data type
* more detailed apache module logging (mainly logger client)
* logging greeting without session


2011-07-04 Jiri Sadek (2.6.0)
-----------------------------

* new poll message for request charging impl.


2011-06-15 Jiri Sadek (2.5.1)
-----------------------------

* bugfix - missing break in evaluation of epp_read_request(...) return code


2011-05-20 Juraj Vicenik (2.5.0)
--------------------------------

* Logger - hello command result code logging fix, closing session in logger on not proper client logout
* detailed error logging


2011-03-23 Jiri Sadek (2.4.4)
-----------------------------

* fix segfault on requests without clTRID element specified


2011-03-14 Jiri Sadek (2.4.3)
-----------------------------

* fix missing files


2011-03-14 Jiri Sadek (2.4.2)
-----------------------------

* fix build - schema version


2011-03-14 Jiri Sadek (2.4.1)
-----------------------------

* Reverted changes to schemas - we don't want them in release (packaging troubles)


2011-02-24 Juraj Vicenik, Jiri Sadek (2.4.0)
--------------------------------------------

* Enhanced error logging
* Option EPPlogdMandatory to enabe semi-mandatory fred-logd in EPP
* Variables missing initialization fixes


2010-12-13 Juraj Vicenik (2.3.8)
--------------------------------

* Fixed incorrect logging of UTF-16 via fred-logd


2010-09-29 Jiri Sadek, Juraj Vicenik (2.3.7)
--------------------------------------------

* Logger interface changes


2010-08-05 Juraj Vicenik (2.3.6)
--------------------------------

* Logger - property handle for object handles and names, added logging for extended commands


2010-07-22 Jiri Sadek, Juraj Vicenik (2.3.5)
--------------------------------------------

* Logger - logging nsset reportlevel fixed
* Coverity errors fixes


2010-06-17 Jiri Sadek (2.3.4)
-----------------------------

* Fixes in Logger - fred-logd restart issues
* Minor configuration changes (lcrypto)


2010-04-29 Jaromir Talir (2.3.3)
--------------------------------

* Adding missing autotools files


2010-03-09 Juraj Vicenik, Jiri Sadek (2.3.2)
--------------------------------------------

* Fixing module config to be not dependent on Logger
* DUMMY-SVTRID response changed code from 2400 to 2500 and will disconnect client from server


2010-02-24 Juraj Vicenik (2.3.1)
--------------------------------

* Fixes in Logger int. - Hello command and Svtrid parameter was not logged properly


2010-02-16 Juraj Vicenik (2.3.0)
--------------------------------

* Audit (Logger client) component integration


2009-11-09 Jiri Sadek, Juraj Vicenik (2.2.0)
--------------------------------------------

* Functionality for enum dictionary project
* Removing ds records from keyset


2009-05-19 Jiri Sadek (2.1.1)
-----------------------------

* Added more logging messages for debug purpose


2008-10-18 Jaromir Talir (2.1.0)
--------------------------------

* Adding dnskey list to keysets


2008-09-29 Jaromir Talir (2.0.2)
--------------------------------

* Missing handling of poll delete_keyset message


2008-08-29 Juraj Vicenik (2.0.1)
--------------------------------

* Hello message support keyset version


2008-08-14 Jaromir Talir, Juraj Vicenik (2.0.0)
-----------------------------------------------

* Schema updated for DNSSEC and info-contact option params
* DNSSEC functions for KeySet manipulation implemented


2008-06-20 Jaromir Talir (1.7.0)
--------------------------------

* Minor configuration and build enhancements
* Apache log messages translated in log file


2008-02-29 Jiri Sadek (version 1.6.1)
-------------------------------------

* added configuration option 'EPPdeferErrors <num>' for defering all epp error response codes (those >=2000) - ticket #1400


2008-02-08 Jiri Sadek (version 1.6.0)
-------------------------------------

* Release 1.6.0
* Fixed double logout call to Central Register when user issue proper connection close.


2008-01-12 Jaromir Talir
------------------------

* Adding test ssl certificate and updating test configuration
* RPM support added and other small autotools changes


2008-01-10 Jiri Sadek
---------------------

* Automake support and autoconf somewhat rewritten
* Log message after successfuly initialization uniformalized with other modules


2007-11-07 Jan Kryl (version 1.5.1)
-----------------------------------

* Minor issues pointed by a coverity test were fixed.
* Hack to accomodate connection closing on certain return codes was incorporated. In future the logic should be
  incorporated in CORBA interface.
* New option -p of epp_test can be used to test corba nameservice functionality.


2007-09-26 Jan Kryl (version 1.5.0)
-----------------------------------

* New mechanism of creating poll message's content. The XML of message is created in mod_eppd and not in central
  register. Maintenance of XML generators scattered all over the central register was a nightmare.
* Upon tcp connection close is called new CORBA function which signals this event to Central Register. Central
  register in response deletes a session entry from its table, so that it doesn't get overfilled by stale connections.
* Bugfix in test_nsset function, which didn't properly incremented index in a list and led to segmentation fault.
* XML response is send for archivation to central-register only if it has real svTRID assigned by Central
  register (otherwise the CR is not able to pair the response with request).


2007-09-19 Jan Kryl (version 1.4.4)
-----------------------------------

* Remove bashism from Makefile (output redirection).


2007-07-26 Jaromir Talir (version 1.4.3)
----------------------------------------

* Simple schema change.


2007-07-13 Jan Kryl (version 1.4.2)
-----------------------------------

* Error messages triggered by XML validator were using namespaces which were not declared.
* Bug in update of ident attribute was fixed. It was not possible to nullify ident attribute.


2007-06-25 Jan Kryl (version 1.4.1)
-----------------------------------

* Viewport of client's document identifing an error was cut out without proper modifications, which resulted in usage
  of namespaces which were not defined. This is fixed now.
* The input XML documents sent to central register for archivation are encoded in UTF-8. The old behaviour of sending
  the raw text could result in db insert failure, if the input was encoded in other than UTF-8 encoding.
* The policy when required parameter is not returned from central register was changed. Mod_eppd generates invalid
  XML and logs the error.
* The ident type birthday was not tranformed in output XML. This was fixed.
* Disclose on vat, ident and notifyEmail was not displayed in output XML. This was fixed.
* Changes in XML schemas - see schemas' changelog for more detailed information. Schemas versions were bumped up.


version 1.4.0
-------------

* Configuration utilities (apr-config, apxs, pkg-config) are run as part of configure rather than in makefile. Makefile gets
  real parameters and not just paths of these utilities. I belive it's more correct solution.
* Missing tests for header files as well as errors in 'with' parameters in configure.ac were corrected.
* mod_eppd creates "dummy answer" if it cannot get response from some reason from CORBA server. Dummy answer looks like
  normal error response, but the svtrid is faked. If the error occures during the first greeting, the mod_eppd closes the
  connection without responding with error message, which is the same behaviour as before.
* Again changes in XML schemas, see schemas' changelog for more information. Schemas versions were bumped up.


version 1.3.1
-------------

* New 'tempcontact' element in domain, new technical check interface ... see changelog of XML schemas.


version 1.3.0
-------------

* The client provided values which caused errors repeated in error message are now taken directly from input document, rather
  than constructed ad-hoc as it was before. At source code level this implies that parsed document and its context must be attached
  to command structure and is freed after the whole request is proccessed.
* New CORBA backend which exploits better possibility of exceptions is in place. The return codes are no more overloaded.
* Functions for logging were exported in other components of mod_eppd. This results in better error reporting in log
  file, which was not possible when we identified problem just based on return code.
* The code of epp-client.c was restructured and is more readable than it was.


version 1.2.1
-------------

* Bugfix - instead of EPP protocol version was in greeting mod_eppd's version.


version 1.2.0
-------------

* ... major rebuild of all source files and code cleanup
* New memory allocator. Memory is now allocated from pools and freed all at once when request processing is over.
* Structure for lists 'circ_list' was replaced by 'qhead' and 'qitem'.
* The mega-structure containing all possible request was parted in smaller peaces, which ease manipulation.
* New reference manager mod_corba was added, mod_eppd was adapted to changed reference management policy. Now each connection
  has its own unique CORBA reference.
* As a side effect of changes in reference management code, the apache can be started without omninames running. The object
  references are obtained and resolved upon request arrival.
* The epp-client.c file (CORBA component) was made bullet-proof against possible memory allocation failures.
* Exceptions in CORBA functions are used instead of the hack (svTRID == 0).
* All errors are translated on CR side from now (even libxml errors).
* Extension handling mechanism was changed in order to make adding of new extensions easier (DNSSEC extension was dropped for now).
* Handling of period in renew and create was changed. The period is now structured as 'value' and 'unit'. No conversion to
  months is done on behalf of mod_eppd.
* Support for update of status flags was removed.
* New EPP command 'sendAuthInfo' was implemented.
* New EPP command for credit balance retrieval (creditInfo) was added.
* New EPP command for trigering of technical check on nsset was added.
* New attribute of nsset 'reportlevel' was added. This attribute is related to technical checks.
* XML documents sent in response to EPP commands are from now logged to central register over corba.
* Script for regular update of CRL is now part of mod_eppd distribution.
* Changes in schema files (see ChangeLog in subdirectory schemas). The versions on most schema files were bumped up.


version 1.1.1
-------------

* AuthInfo parameter when creating an object is not mandatory parameter anymore but optional.
* Missing attribute 'lang' in reason element in check response was added.
* Schema changes (see ChangeLog in schema subdirectory).


version 1.1.0
-------------

* First version targeted for production release (does not have a tag in repository).
