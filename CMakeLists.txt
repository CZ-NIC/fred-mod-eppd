cmake_minimum_required(VERSION 3.5)

set(module_name fred-mod-eppd)
project(${module_name} C)

macro(set_default variable_name variable_value)
    if(NOT ${variable_name})
        set(${variable_name} ${variable_value})
    endif()
endmacro()

#Make sure that custom modules like FindORBIT2 are found
set_default(IDL_PROJECT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/external/idl)
set(IDL_SOURCE_DIR ${IDL_PROJECT_DIR}/idl)
set(IDL_DESTINATION_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated/corba)
list(INSERT CMAKE_MODULE_PATH 0 ${IDL_PROJECT_DIR}/cmake)

##############################################
# Declare dependencies
find_package(ORBIT2 REQUIRED)

macro(assert_binary_in_path name binary)
    find_program(${name} ${binary})
    if(NOT ${name})
        message(FATAL_ERROR "${binary} not found!")
    endif()
endmacro()

assert_binary_in_path(APXS_PROGRAM apxs)
assert_binary_in_path(APR_PROGRAM apr-1-config)

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CCACHE_PROGRAM}")
endif()

macro(normalize_path variable_name variable_value)
    string(REGEX REPLACE "//*" "/" "${variable_name}" "${variable_value}")
    if(NOT "${${variable_name}}" STREQUAL "/")
        string(REGEX REPLACE "/$" "" "${variable_name}" "${${variable_name}}")
    endif()
endmacro()

macro(set_default_path variable_name variable_value)
    if(NOT ${variable_name})
        normalize_path(${variable_name} ${variable_value})
    endif()
endmacro()

normalize_path(NORMALIZED_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
if("${NORMALIZED_INSTALL_PREFIX}" STREQUAL "/usr/local")
    set(USR_SHARE_PREFIX "")
else()
    set(USR_SHARE_PREFIX "/usr")
endif()

set_default(CMAKE_BUILD_TYPE "Release")
set(CMAKE_C_FLAGS_RELEASE "-O2")

set_default(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_program(GIT_PROGRAM git)
if(NOT VERSION)
    if(NOT GIT_PROGRAM)
        message(FATAL_ERROR "git not found; you need to pass -DVERSION=")
    endif()
    execute_process(COMMAND ${GIT_PROGRAM} "describe" "--tags"
                    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                    OUTPUT_VARIABLE RAWVERSION)
    string(REGEX REPLACE "(-.*)?\n" "" VERSION "${RAWVERSION}")
endif()
set(TARBALL_FILE_NAME "${module_name}-${VERSION}")

if(NOT REVISION)
    if(NOT GIT_PROGRAM)
        set(REVISION "unknown")
    else()
        execute_process(COMMAND ${GIT_PROGRAM} "rev-parse" "HEAD"
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            OUTPUT_VARIABLE RAWREVISION)
        string(REGEX REPLACE "\n" "" REVISION "${RAWREVISION}")
    endif()
endif()

set_default_path(LOCALSTATEDIR ${CMAKE_INSTALL_PREFIX}/var)
normalize_path(LOCALSTATEDIR ${LOCALSTATEDIR})
set_default_path(DATAROOTDIR ${CMAKE_INSTALL_PREFIX}/${USR_SHARE_PREFIX}/share)
normalize_path(DATAROOTDIR ${DATAROOTDIR})

set_default(NSHOST localhost)
set_default(OBJECTNAME EPP)
set_default(LOGGER_OBJECTNAME Logger)
set_default(EPP_PERF 1)

set_default(PORT 700)
set_default(GIT_REVISION "${REVISION}")
set_default(MOD_VERSION "${VERSION}")

set_default(CONFIG_FILE_NAME 02-fred-mod-eppd-apache.conf)

set_default(SRCDIR ${CMAKE_CURRENT_SOURCE_DIR})
set_default(PROJECT ${module_name})
set_default(PACKAGE ${module_name})
set_default(DOCDIR doc)
if(NOT PERL_PATH)
    find_package(Perl)
    if(PERL_FOUND)
        set(PERL_PATH "${PERL_EXECUTABLE}")
    endif()
endif()

set_default(DOXYGEN_GENERATE_MAN "NO")
set_default(DOXYGEN_GENERATE_RTF "NO")
set_default(DOXYGEN_GENERATE_XML "NO")
set_default(DOXYGEN_GENERATE_HTMLHELP "NO")
set_default(DOXYGEN_GENERATE_CHI "NO")
set(DOXYGEN_GENERATE_HTML "YES")
set_default(DOXYGEN_GENERATE_LATEX "NO")
set(DOXYGEN_EXCLUDE_PATTERNS "*/external/*")
set(DOXYGEN_IMAGE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/doc")
set(DOXYGEN_QUIET "YES")
set(DOXYGEN_WARNINGS "NO")
set(DOXYGEN_WARN_LOGFILE "/dev/null")
set_default(DOXYGEN_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${DOCDIR})
if((${CMAKE_MAJOR_VERSION} LESS 3) OR
   ((${CMAKE_MAJOR_VERSION} EQUAL 3) AND (${CMAKE_MINOR_VERSION} LESS 10)))
    list(INSERT CMAKE_MODULE_PATH 0 ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
endif()
find_package(Doxygen OPTIONAL_COMPONENTS dot)
if (DOXYGEN_FOUND)
    doxygen_add_docs(doc ${CMAKE_CURRENT_SOURCE_DIR}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
endif()

ORBIT2_IDL_TO_C("${IDL_SOURCE_DIR}" "${IDL_DESTINATION_DIR}" IDL_C IDL_H
    DateTime.idl
    _dataTypes.idl
    Filters.idl
    Admin.idl
    Registry.idl
    Logger.idl
    EPP.idl)

find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)

macro(store_flag_info key value)
    string(STRIP "${${value}}" cmake_sucks_${key})
    string(REPLACE " " ";" cmake_sucks_${key} "${cmake_sucks_${key}}")
    set(flag_info_${key} "${cmake_sucks_${key}}")
    message(STATUS "flag_info_${key}: ${flag_info_${key}}")
endmacro()

macro(store_include_info key value)
    string(STRIP "${${value}}" cmake_sucks_${key})
    string(REPLACE " " ";" cmake_sucks_${key} "${cmake_sucks_${key}}")
    set(include_info_${key} "${cmake_sucks_${key}}")
    message(STATUS "include_info_${key}: ${include_info_${key}}")
endmacro()

macro(store_linker_info key value)
    string(STRIP "${${value}}" cmake_sucks_${key})
    string(REPLACE " " ";" cmake_sucks_${key} "${cmake_sucks_${key}}")
    set(linker_info_${key} "${cmake_sucks_${key}}")
    message(STATUS "linker_info_${key}: ${linker_info_${key}}")
endmacro()

execute_process(COMMAND ${APXS_PROGRAM} "-q" "CFLAGS" OUTPUT_VARIABLE APXS_CFLAGS)
execute_process(COMMAND ${APXS_PROGRAM} "-q" "CPPFLAGS" OUTPUT_VARIABLE APXS_CPPFLAGS)
execute_process(COMMAND ${APXS_PROGRAM} "-q" "LDFLAGS" OUTPUT_VARIABLE APXS_LDFLAGS)
string(STRIP "${APXS_CFLAGS}" APXS_CFLAGS)
string(STRIP "${APXS_CPPFLAGS}" APXS_CPPFLAGS)
string(STRIP "${APXS_LDFLAGS}" APXS_LDFLAGS)
string(CONCAT APXS_FLAGS ${APXS_CFLAGS} " " ${APXS_CPPFLAGS} " " ${APXS_LDFLAGS})
store_flag_info(apxs APXS_FLAGS)

execute_process(COMMAND ${APXS_PROGRAM} "-q" "INCLUDEDIR" OUTPUT_VARIABLE APXS_INCLUDES)
store_include_info(apxs APXS_INCLUDES)

execute_process(COMMAND ${APXS_PROGRAM} "-q" "LIBS" OUTPUT_VARIABLE APXS_LIBS)
store_linker_info(apxs APXS_LIBS)

execute_process(COMMAND ${APXS_PROGRAM} "-q" "LIBEXECDIR" OUTPUT_VARIABLE APXS_MODULES)
string(STRIP ${APXS_MODULES} APXS_MODULES)
string(REGEX REPLACE "^/" "" APXS_MODULES ${APXS_MODULES})

set_default(MODULE_INSTALLDIR ${CMAKE_INSTALL_PREFIX}/${APXS_MODULES})
normalize_path(MODULE_INSTALLDIR ${MODULE_INSTALLDIR})

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_BINARY_DIR}/config.h)
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/conf/${CONFIG_FILE_NAME}.in
    ${CMAKE_BINARY_DIR}/conf/${CONFIG_FILE_NAME})

execute_process(COMMAND ${APR_PROGRAM} "--cflags" OUTPUT_VARIABLE APR_CFLAGS)
execute_process(COMMAND ${APR_PROGRAM} "--cppflags" OUTPUT_VARIABLE APR_CPPFLAGS)
execute_process(COMMAND ${APR_PROGRAM} "--ldflags" OUTPUT_VARIABLE APR_LDFLAGS)
string(STRIP "${APR_CFLAGS}" APR_CFLAGS)
string(STRIP "${APR_CPPFLAGS}" APR_CPPFLAGS)
string(STRIP "${APR_LDFLAGS}" APR_LDFLAGS)
string(CONCAT APR_FLAGS ${APR_CFLAGS} " " ${APR_CPPFLAGS} " " ${APR_LDFLAGS})
store_flag_info(apr APR_FLAGS)

execute_process(COMMAND ${APR_PROGRAM} "--includedir" OUTPUT_VARIABLE APR_INCLUDES)
store_include_info(apr APR_INCLUDES)

execute_process(COMMAND ${APR_PROGRAM} "--libs" OUTPUT_VARIABLE APR_LIBS)
store_linker_info(apr APR_LIBS)

pkg_search_module(XML2 REQUIRED libxml-2.0>=2.5.0)
store_flag_info(xml2 XML2_CFLAGS)
store_include_info(xml2 XML2_INCLUDE_DIRS)
store_linker_info(xml2 XML2_LIBRARIES)

store_flag_info(orbit2 ORBIT2_CFLAGS)
store_include_info(orbit2 ORBIT2_INCLUDE_DIRS)
store_linker_info(orbit2 ORBIT2_LIBRARIES)

pkg_search_module(ORBITCOSNAMING2 REQUIRED ORBit-CosNaming-2.0)
store_flag_info(orbitcosnaming2 ORBITCOSNAMING2_CFLAGS)
store_include_info(orbitcosnaming2 ORBITCOSNAMING2_INCLUDE_DIRS)
store_linker_info(orbitcosnaming2 ORBITCOSNAMING2_LIBRARIES)

pkg_search_module(LIBCRYPTO REQUIRED libcrypto)
store_flag_info(crypto LIBCRYPTO_CFLAGS)
store_include_info(crypto LIBCRYPTO_INCLUDE_DIRS)
store_linker_info(crypto LIBCRYPTO_LIBRARIES)


function(set_common_properties_on_targets)
    foreach(target_name ${ARGN})
        message(STATUS "setting properties on: " ${target_name})
        set_target_properties(${target_name} PROPERTIES
            C_STANDARD 99
            C_STANDARD_REQUIRED YES
            C_EXTENSIONS NO
            ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
            LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
        target_compile_options(${target_name}
            PUBLIC "-ggdb"
            PUBLIC "-grecord-gcc-switches"
            PUBLIC "-Wall"
            PUBLIC "-Wextra"
            PUBLIC "-fdiagnostics-color=auto"
            PUBLIC "-fPIC"
            PUBLIC "-DHAVE_CONFIG_H")
        target_include_directories(${target_name} PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${CMAKE_BINARY_DIR}
            ${IDL_DESTINATION_DIR})
    endforeach()
endfunction()

function(set_corba_properties_on_targets)
    foreach(target_name ${ARGN})
        message(STATUS "setting properties on: " ${target_name})
        target_compile_options(${target_name}
           PUBLIC "-Wno-unused-const-variable"
           PUBLIC "-Wno-unused-parameter")
    endforeach()
endfunction()

function(target_link_external_libraries target_name)
    foreach(library_name ${ARGN})
        target_link_libraries(${target_name} ${linker_info_${library_name}})
    endforeach()
endfunction()

function(target_include_external_libraries target_name)
    foreach(library_name ${ARGN})
        target_include_directories(${target_name} PUBLIC ${include_info_${library_name}})
    endforeach()
endfunction()

function(target_add_flags_for_external_libraries target_name)
    foreach(library_name ${ARGN})
        foreach(library_name ${flag_info_${library_name}})
            target_compile_options(${target_name} PRIVATE ${library_name})
        endforeach()
    endforeach()
endfunction()

function(target_depends_on_external_libraries target_name)
    target_link_external_libraries(${target_name} ${ARGN})
    target_include_external_libraries(${target_name} ${ARGN})
    target_add_flags_for_external_libraries(${target_name} ${ARGN})
endfunction()


add_library(corba_datetime STATIC
    ${IDL_DESTINATION_DIR}/DateTime-common.c
    ${IDL_DESTINATION_DIR}/DateTime-stubs.c)
target_depends_on_external_libraries(corba_datetime orbit2)

add_library(corba_datatypes STATIC
    ${IDL_DESTINATION_DIR}/_dataTypes-common.c
    ${IDL_DESTINATION_DIR}/_dataTypes-stubs.c)
target_depends_on_external_libraries(corba_datatypes orbit2)
target_link_libraries(corba_datatypes corba_datetime)

add_library(corba_filters STATIC
    ${IDL_DESTINATION_DIR}/Filters-common.c
    ${IDL_DESTINATION_DIR}/Filters-stubs.c)
target_depends_on_external_libraries(corba_filters orbit2)
target_link_libraries(corba_filters corba_datatypes)

add_library(corba_registry STATIC
    ${IDL_DESTINATION_DIR}/Registry-common.c
    ${IDL_DESTINATION_DIR}/Registry-stubs.c)
target_depends_on_external_libraries(corba_registry orbit2)
target_link_libraries(corba_registry corba_filters)

add_library(corba_epp STATIC
    ${IDL_DESTINATION_DIR}/EPP-common.c
    ${IDL_DESTINATION_DIR}/EPP-stubs.c)
target_depends_on_external_libraries(corba_epp orbit2)
target_link_libraries(corba_epp corba_datatypes)

add_library(corba_admin STATIC
    ${IDL_DESTINATION_DIR}/Admin-common.c
    ${IDL_DESTINATION_DIR}/Admin-stubs.c)
target_depends_on_external_libraries(corba_admin orbit2)
target_link_libraries(corba_admin corba_registry)

add_library(corba_logger STATIC
    ${IDL_DESTINATION_DIR}/Logger-common.c
    ${IDL_DESTINATION_DIR}/Logger-stubs.c)
target_depends_on_external_libraries(corba_logger orbit2)
target_link_libraries(corba_logger corba_admin)


add_library(xmleppd STATIC
    epp_gen.c
    epp_parser.c
    epp_xmlcommon.c)
target_depends_on_external_libraries(xmleppd
    apr
    xml2)

add_library(modeppd STATIC
    epp_common.c
    epp-client.c
    logd-client.c
    xml-in-out-log.c
    xml-in-out-log-details.c)
target_depends_on_external_libraries(modeppd
    apr
    apxs)
target_link_libraries(modeppd
    corba_logger
    corba_epp)

add_library(eppd SHARED mod_eppd.c)
set_target_properties(eppd PROPERTIES PREFIX "mod_")
target_link_libraries(eppd
    modeppd
    xmleppd)
target_depends_on_external_libraries(eppd
    apr
    crypto
    orbitcosnaming2)

add_executable(epp_test
    epp_test.c)
target_link_libraries(epp_test
    modeppd
    xmleppd)
target_depends_on_external_libraries(epp_test
    orbitcosnaming2)

set_common_properties_on_targets(
    modeppd
    corba_datetime
    corba_datatypes
    corba_registry
    corba_epp
    corba_logger
    corba_filters
    corba_admin
    xmleppd
    eppd)

set_corba_properties_on_targets(
    corba_admin
    corba_epp
    corba_filters
    corba_logger
    corba_registry
    corba_datatypes)

install(TARGETS eppd LIBRARY DESTINATION ${MODULE_INSTALLDIR})
install(DIRECTORY ${CMAKE_BINARY_DIR}/conf/ DESTINATION ${DATAROOTDIR}/fred-mod-eppd FILES_MATCHING PATTERN "*.conf")
install(DIRECTORY ${CMAKE_SOURCE_DIR}/schemas/ DESTINATION ${DATAROOTDIR}/fred-mod-eppd/schemas FILES_MATCHING PATTERN "*")
install(DIRECTORY ${CMAKE_SOURCE_DIR}/ssl/ DESTINATION ${DATAROOTDIR}/fred-mod-eppd/ssl FILES_MATCHING PATTERN "*")
if(TARGET doc)
    install(DIRECTORY ${DOXYGEN_OUTPUT_DIRECTORY}/html/ DESTINATION ${DATAROOTDIR}/doc/fred-mod-eppd FILES_MATCHING PATTERN "*")
endif()

add_custom_target(uninstall_module COMMAND rm ${MODULE_INSTALLDIR}/mod_eppd.so)
if(TARGET doc)
    add_custom_target(make_doc ALL DEPENDS doc)
    add_custom_target(uninstall_doc COMMAND rm -rf ${DATAROOTDIR}/doc/fred-mod-eppd)
endif()
add_custom_target(uninstall_others COMMAND rm -rf ${DATAROOTDIR}/fred-mod-eppd)
if(TARGET doc)
    add_custom_target(uninstall DEPENDS uninstall_module uninstall_doc uninstall_others)
else()
    add_custom_target(uninstall DEPENDS uninstall_module uninstall_others)
endif()

if(EXISTS ${CMAKE_SOURCE_DIR}/.git AND GIT_PROGRAM)
    if(NOT TARGET dist)
        add_custom_target(dist_idl
            COMMAND ${GIT_PROGRAM} archive --format=tar --prefix=${TARBALL_FILE_NAME}/external/idl/ HEAD -o ${CMAKE_CURRENT_BINARY_DIR}/.idl.tar
            WORKING_DIRECTORY ${IDL_PROJECT_DIR})
        add_custom_target(dist
            COMMAND ${GIT_PROGRAM} archive --format=tar --prefix=${TARBALL_FILE_NAME}/ HEAD -o ${CMAKE_CURRENT_BINARY_DIR}/.${TARBALL_FILE_NAME}.tar
            COMMAND tar --concatenate --file=${CMAKE_CURRENT_BINARY_DIR}/.${TARBALL_FILE_NAME}.tar ${CMAKE_CURRENT_BINARY_DIR}/.idl.tar
            COMMAND cat ${CMAKE_CURRENT_BINARY_DIR}/.${TARBALL_FILE_NAME}.tar | gzip > ${CMAKE_CURRENT_BINARY_DIR}/${TARBALL_FILE_NAME}.tar.gz
            COMMAND rm ${CMAKE_CURRENT_BINARY_DIR}/.${TARBALL_FILE_NAME}.tar ${CMAKE_CURRENT_BINARY_DIR}/.idl.tar
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
        add_dependencies(dist dist_idl)
    endif()

    if(NOT TARGET distcheck)
        set(DISTCHECK_BUILD_DIR "_build")
        set(DISTCHECK_INSTALL_DIR "_inst")
        if(${CMAKE_GENERATOR} STREQUAL "Ninja")
            set(DISTCHECK_BUILD_CMD "ninja")
            set(DISTCHECK_MAKEFLAGS "")
        else()
            set(DISTCHECK_BUILD_CMD "make")
            execute_process(COMMAND "grep" "-c" "model name" "/proc/cpuinfo"
                WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                OUTPUT_VARIABLE NOCPUS)
            string(REGEX REPLACE "\n" "" NOCPUS ${NOCPUS})
            set(DISTCHECK_MAKEFLAGS "MAKEFLAGS=-j${NOCPUS}")
        endif()
        add_custom_target(distcheck
            COMMAND
            rm -rf ${DISTCHECK_BUILD_DIR} ${DISTCHECK_INSTALL_DIR} ${TARBALL_FILE_NAME}
            && mkdir ${DISTCHECK_BUILD_DIR} ${DISTCHECK_INSTALL_DIR}
            && (tar xzf ${TARBALL_FILE_NAME}.tar.gz
                || (echo 'Error: failed to unpack the archive' 2>&1\; false))
            && (cd ${DISTCHECK_BUILD_DIR}
                && (${CMAKE_COMMAND} -G${CMAKE_GENERATOR} -DCMAKE_INSTALL_PREFIX=../${DISTCHECK_INSTALL_DIR} -DIDL_SOURCE_DIR=${IDL_SOURCE_DIR} ../${TARBALL_FILE_NAME}
                    || (echo 'Error: failed to configure the archive' 2>&1\; false))
                && (${DISTCHECK_MAKEFLAGS} ${DISTCHECK_BUILD_CMD}
                    || (echo 'Error: the build target failed ' 2>&1\; false))
                && (${DISTCHECK_BUILD_CMD} install
                    || (echo 'Error: the install target failed' 2>&1\; false))
                && (${DISTCHECK_BUILD_CMD} uninstall
                    || (echo 'Error: the uninstall target failed' 2>&1\; false))
                && (${DISTCHECK_BUILD_CMD} clean
                    || (echo 'Error: the clean target failed' 2>&1\; false)))
            && rm -rf ${DISTCHECK_BUILD_DIR} ${DISTCHECK_INSTALL_DIR} ${TARBALL_FILE_NAME}
            && echo 'PASS: ' ${TARBALL_FILE_NAME}.tar.gz 'is ready for distribution.'
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            COMMENT "Checking the distribution archive...")
        add_dependencies(distcheck dist)
    endif()
else()
    message(STATUS "no git -- not including dist and distcheck targets")
endif()
