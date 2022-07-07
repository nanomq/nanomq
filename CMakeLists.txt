#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
# not finished yet #

cmake_minimum_required (VERSION 2.8.8)
SET(CMAKE_C_FLAGS "-std=c99")

project(nanomq-nng)

include(CheckCCompilerFlag)

option (BUILD_CLIENT "Build nanomq client" ON)
option (BUILD_NNG_PROXY "Build nng proxy" ON)
option (BUILD_ZMQ_GATEWAY "Build zmq gateway" OFF)
option (BUILD_BENCH "Build nano-bench" OFF)
option (ENABLE_JWT "Enable jwt library" OFF)
option (ENABLE_RULE_ENGINE "Enable rule engine" OFF)

set (NNG_PROTO_MQTT_BROKER  ON)
set (NNG_TRANSPORT_MQTT_BROKER_TCP ON)
set (NNG_TRANSPORT_MQTT_BROKER_WS  ON)
set (FDB_DFT_API_VERSION 630)
set (FDB_DFT_DATABASE NULL)

if (NNG_ENABLE_TLS) 
  set (NNG_TRANSPORT_MQTT_BROKER_TLS ON)
  set (NNG_TRANSPORT_MQTT_BROKER_WSS ON)
endif()

if (NNG_ENABLE_TLS) 
  add_definitions(-DNNG_SUPP_TLS)
endif()

if (BUILD_BENCH) 
  add_definitions(-DSUPP_BENCH)
endif()

# If the compiler is not on Windows, does it support hiding the
# symbols by default?  For shared libraries we would like to do this.
if (NOT WIN32 AND NOT CYGWIN)
    check_c_compiler_flag(-fvisibility=hidden NANO_HIDDEN_VISIBILITY)
    if (NANO_HIDDEN_VISIBILITY)
        add_definitions(-DNANO_HIDDEN_VISIBILITY)
    endif ()
endif ()

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
    add_definitions(-DNANO_PLATFORM_POSIX)
    add_definitions(-DNANO_PLATFORM_LINUX)
    add_definitions(-DNANO_USE_EVENTFD)
    add_definitions(-DNANO_HAVE_ABSTRACT_SOCKETS)
    # Windows subsystem for Linux -- smells like Linux, but it has
    # some differences (SO_REUSEADDR for one).
    if (CMAKE_SYSTEM_VERSION MATCHES "Microsoft")
        add_definitions(-DNANO_PLATFORM_WSL)
    endif ()
    set(NANO_PLATFORM_POSIX ON)

elseif (CMAKE_SYSTEM_NAME MATCHES "Android")
    add_definitions(-DNANO_PLATFORM_POSIX)
    add_definitions(-DNANO_PLATFORM_LINUX)
    add_definitions(-DNANO_PLATFORM_ANDROID)
    add_definitions(-DNANO_USE_EVENTFD)
    set(NANO_PLATFORM_POSIX ON)

elseif (APPLE)
    add_definitions(-DNANO_PLATFORM_POSIX)
    add_definitions(-DNANO_PLATFORM_DARWIN)
    set(NANO_PLATFORM_POSIX ON)

elseif (CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
    add_definitions(-DNANO_PLATFORM_POSIX)
    add_definitions(-DNANO_PLATFORM_FREEBSD)
    set(NANO_PLATFORM_POSIX ON)

elseif (CMAKE_SYSTEM_NAME MATCHES "NetBSD")
    add_definitions(-DNANO_PLATFORM_POSIX)
    add_definitions(-DNANO_PLATFORM_NETBSD)
    set(NANO_PLATFORM_POSIX ON)

elseif (CMAKE_SYSTEM_NAME MATCHES "OpenBSD")
    add_definitions(-DNANO_PLATFORM_POSIX)
    add_definitions(-DNANO_PLATFORM_OPENBSD)
    set(NANO_PLATFORM_POSIX ON)

elseif (CMAKE_SYSTEM_NAME MATCHES "SunOS")
    add_definitions(-DNANO_PLATFORM_POSIX)
    add_definitions(-DNANO_PLATFORM_SUNOS)
    set(NANO_PLATFORM_POSIX ON)

elseif (CMAKE_SYSTEM_NAME MATCHES "Windows")
    add_definitions(-DNANO_PLATFORM_WINDOWS)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-D_CRT_RAND_S)
    set(NANO_PLATFORM_WINDOWS ON)

    # Target Windows Vista and later
    add_definitions(-D_WIN32_WINNT=0x0600)
    list(APPEND CMAKE_REQUIRED_DEFINITIONS -D_WIN32_WINNT=0x0600)

elseif (CMAKE_SYSTEM_NAME MATCHES "QNX")
    add_definitions(-DNANO_PLATFORM_POSIX)
    add_definitions(-D__EXT_BSD)
    add_definitions(-D_QNX_SOURCE)
    add_definitions(-DNANO_PLATFORM_QNX)
    set(NANO_PLATFORM_POSIX ON)

else ()
    message(AUTHOR_WARNING "WARNING: This platform may not be supported: ${CMAKE_SYSTEM_NAME}")
    message(AUTHOR_WARNING "${ISSUE_REPORT_MSG}")
    # blithely hope for POSIX to work
    add_definitions(-DNANO_PLATFORM_POSIX)
    set(NANO_PLATFORM_POSIX ON)
endif ()


set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  "${CMAKE_CURRENT_LIST_DIR}/cmake"
)

message("-- NanoMQ versions --")
# Determine NanoMQ versions.
file(READ "nanomq/include/version.h" nano_ver_h)

string(REGEX MATCH "NANO_VER_MAJOR ([0-9]*)" _ ${nano_ver_h})
set(NANO_MAJOR_VERSION ${CMAKE_MATCH_1})
string(REGEX MATCH "NANO_VER_MINOR ([0-9]*)" _ ${nano_ver_h})
set(NANO_MINOR_VERSION ${CMAKE_MATCH_1})
string(REGEX MATCH "NANO_VER_PATCH ([0-9]*)" _ ${nano_ver_h})
set(NANO_PATCH_VERSION ${CMAKE_MATCH_1})

set(NANO_ABI_SOVERSION 1)
set(NANO_ABI_VERSION "${NANO_MAJOR_VERSION}.${NANO_MINOR_VERSION}.${NANO_PATCH_VERSION}")
set(NANO_PACKAGE_VERSION "${NANO_ABI_VERSION}")
message(STATUS "Configuring for NanoMQ version ${NANO_ABI_VERSION}")

message("--configure--")

if (NOT DEFINED CFG_METHOD)
  message(STATUS "Default config method [CMAKE_CONFIG]")
  SET (CFG_METHOD CMAKE_CONFIG)
endif ()

if ("${CFG_METHOD}" STREQUAL "FILE_CONFIG")
  include(${CMAKE_CURRENT_SOURCE_DIR}/config.cmake.in)
elseif ("${CFG_METHOD}" STREQUAL "CMAKE_CONFIG")
  SET(NOLOG 1 CACHE STRING "run NanoMQ without printing log")
  SET(MQ 1 CACHE STRING "build this project suport mq")
  SET(NOWARNING 0 CACHE STRING "run NanoMQ without printing warning")
  SET(DEBUG 0 CACHE STRING "gdb support")
  SET(ASAN 0 CACHE STRING "asan support")
  SET(TSAN 0 CACHE STRING "tsan support")
  SET(PARALLEL 32 CACHE STRING "Parallelism (min 4, max 1000)")
else ()
  message(FATAL_ERROR "CFG_METHOD ERROR.")
endif ()

if (NOLOG)
  message("LOG=OFF")
  add_definitions(-DNOLOG)
else ()
  message("LOG=ON")
endif (NOLOG)


if (NOWARNING)
  message("NOWARNING")
  add_definitions(-DNOWARNING)
endif (NOWARNING)

if (MQ)
  if (NOT (APPLE OR NANO_PLATFORM_WINDOWS))
    add_definitions(-DMQ)
  endif()
endif (MQ)

if (BUILD_CLIENT)
  add_definitions(-DSUPP_CLIENT)
endif(BUILD_CLIENT)

if (BUILD_NNG_PROXY)
  add_definitions(-DSUPP_NNG_PROXY)
endif(BUILD_NNG_PROXY)

if (BUILD_ZMQ_GATEWAY)
  add_definitions(-DSUPP_ZMQ_GATEWAY)
endif(BUILD_ZMQ_GATEWAY)

if (DEBUG)
  message("DEBUG ")
  SET(CMAKE_BUILD_TYPE "Debug")
  add_definitions(-DDEBUG)
  if (ASAN)
    message("ASAN")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -fsanitize=address")
    add_definitions(-DASAN)
  endif (ASAN)
  if (TSAN)
    message("TSAN")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -fsanitize=thread")
    add_definitions(-DASAN)
  endif (TSAN)
endif(DEBUG)
message("-------------")

#add_executable(nanomq-nng nanomq/nanomq.c)

#add_dependencies(nanomq-nng nng_h)
if (ENABLE_JWT) 
  add_subdirectory(extern/l8w8jwt)
  add_definitions(-DSUPP_JWT)
endif (ENABLE_JWT)

if (ENABLE_RULE_ENGINE)
  add_definitions(-DSUPP_RULE_ENGINE)
  find_path(FOUNDATION_INCLUDE_DIR fdb_c.h /usr/include/foundationdb/ /usr/local/include/foundationdb/)
  find_library(FOUNDATION_LIBRARY NAMES fdb_c PATHS /usr/lib/ /usr/local/lib/)
  if (NOT FOUNDATION_INCLUDE_DIR OR NOT FOUNDATION_LIBRARY)
      message(FATAL_ERROR "Not found foundationdb")
  else ()
      message(STATUS "Found foundationdb: ${FOUNDATION_LIBRARY}")
  endif()

  if (NOT FDB_API_VERSION)
      set(FDB_API_VERSION 630)
  endif()

  if (FDB_DATABASE)
      set(FDB_DATABASE "\"${FDB_DATABASE}\"")
  else()
      set(FDB_DATABASE NULL)
  endif()

      configure_file(
            "${PROJECT_SOURCE_DIR}/fdbversionConfig.h.in"
            "${PROJECT_SOURCE_DIR}/nanolib/include/fdb_version.h"
      )

endif (ENABLE_RULE_ENGINE)

add_subdirectory(nng)
add_subdirectory(nanomq)

add_dependencies(nanomq nng)

if (ENABLE_JWT) 
  add_dependencies(nanomq l8w8jwt)
endif (ENABLE_JWT)


# Build Windows MSI package with WIX
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
	set(CMAKE_INSTALL_PREFIX "${PROJECT_SOURCE_DIR}/install")
endif()
message("Install prefix: " ${CMAKE_INSTALL_PREFIX})

# copy and relocate files
# install(TARGETS nanomq nanolib nng
# 	RUNTIME DESTINATION bin # executable file
# 	LIBRARY DESTINATION bin # dynamic library
# 	ARCHIVE DESTINATION lib)# static library
# install(FILES nng.h DESTINATION include)
install(FILES etc/nanomq.conf etc/nanomq_bridge.conf etc/nanomq_auth_http.conf etc/nanomq_auth_username.conf  DESTINATION config)
install(FILES etc/nanomq_gateway.conf etc/nanomq_rule.conf etc/nanomq_rule_engine.conf etc/nanomq_rule_sqlite.conf etc/nanomq_web_hook.conf DESTINATION config)
install(FILES libwinpthread-1.dll DESTINATION bin)

# set CPACK params

set(CPACK_PACKAGE_NAME "NanoMQ")
set(CPACK_PACKAGE_VERSION ${NANO_PACKAGE_VERSION})
set(CPACK_PACKAGE_CONTACT "contact@emqx.io")
set(CPACK_PACKAGE_VENDOR "nanomq.io")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "NanoMQ Edge Computing Kit")
set(CPACK_SOURCE_GENERATOR "TBZ2;TGZ;ZIP;WIX")
set(CPACK_SOURCE_IGNORE_FILES "/build/;/.git/;~$;${CPACK_SOURCE_IGNORE_FILES}")
set(CPACK_SOURCE_PACKAGE_FILE_NAME
        "${PROJECT_NAME}-v${NANO_PACKAGE_VERSION}-src")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "nanomq")
set(CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}-v${NANO_PACKAGE_VERSION}")  # set package name

set(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/LICENSE.txt") # set license in installer
set(CPACK_WIX_PATCH_FILE "${PROJECT_SOURCE_DIR}/wix-patch.xml") # set environment variables
set(CPACK_VER)

# package files into installer
include(CPack)
