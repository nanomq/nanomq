#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
# not finished yet #

cmake_minimum_required (VERSION 2.8.12)
SET(CMAKE_C_STANDARD 99)

project(nanomq-nng)

include(CheckCCompilerFlag)

set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  "${CMAKE_CURRENT_LIST_DIR}/cmake"
)

include(NanoMQHelpers)

option (BUILD_NANOMQ_CLI "Build nanomq CLI" OFF)
option (BUILD_CLIENT "Build nanomq client" ON)
option (BUILD_QUIC_CLI "Build quic client" OFF)
option (BUILD_NNG_PROXY "Build nng proxy" ON)
option (BUILD_ZMQ_GATEWAY "Build zmq gateway" OFF)
option (BUILD_VSOMEIP_GATEWAY "Build vsomeip gateway" OFF)
option (BUILD_DDS_PROXY "Build dds proxy" OFF)
option (BUILD_NFTP "Build nftp client" OFF)
option (BUILD_BENCH "Build nano-bench" OFF)
option (BUILD_APP_LIB "Build library for app" OFF)
option (ENABLE_JWT "Enable jwt library" OFF)
option (ENABLE_RULE_ENGINE "Enable rule engine" OFF)
option (ENABLE_MYSQL "Enable MYSQL" OFF)
option (ENABLE_POSTGRESQL "Enable POSTGRESQL" OFF)
option (ENABLE_TIMESCALEDB "Enable TIMESCALEDB" OFF)
option (ENABLE_AWS_BRIDGE "Enable aws bridge" OFF)
option (ENABLE_SYSLOG "Enable syslog" ON)
option (ENABLE_PARQUET "Enable parquet" OFF)
option (ENABLE_BLF "Enable BLF" OFF)
option (ENABLE_ICEORYX "Enable iceoryx" OFF)
option (NOLOG "Disable log" OFF)
option (ENABLE_ACL "Enable ACL" ON)
option (NANOMQ_TESTS "Enable nanomq unit tests" OFF)
option (BUILD_WITH_STATIC_LIBS "build with static libs" OFF)

set (NNG_PROTO_MQTT_BROKER  ON)
set (NNG_TRANSPORT_MQTT_BROKER_TCP ON)
set (NNG_TRANSPORT_MQTT_BROKER_WS  ON)
set (FDB_DFT_API_VERSION 630)
set (FDB_DFT_DATABASE NULL)

if (NNG_ENABLE_TLS) 
  set (NNG_TRANSPORT_MQTT_BROKER_TLS ON)
  set (NNG_TRANSPORT_MQTT_BROKER_WSS ON)
  add_definitions(-DNNG_SUPP_TLS)
endif()

if (NNG_ENABLE_SQLITE)
  add_definitions(-DNNG_SUPP_SQLITE)
endif()

if (NANOMQ_TESTS)
    enable_testing()
    set(all_tests, "")
    set(BUILD_STATIC_LIB ON)
    add_definitions(-DENABLE_NANOMQ_TESTS)
endif ()

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

if (NANO_PLATFORM_WINDOWS)
  set (ENABLE_SYSLOG OFF)
endif ()

if(BUILD_APP_LIB)
  set(BUILD_NANO_LIB ON)
  set(BUILD_CLIENT OFF)
  set(BUILD_BENCH OFF)
  set(BUILD_NNG_PROXY OFF)
  set(NOLOG ON)
  set(ENABLE_SYSLOG OFF)
  add_definitions(-DBUILD_APP_LIB)
endif()

if (NOT NOLOG)
  add_definitions(-DENABLE_LOG)

  if (ENABLE_SYSLOG)
    add_definitions(-DSUPP_SYSLOG)
  endif ()

endif ()

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

SET(DEBUG 0 CACHE STRING "gdb support")
SET(ASAN 0 CACHE STRING "asan support")
SET(TSAN 0 CACHE STRING "tsan support")

if(BUILD_NANO_LIB)
  add_definitions(-DSUPP_NANO_LIB)
endif(BUILD_NANO_LIB)

if(BUILD_STATIC_LIB OR BUILD_SHARED_LIBS)
  add_definitions(-DSUPP_NANO_LIB)
endif()

if(BUILD_CLIENT)
  set(BUILD_NANOMQ_CLI ON)
  add_definitions(-DSUPP_CLIENT)
endif(BUILD_CLIENT)

if(BUILD_BENCH)
  set(BUILD_NANOMQ_CLI ON)
  add_definitions(-DSUPP_BENCH)
endif()

if(ENABLE_PARQUET)
  set(NNG_ENABLE_PARQUET ON)
  add_definitions(-DSUPP_PARQUET)
endif()

if(ENABLE_BLF)
  set(NNG_ENABLE_BLF ON)
  add_definitions(-DSUPP_BLF)
endif()

if(ENABLE_PLUGIN)
  if (NOT WIN32 AND NOT CYGWIN)
    set(NNG_ENABLE_PLUGIN ON)
    add_definitions(-DSUPP_PLUGIN)
  else()
    message(FATAL_ERROR "Plugin is not supported on Windows")
  endif()
endif(ENABLE_PLUGIN)

if(NNG_ENABLE_QUIC)
  set(BUILD_QUIC_CLI ON)
  add_definitions(-DSUPP_QUIC)
  # This is for enabling beta feature of MSQUIC such as CUBIC/BBR
  add_definitions(-DQUIC_API_ENABLE_PREVIEW_FEATURES)
endif()

if(ENABLE_ICEORYX)
  set(BUILD_ICEORYX_CLI ON)
  set(NNG_ENABLE_ICEORYX ON)
  add_definitions(-DSUPP_ICEORYX)
endif(ENABLE_ICEORYX)

if(ENABLE_ACL)
  message("-- Build NanoMQ with ACL support --")
  set(ENABLE_ACL ON)
  add_definitions(-DACL_SUPP)
endif()

if(BUILD_NNG_PROXY)
  set(BUILD_NANOMQ_CLI ON)
  add_definitions(-DSUPP_NNG_PROXY)
endif(BUILD_NNG_PROXY)

if(BUILD_ZMQ_GATEWAY)
  set(BUILD_NANOMQ_CLI ON)
  add_definitions(-DSUPP_ZMQ_GATEWAY)
endif(BUILD_ZMQ_GATEWAY)

if(BUILD_VSOMEIP_GATEWAY)
  set(BUILD_NANOMQ_CLI ON)
  add_definitions(-DSUPP_VSOMEIP_GATEWAY)
endif(BUILD_VSOMEIP_GATEWAY)

if(BUILD_DDS_PROXY)
  set(BUILD_NANOMQ_CLI ON)
  add_definitions(-DSUPP_DDS_PROXY)
endif(BUILD_DDS_PROXY)

if(BUILD_NFTP)
  set(BUILD_NANOMQ_CLI ON)
  add_definitions(-DSUPP_NFTP)
endif(BUILD_NFTP)

if (DEBUG)
  message("-- MODE [Debug] --")
  SET(CMAKE_BUILD_TYPE "Debug")
  add_definitions(-DDEBUG)
  add_definitions(-DLOG_USE_COLOR)
  set(CMAKE_C_CLANG_TIDY ${CMAKE_C_CLANG_TIDY_AVAILABLE})
  if (NNG_ENABLE_PARQUET)
    set(CMAKE_CXX_CLANG_TIDY ${CMAKE_C_CLANG_TIDY_AVAILABLE})
    set(CMAKE_CXX_CPPCHECK ${CMAKE_C_CPPCHECK_AVAILABLE})
    set(CMAKE_C_CPPCHECK ${CMAKE_C_CPPCHECK_AVAILABLE})
  endif (NNG_ENABLE_PARQUET)

  if (ASAN)
    message("* ASAN")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -fsanitize=address")
    if (NNG_ENABLE_PARQUET OR NNG_ENABLE_BLF)
      SET(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -g -fsanitize=address")
    endif (NNG_ENABLE_PARQUET OR NNG_ENABLE_BLF)
    add_definitions(-DASAN)
  endif (ASAN)
  if (TSAN)
    message("* TSAN")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -fsanitize=thread")
    if (NNG_ENABLE_PARQUET OR NNG_ENABLE_BLF)
      SET(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -g -fsanitize=thread")
    endif (NNG_ENABLE_PARQUET OR NNG_ENABLE_BLF)
    add_definitions(-DTSAN)
  endif (TSAN)
else()
  message("-- MODE [Release] --")
endif(DEBUG)

if (DEBUG_TRACE)
  message("-- MODE [enable ptrace] --")
  SET(CMAKE_BUILD_TYPE "Debug")
  add_definitions(-DDEBUG_TRACE)
endif(DEBUG_TRACE)

if (NNG_ENABLE_COVERAGE)
    # NB: This only works for GCC and Clang 3.0 and newer.  If your stuff
    # is older than that, you will need to find something newer.  For
    # correct reporting, we always turn off all optimizations.
    if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
        set(NNG_COVERAGE_C_FLAGS "-g -O0 --coverage")
        set(CMAKE_SHARED_LINKER_FLAGS --coverage)
    elseif (CMAKE_C_COMPILER_ID MATCHES "Clang")
        set(NNG_COVERAGE_C_FLAGS "-g -O0 --coverage")
        set(CMAKE_SHARED_LINKER_FLAGS --coverage)
    else ()
        message(FATAL_ERROR "Unable to enable coverage for your compiler.")
    endif ()
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${NNG_COVERAGE_C_FLAGS}")
endif ()

if (ENABLE_JWT) 
  add_subdirectory(extern/l8w8jwt)
  add_definitions(-DSUPP_JWT)
endif (ENABLE_JWT)

if(ENABLE_AWS_BRIDGE)
  message("ENABLE_AWS_BRIDGE=ON")
  add_definitions(-DSUPP_AWS_BRIDGE)
  add_definitions(-DMQTT_DO_NOT_USE_CUSTOM_CONFIG)
endif(ENABLE_AWS_BRIDGE)

if (ENABLE_RULE_ENGINE)
  add_definitions(-DSUPP_RULE_ENGINE)
  ## find_path(FOUNDATION_INCLUDE_DIR fdb_c.h /usr/include/foundationdb/ /usr/local/include/foundationdb/)
  ## find_library(FOUNDATION_LIBRARY NAMES fdb_c PATHS /usr/lib/ /usr/local/lib/)
  ## if (NOT FOUNDATION_INCLUDE_DIR OR NOT FOUNDATION_LIBRARY)
  ##     message(FATAL_ERROR "Not found foundationdb")
  ## else ()
  ##     message(STATUS "Found foundationdb: ${FOUNDATION_LIBRARY}")
  ## endif()

  ## if (NOT FDB_API_VERSION)
  ##     set(FDB_API_VERSION 630)
  ## endif()

  ## if (FDB_DATABASE)
  ##     set(FDB_DATABASE "\"${FDB_DATABASE}\"")
  ## else()
  ##     set(FDB_DATABASE NULL)
  ## endif()

  ## configure_file(
  ##       "${PROJECT_SOURCE_DIR}/fdbversionConfig.h.in"
  ##       "${PROJECT_SOURCE_DIR}/nanomq/include/fdb_version.h"
  ## )

endif (ENABLE_RULE_ENGINE)

if (ENABLE_MYSQL)
  add_definitions(-DSUPP_MYSQL)
endif (ENABLE_MYSQL)

if (ENABLE_POSTGRESQL)
  add_definitions(-DSUPP_POSTGRESQL)
endif (ENABLE_POSTGRESQL)

if (ENABLE_TIMESCALEDB)
  add_definitions(-DSUPP_TIMESCALEDB)
endif (ENABLE_TIMESCALEDB)


add_subdirectory(nng)
add_subdirectory(nanomq)

add_dependencies(nanomq nng)

if (ENABLE_JWT) 
  add_dependencies(nanomq l8w8jwt)
endif (ENABLE_JWT)

if(BUILD_NANOMQ_CLI)
  add_subdirectory(nanomq_cli)
endif(BUILD_NANOMQ_CLI)

# Build Windows MSI package with WIX
if (NANO_PLATFORM_WINDOWS)
  if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
         set(CMAKE_INSTALL_PREFIX "${PROJECT_SOURCE_DIR}/install")
  endif()
endif()
message("Install prefix: " ${CMAKE_INSTALL_PREFIX})

# copy and relocate files
# install(TARGETS nanomq nanolib nng
# 	RUNTIME DESTINATION bin # executable file
# 	LIBRARY DESTINATION bin # dynamic library
# 	ARCHIVE DESTINATION lib)# static library
# install(FILES nng.h DESTINATION include)

FILE(GLOB CONFIG_FILES "${PROJECT_SOURCE_DIR}/etc/*.conf")

if (NOT WIN32 AND NOT CYGWIN)
  install(FILES ${CONFIG_FILES} DESTINATION ${CMAKE_INSTALL_PREFIX}/etc)
else ()
  install(FILES ${CONFIG_FILES}  DESTINATION config)
  install(FILES libwinpthread-1.dll DESTINATION bin)
endif ()


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
