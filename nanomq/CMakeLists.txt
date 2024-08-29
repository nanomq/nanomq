#
# This software is supplied under the terms of the MIT License, a copy of which
# should be located in the distribution where this file was obtained
# (LICENSE.txt).  A copy of the license may also be found online at
# https://opensource.org/licenses/MIT.

cmake_minimum_required(VERSION 2.8.12)

project(nanomq)
SET(CMAKE_C_STANDARD 99)

if(DEBUG AND ASAN)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -fsanitize=address")
  # set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fsanitize=address")
endif(DEBUG AND ASAN)

if(DEBUG AND TSAN)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -fsanitize=thread")
  # SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fsanitize=thread")
endif(DEBUG AND TSAN)

aux_source_directory(. DIRSRCS)

include_directories(./)
include_directories(${CMAKE_SOURCE_DIR}/nanomq/include)
include_directories(${CMAKE_SOURCE_DIR}/nng/include/nng)
if(ENABLE_JWT)
  include_directories(${CMAKE_SOURCE_DIR}/extern/l8w8jwt/include)
endif(ENABLE_JWT)

add_subdirectory(apps)
add_subdirectory(tests)

# set(PARALLEL 128 CACHE STRING "Parallelism (min 4, max 1000)")

set(SOURCES
    process.c
    bridge.c
    pub_handler.c
    sub_handler.c
    unsub_handler.c
    hashmap.c
    rest_api.c
    web_server.c
    webhook_inproc.c
    webhook_post.c
    aws_bridge.c
    nanomq_rule.c
    conf_api.c
    cmd_proc.c
    acl_handler.c
    mqtt_api.c
    nanomq.c
    apps/broker.c
)

if(NNG_ENABLE_PLUGIN)
  set(SOURCES ${SOURCES} plugin/plugin.c)
endif(NNG_ENABLE_PLUGIN)

include_directories(${FOUNDATION_INCLUDE_DIR})

if(BUILD_STATIC_LIB)
  add_library(nanomq  ${SOURCES})
elseif (BUILD_SHARED_LIBS) 
  add_library(nanomq SHARED ${SOURCES})
  set_property(TARGET nanomq PROPERTY POSITION_INDEPENDENT_CODE 1)
else()
  add_executable(nanomq ${SOURCES})
endif()

if(ENABLE_MYSQL)

  include(FindPkgConfig)
  pkg_check_modules(LIBMYSQLCLIENT REQUIRED mysqlclient)

  foreach(FLAG ${LIBMYSQLCLIENT_CFLAGS_OTHER})
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${FLAG}")
  endforeach()

  link_directories(${LIBMYSQLCLIENT_LIBRARY_DIRS})
  include_directories(${MYSQL_INCLUDE_DIR})
  include_directories(${LIBMYSQLCLIENT_INCLUDE_DIRS})
  # message(STATUS, "${LIBMYSQLCLIENT_INCLUDE_DIRS}")
  target_link_libraries(nanomq ${LIBMYSQLCLIENT_LIBRARIES})

endif(ENABLE_MYSQL)

if(ENABLE_POSTGRESQL)

  find_package(PostgreSQL REQUIRED)

  # Link to the PostgreSQL C library
  target_link_libraries(nanomq ${PostgreSQL_LIBRARIES})

  # Include the PostgreSQL C library headers
  target_include_directories(nanomq PUBLIC ${PostgreSQL_INCLUDE_DIRS})

endif(ENABLE_POSTGRESQL)

if(ENABLE_TIMESCALEDB)

  find_package(PostgreSQL REQUIRED)

  # Link to the PostgreSQL C library
  target_link_libraries(nanomq ${PostgreSQL_LIBRARIES})

  # Include the PostgreSQL C library headers
  target_include_directories(nanomq PUBLIC ${PostgreSQL_INCLUDE_DIRS})

endif(ENABLE_TIMESCALEDB)

if(ENABLE_AWS_BRIDGE)
  target_link_libraries(nanomq
      aws_iot_mqtt
      aws_iot_backoff_algorithm
      sockets_posix
      openssl_posix
      clock_posix)

endif(ENABLE_AWS_BRIDGE)

if(ENABLE_JWT)
  target_link_libraries(nanomq l8w8jwt)
endif(ENABLE_JWT)

if(NNG_ENABLE_QUIC)
  target_link_libraries(nanomq msquic OpenSSLQuic)
endif(NNG_ENABLE_QUIC)

if(BUILD_QUIC_CLI)
  target_link_libraries(nanomq nng msquic)
endif(BUILD_QUIC_CLI)

if (CMAKE_INSTALL_RPATH)
  set_target_properties(nanomq PROPERTIES LINK_FLAGS "-Wl,-rpath,${CMAKE_INSTALL_RPATH}")
  message("Dynamic link rpath: ${CMAKE_INSTALL_RPATH}")
endif()



target_link_libraries(nanomq nng)

target_compile_definitions(nanomq PRIVATE -DPARALLEL=${PARALLEL})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
# Package all static files into one libnanomq.a
if(BUILD_STATIC_LIB)
  set(FULL_OUTPUT_PATH ${CMAKE_BINARY_DIR}/libnanomq.a)
  set (tmp ${CMAKE_BINARY_DIR}/tmp)
  file(WRITE ${tmp} "create ${FULL_OUTPUT_PATH}\n")
  file(APPEND ${tmp} "addlib ${CMAKE_BINARY_DIR}/nanomq/libnanomq.a\n")
  file(APPEND ${tmp} "addlib ${CMAKE_BINARY_DIR}/nng/libnng.a\n")
  file(APPEND ${tmp} "addlib ${CMAKE_BINARY_DIR}/nanomq/apps/libapps.a\n")
  file(APPEND ${tmp} "save\n")
  file(APPEND ${tmp} "end\n")

  add_custom_target(libnano
          COMMAND ar -M < ${CMAKE_BINARY_DIR}/tmp
          COMMAND rm ${CMAKE_BINARY_DIR}/tmp
          COMMAND rm ${CMAKE_BINARY_DIR}/nanomq/libnanomq.a
          WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
          DEPENDS nanomq nng
          )
endif(BUILD_STATIC_LIB)

# TODO INSTALL

if(BUILD_STATIC_LIB OR BUILD_SHARED_LIBS)
  # install(
  #   FILES ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/libnanomq.a
  #   LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR})

else()
  install(
    TARGETS nanomq
    EXPORT nanomqConfig
    # ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    # LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT services)

  install(
    DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}
    COMPONENT services)

  install(
    EXPORT nanomqConfig
    DESTINATION share/nanomq/cmake
    COMPONENT services)

endif()
