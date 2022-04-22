#
# This software is supplied under the terms of the MIT License, a copy of which
# should be located in the distribution where this file was obtained
# (LICENSE.txt).  A copy of the license may also be found online at
# https://opensource.org/licenses/MIT.

cmake_minimum_required(VERSION 2.8.8)

project(nanomq)
# SET(CMAKE_C_FLAGS "-std=c99")
set(CMAKE_C_FLAGS "-std=gnu99")
set(CMAKE_CXX_FLAGS "-std=c++11 -O3")

if(DEBUG AND ASAN)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -fsanitize=address")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fsanitize=address")
endif(DEBUG AND ASAN)

aux_source_directory(. DIRSRCS)

include_directories(./)
include_directories(${CMAKE_SOURCE_DIR}/nanomq/include)
include_directories(${CMAKE_SOURCE_DIR}/nng/include/nng)
include_directories(${CMAKE_SOURCE_DIR}/nanolib/include)
if (ENABLE_JWT)
  include_directories(${CMAKE_SOURCE_DIR}/extern/l8w8jwt/include)
endif (ENABLE_JWT)

add_subdirectory(apps)

# set(PARALLEL 128 CACHE STRING "Parallelism (min 4, max 1000)")

# find_package(nng CONFIG REQUIRED) find_package(nanolib CONFIG REQUIRED)

# if (NANOLIB_FOUND) INCLUDE_DIRECTORIES(${NANOLIB_INCLUDE_DIR})
# TARGET_LINK_LIBRARIES(nanomq ${NANOLIB_LIBRARY}) else (NANOLIB_FOUND)
# MESSAGE(FATAL_ERROR "nanolib library not found")
set(SOURCES
    nanomq.c
    process.c
    apps.c
    bridge.c
    pub_handler.c
    sub_handler.c
    unsub_handler.c
    rest_api.c
    web_server.c
    webhook_inproc.c
    webhook_post.c
    )

add_executable(nanomq ${SOURCES})

# target_link_libraries(nanomq apps nano_shared)
if (ENABLE_JWT)
  target_link_libraries(nanomq l8w8jwt)
endif (ENABLE_JWT)
target_link_libraries(nanomq apps nanolib)
target_link_libraries(nanomq nng)
target_compile_definitions(nanomq PRIVATE -DPARALLEL=${PARALLEL})

install(
  TARGETS nanomq
  EXPORT nanomqConfig
  # ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
  # LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

install(DIRECTORY include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME})

install(EXPORT nanomqConfig DESTINATION share/nanomq/cmake)
