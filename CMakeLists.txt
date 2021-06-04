#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
# not finished yet #

cmake_minimum_required (VERSION 2.8.8)
SET(CMAKE_C_FLAGS "-std=c99")
SET(CMAKE_CXX_FLAGS "-std=c++11 -O3")

project(nanomq-nng)

set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  "${CMAKE_CURRENT_LIST_DIR}/cmake"
)

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
  SET(PARALLEL 32 CACHE STRING "Parallelism (min 4, max 1000)")
else ()
  message(FATAL_ERROR "CFG_METHOD ERROR.")
endif ()

message("--configure--")
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
  add_definitions(-DMQ)
endif (MQ)

if (DEBUG)
  message("DEBUG ")
  SET(CMAKE_BUILD_TYPE "Debug")
  SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g2 -ggdb")
  SET(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")
  add_definitions(-DDEBUG)
  if (ASAN)
    message("ASAN")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -fsanitize=address")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fsanitize=address")
    add_definitions(-DASAN)
  endif (ASAN)
endif(DEBUG)
message("-------------")

#add_executable(nanomq-nng nanomq/nanomq.c)

#add_dependencies(nanomq-nng nng_h)


add_subdirectory(nng)
add_subdirectory(nanolib)
add_subdirectory(nanomq)


add_dependencies(nanomq nng)
add_dependencies(nanomq nanolib)
