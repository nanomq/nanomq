
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

option(NOLOG "build this project nolog" OFF)
option(MQ "build this project suport mq" ON)
option(DEBUG "gdb support" OFF)

if (NOLOG)
	add_definitions(-DNOLOG)
endif (NOLOG)

if (DEBUG)
  SET(CMAKE_BUILD_TYPE "Debug")
  SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g2 -ggdb")
  SET(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")
  add_definitions(-DDEBUG)
endif(DEBUG)
if (MQ)
	add_definitions(-DMQ)
endif (MQ)

#add_executable(nanomq-nng nanomq/nanomq.c)

#add_dependencies(nanomq-nng nng_h)


add_subdirectory(nng)
add_subdirectory(nanolib)
add_subdirectory(nanomq)


add_dependencies(nanomq nng)
add_dependencies(nanomq nanolib)
