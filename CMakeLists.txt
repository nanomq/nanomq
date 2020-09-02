
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
# not finished yet #

cmake_minimum_required (VERSION 2.8.8)

project(nanomq-nng)

set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  "${CMAKE_CURRENT_LIST_DIR}/cmake"
)

option(NOLOG "build this project nolog" OFF)

if (NOLOG)
	add_definitions(-DNOLOG)
endif (NOLOG)

#add_executable(nanomq-nng nanomq/nanomq.c)

#add_dependencies(nanomq-nng nng_h)


add_subdirectory(nng)
add_subdirectory(nanolib)
add_subdirectory(nanomq)


add_dependencies(nanomq nng)
add_dependencies(nanomq nanolib)
