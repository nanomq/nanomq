# Copyright 2023 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.



####### Expanded from @PACKAGE_INIT@ by configure_package_config_file() #######
####### Any changes to this file will be overwritten by the next CMake run ####
####### The input file was nng-config.cmake.in                            ########

get_filename_component(PACKAGE_PREFIX_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../" ABSOLUTE)

macro(set_and_check _var _file)
  set(${_var} "${_file}")
  if(NOT EXISTS "${_file}")
    message(FATAL_ERROR "File or directory ${_file} referenced by variable ${_var} does not exist !")
  endif()
endmacro()

macro(check_required_components _NAME)
  foreach(comp ${${_NAME}_FIND_COMPONENTS})
    if(NOT ${_NAME}_${comp}_FOUND)
      if(${_NAME}_FIND_REQUIRED_${comp})
        set(${_NAME}_FOUND FALSE)
      endif()
    endif()
  endforeach()
endmacro()

####################################################################################

set(NNG_MAJOR_VERSION "1")
set(NNG_MINOR_VERSION "11")
set(NNG_PATCH_VERSION "0")

set_and_check(NNG_INCLUDE_DIRS "${PACKAGE_PREFIX_DIR}/include/nng")

include("${CMAKE_CURRENT_LIST_DIR}/nng-targets.cmake")

# Make sure we find packages for our dependencies
foreach(_PKG IN ITEMS Threads)
	find_package(${_PKG} REQUIRED)
endforeach ()

set(NNG_LIBRARY nng::nng)

check_required_components(nng)
