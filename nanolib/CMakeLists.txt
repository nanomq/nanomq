#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.

cmake_minimum_required (VERSION 2.8.8)
# SET(CMAKE_C_FLAGS "-std=c99")
SET(CMAKE_C_FLAGS "-std=gnu99")
SET(CMAKE_CXX_FLAGS "-std=c++11 -O3")

project(nanolib)

SET(CMAKE_CXX_FLAGS "-std=c++11 -O3")

if (DEBUG AND ASAN)
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -fsanitize=address")
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fsanitize=address")
endif (DEBUG AND ASAN)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to '${DEFAULT_BUILD_TYPE}' as none was specified.")
  set(CMAKE_BUILD_TYPE "${DEFAULT_BUILD_TYPE}" CACHE STRING "Choose the type of build." FORCE)
  # Set the possible values of build type for cmake-gui
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

#aux_source_directory(. DIRSRCS)

include_directories(./include)
include_directories(${CMAKE_SOURCE_DIR}/nanomq/include)
find_package(Threads)

#add_subdirectory(./packet_parser)

# find_package(nng CONFIG REQUIRED)

# list of source files
set(libsrc hash.cc mqtt_db.c zmalloc.c conf.c file.c cmd.c)

# this is the "object library" target: compiles the sources only once
add_library(nanolib OBJECT ${libsrc})

target_include_directories(${PROJECT_NAME} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
    PRIVATE src)

# shared libraries need PIC
set_property(TARGET nanolib PROPERTY POSITION_INDEPENDENT_CODE 1)
#set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION 1)

# shared and static libraries built from the same object files
add_library(nano_shared SHARED $<TARGET_OBJECTS:nanolib>)
#add_library(nanolib_static STATIC $<TARGET_OBJECTS:nanolib>)
target_link_libraries(nano_shared ${CMAKE_THREAD_LIBS_INIT})

target_link_libraries(nano_shared ${CMAKE_THREAD_LIBS_INIT})

add_executable(test test.c)
target_link_libraries(test nano_shared)


install(TARGETS nano_shared EXPORT nanolibConfig
    ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR})

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME})

install(EXPORT nanolibConfig DESTINATION share/nanolib/cmake)

export(TARGETS ${PROJECT_NAME} FILE nanolibConfig.cmake)
add_custom_target(nanodist COMMAND ${CMAKE_MAKE_PROGRAM} package_source)
