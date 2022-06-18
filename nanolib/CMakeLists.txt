#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.


cmake_minimum_required (VERSION 2.8.8)

# SET(CMAKE_C_FLAGS "-std=c99")
SET(CMAKE_C_FLAGS "-std=gnu99")
project(nanolib)

if (DEBUG AND ASAN)
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -fsanitize=address")
#   SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fsanitize=address")
endif (DEBUG AND ASAN)

if (DEBUG AND TSAN)
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -fsanitize=thread")
#   SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fsanitize=thread")
endif (DEBUG AND TSAN)

# Build Types
set(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE}
    CACHE STRING "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel tsan asan lsan msan ubsan"
    FORCE)

# ThreadSanitizer
set(CMAKE_C_FLAGS_TSAN
    "-fsanitize=thread -g -O1"
    CACHE STRING "Flags used by the C compiler during ThreadSanitizer builds."
    FORCE)
# set(CMAKE_CXX_FLAGS_TSAN
#     "-fsanitize=thread -g -O1"
#     CACHE STRING "Flags used by the C++ compiler during ThreadSanitizer builds."
#     FORCE)

# AddressSanitize
set(CMAKE_C_FLAGS_ASAN
    "-fsanitize=address -fno-optimize-sibling-calls -fsanitize-address-use-after-scope -fno-omit-frame-pointer -g -O1"
    CACHE STRING "Flags used by the C compiler during AddressSanitizer builds."
    FORCE)
# set(CMAKE_CXX_FLAGS_ASAN
#     "-fsanitize=address -fno-optimize-sibling-calls -fsanitize-address-use-after-scope -fno-omit-frame-pointer -g -O1"
#     CACHE STRING "Flags used by the C++ compiler during AddressSanitizer builds."
#     FORCE)

# LeakSanitizer
set(CMAKE_C_FLAGS_LSAN
    "-fsanitize=leak -fno-omit-frame-pointer -g -O1"
    CACHE STRING "Flags used by the C compiler during LeakSanitizer builds."
    FORCE)
# set(CMAKE_CXX_FLAGS_LSAN
#     "-fsanitize=leak -fno-omit-frame-pointer -g -O1"
#     CACHE STRING "Flags used by the C++ compiler during LeakSanitizer builds."
#     FORCE)

# MemorySanitizer
set(CMAKE_C_FLAGS_MSAN
    "-fsanitize=memory -fno-optimize-sibling-calls -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer -g -O2"
    CACHE STRING "Flags used by the C compiler during MemorySanitizer builds."
    FORCE)
#  set(CMAKE_CXX_FLAGS_MSAN
#      "-fsanitize=memory -fno-optimize-sibling-calls -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer -g -O2"
#      CACHE STRING "Flags used by the C++ compiler during MemorySanitizer builds."
#      FORCE)

# UndefinedBehaviour
set(CMAKE_C_FLAGS_UBSAN
    "-fsanitize=undefined"
    CACHE STRING "Flags used by the C compiler during UndefinedBehaviourSanitizer builds."
    FORCE)
# set(CMAKE_CXX_FLAGS_UBSAN
#     "-fsanitize=undefined"
#     CACHE STRING "Flags used by the C++ compiler during UndefinedBehaviourSanitizer builds."
#     FORCE)


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
# set(libsrc hash_table.c mqtt_db.c zmalloc.c ) #conf.c file.c cmd.c nano_alloc.c nano_lmq.c)
set(libsrc hash_table.c mqtt_db.c zmalloc.c conf.c file.c 
    cmd.c nano_alloc.c nano_lmq.c env.c 
    libs/base64.c libs/cJSON.c db_cli.c)

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

if (ENABLE_RULE_ENGINE) 
    target_link_libraries(nano_shared ${FOUNDATION_LIBRARY})
endif (ENABLE_RULE_ENGINE)


## add_executable(nano_test test.c test_hash.c test_dbtree.c)
## target_link_libraries(nano_test nano_shared)
## target_link_libraries(nano_test ${FOUNDATION_LIBRARY})



install(TARGETS nano_shared EXPORT nanolibConfig
    ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR})

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME})

install(EXPORT nanolibConfig DESTINATION share/nanolib/cmake)

export(TARGETS ${PROJECT_NAME} FILE nanolibConfig.cmake)
add_custom_target(nanodist COMMAND ${CMAKE_MAKE_PROGRAM} package_source)
