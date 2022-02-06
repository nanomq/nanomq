#
# Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

nng_directory(nngcat)

if (NNG_ENABLE_NNGCAT)
    add_executable(nngcat nngcat.c)
    target_include_directories(nngcat PUBLIC ${PROJECT_SOURCE_DIR}/src)
    target_link_libraries(nngcat nng nng_private)
    install(TARGETS nngcat RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            COMPONENT Tools)

    if (NNG_TESTS AND CMAKE_SYSTEM_NAME MATCHES "Linux")
        include(FindUnixCommands)
    endif ()
endif ()
