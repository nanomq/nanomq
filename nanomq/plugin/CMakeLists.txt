# cmake_minimum_required(VERSION 3.0)
project(plugin_spi_stream)

set(SOURCE_FILE plugin_spi_stream.c)

set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/lib)

include_directories(${CMAKE_SOURCE_DIR}/nng/include)

add_library(plugin_spi_stream SHARED ${SOURCE_FILE})

target_compile_options(plugin_spi_stream PRIVATE -Wall -Wextra)
