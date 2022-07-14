cmake_minimum_required(VERSION 3.3)
project(nanomq_cli)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/nng/include/nng)

file(GLOB CLI_SOURCE "*.c")

add_executable(nanomq_cli ${CLI_SOURCE})

target_link_libraries(nanomq_cli nng)
add_dependencies(nanomq_cli nng)

if(BUILD_ZMQ_GATEWAY)
  find_package(ZeroMQ REQUIRED)
  include_directories("${ZeroMQ_INCLUDE_DIR}")
  target_link_libraries(nanomq_cli libzmq)
endif(BUILD_ZMQ_GATEWAY)
