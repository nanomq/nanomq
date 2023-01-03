cmake_minimum_required(VERSION 3.3)
project(nanomq_cli)


if(DEBUG AND ASAN)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -fsanitize=address")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fsanitize=address")
endif(DEBUG AND ASAN)

if(DEBUG AND TSAN)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -fsanitize=thread")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fsanitize=thread")
endif(DEBUG AND TSAN)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/nng/include/nng)

file(GLOB CLI_SOURCE "*.c")

if(BUILD_SOMEIP_GATEWAY) 
  find_package (vsomeip3 REQUIRED)
  find_package(Boost 1.55 COMPONENTS system thread log REQUIRED)
  include_directories (
      ${Boost_INCLUDE_DIR}
      ${VSOMEIP_INCLUDE_DIRS}
  )
  add_executable(nanomq_cli ${CLI_SOURCE} vsomeip_gateway.cc)
  target_link_libraries(nanomq_cli vsomeip3 ${Boost_LIBRARIES})
else()
  add_executable(nanomq_cli ${CLI_SOURCE})
endif(BUILD_SOMEIP_GATEWAY) 

target_link_libraries(nanomq_cli nng)

if(BUILD_QUIC_CLI)
  target_link_libraries(nanomq_cli msquic)
endif(BUILD_QUIC_CLI)

add_dependencies(nanomq_cli nng)

if(BUILD_ZMQ_GATEWAY)
  find_package(ZeroMQ REQUIRED)
  include_directories("${ZeroMQ_INCLUDE_DIR}")
  target_link_libraries(nanomq_cli zmq)
  target_link_libraries(nanomq_cli stdc++)
endif(BUILD_ZMQ_GATEWAY)

install(TARGETS nanomq_cli RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
                                   COMPONENT Tools)
