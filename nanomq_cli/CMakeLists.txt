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
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/dds2mqtt)
include_directories(${CMAKE_SOURCE_DIR}/nng/include/nng)

file(GLOB CLI_SOURCE "*.c" "dds2mqtt/*.c")


if(BUILD_VSOMEIP_GATEWAY)
  file(GLOB CLI_CXX_SOURCE "*.cc")
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${NNG_COVERAGE_C_FLAGS}")
  set(CLI_SOURCE ${CLI_SOURCE} ${CLI_CXX_SOURCE})
endif(BUILD_VSOMEIP_GATEWAY)


add_executable(nanomq_cli ${CLI_SOURCE})

if(BUILD_DDS_PROXY)
  find_package(CycloneDDS REQUIRED)
  idlc_generate(TARGET dds_type_lib FILES "dds2mqtt/dds_type.idl" WARNINGS no-implicit-extensibility)

  target_link_libraries(nanomq_cli dds_type_lib CycloneDDS::ddsc)
endif(BUILD_DDS_PROXY)

target_link_libraries(nanomq_cli nng)

if(BUILD_QUIC_CLI)
  target_link_libraries(nanomq_cli msquic OpenSSLQuic)
endif(BUILD_QUIC_CLI)

if(BUILD_ZMQ_GATEWAY)
  find_package(ZeroMQ REQUIRED)
  include_directories("${ZeroMQ_INCLUDE_DIR}")
  target_link_libraries(nanomq_cli zmq)
  target_link_libraries(nanomq_cli stdc++)
endif(BUILD_ZMQ_GATEWAY)

if(BUILD_VSOMEIP_GATEWAY)
  find_package (vsomeip3 REQUIRED)
  find_package(Boost 1.55 COMPONENTS system thread log REQUIRED)
  include_directories (
      ${Boost_INCLUDE_DIR}
      ${VSOMEIP_INCLUDE_DIRS}
  )


  target_link_libraries(nanomq_cli vsomeip3 ${Boost_LIBRARIES})
endif(BUILD_VSOMEIP_GATEWAY)

add_dependencies(nanomq_cli nng)


install(TARGETS nanomq_cli RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
                                   COMPONENT Tools)

