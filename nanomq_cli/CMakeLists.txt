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

file(GLOB CLI_SOURCE "*.c")

if(BUILD_VSOMEIP_GATEWAY)
  file(GLOB CLI_CXX_SOURCE "*.cc")
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${NNG_COVERAGE_C_FLAGS}")
  set(CLI_SOURCE ${CLI_SOURCE} ${CLI_CXX_SOURCE})
endif(BUILD_VSOMEIP_GATEWAY)

if(BUILD_DDS_PROXY)
  if(NOT IDL_FILE_PATH)
    set(IDL_FILE_PATH "${CMAKE_SOURCE_DIR}/etc/idl/dds_type.idl")
    message("Set default idl file path: ${IDL_FILE_PATH}")
  else()
    message("Set user's idl file path: ${IDL_FILE_PATH}")
  endif()

  get_filename_component(IDL_FILE_NAME ${IDL_FILE_PATH} NAME_WE)

  set(IDL_LIB_NAME "${IDL_FILE_NAME}_lib")

  include(SerialGenerate)
  serial_generate(${IDL_FILE_PATH} idl_convert ${CMAKE_CURRENT_SOURCE_DIR}/dds2mqtt)

  find_package(CycloneDDS REQUIRED)
  find_package(OpenSSL)
  idlc_generate(TARGET ${IDL_LIB_NAME} FILES ${IDL_FILE_PATH})
  file(GLOB CLI_SOURCE ${CLI_SOURCE} "dds2mqtt/*.c")
endif(BUILD_DDS_PROXY)

add_executable(nanomq_cli ${CLI_SOURCE})

if(BUILD_NFTP)
  add_subdirectory(nftp-codec)
  target_link_libraries(nanomq_cli nftp-codec)
endif(BUILD_NFTP)

target_link_libraries(nanomq_cli nng)
if (CMAKE_INSTALL_RPATH)
  set_target_properties(nanomq_cli PROPERTIES LINK_FLAGS "-Wl,-rpath,${CMAKE_INSTALL_RPATH}")
endif()

if(BUILD_DDS_PROXY)
  target_link_libraries(nanomq_cli ${IDL_LIB_NAME} CycloneDDS::ddsc)
  target_link_libraries(nanomq_cli OpenSSL::SSL OpenSSL::Crypto)
endif(BUILD_DDS_PROXY)

if(BUILD_QUIC_CLI)
  target_link_libraries(nanomq_cli msquic OpenSSLQuic)
endif(BUILD_QUIC_CLI)

if(BUILD_ZMQ_GATEWAY)
  find_package(ZeroMQ REQUIRED)
  include_directories("${ZeroMQ_INCLUDE_DIR}")
  target_link_libraries(nanomq_cli zmq)
  target_link_libraries(nanomq_cli stdc++)
endif(BUILD_ZMQ_GATEWAY)

if(BUILD_ICEORYX_CLI)
  find_package(iceoryx_binding_c REQUIRED)
  find_package(iceoryx_platform REQUIRED)
  find_package(iceoryx_posh CONFIG REQUIRED)
  find_package(iceoryx_hoofs CONFIG REQUIRED)

  target_link_libraries(nanomq_cli iceoryx_binding_c::iceoryx_binding_c)
endif(BUILD_ICEORYX_CLI)

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

