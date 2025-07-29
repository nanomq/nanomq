#
# This software is supplied under the terms of the MIT License, a copy of which
# should be located in the distribution where this file was obtained
# (LICENSE.txt).  A copy of the license may also be found online at
# https://opensource.org/licenses/MIT.

# cmake_minimum_required(VERSION 2.8.12)

project(nanomq)
SET(CMAKE_C_STANDARD 99)

if(DEBUG AND ASAN)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -fsanitize=address")
  # set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fsanitize=address")
endif(DEBUG AND ASAN)

if(DEBUG AND TSAN)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -fsanitize=thread")
  # SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fsanitize=thread")
endif(DEBUG AND TSAN)

aux_source_directory(. DIRSRCS)

include_directories(./)
include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${PROJECT_SOURCE_DIR}/../nng/include/nng)
if(ENABLE_JWT)
  include_directories(${PROJECT_SOURCE_DIR}/../extern/l8w8jwt/include)
endif(ENABLE_JWT)
if(ENABLE_LICENSE_DK)
  include_directories(${CMAKE_SOURCE_DIR}/nanomq/extern/include)
endif(ENABLE_LICENSE_DK)

add_subdirectory(apps)
add_subdirectory(tests)
#add_subdirectory(plugin)

# set(PARALLEL 128 CACHE STRING "Parallelism (min 4, max 1000)")

set(SOURCES
    process.c
    bridge.c
    pub_handler.c
    sub_handler.c
    unsub_handler.c
    hashmap.c
    rest_api.c
    web_server.c
    webhook_inproc.c
    webhook_post.c
    aws_bridge.c
    nanomq_rule.c
    conf_api.c
    cmd_proc.c
    acl_handler.c
    mqtt_api.c
    nanomq.c
    plugin_spi_stream.c
    apps/broker.c
)

if(ENABLE_LICENSE_DK)
  set(SOURCES ${SOURCES} license_dk.c extern/aes_gcm.c)
endif(ENABLE_LICENSE_DK)
if(ENABLE_LICENSE_STD)
  set(SOURCES ${SOURCES} license_std.c)
endif(ENABLE_LICENSE_STD)

if(NNG_ENABLE_PLUGIN)
  set(SOURCES ${SOURCES} plugin/plugin.c)
endif(NNG_ENABLE_PLUGIN)

if(NNG_ENABLE_PARQUET)
  include_directories(${CMAKE_SOURCE_DIR}/nanomq/extern/include)
  set(SOURCES ${SOURCES} extern/aes_gcm.c)
endif()

if(ENABLE_FILETRANSFER)
  ADD_DEFINITIONS(-DENABLE_FILETRANSFER)
  include_directories(${CMAKE_SOURCE_DIR}/nanomq/extern/include)
  set(SOURCES ${SOURCES} extern/file_transfer_nano.c)
endif(ENABLE_FILETRANSFER)

include_directories(${FOUNDATION_INCLUDE_DIR})

if(BUILD_STATIC_LIB)
  add_library(nanomq  ${SOURCES})
elseif (BUILD_SHARED_LIBS) 
  add_library(nanomq SHARED ${SOURCES})
  set_property(TARGET nanomq PROPERTY POSITION_INDEPENDENT_CODE 1)
else()
  add_executable(nanomq ${SOURCES})
endif()

if(ENABLE_MYSQL)

  include(FindPkgConfig)
  pkg_check_modules(LIBMYSQLCLIENT REQUIRED mysqlclient)

  foreach(FLAG ${LIBMYSQLCLIENT_CFLAGS_OTHER})
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${FLAG}")
  endforeach()

  link_directories(${LIBMYSQLCLIENT_LIBRARY_DIRS})
  include_directories(${MYSQL_INCLUDE_DIR})
  include_directories(${LIBMYSQLCLIENT_INCLUDE_DIRS})
  # message(STATUS, "${LIBMYSQLCLIENT_INCLUDE_DIRS}")
  target_link_libraries(nanomq ${LIBMYSQLCLIENT_LIBRARIES})

endif(ENABLE_MYSQL)

if(ENABLE_POSTGRESQL)

  find_package(PostgreSQL REQUIRED)

  # Link to the PostgreSQL C library
  target_link_libraries(nanomq ${PostgreSQL_LIBRARIES})

  # Include the PostgreSQL C library headers
  target_include_directories(nanomq PUBLIC ${PostgreSQL_INCLUDE_DIRS})

endif(ENABLE_POSTGRESQL)

if(ENABLE_TIMESCALEDB)

  find_package(PostgreSQL REQUIRED)

  # Link to the PostgreSQL C library
  target_link_libraries(nanomq ${PostgreSQL_LIBRARIES})

  # Include the PostgreSQL C library headers
  target_include_directories(nanomq PUBLIC ${PostgreSQL_INCLUDE_DIRS})

endif(ENABLE_TIMESCALEDB)

if(ENABLE_AWS_BRIDGE)
  target_link_libraries(nanomq
      aws_iot_mqtt
      aws_iot_backoff_algorithm
      sockets_posix
      openssl_posix
      clock_posix)

endif(ENABLE_AWS_BRIDGE)

if(ENABLE_FILETRANSFER)
  find_package(OpenSSL REQUIRED)
  target_link_libraries(nanomq OpenSSL::Crypto)
endif(ENABLE_FILETRANSFER)

if(ENABLE_JWT)
  target_link_libraries(nanomq l8w8jwt)
endif(ENABLE_JWT)

if(NNG_ENABLE_QUIC)
  target_link_libraries(nanomq msquic OpenSSLQuic)
endif(NNG_ENABLE_QUIC)

if(BUILD_QUIC_CLI)
  target_link_libraries(nanomq nng msquic)
endif(BUILD_QUIC_CLI)

if (CMAKE_INSTALL_RPATH)
  set_target_properties(nanomq PROPERTIES LINK_FLAGS "-Wl,-rpath,${CMAKE_INSTALL_RPATH}")
  message("Dynamic link rpath: ${CMAKE_INSTALL_RPATH}")
endif()

if (NOT WIN32)
  if (NNG_ENABLE_HTTP)
    target_link_libraries(nanomq nng m)
  endif()
endif()

if(BUILD_STATIC)
  target_link_libraries(nanomq nng -static)
else()
    target_link_libraries(nanomq nng)
endif()

target_compile_definitions(nanomq PRIVATE -DPARALLEL=${PARALLEL})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
# Package all static files into one libnanomq.a
if(BUILD_STATIC_LIB)
  set(FULL_OUTPUT_PATH ${CMAKE_BINARY_DIR}/libnanomq.a)
  set (tmp ${CMAKE_BINARY_DIR}/tmp)
  file(WRITE ${tmp} "create ${FULL_OUTPUT_PATH}\n")
  file(APPEND ${tmp} "addlib ${CMAKE_BINARY_DIR}/nanomq/libnanomq.a\n")
  file(APPEND ${tmp} "addlib ${CMAKE_BINARY_DIR}/nng/libnng.a\n")
  file(APPEND ${tmp} "addlib ${CMAKE_BINARY_DIR}/nanomq/apps/libapps.a\n")
  file(APPEND ${tmp} "save\n")
  file(APPEND ${tmp} "end\n")

  add_custom_target(libnano
          COMMAND ar -M < ${CMAKE_BINARY_DIR}/tmp
          COMMAND rm ${CMAKE_BINARY_DIR}/tmp
          COMMAND rm ${CMAKE_BINARY_DIR}/nanomq/libnanomq.a
          WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
          DEPENDS nanomq nng
          )
endif(BUILD_STATIC_LIB)

# TODO INSTALL

if(BUILD_STATIC_LIB OR BUILD_SHARED_LIBS)
  # install(
  #   FILES ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/libnanomq.a
  #   LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR})

else()
  install(
    TARGETS nanomq
    EXPORT nanomqConfig
    # ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    # LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT services)

  install(
    DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}
    COMPONENT services)

  install(
    EXPORT nanomqConfig
    DESTINATION share/nanomq/cmake
    COMPONENT services)

endif()

if (NANOMQ_TESTS)
    add_definitions(-DENABLE_NANOMQ_TESTS)
endif(NANOMQ_TESTS)

# Download and extract dashboard
if (ENABLE_DASHBOARD)
    message("-- Setting up dashboard --")
    
    # Set default dashboard version if not provided
    if(NOT DEFINED DASHBOARD_VERSION OR "${DASHBOARD_VERSION}" STREQUAL "")
        set(DASHBOARD_VERSION "0.0.1-alpha.1")
    endif()
    
    # Set repository and asset name
    set(DASHBOARD_REPO "emqx/edge-dashboard")
    set(DASHBOARD_ASSET_NAME "edge-dashboard.zip")
    
    set(FRONTEND_ZIP "${CMAKE_BINARY_DIR}/nanomq/${DASHBOARD_ASSET_NAME}")
    set(FRONTEND_EXTRACT_DIR "${CMAKE_BINARY_DIR}/nanomq")
    
    # Download the frontend package
    if(NOT EXISTS ${FRONTEND_ZIP})
        message(STATUS "Getting dashboard release info for version ${DASHBOARD_VERSION}")
        
        # Check if GitHub token is provided for private repository access
        if(NOT DEFINED GITHUB_TOKEN OR "${GITHUB_TOKEN}" STREQUAL "")
            message(WARNING "GitHub token is required for private repository access")
            message(STATUS "Please provide GitHub token:")
            message(STATUS "  cmake .. -DENABLE_DASHBOARD=ON -DGITHUB_TOKEN=<your_personal_access_token> -DDASHBOARD_VERSION=${DASHBOARD_VERSION}")
            set(ENABLE_DASHBOARD OFF)
        else()
            # Get release information from GitHub API
            set(API_URL "https://api.github.com/repos/${DASHBOARD_REPO}/releases/tags/${DASHBOARD_VERSION}")
            set(RELEASE_INFO_FILE "${CMAKE_BINARY_DIR}/release_info.json")
            
            message(STATUS "Fetching release info from GitHub API...")
            execute_process(
                COMMAND curl -s -H "Authorization: token ${GITHUB_TOKEN}" -H "Accept: application/vnd.github.v3+json" "${API_URL}"
                OUTPUT_FILE "${RELEASE_INFO_FILE}"
                RESULT_VARIABLE API_RESULT
                ERROR_QUIET
            )
            
            if(API_RESULT EQUAL 0 AND EXISTS "${RELEASE_INFO_FILE}")
                # Find the asset URL by matching the specific GitHub API URL pattern
                # Build the grep pattern with proper variable substitution (handle possible spaces after colon)
                set(GREP_PATTERN "\"url\":[[:space:]]*\"https://api.github.com/repos/${DASHBOARD_REPO}/releases/assets/[0-9]*\"")

                execute_process(
                    COMMAND grep -o "${GREP_PATTERN}" "${RELEASE_INFO_FILE}"
                    COMMAND sed "s/.*\"url\":[[:space:]]*\"\\([^\"]*\\)\".*/\\1/"
                    OUTPUT_VARIABLE DOWNLOAD_URL
                    OUTPUT_STRIP_TRAILING_WHITESPACE
                    RESULT_VARIABLE GREP_RESULT
                )
                
                if(GREP_RESULT EQUAL 0 AND NOT "${DOWNLOAD_URL}" STREQUAL "")
                    message(STATUS "Found asset URL: ${DOWNLOAD_URL}")
                    
                    # Download the asset using the GitHub API URL with proper Accept header
                    file(DOWNLOAD "${DOWNLOAD_URL}" "${FRONTEND_ZIP}"
                         HTTPHEADER "Authorization: token ${GITHUB_TOKEN}"
                         HTTPHEADER "Accept: application/octet-stream"
                         SHOW_PROGRESS
                         STATUS DOWNLOAD_STATUS
                         TIMEOUT 300)
                    
                    list(GET DOWNLOAD_STATUS 0 DOWNLOAD_ERROR)
                    if(DOWNLOAD_ERROR)
                        message(WARNING "Failed to download dashboard: ${DOWNLOAD_STATUS}")
                        set(ENABLE_DASHBOARD OFF)
                        if(EXISTS ${FRONTEND_ZIP})
                            file(REMOVE ${FRONTEND_ZIP})
                        endif()
                    else()
                        message(STATUS "Dashboard downloaded successfully")
                    endif()
                else()
                    message(WARNING "Could not find download URL for ${DASHBOARD_ASSET_NAME}")
                    message(STATUS "Available assets in release ${DASHBOARD_VERSION}:")
                    execute_process(
                        COMMAND grep -o "\"name\":\"[^\"]*\\.zip\"" "${RELEASE_INFO_FILE}"
                        COMMAND sed "s/.*\"name\":\"\\([^\"]*\\)\".*/  - \\1/"
                        OUTPUT_VARIABLE AVAILABLE_ASSETS
                    )
                    message(STATUS "${AVAILABLE_ASSETS}")
                    set(ENABLE_DASHBOARD OFF)
                endif()
                
                # Clean up temporary file
                file(REMOVE "${RELEASE_INFO_FILE}")
            else()
                message(WARNING "Failed to fetch release information from GitHub API")
                message(STATUS "Please check:")
                message(STATUS "  - GitHub token has correct permissions")
                message(STATUS "  - Repository ${DASHBOARD_REPO} is accessible")
                message(STATUS "  - Version ${DASHBOARD_VERSION} exists")
                set(ENABLE_DASHBOARD OFF)
            endif()
        endif()
    endif()
    
    # Extract the frontend package
    if(EXISTS ${FRONTEND_ZIP} AND NOT EXISTS ${FRONTEND_EXTRACT_DIR}/dist)
        message(STATUS "Extracting frontend dashboard to ${FRONTEND_EXTRACT_DIR}")
        file(ARCHIVE_EXTRACT INPUT ${FRONTEND_ZIP} DESTINATION ${FRONTEND_EXTRACT_DIR})
        message(STATUS "Dashboard extracted successfully")
        
        # Remove the zip file after successful extraction
        file(REMOVE ${FRONTEND_ZIP})
        message(STATUS "Removed dashboard zip file")
    endif()
    
    # Install frontend files to the same directory as nanomq binary
    set(FRONTEND_DIST_DIR "${FRONTEND_EXTRACT_DIR}/dist")
    if(EXISTS ${FRONTEND_DIST_DIR})
        file(GLOB_RECURSE FRONTEND_FILES "${FRONTEND_DIST_DIR}/*")
        if(FRONTEND_FILES)
            if (NOT WIN32 AND NOT CYGWIN)
                install(DIRECTORY ${FRONTEND_DIST_DIR}/ DESTINATION ${CMAKE_INSTALL_PREFIX}/bin/dist)
            else()
                install(DIRECTORY ${FRONTEND_DIST_DIR}/ DESTINATION bin/dist)
            endif()
            message(STATUS "Frontend dashboard will be installed to bin/dist directory")
        endif()
    endif()
endif()
