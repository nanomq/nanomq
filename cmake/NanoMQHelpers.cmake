include(CheckFunctionExists)
include(CheckSymbolExists)
include(CheckStructHasMember)
include(CheckLibraryExists)
include(CheckCSourceCompiles)

function(nanomq_test NAME)
    if (NANOMQ_TESTS)
        add_executable(${NAME} ${NAME}.c ${ARGN})
        target_link_libraries(${NAME} nanomq)
        if (NNG_ENABLE_QUIC)
            target_link_libraries(${NAME} nng)
        endif()
        target_include_directories(${NAME} PRIVATE
                ${PROJECT_SOURCE_DIR}/include)
        add_test(NAME nanomq.${NAME} COMMAND ${NAME} -t -v)
        set_tests_properties(nanomq.${NAME} PROPERTIES TIMEOUT 60)
		if (NAME STREQUAL "broker_test" OR NAME STREQUAL "webhook_test" OR
			NAME STREQUAL "webhook_base62_test" OR NAME STREQUAL "webhook_base64_test" OR
			NAME STREQUAL "http_server_test" OR NAME STREQUAL "rule_engine_test" OR
			NAME STREQUAL "bridge_test" OR NAME STREQUAL "bridge_rap_rh_test" OR
			NAME STREQUAL "bridge_aws_test" OR NAME STREQUAL "bridge_muti_bridge_test" OR
			NAME STREQUAL "broker_tls_test" OR NAME STREQUAL "bridge_tls_test" OR
			NAME STREQUAL "nmq_ws_test")
			set_tests_properties(nanomq.${NAME} PROPERTIES RUN_SERIAL TRUE)
		endif()
    endif ()
endfunction()
