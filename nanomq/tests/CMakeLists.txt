nanomq_test(sub_handler_test)
nanomq_test(unsub_handler_test)
if(NANOMQ_TESTS AND CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT BUILD_SHARED_LIBS)
    # GNU-compatible linker wrapping keeps fault injection out of production.
    nanomq_test(unsub_failure_contract_test)
    foreach(unsub_symbol decode_unsub_msg unsub_ctx_handle bridge_sub_handler
            encode_unsuback_msg decode_properties property_free nng_zalloc
            nng_free nng_aio_finish nng_ctx_send)
        set_property(TARGET unsub_failure_contract_test APPEND_STRING PROPERTY
            LINK_FLAGS " -Wl,--wrap=${unsub_symbol}")
    endforeach()
    nanomq_test(unsub_workflow_test)
    foreach(unsub_symbol nng_mqtt_unsubscribe_async nng_ctx_send nng_ctx_recv
            nng_aio_finish)
        set_property(TARGET unsub_workflow_test APPEND_STRING PROPERTY
            LINK_FLAGS " -Wl,--wrap=${unsub_symbol}")
    endforeach()
endif()
nanomq_test(pub_handler_test)
if(ENABLE_ACL)
nanomq_test(acl_deny_action_test)
endif()
nanomq_test(broker_test)
nanomq_test(broker_dup_test)
if(NANOMQ_TESTS)
    target_include_directories(broker_dup_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../../nng/src")
    target_compile_definitions(broker_dup_test PRIVATE
        NANOMQ_TEST_CERT_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../../etc/certs")
    set_tests_properties(nanomq.broker_dup_test PROPERTIES
        RUN_SERIAL TRUE SKIP_RETURN_CODE 77 TIMEOUT 240)
endif()
nanomq_test(webhook_test)
nanomq_test(webhook_base62_test)
nanomq_test(webhook_base64_test)
nanomq_test(http_server_test)
nanomq_test(rest_pipe_snapshot_contract_test)
if(NANOMQ_TESTS)
    # The synthetic transport uses NNG's internal structs and must share its
    # platform definitions as well as the feature definitions in nng_private.
    get_directory_property(snapshot_nng_definitions
        DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../../nng" COMPILE_DEFINITIONS)
    target_compile_definitions(rest_pipe_snapshot_contract_test PRIVATE
        ${snapshot_nng_definitions})
    target_link_libraries(rest_pipe_snapshot_contract_test nng_private)
    target_include_directories(rest_pipe_snapshot_contract_test PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/../../nng/src")
    set_tests_properties(nanomq.rest_pipe_snapshot_contract_test PROPERTIES
        RUN_SERIAL TRUE)
endif()
nanomq_test(bridge_test)
nanomq_test(rule_engine_test)
nanomq_test(hashmap_test)
if (NNG_ENABLE_TLS)
	nanomq_test(broker_tls_test)
	nanomq_test(bridge_tls_test)
endif()
nanomq_test(broker_auth_anon_test)
nanomq_test(bridge_rap_rh_test)
nanomq_test(mqtt_api_test)
nanomq_test(nmq_ws_test)
nanomq_test(properties_test)
nanomq_test(nng_bridge_test)
nanomq_test(tests_api_test)
if(NNG_ENABLE_QUIC)
    nanomq_test(quic_smoke_test)
endif()

add_subdirectory(fuzz)
