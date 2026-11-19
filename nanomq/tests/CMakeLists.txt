nanomq_test(sub_handler_test)
nanomq_test(unsub_handler_test)
if(NANOMQ_TESTS AND CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT BUILD_SHARED_LIBS)
    nanomq_test(broker_recv_error_test)
    set_property(TARGET broker_recv_error_test APPEND_STRING PROPERTY
        LINK_FLAGS " -Wl,--wrap=nng_ctx_recv")
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
if(NANOMQ_TESTS AND CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT BUILD_SHARED_LIBS)
    nanomq_test(acl_reload_test)
    set_property(TARGET acl_reload_test APPEND_STRING PROPERTY
        LINK_FLAGS " -Wl,--wrap=nng_pipe_cparam")
    nanomq_test(auth_http_fail_closed_test)
    foreach(auth_symbol topic_queue_init init_topic_queue_with_topic_node
            nni_alloc nni_zalloc nmq_auth_http_sub_pub topic_queue_release)
        set_property(TARGET auth_http_fail_closed_test APPEND_STRING PROPERTY
            LINK_FLAGS " -Wl,--wrap=${auth_symbol}")
    endforeach()
endif()
endif()
nanomq_test(broker_test)
nanomq_test(broker_dup_test)
nanomq_test(broker_order_test)
nanomq_test(broker_order_contract_test)
if(NANOMQ_TESTS)
    set_tests_properties(nanomq.broker_order_test PROPERTIES
        RUN_SERIAL TRUE SKIP_RETURN_CODE 77 TIMEOUT 240)
    add_test(NAME nanomq.broker_order_backpressure_test COMMAND broker_order_test)
    set_tests_properties(nanomq.broker_order_backpressure_test PROPERTIES
        ENVIRONMENT "ORDER_TEST_PARALLEL=2;ORDER_TEST_PUBLISHERS=4"
        RUN_SERIAL TRUE SKIP_RETURN_CODE 77 TIMEOUT 240)
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
    target_compile_definitions(broker_order_contract_test PRIVATE
        ${snapshot_nng_definitions})
    target_link_libraries(broker_order_contract_test nng_private)
    target_include_directories(broker_order_contract_test PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/../../nng/src")
    set_tests_properties(nanomq.broker_order_contract_test PROPERTIES
        RUN_SERIAL TRUE TIMEOUT 30)
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
nanomq_test(connect_limit_test)
if(NANOMQ_TESTS)
    set(connect_limit_targets connect_limit_test)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT BUILD_SHARED_LIBS)
        add_executable(connect_alloc_failure_test connect_limit_test.c)
        target_link_libraries(connect_alloc_failure_test nng)
        target_compile_definitions(connect_alloc_failure_test PRIVATE
            CONNECT_FAULT_INJECTION)
        set_property(TARGET connect_alloc_failure_test PROPERTY C_STANDARD 11)
        set_property(TARGET connect_alloc_failure_test APPEND_STRING PROPERTY
            LINK_FLAGS " -Wl,--wrap=nng_alloc -Wl,--wrap=nni_msg_append -Wl,--wrap=conn_param_alloc")
        add_test(NAME nanomq.connect_alloc_failure_test
            COMMAND connect_alloc_failure_test)
        list(APPEND connect_limit_targets connect_alloc_failure_test)
    endif()
    foreach(connect_target ${connect_limit_targets})
        target_compile_definitions(${connect_target} PRIVATE
            NANOMQ_TEST_CERT_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../../etc/certs")
        if(NNG_TRANSPORT_MQTT_BROKER_WS)
            target_compile_definitions(${connect_target} PRIVATE NANO_TEST_WS)
        endif()
        if(NNG_TRANSPORT_MQTT_BROKER_WSS)
            target_compile_definitions(${connect_target} PRIVATE NANO_TEST_WSS)
        endif()
        set_tests_properties(nanomq.${connect_target} PROPERTIES
            SKIP_RETURN_CODE 77 TIMEOUT 60)
    endforeach()
endif()
nanomq_test(nng_bridge_test)
nanomq_test(tests_api_test)
if(NNG_ENABLE_QUIC)
    nanomq_test(quic_smoke_test)
endif()

add_subdirectory(fuzz)
