if (NANOMQ_TESTS)
    add_definitions(-DENABLE_NANOMQ_TESTS)
endif(NANOMQ_TESTS)

nanomq_test(broker_test)
