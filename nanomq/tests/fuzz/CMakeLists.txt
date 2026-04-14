if(ENABLE_FUZZING)
    set(FUZZ_TARGETS pub_decode_fuzzer)

    foreach(TARGET ${FUZZ_TARGETS})
        add_executable(${TARGET} ${CMAKE_SOURCE_DIR}/fuzz/${TARGET}.c)
        target_link_libraries(${TARGET} nanomq nng ${LIB_FUZZING_ENGINE})
        target_include_directories(${TARGET} PRIVATE
            ${PROJECT_SOURCE_DIR}/include
            ${PROJECT_SOURCE_DIR}
            ${PROJECT_SOURCE_DIR}/nanomq
            ${PROJECT_SOURCE_DIR}/../nng/include
        )
    endforeach()
endif()
