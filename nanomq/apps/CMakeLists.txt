aux_source_directory(. DIR_LIB_SRCS)
include_directories(${CMAKE_SOURCE_DIR}/nanomq/include)
include_directories(${CMAKE_SOURCE_DIR}/nng/include/nng)

# find_library(LIBRT rt) 

# set(PARALLEL 128 CACHE STRING "Parallelism (min 4, max 1000)")

if (BUILD_SHARED_LIBS) 
    add_library(apps SHARED ${DIR_LIB_SRCS})
    set_property(TARGET apps PROPERTY POSITION_INDEPENDENT_CODE 1)
else()
    add_library (apps ${DIR_LIB_SRCS})
    target_link_libraries(apps ${LIBRT})
endif()

target_link_libraries(apps nng)
target_compile_definitions(apps PRIVATE -DPARALLEL=${PARALLEL})

if (NANOMQ_TESTS)
    add_definitions(-DENABLE_NANOMQ_TESTS)
endif(NANOMQ_TESTS)

nanomq_test(broker_test)
