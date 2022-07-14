aux_source_directory(. DIR_LIB_SRCS)
include_directories(${CMAKE_SOURCE_DIR}/nanomq/include)
include_directories(${CMAKE_SOURCE_DIR}/nng/include/nng)

# find_library(LIBRT rt) 

# set(PARALLEL 128 CACHE STRING "Parallelism (min 4, max 1000)")

add_library (apps ${DIR_LIB_SRCS})
# target_link_libraries(apps ${LIBRT})

target_link_libraries(apps nng)
target_compile_definitions(apps PRIVATE -DPARALLEL=${PARALLEL})
