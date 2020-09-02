aux_source_directory(. DIR_LIB_SRCS)
include_directories(../include)
include_directories(${CMAKE_SOURCE_DIR}/nng/include/nng)
include_directories(${CMAKE_SOURCE_DIR}/nanolib/include)

find_library(LIBRT rt) 

find_package(nng CONFIG REQUIRED)
find_package(nanolib REQUIRED)

set(PARALLEL 128 CACHE STRING "Parallelism (min 4, max 1000)")

add_library (apps ${DIR_LIB_SRCS})
target_link_libraries(apps ${LIBRT})

target_link_libraries(apps nng)
#target_link_libraries(apps nano_shared)
target_link_libraries(apps nanolib)
target_compile_definitions(apps PRIVATE -DPARALLEL=${PARALLEL})
