cmake_minimum_required(VERSION 3.0.0)
project(c-vector VERSION 0.1.0)

add_library(c-vector INTERFACE)

target_sources(c-vector INTERFACE 
	${CMAKE_CURRENT_SOURCE_DIR}/cvector.h
)

add_executable(c-vector-example
	example.c
)

target_link_libraries(c-vector-example
PUBLIC
	c-vector
)
