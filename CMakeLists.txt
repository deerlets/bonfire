cmake_minimum_required(VERSION 2.8)
project(zebra)

set(CMAKE_MACOSX_RPATH 1)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -Wall")
option(BUILD_DEBUG "Build with debug info." OFF)
if (BUILD_DEBUG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
    message(STATUS "Build with -g for debug")
else ()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")
    message(STATUS "Build with -O3 for release")
endif ()

option(SPDNET_DEBUG "Debug spdnet" OFF)
if (SPDNET_DEBUG)
    add_definitions(-DSPDNET_DEBUG)
endif ()

option(HAVE_ZMQ_BUG "ZMQ have bug in 4.2.2-2 on arhclinux" ON)
if (HAVE_ZMQ_BUG)
    add_definitions(-DHAVE_ZMQ_BUG)
endif ()

# extlibc
include_directories(src/extlibc)
add_subdirectory(src/extlibc)

# spdnet
include_directories(src/spdnet)
add_subdirectory(src/spdnet)

# zebra
#include_directories(src)
#add_subdirectory(src)

# tests
option(BUILD_TESTS "Build all tests." OFF)
if (BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif ()
