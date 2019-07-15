cmake_minimum_required(VERSION 2.8)
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
    message(STATUS "Build without -g but with -O3 for release")
endif ()
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11")

option(DEBUG_SPDNET "Debug spdnet" OFF)
if (DEBUG_SPDNET)
    add_definitions(-DDEBUG_SPDNET)
endif ()

option(HAVE_ZMQ_BUG "ZMQ have bug in 4.2.2-2 on arhclinux" ON)
if (HAVE_ZMQ_BUG)
    add_definitions(-DHAVE_ZMQ_BUG)
endif ()

# git submodule
find_package(Git QUIET)
if(GIT_FOUND AND EXISTS "${PROJECT_SOURCE_DIR}/.git")
# Update submodules as needed
    option(GIT_SUBMODULE "Check submodules during build" ON)
    if(GIT_SUBMODULE)
        message(STATUS "Submodule update")
        #execute_process(COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive
        execute_process(COMMAND ${GIT_EXECUTABLE} submodule update --init deps/extlibc
                        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                        RESULT_VARIABLE GIT_SUBMOD_RESULT)
        if(NOT GIT_SUBMOD_RESULT EQUAL "0")
            message(FATAL_ERROR "git submodule update --init failed with ${GIT_SUBMOD_RESULT}, please checkout submodules")
        endif()
    endif()
endif()

# extlibc, only used extlist.h
include_directories(deps/extlibc/src)
#add_subdirectory(deps/extlibc)

# zebra
include_directories(include)
link_directories(${PROJECT_SOURCE_DIR}/lib ${PROJECT_SOURCE_DIR}/lib64)

include_directories(src/spdnet)
add_subdirectory(src/spdnet)
include_directories(src)
add_subdirectory(src)

option(BUILD_TESTS "Build all tests." OFF)
if (BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif ()
