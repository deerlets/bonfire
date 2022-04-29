cmake_minimum_required(VERSION 3.12)
project(bonfirelua)

set(CMAKE_MACOSX_RPATH 1)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# cflags & cppflags
option(BUILD_DEBUG "Build with debug info." OFF)
if (BUILD_DEBUG)
    set(MODE_FLAGS "-g")
    message(STATUS "Build with -g for debug")
else ()
    set(MODE_FLAGS "-O3")
    message(STATUS "Build with -O3 for release")
endif ()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${MODE_FLAGS} -std=gnu99 -Wall")

file(GLOB SRC src/*.c)

add_library(bonfirelua SHARED ${SRC})
target_link_libraries(bonfirelua bonfire lua5.3)

set_target_properties(bonfirelua PROPERTIES PREFIX "")
set_target_properties(bonfirelua PROPERTIES SUFFIX ".so")
