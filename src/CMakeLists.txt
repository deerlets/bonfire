cmake_minimum_required(VERSION 3.12)

file(GLOB SRC *.cpp)
file(GLOB INC bonfire.h)

add_library(bonfire-static STATIC ${SRC} ${SRC_EXT})
set_target_properties(bonfire-static PROPERTIES OUTPUT_NAME bonfire)
set_target_properties(bonfire-static PROPERTIES PUBLIC_HEADER "${INC}")
set(TARGET_STATIC bonfire-static spdnet pthread)

add_library(bonfire SHARED ${SRC})
set_target_properties(bonfire PROPERTIES PUBLIC_HEADER "${INC}")
set_target_properties(bonfire PROPERTIES VERSION 2.0.0 SOVERSION 2)
target_link_libraries(bonfire spdnet pthread)

install(TARGETS bonfire
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include)
