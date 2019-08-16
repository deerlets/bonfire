cmake_minimum_required(VERSION 2.8)

file(GLOB SRC *.cpp)
file(GLOB INC *.h)

add_library(bonfire SHARED ${SRC})
set_target_properties(bonfire PROPERTIES PUBLIC_HEADER "${INC}")
set_target_properties(bonfire PROPERTIES VERSION 2.0.0 SOVERSION 2)
target_link_libraries(bonfire spdnet cx)

install(TARGETS bonfire
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include)
