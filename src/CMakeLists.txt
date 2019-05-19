cmake_minimum_required(VERSION 2.8)

file(GLOB_RECURSE SRC *.c)
file(GLOB_RECURSE INC *.h)

add_library(zebra SHARED ${SRC})
set_target_properties(zebra PROPERTIES PUBLIC_HEADER "${INC}")
set_target_properties(zebra PROPERTIES VERSION 0.1.0 SOVERSION 0.1)
target_link_libraries(zebra pthread dl spdnet)

install(TARGETS zebra
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include/zebra)
