cmake_minimum_required(VERSION 2.8)

file(GLOB SRC *.c)
file(GLOB INC *.h)

add_definitions(-DZEBRA_INTERNAL)

add_library(zebra SHARED ${SRC})
set_target_properties(zebra PROPERTIES PUBLIC_HEADER "${INC}")
set_target_properties(zebra PROPERTIES VERSION 1.6.0 SOVERSION 1)
target_link_libraries(zebra pthread dl spdnet)

install(TARGETS zebra
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include/zebra)
