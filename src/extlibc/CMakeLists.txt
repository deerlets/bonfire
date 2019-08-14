cmake_minimum_required(VERSION 2.8)

file(GLOB SRC *.c)
file(GLOB INC *.h)

add_library(cx SHARED ${SRC})
set_target_properties(cx PROPERTIES PUBLIC_HEADER "${INC}")
set_target_properties(cx PROPERTIES VERSION 0.0.2 SOVERSION 0)

install(TARGETS cx
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include
)
