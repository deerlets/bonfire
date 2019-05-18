cmake_minimum_required(VERSION 2.8)

file(GLOB_RECURSE SRC *.c)
file(GLOB_RECURSE INC *.h)

add_library(zero SHARED ${SRC})
target_link_libraries(zero pthread dl zmq)
set_target_properties(zero PROPERTIES VERSION 0.1.0 SOVERSION 0.1)

if (WIN32)
target_link_libraries(zero ws2_32)
endif ()

install(TARGETS zero
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)

install(FILES ${INC} DESTINATION include/zero)
