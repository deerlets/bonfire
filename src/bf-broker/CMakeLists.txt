cmake_minimum_required(VERSION 3.12)

file(GLOB SRC *.cpp *.c)

add_executable(bf-broker ${SRC})
target_link_libraries(bf-broker bonfire)

install(TARGETS bf-broker
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include)
