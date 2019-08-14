cmake_minimum_required(VERSION 2.8)

#
# extlibc
#

add_executable(test-extlog test_extlog.c)
target_link_libraries(test-extlog cmocka cx)
add_test(test-extlog ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-extlog)

add_executable(test-extopt test_extopt.c)
target_link_libraries(test-extopt cmocka cx)
add_test(test-extopt ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-extopt)

add_executable(test-task test_task.c)
target_link_libraries(test-task cmocka cx)
add_test(test-task ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-task)

add_library(mock_module SHARED mock_module.c)
set_target_properties(mock_module PROPERTIES PREFIX "")
set_target_properties(mock_module PROPERTIES SUFFIX ".zo")

add_executable(test-module test_module.c)
target_link_libraries(test-module cmocka cx)
add_test(test-module ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-module)

#
# spdnet
#

add_executable(test-spdnet test_spdnet.c)
target_link_libraries(test-spdnet cmocka spdnet cx)
add_test(test-spdnet ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-spdnet)

#
# zebra
#

#add_executable(test-service test_service.c)
#target_link_libraries(test-service cmocka zebra)
#add_test(test-service ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-service)
