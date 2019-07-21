cmake_minimum_required(VERSION 2.8)

set(PROJECT_NAME tests)

add_library(mock_module SHARED mock_module.c)
set_target_properties(mock_module PROPERTIES PREFIX "")
set_target_properties(mock_module PROPERTIES SUFFIX ".zo")

add_executable(test-spdnet test_spdnet.c)
target_link_libraries(test-spdnet cmocka zebra)
add_test(test-spdnet ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-spdnet)
 
add_executable(test-service test_service.c)
target_link_libraries(test-service cmocka zebra)
add_test(test-service ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-service)
 
add_executable(test-task test_task.c)
target_link_libraries(test-task cmocka zebra)
add_test(test-task ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-task)
 
add_executable(test-module test_module.c)
target_link_libraries(test-module cmocka zebra)
add_test(test-module ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-module)
