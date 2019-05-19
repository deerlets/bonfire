cmake_minimum_required(VERSION 2.8)

set(CMAKE_CXX_STANDARD 11)
set(PROJECT_NAME tests)

project(${PROJECT_NAME} C CXX)

add_library(mock_module SHARED mock_module.c)
set_target_properties(mock_module PROPERTIES PREFIX "")
set_target_properties(mock_module PROPERTIES SUFFIX ".zo")

add_executable(test-spdnet test_spdnet.cpp)
target_link_libraries(test-spdnet gtest gtest_main zserv)
add_test(test-spdnet ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-spdnet)

add_executable(test-service test_service.cpp)
target_link_libraries(test-service gtest gtest_main zserv)
add_test(test-service ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-service)

add_executable(test-task test_task.cpp)
target_link_libraries(test-task gtest gtest_main zserv)
add_test(test-task ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-task)

add_executable(test-module test_module.cpp)
target_link_libraries(test-module gtest gtest_main zserv)
add_test(test-module ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-module)
