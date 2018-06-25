cmake_minimum_required(VERSION 2.8)

set(CMAKE_CXX_STANDARD 11)
set(PROJECT_NAME zerox-test)

project(${PROJECT_NAME} C CXX)
add_definitions(-DWITH_TESTS)

add_library(mock_module SHARED mock_module.c)
set_target_properties(mock_module PROPERTIES PREFIX "")
set_target_properties(mock_module PROPERTIES SUFFIX ".zo")

add_executable(runZeroTests
	spdnet_test.cpp
	zbuf_test.cpp
	service_test.cpp
	task_test.cpp
	module_test.cpp)
target_link_libraries(runZeroTests gtest gtest_main zero)
add_test(runZeroTests ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/runZeroTests)
