cmake_minimum_required(VERSION 2.8)

set(CMAKE_CXX_STANDARD 11)
set(PROJECT_NAME zerox-test)

project(${PROJECT_NAME} C CXX)
add_definitions(-DWITH_TESTS)

add_library(mock_module SHARED mock_module.c)
set_target_properties(mock_module PROPERTIES PREFIX "")
set_target_properties(mock_module PROPERTIES SUFFIX ".zo")

add_executable(runSpdnetTests spdnet_test.cpp)
target_link_libraries(runSpdnetTests gtest gtest_main zero)
add_test(runSpdnetTests ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/runSpdnetTests)

add_executable(runServiceTests service_test.cpp)
target_link_libraries(runServiceTests gtest gtest_main zero)
add_test(runServiceTests ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/runServiceTests)

add_executable(runTaskTests task_test.cpp)
target_link_libraries(runTaskTests gtest gtest_main zero)
add_test(runTaskTests ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/runTaskTests)

add_executable(runModuleTests module_test.cpp)
target_link_libraries(runModuleTests gtest gtest_main zero)
add_test(runModuleTests ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/runModuleTests)

add_executable(runZbufTests zbuf_test.cpp)
target_link_libraries(runZbufTests gtest gtest_main zero)
add_test(runZbufTests ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/runZbufTests)

add_executable(runZsocketTests zsocket_test.cpp)
target_link_libraries(runZsocketTests gtest gtest_main zero)
add_test(runZsocketTests ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/runZsocketTests)

add_executable(runUtilsTests utils_test.cpp)
target_link_libraries(runUtilsTests gtest gtest_main zero)
add_test(runUtilsTests ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/runUtilsTests)
