cmake_minimum_required(VERSION 3.12)

#
# spdnet
#

add_executable(test-spdnet test_spdnet.c task.c)
target_link_libraries(test-spdnet cmocka spdnet)
add_test(test-spdnet ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-spdnet)

#
# bonfire
#

add_executable(test-bonfire test_bonfire.c task.c)
target_link_libraries(test-bonfire cmocka bonfire)
add_test(test-bonfire ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-bonfire)
