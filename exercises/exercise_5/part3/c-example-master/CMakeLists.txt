cmake_minimum_required(VERSION 3.10)

project(c_example)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -Wall -Wextra")

add_executable(c_example main.c a_function.c more_functions.c)
