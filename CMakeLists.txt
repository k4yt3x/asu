cmake_minimum_required(VERSION 3.10)
project(asu VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_library(KEYSTONE_LIB keystone REQUIRED)
find_library(CAPSTONE_LIB capstone REQUIRED)
find_package(argparse REQUIRED)

add_executable(asu src/asu.cpp)

target_link_libraries(asu PRIVATE
    ${KEYSTONE_LIB}
    ${CAPSTONE_LIB}
    argparse::argparse
)
