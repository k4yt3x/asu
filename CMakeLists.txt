cmake_minimum_required(VERSION 3.10)
project(as2b VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_library(KEYSTONE_LIB keystone REQUIRED)
find_package(argparse REQUIRED)

add_executable(as2b src/as2b.cpp)

target_link_libraries(as2b
    PRIVATE
        ${KEYSTONE_LIB}
        argparse::argparse
)
