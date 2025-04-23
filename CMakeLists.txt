cmake_minimum_required(VERSION 3.30)
project(RSA_CBC)

set(CMAKE_CXX_STANDARD 20)

set(BOOST_INCLUDE_DIR "C:/boost_1_84_0")
include_directories(${BOOST_INCLUDE_DIR})

if (MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra)
endif()


add_executable(RSA_CBC common/rsa_cbc.cpp
        common/rsa_cbc.h)
