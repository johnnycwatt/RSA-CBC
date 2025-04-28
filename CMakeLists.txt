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

include_directories(${CMAKE_SOURCE_DIR}/common)


add_executable(server server/server.cpp common/rsa_cbc.cpp)
if (WIN32)
    target_link_libraries(server ws2_32)
endif()

add_executable(client client/client.cpp common/rsa_cbc.cpp)
if (WIN32)
    target_link_libraries(client ws2_32)
endif()