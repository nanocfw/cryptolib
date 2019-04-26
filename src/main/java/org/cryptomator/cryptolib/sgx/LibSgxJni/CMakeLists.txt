cmake_minimum_required(VERSION 3.13)
project(Sgx)
find_package(JNI REQUIRED)

set(SGX_SDK /home/storage/Documentos/linux-sgx/linux/installer/bin/sgxsdk)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY /usr/lib)

include_directories(${JNI_INCLUDE_DIRS})
include_directories(${SGX_SDK}/include)

#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
set(CMAKE_CXX_STANDARD 14)

include_directories(.)

add_library(Sgx SHARED
        Enclave_u.c
        Enclave_u.h
        LibSgxJni.cpp
        LibSgxJni.h)
