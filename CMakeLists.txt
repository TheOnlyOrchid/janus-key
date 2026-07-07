cmake_minimum_required(VERSION 3.24)
project(janus_key LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(janus_key_pintool
        src/main.cpp
        src/main.h
)

include_directories(
        third_party/pin/source/include/pin
)