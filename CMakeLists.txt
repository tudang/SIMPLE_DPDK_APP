cmake_minimum_required(VERSION 2.8)
project(planeDB)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -Wall")
set(CMAKE_MACOSX_RPATH 1)


add_subdirectory(icmp)
