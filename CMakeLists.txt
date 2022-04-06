cmake_minimum_required(VERSION 3.16)
project(pcap)

set(CMAKE_CXX_STANDARD 14)

include(FindPCAP.cmake)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/")

find_package(PCAP REQUIRED)
find_package(PkgConfig REQUIRED)

pkg_check_modules(JSONCPP jsoncpp)
link_libraries(${JSONCPP_LIBRARIES})

set(SOURCE_FILES main.cpp)

add_executable(pcap ${SOURCE_FILES})

target_link_libraries(pcap ${PCAP_LIBRARY})
target_link_libraries(pcap ${JSONCPP_LIBRARIES})
