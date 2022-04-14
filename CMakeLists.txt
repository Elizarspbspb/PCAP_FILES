cmake_minimum_required(VERSION 3.16)
project(Clion_pcap_new)

set(CMAKE_CXX_STANDARD 14)

include(FindPCAP.cmake)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/")

find_package(PCAP REQUIRED)
find_package(PkgConfig REQUIRED)

pkg_check_modules(JSONCPP jsoncpp)
link_libraries(${JSONCPP_LIBRARIES})

set(SOURCE_FILES structures.h filter.cpp filter.h main.cpp)

add_executable(Clion_pcap_new ${SOURCE_FILES})

target_link_libraries(Clion_pcap_new ${PCAP_LIBRARY})
target_link_libraries(Clion_pcap_new ${JSONCPP_LIBRARIES})

############
#find_package(PCAP REQUIRED)
#MESSAGE( [Main] " PCAP_INCLUDE_DIR = ${PCAP_INCLUDE_DIR}")
#MESSAGE( [Main] " PCAP_LIBRARY = ${PCAP_LIBRARY}")

#[Main] PCAP_INCLUDE_DIR = /usr/include
#[Main] PCAP_LIBRARY = /usr/lib/x86_64-linux-gnu/libpcap.so

################################
