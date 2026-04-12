cmake_minimum_required(VERSION 3.20)
project(packet_sniffer C)

set(CMAKE_C_STANDARD 11)

add_executable(packet_sniffer src/main.c src/packet-handler.c src/packet-handler.h)

find_library(PCAP_LIBRARY pcap REQUIRED)
target_link_libraries(packet_sniffer ${PCAP_LIBRARY})

