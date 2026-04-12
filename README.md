# Packet Sniffer

## Project Description

This project is a simple packet sniffer written in C using the **libpcap** library.  
It reads packets from an offline `.pcapng` file and analyzes them.

There is a sample pcap file under pcaps directory to be used for tests.

The program prints:

- Packet timestamp
- Packet length information
- Source and destination MAC addresses
- EtherType
- Source and destination IP addresses
- Protocol (TCP / UDP)
- Source and destination ports

---

## Requirements (Ubuntu)

Install the required tools and libraries:

```bash
sudo apt update
sudo apt install build-essential cmake libpcap-dev


mkdir build
cd build
cmake ..
cmake --build .

## executing the application 
./packet_sniffer ../pcaps/sample.pcapng
