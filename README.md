# Packet Sniffer

## Project Description

This project is a packet sniffer written in C using the **libpcap** library.  
It reads packets from an offline `.pcapng` file and analyzes network traffic.

In addition to basic packet parsing, the project also:

- Calculates **payload size (in bytes)** for each packet
- Tracks flows using **5-tuple (src/dst IP, port, protocol)**
- Stores **total payload bytes per flow**
- Extracts HTTP requests (GET / POST)
- Uses **multithreading (producer-consumer)** for file writing

There is a sample pcap file under the `pcaps` directory to be used for testing.

---

## Features

### Packet Analysis
The program prints:

- Source and destination IP addresses
- Protocol (TCP / UDP)
- Source and destination ports
- Payload length (in bytes)

Payload is calculated as: Payload Length = IP Total Length - IP Header Length - TCP/UDP Header Length



---

### HTTP Extraction
- Detects HTTP requests (`GET`, `POST`)
- Extracts header lines
- Writes them asynchronously to output file

This is handled using a **producer-consumer queue** with threads.

---

### Flow Tracking (uthash)

Flows are tracked using:

- Source IP
- Destination IP
- Source Port
- Destination Port
- Protocol

Instead of counting packets, the program accumulates:

**Total payload bytes per flow**

Example output: Flow -> src_ip=192.168.1.10, dst_ip=93.184.216.34, src_port=53210, dst_port=80, protocol=6, byte_count=2048


---

### Multithreading

- Producer thread → pushes HTTP data into queue
- Consumer thread → writes to file
- Uses:
    - `pthread`
    - mutex
    - condition variables

---

## Requirements (Ubuntu)

Install required dependencies:

```bash
sudo apt update
sudo apt install build-essential cmake libpcap-dev


mkdir build
cd build
cmake ..
cmake --build .


./packet_sniffer ../pcaps/sample.pcapng output.txt flows.txt