# CS155: Network Security

This repository contains my completed implementation of Stanford's CS155 Computer Security course Project #3, which explores various aspects of network security through hands-on exercises.

## Overview

The project consisted of four main parts:

1. **Port Scanning**: Used nmap to analyze open ports and services on a remote server
2. **Packet Sniffing**: Analyzed network traffic using Wireshark to understand protocol behaviors  
3. **Programmatic Packet Processing**: Implemented a network traffic analyzer in Go to detect port scanning and ARP spoofing attacks
4. **Monster-in-the-Middle Attack**: Created a DNS spoofing attack that hijacks HTTP connections, implementing ARP spoofing, DNS spoofing, and HTTP traffic interception

## Technologies Used

- Go (golang)
- nmap  
- Wireshark
- Docker
- gopacket library

## Setup Instructions

1. **Install required tools**:
   - nmap
   - Wireshark 
   - Go
   - Docker

2. **Install Go dependencies**:
```
go mod download
```

3. **For Part 4 testing**:
```
bash start_images.sh
bash run_client.sh
bash stop_images.sh
```

## Acknowledgements

Project components were originally developed by Stanford University, incorporating elements from the University of Michigan and University of Illinois.
