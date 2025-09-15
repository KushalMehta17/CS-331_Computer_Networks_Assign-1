# DNS Resolver & Traceroute Analysis

## Assignment Overview
This project is a solution for Computer Networks Assignment 1, consisting of two main tasks:
1. **Task 1:** Implementation of a custom DNS resolver client-server system with time-based routing rules.
2. **Task 2:** Analysis of traceroute protocol behaviour across different operating systems.

## Project Structure
```
CS-331_Computer_Networks_Assign-1/
├── client.py              # DNS client implementation
├── server.py              # DNS server implementation
├── rules.json             # Time-based routing rules configuration
├── README.md              # This file
├── Report.pdf             # Report explaining our approach and results
```

## File Descriptions

### client.py
The DNS client is responsible for:
- Reading and parsing PCAP files
- Filtering DNS query packets
- Adding custom timestamp headers to each query
- Communicating with the DNS server
- Logging and displaying resolution results

### server.py
The DNS server:
- Listens for incoming DNS requests
- Processes custom timestamp headers
- Applies time-based routing rules from rules.json
- Returns appropriate IP addresses based on the rules
- Handles multiple client requests simultaneously

### rules.json
Configuration file containing the time-based routing rules:
- Morning (04:00-11:59): Routes to IP pool 192.168.1.1-192.168.1.5
- Afternoon (12:00-19:59): Routes to IP pool 192.168.1.6-192.168.1.10  
- Night (20:00-03:59): Routes to IP pool 192.168.1.11-192.168.1.15

## Running the DNS Resolver (Task 1)

### Step 1: Start the DNS Server
Open a terminal window and run:
```
python server.py
```
The server will start listening on port 5300 and display a confirmation message. Press `Ctrl+C` to interrupt and terminate the process once completed.

### Step 2: Run the DNS Client
Open another terminal window and run:
```
python client.py 9.pcap
```
Replace `9.pcap` with your designated PCAP filename if different (ensure that the PCAP file is in the same directory as the scripts).

### Expected Output
The client will:
1. Display the number of DNS queries found in the PCAP file
2. Show each query being processed with its custom header
3. Display the resolved IP address for each query
4. Print a final summary table with all resolutions

The server will:
1. Confirm startup and display listening status
2. Show each received request with its custom header
3. Display the applied rule and selected IP address
4. Confirm response sent back to client

## Task 2: Traceroute Analysis
For the second part of the assignment, we analyzed traceroute behavior by:

1. Running traceroute commands on different operating systems:
   - Windows: `tracert www.google.com`
   - Linux: `traceroute www.google.com`

2. Capturing network traffic during execution using Wireshark

3. Analyzing the differences in:
   - Default protocols used (ICMP vs UDP)
   - Packet structures and field variations
   - Firewall impact on results
   - Response patterns at intermediate and final hops

## Results
The implementation successfully processes DNS queries according to the time-based rules and generates a comprehensive report table showing:
- Custom header values (HHMMSSID)
- Queried domain names
- Resolved IP addresses based on time-based rules

The traceroute analysis provides insights into protocol differences between operating systems and how network conditions affect path discovery.
