import sys
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
import socket
import datetime

# Server configuration 
SERVER_IP = '127.0.0.1'  # Localhost (since our server is on the same machine)
SERVER_PORT = 5300        # Port the server is listening on

# Created a list to store our results for the final report
results_table = []

def main():
    # Just to ensure correct usage and handle edge cases
    if len(sys.argv) != 2:
        print("Usage command format: python client.py <path_to_pcap_file>")
        sys.exit(1)

    pcap_path = sys.argv[1]

    # Read all the packets from the PCAP file
    print(f"Reading packets from {pcap_path}...")
    packets = rdpcap(pcap_path)

    # Now we filtered out the DNS Query packets 
    print("\nFiltering for DNS query packets...")

    # Improved this filter after debugging: We filter out standard DNS queries over UDP on port 53
    dns_query_packets = [
        pkt for pkt in packets
        if (pkt.haslayer(DNSQR) and           # Has a DNS question
            pkt.haslayer(UDP) and             # Is a UDP packet
            pkt[UDP].dport == 53 and          # Is sent to DNS port (53)
            pkt.haslayer(DNS) and             # Has a DNS layer (most important)
            pkt[DNS].qr == 0 and              # Is a Query (0), not a Response (1)
            pkt[DNS].opcode == 0)             # Is a standard query (opcode 0)
    ]
    print(f" - Found {len(dns_query_packets)} DNS query packets.\n")

    # Created a socket object for network communication
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Here we processed each DNS query packet as explained in the below steps
    for idx, packet in enumerate(dns_query_packets):
        # First, we extract the domain name being queried
        dns_layer = packet.getlayer(DNS)

        # This code snippet was added as a debug after first attempt of testing: We skip the packet if getlayer(DNS) fails
        if dns_layer is None or dns_layer.qd is None:
            print(f"   Skipping packet {idx}: Could not find valid DNS layer.")
            continue # This skips the rest of the loop for this packet

        domain = dns_layer.qd.qname.decode('utf-8')
        # Next, we create the Custom Header (HHMMSSID)
        now = datetime.datetime.now()
        custom_header = now.strftime("%H%M%S") + f"{idx:02d}"  # For example, "14321500"

        # Now we build the payload: [8-byte header] + [DNS Layer Bytes Only]
        # Extract the DNS layer from the packet
        dns_layer = packet.getlayer(DNS)
        # Converted only the DNS layer to bytes
        dns_layer_bytes = bytes(dns_layer)

        payload_to_send = custom_header.encode() + dns_layer_bytes

        # Next, we send the payload to the server
        print(f"Sending packet {idx} for domain '{domain}' with header {custom_header}")
        client_socket.sendto(payload_to_send, (SERVER_IP, SERVER_PORT))

        # We wait and receive the response from the server
        response_data, server_address = client_socket.recvfrom(4096) # 4096 is buffer size
        print(f"Received response from server for header {custom_header}")

        # The server's response is a DNS message and thus we parse it with Scapy
        dns_response = DNS(response_data)

        # Next, we extract the resolved IP address from the response.
        # Check if there's an answer and if it's an IP
        resolved_ip = "No Answer"
        if dns_response.an and dns_response.an.type == 1: # Type 1 is A record (IPv4)
            resolved_ip = dns_response.an.rdata
            if isinstance(resolved_ip, bytes):
                resolved_ip = resolved_ip.decode('utf-8')

        # We add the result to our table
        results_table.append({
            'header': custom_header,
            'domain': domain,
            'resolved_ip': resolved_ip
        })
        print(f"    Domain: {domain} -> IP: {resolved_ip}\n")

    # Close the socket after processing all packets
    client_socket.close()

    # Finally, we printed the final report table to the console
    print()
    print("FINAL REPORT TABLE")
    print()
    print(f"| {'Custom Header':<16} | {'Domain':<25} | {'Resolved IP':<15} |")
    print("|------------------|---------------------------|-----------------|")

    for result in results_table:
        print(f"| {result['header']:<16} | www.{result['domain']:<21} | {result['resolved_ip']:<15} |")
    print()

if __name__ == "__main__":
    main()