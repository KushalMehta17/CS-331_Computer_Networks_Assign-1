import socket
import json
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP

# First, we load the rules from the JSON file
with open('rules.json', 'r') as f:
    RULES = json.load(f)

# Next, defined the pool of IP addresses to choose from
IP_POOL = [
    "192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5",
    "192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9", "192.168.1.10",
    "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"
]

# Server configuration 
SERVER_IP = '0.0.0.0'  # Listen on all available network interfaces
SERVER_PORT = 5300      # Port to listen on

def resolve_ip(custom_header):

    """
    This function applies the rules to the custom header to select an IP from the pool.
    Args- custom_header (str): The 8-byte header string (For example, '12105500')
    Returns- str: The selected IP address (For example, '192.168.1.6')
    """

    # First, we extract hour and ID from the header string
    hour_str = custom_header[:2]  
    session_id_str = custom_header[6:8]  
    hour = int(hour_str)
    session_id = int(session_id_str)

    # Next, we determine the time of day and get the corresponding rule set
    time_rules = RULES['timestamp_rules']['time_based_routing']
    
    if 4 <= hour < 12:
        rule = time_rules['morning']
    elif 12 <= hour < 20:
        rule = time_rules['afternoon']
    else: 
        rule = time_rules['night']

    # Now we apply the rule and calculate the index in the IP_POOL
    pool_index = rule['ip_pool_start'] + (session_id % rule['hash_mod'])

    # Finally, we return the IP address at the calculated index
    return IP_POOL[pool_index]

def main():
    # We start by creating a UDP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Then we bind the socket to the IP and port
    server_socket.bind((SERVER_IP, SERVER_PORT))
    
    print(f"DNS Resolution Server started. Listening on {SERVER_IP}:{SERVER_PORT}")

    try:
        while True:
            # Receive data from the client first
            data, client_address = server_socket.recvfrom(4096)
            server_socket.settimeout(3.0)
            print(f"\nReceived a packet from {client_address}")

            # We split the received data into custom header and original DNS packet
            custom_header = data[:8].decode()  # First 8 bytes are our header
            original_dns_packet_bytes = data[8:] # The rest is the original DNS query

            print(f"    Custom Header: {custom_header}")

            # Next, we parse the original DNS query packet using Scapy
            try:
                dns_query = DNS(original_dns_packet_bytes)
                queried_domain = dns_query.qd.qname.decode('utf-8')
                print(f"    Queried Domain: {queried_domain}")
            except Exception as e:
                print(f"Error: Could not parse DNS query. {e}")
                print(f"    Raw bytes (first 50): {original_dns_packet_bytes[:50]}")
                continue

            # Then apply the rules to resolve the IP based on the custom header
            resolved_ip = resolve_ip(custom_header)
            print(f"    Resolved IP (by provided rules): {resolved_ip}")

            # Finally, crafted a DNS response packet
            dns_response = DNS(
                id=dns_query.id, # Matched the ID from the query
                qr=1,           # 1 = Response (0 is Query)
                aa=1,           # 1 = Authoritative Answer
                qd=dns_query.qd, # Copied the question section from the query
                an=DNSRR(
                    rrname=dns_query.qd.qname, # The domain that was queried
                    type='A',                  # Answer with an A record (IPv4)
                    rclass='IN',               # Internet class
                    ttl=300,                   # Time to live (5 minutes)
                    rdata=resolved_ip          # The IP we chose based on rules
                )
            )

            # Sent the crafted DNS response back to the client
            server_socket.sendto(bytes(dns_response), client_address)
            print(f"Sent DNS response to {client_address}\n")

    except socket.timeout:
                # This exception is raised every 3 seconds when no data is received.
                # We just use it to break out of the recvfrom call.
                # We can simply pass and let the loop continue, which will check for KeyboardInterrupt.
                pass

    except KeyboardInterrupt:
        print("\nServer is shutting down.")
        
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()