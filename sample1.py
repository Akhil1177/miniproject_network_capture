from scapy.all import sniff, IP, TCP, UDP, ICMP,Ether
from collections import defaultdict
import numpy as np
import pandas as pd
import math
import time
import statistics

# Store network traffic data with the last four keys correctly placed
traffic_data = defaultdict(lambda: {key: 0 for key in [
    "flow_duration", "header_length", "protocol_type", "duration", "srate",
    "fin_flag", "syn_flag", "rst_flag", "psh_flag", "ack_flag", "ece_flag", "cwr_flag",
    "ack_count", "syn_count", "fin_count", "urg_count", "rst_count",
    "TCP", "UDP", "ICMP", "IPv", "LLC",
    "tot_sum", "min", "max", "avg", "std", "tot_size", "number", "magnitude", "radius", 
    # Last four items in the dictionary
    "covariance", "variance", "weight", "label"
]})

# Store packet sizes and inter-arrival times for covariance calculation
packet_size_data = defaultdict(list)
iat_data = defaultdict(list)

# Packet capture duration (seconds)
CAPTURE_TIME = 30  
start_time = time.time()
last_packet_time = {}

def process_packet(packet):
    """Processes each captured packet and extracts features."""
    if packet.haslayer(IP):
        src_ip = packet[IP].src  
        packet_size = len(packet)  
        current_time = time.time()

        # Compute Inter-Arrival Time (IAT)
        iat = (current_time - last_packet_time[src_ip]) if src_ip in last_packet_time else 0
        last_packet_time[src_ip] = current_time  

        # Store values
        packet_size_data[src_ip].append(packet_size)
        iat_data[src_ip].append(iat)

        # Extract protocol type
        protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "ICMP" if packet.haslayer(ICMP) else "Other"
        
        # Extract TCP Flags
        fin_flag = int(packet[TCP].flags & 0x01) if packet.haslayer(TCP) else 0
        syn_flag = int(packet[TCP].flags & 0x02) if packet.haslayer(TCP) else 0
        rst_flag = int(packet[TCP].flags & 0x04) if packet.haslayer(TCP) else 0
        psh_flag = int(packet[TCP].flags & 0x08) if packet.haslayer(TCP) else 0
        ack_flag = int(packet[TCP].flags & 0x10) if packet.haslayer(TCP) else 0
        ece_flag = int(packet[TCP].flags & 0x40) if packet.haslayer(TCP) else 0
        cwr_flag = int(packet[TCP].flags & 0x80) if packet.haslayer(TCP) else 0

        # Calculate Header Length
        traffic_data[src_ip]["header_length"] = packet[IP].ihl * 4  # Internet Header Length (IHL) in bytes

        # Update traffic data
        traffic_data[src_ip]["flow_duration"] = current_time - start_time
        traffic_data[src_ip]["protocol_type"] = protocol
        traffic_data[src_ip]["duration"] = packet[IP].ttl
        traffic_data[src_ip]["srate"] += 1 / (time.time() - start_time)

        # Store TCP flag values
        traffic_data[src_ip]["fin_flag"] = fin_flag
        traffic_data[src_ip]["syn_flag"] = syn_flag
        traffic_data[src_ip]["rst_flag"] = rst_flag
        traffic_data[src_ip]["psh_flag"] = psh_flag
        traffic_data[src_ip]["ack_flag"] = ack_flag
        traffic_data[src_ip]["ece_flag"] = ece_flag
        traffic_data[src_ip]["cwr_flag"] = cwr_flag

        # TCP flag counts
        traffic_data[src_ip]["ack_count"] += ack_flag
        traffic_data[src_ip]["syn_count"] += syn_flag
        traffic_data[src_ip]["fin_count"] += fin_flag
        traffic_data[src_ip]["rst_count"] += rst_flag

        # Protocol mapping
        traffic_data[src_ip]["TCP"] = 1 if protocol == "TCP" else 0
        traffic_data[src_ip]["UDP"] = 1 if protocol == "UDP" else 0
        traffic_data[src_ip]["ICMP"] = 1 if protocol == "ICMP" else 0



         # Determine IPv version (IPv4 or IPv6)
        if packet.haslayer(IP):
            
            traffic_data[src_ip]["IPv"] = 1  # IPv4

        else:
           traffic_data[src_ip]["IPv"] = 0  # IPv4

           

       
        #Determine LLC
        traffic_data[src_ip]["LLC"] = 1 if packet.haslayer(Ether) and packet[Ether].type < 0x0600 else 0



        # Packet size statistics
        traffic_data[src_ip]["tot_sum"] += packet_size
        traffic_data[src_ip]["min"] = min(traffic_data[src_ip]["min"], packet_size) if traffic_data[src_ip]["min"] else packet_size
        traffic_data[src_ip]["max"] = max(traffic_data[src_ip]["max"], packet_size)
        traffic_data[src_ip]["avg"] = traffic_data[src_ip]["tot_sum"] / len(packet_size_data[src_ip])
        traffic_data[src_ip]["tot_size"] = len(packet_size_data[src_ip])
        traffic_data[src_ip]["number"] = len(packet_size_data[src_ip])

        # Standard deviation and variance
        if len(packet_size_data[src_ip]) > 1:
            traffic_data[src_ip]["std"] = statistics.stdev(packet_size_data[src_ip])
            traffic_data[src_ip]["variance"] = statistics.variance(packet_size_data[src_ip])
        else:
            traffic_data[src_ip]["std"] = 0
            traffic_data[src_ip]["variance"] = 0

        # Compute magnitude
        traffic_data[src_ip]["magnitude"] = math.sqrt(sum(size ** 2 for size in packet_size_data[src_ip]))

        # Compute radius
        mean_size = statistics.mean(packet_size_data[src_ip]) if packet_size_data[src_ip] else 0
        traffic_data[src_ip]["radius"] = math.sqrt(sum((size - mean_size) ** 2 for size in packet_size_data[src_ip]))

        # Compute weight
        traffic_data[src_ip]["weight"] = sum(packet_size_data[src_ip]) / len(packet_size_data[src_ip]) if packet_size_data[src_ip] else 0

        # Compute covariance (between packet sizes & inter-arrival times)
        if len(packet_size_data[src_ip]) > 1 and len(iat_data[src_ip]) > 1:
            traffic_data[src_ip]["covariance"] = np.cov(packet_size_data[src_ip], iat_data[src_ip])[0][1]
        else:
            traffic_data[src_ip]["covariance"] = 0

        # Labeling (To be replaced by ML classification)
        traffic_data[src_ip]["label"] = "Normal"

# Start sniffing
print(f"🚀 Capturing network packets for {CAPTURE_TIME} seconds...\n")
sniff(iface="Wi-Fi", prn=process_packet, store=False, timeout=CAPTURE_TIME)

# Convert to DataFrame
df = pd.DataFrame.from_dict(traffic_data, orient='index')
df.reset_index(inplace=True)
df.rename(columns={'index': 'Source_IP'}, inplace=True)

# Save the data
df.to_csv("network_traffic.csv", index=False)
print("\n✅ Data saved as 'network_traffic.csv'. Ready for ML training!")
