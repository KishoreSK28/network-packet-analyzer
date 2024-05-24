from scapy.all import sniff, IP

# Function to process captured packets
def process_packet(packet):
    if IP in packet:
        # Extract IP layer information
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        # Print packet information
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {proto}")

# Start capturing packets
print("Starting packet capture...")

# Sniff function with a filter to capture only IP packets
sniff(filter="ip", prn=process_packet, store=True)

# End of capturing
print("Packet capture stopped.")
