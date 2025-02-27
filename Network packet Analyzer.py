from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "Unknown"
        
        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        
        print(f"Source: {src_ip} -> Destination: {dst_ip} | Protocol: {protocol}")

if __name__ == "__main__":
    print("Starting Packet Sniffer... Press Ctrl+C to stop.")
    sniff(prn=packet_callback, store=False)
