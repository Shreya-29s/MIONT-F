# packetMatching.py
import pyshark
from collections import defaultdict

def process_packets(pcap_file):
    ip_count = defaultdict(int)
    
    # Open the pcap file
    cap = pyshark.FileCapture(pcap_file)
    
    # Loop through each packet and count the IPs
    for packet in cap:
        if 'IP' in packet:
            ip_src = packet.ip.src
            ip_dst = packet.ip.dst
            ip_count[ip_src] += 1
            ip_count[ip_dst] += 1
    
    return ip_count
