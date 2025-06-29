from scapy.all import ICMP, IP, sniff
from collections import defaultdict
from datetime import datetime
from utils.logger import log_alert

# Stores timestamps of ICMP packets per source IP
icmp_count = defaultdict(list)

# Threshold for number of ICMP packets per second per IP
THRESHOLD = 100

def detect_ping_flood():
    """
    Starts sniffing ICMP packets and detects ping flood attacks in real time.
    """
    sniff(prn=handle_packet, store=0)

def handle_packet(pkt):
    """
    Callback function that processes each sniffed packet and detects ICMP flooding.

    Parameters:
    - pkt: The captured network packet.
    """
    if pkt.haslayer(ICMP):
        src_ip = pkt[IP].src
        now = datetime.now()

        # Keep only timestamps within the last second
        icmp_count[src_ip] = [t for t in icmp_count[src_ip] if (now - t).seconds < 1]
        icmp_count[src_ip].append(now)

        # Trigger alert if threshold is exceeded
        if len(icmp_count[src_ip]) > THRESHOLD:
            log_alert("Ping Flood detected!", attack_type="Ping Flood", source_ip=src_ip)
            icmp_count[src_ip] = []
