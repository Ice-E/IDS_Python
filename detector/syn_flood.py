from scapy.all import TCP, IP, sniff
from collections import defaultdict
from datetime import datetime
from utils.logger import log_alert

# Tracks SYN packet timestamps per source IP
syn_tracker = defaultdict(list)

# Maximum allowed SYN packets per IP per second before triggering an alert
THRESHOLD = 200

def detect_syn_flood():
    """
    Starts sniffing TCP packets and detects SYN flood attacks in real time.
    """
    sniff(prn=handle_packet, store=0)

def handle_packet(pkt):
    """
    Callback function to process each packet and detect SYN flood patterns.

    Parameters:
    - pkt: The captured TCP packet.
    """
    if pkt.haslayer(TCP) and pkt[TCP].flags == "S":  # Only handle SYN packets
        src_ip = pkt[IP].src
        now = datetime.now()

        # Keep only timestamps from the last second
        syn_tracker[src_ip] = [t for t in syn_tracker[src_ip] if (now - t).seconds < 1]
        syn_tracker[src_ip].append(now)

        # Trigger alert if the threshold is exceeded
        if len(syn_tracker[src_ip]) > THRESHOLD:
            log_alert("SYN Flood detected!", attack_type="SYN Flood", source_ip=src_ip)
            syn_tracker[src_ip] = []
