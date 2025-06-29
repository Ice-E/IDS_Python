from scapy.all import TCP, IP, sniff
from collections import defaultdict
from datetime import datetime
from utils.logger import log_alert

# Tracks connection attempts per source IP and port
scan_tracker = defaultdict(lambda: defaultdict(list))

# Number of unique ports accessed within the time window to trigger an alert
THRESHOLD = 20

def detect_port_scan():
    """
    Starts sniffing TCP packets and detects port scanning activity in real time.
    """
    sniff(prn=handle_packet, store=0)

def handle_packet(pkt):
    """
    Callback function that processes each sniffed packet and tracks connection attempts.

    Parameters:
    - pkt: The captured TCP packet.
    """
    if pkt.haslayer(TCP):
        src_ip = pkt[IP].src
        dst_port = pkt[TCP].dport
        now = datetime.now()

        # Record the timestamp for the destination port
        scan_tracker[src_ip][dst_port].append(now)

        # Filter out ports not accessed in the last 10 seconds
        active_ports = [
            port for port, times in scan_tracker[src_ip].items()
            if any((now - t).seconds < 10 for t in times)
        ]

        # If the number of active ports exceeds the threshold, raise an alert
        if len(active_ports) >= THRESHOLD:
            log_alert("Port Scan detected!", attack_type="Port Scan", source_ip=src_ip)
            scan_tracker[src_ip] = defaultdict(list)
