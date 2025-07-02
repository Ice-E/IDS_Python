from scapy.all import sniff, ICMP, IP
from collections import defaultdict
from utils.logger import log_alert
import time, json

# Load configuration from external JSON file
with open("config.json") as f:
    config = json.load(f)

interface   = config["network"]["interface"]
monitor_ips = config["network"]["monitor_ips"]
threshold   = config["detection"]["ping_flood"]["threshold"]

# Mapping of source IP to a list of ICMP request timestamps (within the last 10 seconds)
icmp_requests = defaultdict(list)

# Keeps track of 10-second time windows already alerted for each source IP
alerts_issued = defaultdict(set)

def process_packet(pkt):
    """
    Callback function executed for each sniffed packet. It inspects ICMP Echo Requests (type 8),
    tracks per-source packet rates over a sliding 10-second window, and triggers alerts
    if a flood threshold is exceeded.
    """
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8 and pkt.haslayer(IP):
        dst_ip = pkt[IP].dst
        src_ip = pkt[IP].src
        now    = time.time()
        window = int(now // 10)  # 10-second window bucket

        # Only process packets targeting monitored IPs
        if dst_ip not in monitor_ips:
            return

        # Keep only timestamps within the last 10 seconds
        icmp_requests[src_ip].append(now)
        icmp_requests[src_ip] = [t for t in icmp_requests[src_ip] if now - t <= 10]

        # Raise an alert if threshold is exceeded and not already reported in this window
        if len(icmp_requests[src_ip]) > threshold and window not in alerts_issued[src_ip]:
            print("Ping flooding detected")
            log_alert(
                f"Ping flood detected from {src_ip} (> {threshold} pkts/10s)",
                attack_type="Ping Flood",
                source_ip=src_ip
            )
            alerts_issued[src_ip].add(window)

            # Clear timestamps to avoid duplicate alerts in same window
            icmp_requests[src_ip].clear()

def detect_ping_flood():
    """
    Starts real-time detection of ICMP ping flood attacks by sniffing incoming ICMP packets
    on the configured network interface.
    
    This function runs indefinitely and processes each packet through `process_packet`.
    """
    print("Ping flood detection started")
    sniff(filter="icmp", prn=process_packet, store=0, iface=interface)