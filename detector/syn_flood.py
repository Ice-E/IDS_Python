from scapy.all import sniff, TCP, IP
from collections import defaultdict
from utils.logger import log_alert
import time, json

# Load configuration from external JSON file
with open("config.json") as f:
    config = json.load(f)

interface   = config["network"]["interface"]
monitor_ips = config["network"]["monitor_ips"]
threshold   = config["detection"]["syn_flood"]["threshold"]

# Tracks (dst_ip:dst_port) -> list of timestamps of incoming SYN packets (last 10 seconds)
syn_packets = defaultdict(list)

# Tracks which 10-second windows have already triggered alerts to avoid duplicates
alerts_issued = defaultdict(set)

def process_packet(pkt):
    """
    Callback executed for each captured packet.
    Monitors incoming TCP SYN packets and detects possible SYN flood attacks
    by counting SYNs received on each (dst_ip, dst_port) within 10-second windows.
    """
    if pkt.haslayer(TCP) and pkt[TCP].flags == "S" and pkt.haslayer(IP):
        dst_ip   = pkt[IP].dst
        dst_port = pkt[TCP].dport
        key      = f"{dst_ip}:{dst_port}"
        now      = time.time()
        window   = int(now // 10)  # 10-second window bucket

        # Only analyze traffic destined to monitored IPs
        if dst_ip not in monitor_ips:
            return

        # Retain only SYN packets from the last 10 seconds
        syn_packets[key].append(now)
        syn_packets[key] = [t for t in syn_packets[key] if now - t <= 10]

        # Trigger alert once per window if threshold exceeded
        if len(syn_packets[key]) > threshold and window not in alerts_issued[key]:
            print("SYN flooding detected")
            log_alert(
                f"SYN flood detected on {dst_ip}:{dst_port} (> {threshold}/10s)",
                attack_type="SYN Flood",
                source_ip=None  # Could be enhanced to log top sources if needed
            )
            alerts_issued[key].add(window)
            syn_packets[key].clear()

        # Optional: cleanup old alert windows beyond 1 minute
        for k in list(alerts_issued.keys()):
            alerts_issued[k] = {w for w in alerts_issued[k] if window - w <= 6}

def detect_syn_flood():
    """
    Starts real-time detection of TCP SYN flood attacks.
    
    Uses packet sniffing to analyze TCP SYN packets targeting monitored IPs,
    and raises alerts if SYN packet volume exceeds configured thresholds per port.
    """
    print("SYN flood detection started")
    sniff(
        filter="tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0",
        prn=process_packet,
        store=0,
        iface=interface
    )