from scapy.all import sniff, TCP, IP
from collections import defaultdict
from utils.logger import log_alert
import time, json

# Load configuration from external file
with open("config.json") as f:
    config = json.load(f)

interface   = config["network"]["interface"]
monitor_ips = config["network"]["monitor_ips"]
max_ports   = config["detection"]["port_scan"]["max_ports_per_time"]

# Tracks for each source IP: a mapping of 10-second window → set of destination ports contacted
scan_activity = defaultdict(lambda: defaultdict(set))

# Tracks already alerted 10-second windows per source IP
alerts_issued = defaultdict(set)

def process_packet(pkt):
    """
    Callback for each sniffed TCP packet.
    Detects port scan behavior based on number of unique destination ports
    contacted within a short time window.
    """
    if pkt.haslayer(TCP) and pkt.haslayer(IP):
        dst_ip   = pkt[IP].dst
        src_ip   = pkt[IP].src
        dst_port = pkt[TCP].dport
        current_window = int(time.time() // 10)  # current 10-second window

        # Only monitor packets targeting configured IPs
        if dst_ip not in monitor_ips:
            return

        # Register the destination port for this source IP and time window
        ports = scan_activity[src_ip][current_window]
        ports.add(dst_port)

        # Raise alert if port threshold is exceeded in current window
        if len(ports) > max_ports and current_window not in alerts_issued[src_ip]:
            print("Port scanning detected")
            log_alert(
                f"Port scan detected from {src_ip} (> {max_ports} ports/10s)",
                attack_type="Port Scan",
                source_ip=src_ip
            )
            alerts_issued[src_ip].add(current_window)
            scan_activity[src_ip][current_window].clear()  # reset to prevent duplicate alert

        # Clean up old entries beyond 2 windows (~20s)
        for old_window in list(scan_activity[src_ip]):
            if old_window < current_window - 2:
                del scan_activity[src_ip][old_window]
        for old_window in list(alerts_issued[src_ip]):
            if old_window < current_window - 2:
                alerts_issued[src_ip].remove(old_window)

def detect_port_scan():
    """
    Starts TCP port scan detection by sniffing packets on the specified network interface.
    
    Inspects each TCP packet in real-time to determine if a source IP is contacting
    an unusually high number of ports in a short time frame — indicating a potential scan.
    """
    print("Port scan detection started")
    sniff(filter="tcp", prn=process_packet, store=0, iface=interface)
