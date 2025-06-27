from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
from collections import defaultdict
import csv
import time
import os

# === Global reference to GUI ===
gui_ref = None  # Will be assigned from gui_app.py

# === Configuration ===
CONN_LOG = "./logs/connections_log.csv"
ALERT_LOG = "./logs/alerts_log.txt"
IGNORED_IPS = {"127.0.0.1", "localhost"}
IGNORED_PREFIXES = ["192.168.", "10.", "172.16."]
BRUTEFORCE_PORTS = {21, 22, 23, 25, 110, 143, 3389}
PORT_SCAN_THRESHOLD = 15
BRUTEFORCE_THRESHOLD = 10
TIME_WINDOW = 10
COOLDOWN = 30

# === Temporary Data ===
ip_ports = defaultdict(list)
ip_target_ports = defaultdict(lambda: defaultdict(list))
last_alert_time = {}

# === Initialize log file ===
if not os.path.exists(CONN_LOG):
    os.makedirs(os.path.dirname(CONN_LOG), exist_ok=True)
    with open(CONN_LOG, "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol"])

def is_ignored(ip):
    return ip in IGNORED_IPS or any(ip.startswith(pref) for pref in IGNORED_PREFIXES)

def log_connection(ts, ip_src, ip_dst, sport, dport, proto):
    with open(CONN_LOG, "a", newline='') as f:
        writer = csv.writer(f)
        writer.writerow([ts, ip_src, ip_dst, sport, dport, proto])

def log_alert(ip, reason):
    now = time.time()
    key = (ip, reason)
    if key in last_alert_time and now - last_alert_time[key] < COOLDOWN:
        return
    last_alert_time[key] = now

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert_text = f"[{timestamp}] Alerte {reason} : {ip}\n"
    print(alert_text.strip())
    with open(ALERT_LOG, "a") as f:
        f.write(alert_text)

    # GUI alert (visual popup/table update)
    if gui_ref:
        gui_ref.show_alert(ip, reason)

def detect_port_scan(ip, dport):
    now = time.time()
    ip_ports[ip].append((now, dport))
    ip_ports[ip] = [(t, p) for t, p in ip_ports[ip] if now - t < TIME_WINDOW]
    ports = set(p for _, p in ip_ports[ip])
    if len(ports) > PORT_SCAN_THRESHOLD:
        log_alert(ip, "Port Scan")

def detect_brute_force(ip, dport):
    if dport not in BRUTEFORCE_PORTS:
        return
    now = time.time()
    ip_target_ports[ip][dport].append(now)
    ip_target_ports[ip][dport] = [t for t in ip_target_ports[ip][dport] if now - t < TIME_WINDOW]
    if len(ip_target_ports[ip][dport]) > BRUTEFORCE_THRESHOLD:
        log_alert(ip, f"Brute-force on port {dport}")

def process_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        if is_ignored(ip_src):
            return

        proto = sport = dport = None
        if TCP in packet:
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport

        if proto and sport is not None and dport is not None:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_connection(timestamp, ip_src, ip_dst, sport, dport, proto)
            detect_port_scan(ip_src, dport)
            detect_brute_force(ip_src, dport)