from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
from collections import defaultdict
import csv
import time
import os

# Fichiers de log
CONN_LOG = "../logs/connections_log.csv"
ALERT_LOG = "../logs/alerts_log.txt"

# Stockage des activités IP pour détection
ip_activity = defaultdict(list)

# Création des fichiers s'ils n'existent pas
if not os.path.exists(CONN_LOG):
    with open(CONN_LOG, "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol"])

def log_connection(timestamp, src_ip, dst_ip, src_port, dst_port, proto):
    with open(CONN_LOG, "a", newline='') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, src_ip, dst_ip, src_port, dst_port, proto])

def alert(ip, reason):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert_text = f"[{timestamp}] Alerte : {ip} - {reason}\n"
    print(alert_text.strip())
    with open(ALERT_LOG, "a") as f:
        f.write(alert_text)

def detect_intrusion(ip):
    now = time.time()
    ip_activity[ip].append(now)
    # Ne garder que les 10 dernières secondes
    ip_activity[ip] = [t for t in ip_activity[ip] if now - t < 10]
    if len(ip_activity[ip]) > 10:
        alert(ip, "activité réseau excessive (>10 connexions en 10s)")

def process_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = None
        sport = dport = None

        if TCP in packet:
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if proto:
            log_connection(timestamp, ip_src, ip_dst, sport, dport, proto)
            detect_intrusion(ip_src)

# Capture en continu (nécessite les droits admin)
print("Démarrage de la surveillance réseau... (CTRL+C pour arrêter)")
sniff(prn=process_packet, store=False)