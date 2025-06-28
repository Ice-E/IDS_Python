from scapy.all import ARP, sniff
from collections import defaultdict

# Stockage des IPs associées à plusieurs MACs
ip_mac_map = defaultdict(set)

def process_packet(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP reply
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc
        ip_mac_map[ip].add(mac)

def detect_arp_spoofing():
    ip_mac_map.clear()
    # Écoute de 50 paquets ARP seulement pour éviter les blocages
    sniff(filter="arp", prn=process_packet, count=50, store=0)
    
    alerts = []
    for ip, macs in ip_mac_map.items():
        if len(macs) > 1:
            alerts.append({
                "ip": ip,
                "mac": ", ".join(macs),
                "alert": "ARP spoofing détecté (plusieurs MAC pour la même IP)"
            })
    return alerts
