from scapy.all import ARP, sniff
from collections import defaultdict
from utils.logger import log_alert

# ARP table that tracks observed MAC addresses for each IP
arp_table = defaultdict(set)

def detect_arp_spoofing():
    """
    Starts sniffing ARP packets and checks for spoofing attempts in real time.
    """
    sniff(prn=handle_packet, store=0)

def handle_packet(pkt):
    """
    Callback function that processes each sniffed packet and detects ARP spoofing.

    Parameters:
    - pkt: The captured packet.
    """
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP reply
        src_ip = pkt[ARP].psrc
        src_mac = pkt[ARP].hwsrc

        # If a new MAC is associated with a known IP, raise an alert
        if src_mac not in arp_table[src_ip] and arp_table[src_ip]:
            log_alert(
                f"ARP Spoofing detected: {src_ip} is being spoofed!",
                attack_type="ARP Spoofing",
                source_ip=src_ip
            )
        arp_table[src_ip].add(src_mac)
