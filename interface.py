from scapy.all import get_if_list, get_if_addr

# Iterate over all available network interfaces on the system
for iface in get_if_list():
    try:
        # Attempt to retrieve the IP address associated with the interface
        ip = get_if_addr(iface)
    except Exception:
        # If the interface has no IP (or access is denied), mark it as unavailable
        ip = "N/A"
    
    # Print interface name and its associated IP address
    print(f"{iface} -> {ip}")
