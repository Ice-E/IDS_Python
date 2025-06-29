import socket

def port_scan(ip="127.0.0.1", ports=range(20, 100)):
    """
    Performs a basic TCP port scan on the specified IP address.

    Parameters:
    - ip (str): The target IP address to scan. Defaults to localhost.
    - ports (iterable): A range or list of ports to scan. Defaults to 20–99.
    """
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)  # Short timeout for faster scanning
        s.connect_ex((ip, port))  # Attempt to connect; result is ignored
        s.close()

# Example usage (use responsibly in a test environment):
# port_scan()
