import socket

def port_scan(ip="127.0.0.1", ports=range(20, 50)):
    """
    Performs a basic TCP port scan on the specified IP address.

    Parameters:
    - ip (str): The target IP address to scan. Defaults to localhost (127.0.0.1).
    - ports (iterable): A range or list of ports to scan. Defaults to range(20, 50).

    Notes:
    - This function attempts to establish a TCP connection to each port.
    - A short timeout is used for faster scanning.
    - No results are printed or returned — only the scan is executed.
    
    Warning:
    Unauthorized port scanning may be illegal or against terms of service.
    Always scan only systems you own or have permission to test.
    """
    print("Port scanning script started")
    
    for port in ports:
        # Create a new TCP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Set a timeout to prevent long wait times on unresponsive ports
        s.settimeout(0.1)
        
        # Attempt to connect to the target port
        s.connect_ex((ip, port))  # connect_ex returns 0 if port is open, but we ignore the result here
        
        # Close the socket after the attempt
        s.close()
        
if __name__ == "__main__":
    # Replace with a valid and authorized IP address when scanning
    port_scan("100.64.22.76")

# Example usage (use responsibly and only in a legal/test environment):
# port_scan()
