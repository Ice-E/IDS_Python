import socket
import time

def simulate_port_scan(target_ip="127.0.0.1", ports=range(20, 40)):
    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(0.2)
            s.connect((target_ip, port))
        except:
            pass
        finally:
            s.close()
        time.sleep(0.1)  # spread out to simulate a real scan