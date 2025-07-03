from scapy.layers.inet import IP, TCP
from detector import port_scan

class DummyPkt:
    def __init__(self, src, dst, dport):
        self[IP] = IP(src=src, dst=dst)
        self[TCP] = TCP(dport=dport)

    def haslayer(self, layer):
        return layer in [IP, TCP]

    def __getitem__(self, item):
        return self.__dict__.get(item)

    def __setitem__(self, key, value):
        self.__dict__[key] = value

def test_port_scan_detection(monkeypatch):
    port_scan.monitor_ips = ["10.0.0.5"]
    port_scan.max_ports = 5

    alerts = []
    monkeypatch.setattr(port_scan, "log_alert", lambda msg, attack_type=None, source_ip=None: alerts.append((msg, attack_type, source_ip)))

    port_scan.scan_activity.clear()
    port_scan.alerts_issued.clear()

    for port in range(80, 86):
        pkt = DummyPkt(src="192.168.50.10", dst="10.0.0.5", dport=port)
        port_scan.process_packet(pkt)

    assert len(alerts) == 1
    assert "Port scan" in alerts[0][0]
