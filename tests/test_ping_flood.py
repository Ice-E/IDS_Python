from scapy.layers.inet import IP, ICMP
from detector import ping_flood

class DummyPkt:
    def __init__(self, src, dst):
        self[IP] = IP(src=src, dst=dst)
        self[ICMP] = ICMP(type=8)

    def haslayer(self, layer):
        return layer in [IP, ICMP]

    def __getitem__(self, item):
        return self.__dict__.get(item)

    def __setitem__(self, key, value):
        self.__dict__[key] = value

def test_ping_flood_detection(monkeypatch):
    ping_flood.monitor_ips = ["10.0.0.1"]
    ping_flood.threshold = 5

    alerts = []
    monkeypatch.setattr(ping_flood, "log_alert", lambda msg, attack_type=None, source_ip=None: alerts.append((msg, attack_type, source_ip)))

    ping_flood.icmp_requests.clear()
    ping_flood.alerts_issued.clear()

    for _ in range(6):
        pkt = DummyPkt(src="192.168.1.100", dst="10.0.0.1")
        ping_flood.process_packet(pkt)

    assert len(alerts) == 1
    assert "Ping flood" in alerts[0][0]
