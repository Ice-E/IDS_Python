from scapy.layers.inet import IP, TCP
from detector import syn_flood

class DummyPkt:
    def __init__(self, src, dst, dport):
        self[IP] = IP(src=src, dst=dst)
        self[TCP] = TCP(dport=dport, flags='S')

    def haslayer(self, layer):
        return layer in [IP, TCP]

    def __getitem__(self, item):
        return self.__dict__.get(item)

    def __setitem__(self, key, value):
        self.__dict__[key] = value

def test_syn_flood_detection(monkeypatch):
    syn_flood.monitor_ips = ["10.0.0.100"]
    syn_flood.threshold = 5

    alerts = []
    monkeypatch.setattr(syn_flood, "log_alert", lambda msg, attack_type=None, source_ip=None: alerts.append((msg, attack_type, source_ip)))

    syn_flood.syn_packets.clear()
    syn_flood.alerts_issued.clear()

    for _ in range(6):
        pkt = DummyPkt(src="192.168.1.200", dst="10.0.0.100", dport=80)
        syn_flood.process_packet(pkt)

    assert len(alerts) == 1
    assert "SYN flood" in alerts[0][0]
