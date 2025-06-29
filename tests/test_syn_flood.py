from scapy.layers.inet import IP, TCP
from detector import syn_flood

def test_syn_flood_detection(monkeypatch):
    """
    Tests SYN flood detection by sending a burst of SYN packets
    from a single source IP to exceed the detection threshold.
    """
    alerts = []

    # Replace the real logger with a mock to collect alerts
    def fake_log_alert(message, attack_type=None, source_ip=None):
        alerts.append((message, attack_type, source_ip))

    monkeypatch.setattr("detector.syn_flood.log_alert", fake_log_alert)

    # Send 201 SYN packets (threshold is 200) from the same IP
    for _ in range(201):
        pkt = IP(src="172.16.0.8") / TCP(flags="S")
        syn_flood.handle_packet(pkt)

    assert len(alerts) >= 1
    assert alerts[0][1] == "SYN Flood"
