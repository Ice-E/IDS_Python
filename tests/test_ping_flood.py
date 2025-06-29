from scapy.layers.inet import IP, ICMP
from detector import ping_flood

def test_ping_flood_detection(monkeypatch):
    """
    Tests the ping flood detection by simulating a burst of ICMP packets
    from a single source IP to exceed the detection threshold.
    """
    pkt = IP(src="192.168.0.10") / ICMP()
    alerts = []

    # Replace the real alert logger with a mock function
    def fake_log_alert(message, attack_type=None, source_ip=None):
        alerts.append((message, attack_type, source_ip))

    monkeypatch.setattr("detector.ping_flood.log_alert", fake_log_alert)

    # Send 101 packets (threshold is 100) to trigger detection
    for _ in range(101):
        ping_flood.handle_packet(pkt)

    assert len(alerts) >= 1
    assert alerts[0][1] == "Ping Flood"
