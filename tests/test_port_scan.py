from scapy.layers.inet import IP, TCP
from detector import port_scan

def test_port_scan_detection(monkeypatch):
    """
    Tests port scan detection by simulating TCP packets to multiple ports
    from the same source IP, exceeding the scan detection threshold.
    """
    alerts = []

    # Replace the alert logger with a mock to capture alert calls
    def fake_log_alert(message, attack_type=None, source_ip=None):
        alerts.append((message, attack_type, source_ip))

    monkeypatch.setattr("detector.port_scan.log_alert", fake_log_alert)

    # Simulate TCP packets on a range of ports from one IP (threshold = 20)
    for port in range(20, 41):  # 21 ports in total
        pkt = IP(src="10.0.0.5") / TCP(dport=port)
        port_scan.handle_packet(pkt)

    assert len(alerts) >= 1
    assert alerts[0][1] == "Port Scan"
