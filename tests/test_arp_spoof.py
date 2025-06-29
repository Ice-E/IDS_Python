from scapy.layers.l2 import ARP
from detector import arp_spoof

def test_arp_spoof_detection(monkeypatch):
    """
    Unit test for ARP spoofing detection logic.
    """
    # Simulate a legitimate ARP reply
    spoofed_pkt = ARP(op=2, psrc="192.168.1.1", hwsrc="00:11:22:33:44:55")
    alerts = []

    # Mock the alert logger
    def fake_log_alert(message, attack_type=None, source_ip=None):
        alerts.append((message, attack_type, source_ip))

    monkeypatch.setattr("detector.arp_spoof.log_alert", fake_log_alert)

    # First time seeing this IP-MAC pair — should not trigger alert
    arp_spoof.handle_packet(spoofed_pkt)
    assert len(alerts) == 0

    # Simulate the same IP with a different MAC address — should trigger alert
    spoofed_pkt_2 = ARP(op=2, psrc="192.168.1.1", hwsrc="AA:BB:CC:DD:EE:FF")
    arp_spoof.handle_packet(spoofed_pkt_2)
    assert len(alerts) == 1
    assert alerts[0][1] == "ARP Spoofing"
