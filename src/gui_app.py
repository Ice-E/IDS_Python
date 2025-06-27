import threading
from gui_alert import IDS_GUI
from scapy.all import sniff
import main
from attack_sim import simulate_port_scan  # optional testing tool

def start_ids():
    t = threading.Thread(target=lambda: sniff(prn=main.process_packet, store=False))
    t.daemon = True
    t.start()

def simulate_attack():
    threading.Thread(target=simulate_port_scan, daemon=True).start()

if __name__ == "__main__":
    gui = IDS_GUI(start_callback=start_ids, attack_callback=simulate_attack)
    main.gui_ref = gui
    gui.run()
