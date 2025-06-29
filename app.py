import json
import os
from threading import Thread
from flask import Flask, render_template, request, redirect
import subprocess

# Import detection modules
from detector.arp_spoof import detect_arp_spoofing
from detector.syn_flood import detect_syn_flood
from detector.port_scan import detect_port_scan
from detector.ping_flood import detect_ping_flood

# Load configuration from config.json
with open("config.json", "r") as f:
    config = json.load(f)

log_file = config.get("log_file", "logs.json")
enabled_detectors = config.get("detection", {})

# Initialize Flask app
app = Flask(__name__)

def read_logs():
    """
    Reads logs from the configured log file and returns them as a list.
    Most recent logs are returned first.
    """
    logs = []
    if os.path.exists(log_file):
        with open(log_file, "r") as f:
            for line in f:
                try:
                    logs.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue
    return logs[::-1]  # newest logs first

def run_detectors():
    """
    Starts enabled detection modules in separate daemon threads based on config.
    """
    if enabled_detectors.get("arp_spoof", {}).get("enabled", False):
        Thread(target=detect_arp_spoofing, daemon=True).start()
    if enabled_detectors.get("syn_flood", {}).get("enabled", False):
        Thread(target=detect_syn_flood, daemon=True).start()
    if enabled_detectors.get("port_scan", {}).get("enabled", False):
        Thread(target=detect_port_scan, daemon=True).start()
    if enabled_detectors.get("ping_flood", {}).get("enabled", False):
        Thread(target=detect_ping_flood, daemon=True).start()

@app.route("/")
def index():
    """
    Renders the main dashboard page with the event logs.
    """
    logs = read_logs()
    return render_template("index.html", logs=logs)

@app.route("/clear", methods=["POST"])
def clear_logs():
    """
    Clears all logs from the log file.
    """
    open(log_file, "w").close()
    return redirect("/")

@app.route('/attack/<attack_type>')
def launch_attack(attack_type):
    """
    Launches a simulated attack based on the given attack type.
    """
    attack_scripts = {
        "arp": "attacks/arp_spoof.py",
        "ping": "attacks/ping_flood.py",
        "port": "attacks/port_scan.py",
        "syn": "attacks/syn_flood.py"
    }
    if attack_type in attack_scripts:
        subprocess.Popen(["python3", attack_scripts[attack_type]])
        return f"{attack_type} attack launched."
    else:
        return "Unknown attack type.", 400

if __name__ == "__main__":
    run_detectors()
    app.run(debug=True)
