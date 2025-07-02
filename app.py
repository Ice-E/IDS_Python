import os
import json
from collections import Counter
from datetime import datetime
from threading import Thread

from flask import Flask, render_template, redirect

# Import detection modules
from detector.syn_flood import detect_syn_flood
from detector.port_scan import detect_port_scan
from detector.ping_flood import detect_ping_flood

# Load configuration
with open("config.json", "r") as f:
    config = json.load(f)

log_file          = config.get("log_file", "logs/logs.json")
enabled_detectors = config.get("detection", {})
network_cfg       = config.get("network", {})

# Ensure log directory exists
os.makedirs(os.path.dirname(log_file), exist_ok=True)

app = Flask(__name__)

def read_logs():
    """
    Reads the log file and returns the list of entries (one JSON object per line),
    ordered from newest to oldest.
    """
    if not os.path.exists(log_file):
        return []
    with open(log_file, "r") as f:
        lines = [line.strip() for line in f if line.strip()]
    logs = []
    for line in lines:
        try:
            logs.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # Skip malformed lines
    return list(reversed(logs))  # Most recent first

def run_detectors():
    """
    Starts each enabled detector in a separate daemon thread.
    """
    if enabled_detectors.get("syn_flood", {}).get("enabled", False):
        Thread(target=detect_syn_flood, daemon=True).start()
    if enabled_detectors.get("port_scan", {}).get("enabled", False):
        Thread(target=detect_port_scan, daemon=True).start()
    if enabled_detectors.get("ping_flood", {}).get("enabled", False):
        Thread(target=detect_ping_flood, daemon=True).start()

@app.route("/")
def index():
    # Read and sort logs (from oldest to newest)
    logs = read_logs()
    logs_sorted = sorted(logs, key=lambda l: l["timestamp"])

    # Doughnut chart: count per attack type
    attack_counts = Counter(log.get("type") for log in logs_sorted if log.get("type"))

    # Time series data:
    # a) Extract time component (HH:MM:SS) from each timestamp
    seconds = [
        datetime.fromisoformat(log["timestamp"]).strftime("%H:%M:%S")
        for log in logs_sorted
    ]
    # b) Get unique seconds in order
    unique_seconds = sorted(set(seconds), key=lambda s: datetime.strptime(s, "%H:%M:%S"))

    # c) Count number of attacks per second and per type
    counts_per_second = {
        sec: {atype: 0 for atype in attack_counts}
        for sec in unique_seconds
    }
    for sec, log in zip(seconds, logs_sorted):
        atype = log.get("type")
        if atype in counts_per_second[sec]:
            counts_per_second[sec][atype] += 1

    # d) Cumulative count series for line chart
    series = {atype: [] for atype in attack_counts}
    cum    = {atype: 0  for atype in attack_counts}
    for sec in unique_seconds:
        for atype in attack_counts:
            cum[atype] += counts_per_second[sec][atype]
            series[atype].append(cum[atype])

    return render_template(
        "index.html",
        logs=list(reversed(logs_sorted)),  # Show newest logs first
        attack_counts=attack_counts,
        time_labels=unique_seconds,
        series=series
    )

@app.route("/clear", methods=["POST"])
def clear_logs():
    """
    Empties the log file.
    """
    open(log_file, "w").close()
    return redirect("/")

@app.route("/attack/<attack_type>")
def launch_attack(attack_type):
    """
    Launches an attack simulation script in a daemon thread.
    """
    attack_scripts = {
        "ping": "attacks/ping_flood.py",
        "port": "attacks/port_scan.py",
        "syn":  "attacks/syn_flood.py"
    }
    script = attack_scripts.get(attack_type)
    if script:
        Thread(target=lambda: os.system(f"python {script}"), daemon=True).start()
    return redirect("/")

if __name__ == "__main__":
    run_detectors()
    app.run(debug=True, use_reloader=False)