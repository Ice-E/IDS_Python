import os, json
from datetime import datetime

os.makedirs("logs", exist_ok=True)
LOG_FILE = os.path.join("logs", "logs.json")

def log_alert(message, attack_type=None, source_ip=None):
    """
    Logs a structured security alert as a single-line JSON object,
    avec un message lisible par le front.
    """
    if isinstance(message, dict):
        kind   = message.get("type")
        ip     = message.get("ip")
        real   = message.get("real_mac")
        spoof  = message.get("spoofed_mac")
        msg    = f"{kind} @ {ip} → real:{real} fake:{spoof}"
    else:
        msg = str(message)

    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "type": attack_type,
        "source": source_ip,
        "message": msg
    }

    # Debug print
    print(f"Logging alert: {log_entry}")

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log_entry) + "\n")
