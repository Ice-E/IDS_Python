import json
from datetime import datetime

LOG_FILE = "logs.json"

def log_event(event_type, details):
    """
    Logs a generic event to the log file as a single-line JSON object.
    
    Parameters:
    - event_type (str): Type or category of the event.
    - details (str): Description or additional information about the event.
    """
    log_entry = {
        "timestamp": str(datetime.now()),
        "event_type": event_type,
        "details": details
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

def log_alert(message, attack_type=None, source_ip=None):
    """
    Logs a structured security alert into a JSON list in the log file.
    
    Parameters:
    - message (str): Description of the alert.
    - attack_type (str, optional): Type of the attack (e.g., 'ARP Spoofing').
    - source_ip (str, optional): Source IP address involved in the alert.
    """
    log_entry = {
        "timestamp": str(datetime.now()),
        "type": attack_type,
        "source": source_ip,
        "message": message
    }

    try:
        with open(LOG_FILE, "r") as f:
            logs = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        logs = []

    logs.append(log_entry)

    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=2)
