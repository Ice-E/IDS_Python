import json
import os
from utils.logger import log_alert

def test_log_alert_json_format():
    """
    Tests that log_alert correctly writes a structured JSON entry to the log file.
    """
    log_path = "logs/logs.json"

    # Ensure a clean log file before the test
    if os.path.exists(log_path):
        os.remove(log_path)

    # Log a test alert
    log_alert("Test alert message", attack_type="Test", source_ip="1.2.3.4")

    # Read and verify the content of the log file
    with open(log_path, "r") as f:
        data = json.load(f)

    assert isinstance(data, list)
    assert len(data) >= 1
    assert data[-1]["type"] == "Test"
    assert data[-1]["source"] == "1.2.3.4"
    assert "Test alert message" in data[-1]["message"]
