import os
import json
import tempfile
from utils.logger import log_alert

def test_log_alert_json_format():
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = os.path.join(tmpdir, "logs.json")

        import utils.logger
        utils.logger.LOG_FILE = log_path

        message = "Test alert message"
        attack_type = "Unit Test Attack"
        source_ip = "192.0.2.1"

        log_alert(message, attack_type=attack_type, source_ip=source_ip)

        with open(log_path) as f:
            lines = f.readlines()

        assert len(lines) == 1
        log_entry = json.loads(lines[0])
        assert log_entry["message"] == message
        assert log_entry["type"] == attack_type  # Fixed from "attack_type"
        assert log_entry["source"] == source_ip
        assert "timestamp" in log_entry
