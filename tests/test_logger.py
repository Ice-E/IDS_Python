import os
import json
import pytest
from utils.logger import log_event

# Path to the log file used by the logger
LOG_FILE = "logs.json"

def setup_function():
    """
    Deletes the log file before each test to ensure a clean environment.
    """
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)

def teardown_function():
    """
    Cleans up the log file after each test.
    """
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)

def test_log_event_creates_entry():
    """
    Tests that calling log_event creates a valid JSON log entry in the file.
    """
    log_event("TEST_EVENT", "This is a test log entry.")

    with open(LOG_FILE, "r") as f:
        lines = f.readlines()
        assert len(lines) > 0
        entry = json.loads(lines[-1])
        assert "timestamp" in entry
        assert entry["event_type"] == "TEST_EVENT"
        assert entry["details"] == "This is a test log entry."
