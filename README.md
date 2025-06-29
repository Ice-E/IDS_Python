# Python Intrusion Detection System (IDS)

This project is a semester-long university assignment for learning Python through the development of a basic Intrusion Detection System (IDS).

## Features

- **Modular detection** of common attacks:
  - ARP Spoofing
  - SYN Flood
  - Ping Flood
  - Port Scan
- **Real-time monitoring** using Scapy
- **Web Dashboard** using Flask to:
  - View logs and statistics
  - Simulate attacks for testing
  - Clear logs with one click
- **Logging system** writes both structured alerts (`logs.json`) and plain logs

## Directory Structure

```
IDS_Python/
├── app.py               # Main Flask app
├── config.json          # Detection and logging configuration
├── detector/            # Detection modules
├── attacks/             # Simulated attack scripts
├── templates/           # HTML templates (Flask)
├── static/              # CSS styles
├── tests/               # Unit tests (pytest)
├── utils/               # Logger utility
├── logs/                # Logs storage
├── run.sh               # Startup script
├── requirements.txt     # Python dependencies
└── README.md            # This file
```

## Getting Started

1. **Install Dependencies**

```bash
pip install -r requirements.txt
```

2. **Run the IDS**

```bash
bash run.sh
```

3. **Open the Dashboard**

Navigate to [http://localhost:5000](http://localhost:5000) in your browser.

## Attack Simulation

Use the web interface to simulate attacks like:

- ARP Spoofing
- Ping Flood
- SYN Flood
- Port Scan

These scripts are for **educational testing only** and should **never** be used on live networks.

## Configuration

Edit `config.json` to:

- Enable/disable specific detection modules
- Set thresholds for flood detection
- Specify monitored IPs and network interface

## Testing

```bash
pytest
```

Runs unit tests on each detection module and the logging system.

## License

This project is developed for academic purposes. Use it responsibly.
