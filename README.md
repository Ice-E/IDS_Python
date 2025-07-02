# Python Intrusion Detection System (IDS)

This project is a semester-long university assignment for learning Python through the development of a basic Intrusion Detection System (IDS).

## Features

- **Modular detection** of common attacks:
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
├── interface.py         # List network interface using Scapy for config.json
└── README.md            # This file
```

## Getting Started

1. **Install Dependencies**

```bash
pip install -r requirements.txt
```

2. **Run the IDS**

In Linux :
```bash
bash run.sh
```

In windows Powershell :
```bash
python app.py
```

*Warning: You must run the program with administrator/root privileges to allow packet sniffing.*

3. **Open the Dashboard**

Navigate to [http://localhost:5000](http://localhost:5000) in your browser.

## Attack Simulation

Use the web interface to simulate attacks like:

- Ping Flood
- SYN Flood
- Port Scan

These scripts are for **educational testing only** and should **never** be used on live networks.

## Configuration

Edit `config.json` to:

- Enable/disable specific detection modules
- Set thresholds for flood detection
- Specify monitored IPs and network interface

For more details, see:
- [`config.json`](./config.json) for detection setup
- [`utils/logger.py`](./utils/logger.py) for logging format

## Testing

```bash
pytest
```

Runs unit tests on each detection module and the logging system.

## Requirements

- Python 3.10+
- Scapy (Linux or Windows + Npcap)
- Flask
- Chart.js (CDN)

Tested on:
- Windows 10 + Npcap
- Ubuntu 22.04

## Authors

- Emo Solène
- Wu Bang-Guo
  
## License

This project is developed for academic purposes. Use it responsibly.
