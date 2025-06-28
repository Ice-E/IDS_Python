from flask import Flask, render_template
from detector.arp_spoof import detect_arp_spoofing

app = Flask(__name__)

@app.route('/')
def home():
    alerts = detect_arp_spoofing()
    return render_template('index.html', alerts=alerts)

if __name__ == '__main__':
    app.run(debug=True)
