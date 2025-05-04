# app.py
from flask import Flask, jsonify, render_template
from threading import Thread
from collections import defaultdict
import time
import re
from scapy.all import sniff, IP, TCP, Raw
from botprofile import generate_bot_profile

app = Flask(__name__)
stats = defaultdict(lambda: {"count": 0, "last_seen": 0, "rate": 0, "user_agent": "", "ttl": 0, "tcp_flags": ""})

def process_packet(packet):
    if IP in packet:
        ip = packet[IP].src
        ttl = packet[IP].ttl
        flags = packet[TCP].flags if TCP in packet else ""
        user_agent = ""

        if Raw in packet:
            try:
                payload = packet[Raw].load.decode(errors="ignore")
                match = re.search(r"User-Agent:\s*(.*)", payload)
                if match:
                    user_agent = match.group(1).split("\r\n")[0]
            except:
                pass

        now = time.time()
        data = stats[ip]
        data["count"] += 1
        if data["last_seen"]:
            diff = now - data["last_seen"]
            if diff > 0:
                data["rate"] = 1 / diff
        data["last_seen"] = now
        data["ttl"] = ttl
        data["tcp_flags"] = str(flags)
        if user_agent:
            data["user_agent"] = user_agent

def sniffer():
    sniff(filter="ip", prn=process_packet, store=0)

sniffer_thread = Thread(target=sniffer, daemon=True)
sniffer_thread.start()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/stats")
def api_stats():
    return jsonify(stats)

@app.route("/api/bots")
def api_bots():
    bot_profiles = {ip: generate_bot_profile(ip, data) for ip, data in stats.items()}
    return jsonify(bot_profiles)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
