# bot_profile.py
from uuid import uuid4
import random

def generate_bot_profile(ip, data):
    return {
        "id": f"bot-{uuid4().hex[:8]}",
        "attack_type": detect_attack_type(data),
        "ua_os": f"{data.get('user_agent', 'Unknown')}:{detect_os(data.get('user_agent', ''))}",
        "ttl_tcp": f"{data.get('ttl', 0)}:{data.get('tcp_flags', '')}:{detect_ttl_tcp_anomaly(data)}",
        "precheck_status": simulate_precheck(),
        "request_metrics": f"{int(data['rate']*60)}rpm:{detect_burst(data)}:constant:{estimate_payload_size(data)}bytes",
        "origin_data": simulate_origin_data(ip),
        "target_pattern": f"/api/process:POST:database:persistence"
    }

def detect_attack_type(data):
    if data["rate"] > 5 and not data.get("user_agent"):
        return "slowloris_ddos"
    return "normal"

def detect_os(ua):
    if "Windows" in ua:
        return "Windows"
    elif "Linux" in ua:
        return "Linux"
    elif "Mac" in ua:
        return "macOS"
    return "Unknown"

def detect_ttl_tcp_anomaly(data):
    if data["ttl"] < 50 or "SYN" in data.get("tcp_flags", ""):
        return "anomalous"
    return "normal"

def simulate_precheck():
    return random.choice(["bypassed:js_failed:no_cookie_support", "passed", "bypassed:no_js"])

def detect_burst(data):
    return "burst" if data["rate"] > 10 else "steady"

def estimate_payload_size(data):
    return random.choice([2048, 8192, 24576])

def simulate_origin_data(ip):
    countries = ["RU", "CN", "BR", "NL"]
    datacenter = "datacenter" if not ip.startswith("192.168") else "residential"
    return f"multi_country:{','.join(random.sample(countries, 2))}:{random.randint(10, 150)}ips:{datacenter}"
