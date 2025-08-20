import datetime
import os
import re
import hashlib, random, string
import time
from flask import jsonify, request
from bots.botprofile import generate_bot_profile, score_save_bot
import ipaddress
import socket
import struct
import threading
from datetime import datetime
from collections import defaultdict, deque
import psutil
from utils.shared_data import SUSPICIOUS_USER_AGENTS, ip_stats, data_lock, challenge_store, dc_ranges
from utils.shared_data import logger, ANALYSIS_WINDOW, HIGH_RPM_THRESHOLD, SYN_FLOOD_THRESHOLD
from utils.shared_data import SUSPICIOUS_UA_PATTERNS, TTL_SUSPICIOUS_VALUES


def generate_challenge():
    challenge = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    difficulty = get_dynamic_difficulty()
    challenge_store[challenge] = difficulty
    return challenge, difficulty

def get_dynamic_difficulty():
    load_score, cpu, mem = get_server_load()
    attack = is_under_attack()

    if attack:
        return min(6, int(load_score * 2) + 1) 
    return max(1, int(load_score)) 

def get_server_load():
    load = psutil.getloadavg()[0]  # 1 minute load average
    cpu = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory().percent

    load_score = min(10, max(0, load / psutil.cpu_count()))
    
    return load_score, cpu, mem
def is_under_attack():
    cpu_usage = psutil.cpu_percent(interval=1)
    mem_usage = psutil.virtual_memory().percent

    if cpu_usage > 80 or mem_usage > 80:
        return True
    
    # Check for high number of connections
    connections = psutil.net_connections(kind='inet')
    if len(connections) > 1000:  # Arbitrary threshold
        return True
    
    return False


def verify_pow_challenge(challenge, nonce):
    if not challenge or not nonce:
        return False
    
    difficulty = challenge_store.get(challenge)
    if not difficulty:
        return False
    
    # Actually verify the hash meets difficulty
    test_hash = hashlib.sha256((challenge + str(nonce)).encode()).hexdigest()
    if test_hash.startswith('0' * difficulty):
        del challenge_store[challenge]
        return True
    return False

def get_ttl_value(ip):
    try:
        # Create raw socket
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.settimeout(2)

        # ICMP Header: Type 8 (Echo), Code 0, Checksum 0, ID, Sequence
        icmp_type = 8
        code = 0
        chksum = 0
        packet_id = os.getpid() & 0xFFFF
        seq = 1

        header = struct.pack("!BBHHH", icmp_type, code, chksum, packet_id, seq)
        data = b"abcdefghijklmnopqrstuvwabcdefghi"  # 32 bytes of data
        chksum = checksum(header + data)
        header = struct.pack("!BBHHH", icmp_type, code, chksum, packet_id, seq)
        packet = header + data

        start = time.time()
        s.sendto(packet, (ip, 1))
        resp, addr = s.recvfrom(1024)
        end = time.time()

        # Extract TTL (9th byte of IP header)
        ttl = resp[8]
        s.close()
        return ttl
    except Exception as e:
        return None

def checksum(data):
    """Calculate checksum for ICMP packet"""
    if len(data) % 2:
        data += b'\0'
    res = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16
    return (~res) & 0xffff

def analyze_traffic(ip=None):
    results = {}
    current_time = time.time()
    with data_lock:
        ips_to_analyze = [ip] if ip else list(ip_stats.keys())
    for target_ip in ips_to_analyze:
        with data_lock:
            if target_ip not in ip_stats:
                continue
            data = ip_stats[target_ip].copy()  

        if current_time - data["last_seen"] > ANALYSIS_WINDOW:
            logger.info(f"Skipping {target_ip}: inactive beyond analysis window.")
            continue
        time_window = max(data["last_seen"] - data["first_seen"], 0.01)
        if time_window >= 1.0:
            rpm = (data["request_count"] / time_window) * 60
            rps = data["request_count"] / time_window
        else:
            rpm, rps = 0, 0

        is_spiking = False
        ua = data.get("user_agents")
        def has_suspicious_ua(ua_input):
            """Check if any UA in the input is suspicious. Accepts string or list."""
            user_agents = []
            if isinstance(ua_input, str):
                user_agents = [ua_input.strip()]
            elif isinstance(ua_input, (list, set, tuple)):
                user_agents = [str(ua).strip() for ua in ua_input if isinstance(ua, str) and ua.strip()]
            else:
                return True, f"Invalid UA input type: {type(ua_input).__name__}"
            for ua in user_agents:
                if not ua:
                    continue  
                ua_lower = ua.lower()
                for keyword in SUSPICIOUS_USER_AGENTS:
                    if keyword and keyword.lower() in ua_lower:
                        return True, f"Matched suspicious keyword: '{keyword}'"

                for pattern in SUSPICIOUS_UA_PATTERNS:
                    if re.search(pattern, ua, re.IGNORECASE):
                        return True, f"Matched suspicious regex pattern: '{pattern}'"
            return False
        result = {
            "ip": target_ip,
            "is_residential": data.get("is_residential", False),
            "traffic_indicators": {
                "high_request_rate": rpm > HIGH_RPM_THRESHOLD,
                "sudden_traffic_spike": is_spiking,
                "unusual_traffic_distribution": len(data["endpoints_accessed"]) > 18,
                "missing_headers": not data.get("headers_present", True) or len(data["user_agents"]) == 0,
                "suspicious_user_agent": has_suspicious_ua(data.get("user_agents"))
            },
            "packet_indicators": {
                "ttl_obfuscation": data.get("ttl_obfuscation", False),
                "error_response_rate": (
                    # data["response_codes"].get(404, 0) > 5 or
                    # data["response_codes"].get(403, 0) > 3
                )
            },
            "metadata": {
                "request_count": data["request_count"],
                "rpm": round(rpm, 2),
                "rps": round(rps, 2),
                "first_seen": data["first_seen"],
                "last_seen": data["last_seen"],
                "ttl_values": list(data["ttl_values"]),
                "endpoints_accessed": list(data["endpoints_accessed"]),
                "user_agents": list(data["user_agents"]),
                "referrers": list(data["referrers"]),
            }
        }

        # Suspicious summary flag
        result["is_suspicious"] = (
            any(result["traffic_indicators"].values()) or
            any(result["packet_indicators"].values()) or
            result["metadata"]["rpm"] > HIGH_RPM_THRESHOLD or
            result["metadata"]["ttl_values"] and
            any(ttl in TTL_SUSPICIOUS_VALUES for ttl in result["metadata"]["ttl_values"])
            or result["metadata"]["endpoints_accessed"] and
            len(result["metadata"]["endpoints_accessed"]) > 8
            or result["metadata"]["user_agents"] and
            any(re.search(pattern, ua, re.I) for pattern in SUSPICIOUS_UA_PATTERNS for ua in result["metadata"]["user_agents"])
        )

        results[target_ip] = result
        print(f"Analyzed {target_ip}: {result}")
        # Log analysis result summary
        logger.info(f"Analyzed {target_ip}: Suspicious={result['is_suspicious']}, RPM={result['metadata']['rpm']}, RPS={result['metadata']['rps']}")

    return results

def save_results(results):
    if not results:
        return  
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    suspicious_ips = [ip for ip, data in results.items() if data["is_suspicious"]]
    
    logger.info(f"Analysis results at {timestamp}: Found {len(suspicious_ips)} suspicious IPs")
    
    for ip, data in results.items():
        if data["is_suspicious"]:
            logger.warning(f"Suspicious IP {ip}: RPM={data['metadata']['rpm']}, "
                          f"Suspicious indicators: {[k for k,v in data['traffic_indicators'].items() if v]}")
    
    # If you still need full JSON data, you can log it as a structured log
    logger.info(f"Full analysis data: {json.dumps(results)}")

