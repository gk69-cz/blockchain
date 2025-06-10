import datetime
import json
import logging
import os
import re
import hashlib, random, string
import time
from flask import jsonify, request
from botprofile import generate_bot_profile
import ipaddress
import socket
import struct
import threading
from datetime import datetime
from collections import defaultdict, deque

from shared_data import ip_stats, data_lock, challenge_store, dc_ranges
from shared_data import logger, ANALYSIS_WINDOW, HIGH_RPM_THRESHOLD, SYN_FLOOD_THRESHOLD
from shared_data import SUSPICIOUS_UA_PATTERNS, TTL_SUSPICIOUS_VALUES


def generate_challenge():
    challenge = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    difficulty = get_dynamic_difficulty()
    challenge_store[challenge] = difficulty
    return challenge, difficulty

def get_dynamic_difficulty():
    return 5
#  "python-requests",
def verify_pow_challenge(challenge, nonce):
    """Verify a proof of work challenge"""
    if not challenge or not nonce:
        return False
    print(f"Verifying challenge: {challenge} with nonce: {nonce}")  
    difficulty = challenge_store.get(challenge)
      
    if not difficulty:
        return False
    test_hash = hashlib.sha256((challenge + str(nonce)).encode()).hexdigest()
 
    if challenge in challenge_store:
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

def analyze_traffic(ip):
    print(f"Analyzing traffic for IPhhhhhhhhhhhhhhhhhhhhhhhhhhh: {ip}")
    results = {}
    current_time = time.time()
    logger.info(f"Traffic analysis Started for {ip}")
    with data_lock:
        ips_to_analyze = [ip] if ip else ip_stats.keys()
        logger.info(f"data_lock started{ip}")
       
        for ip in ips_to_analyze:
            if ip not in ip_stats:
                continue
            data = ip_stats[ip]
            if current_time - data["last_seen"] > ANALYSIS_WINDOW:
                continue
            time_window = data["last_seen"] - data["first_seen"]
            
            if time_window > 0:
                data["rpm"] = (data["request_count"] / time_window) * 60
                data["rps"] = data["request_count"] / time_window
            logger.info(f"time Window calculation checked for {ip}")
            # Check for sudden traffic spikes
            is_spiking = False
          
            if len(data["last_requests"]) >= 3:
                # Check intervals between last requests
                intervals = []
                prev_time = None
                for req_time in data["last_requests"]:
                    if prev_time:
                        intervals.append(req_time - prev_time)
                    prev_time = req_time
                
                # If average interval is very short, that's a spike
                if intervals and sum(intervals) / len(intervals) < 0.5:  # Less than 0.5 seconds between requests
                    is_spiking = True
            logger.info(f"sudden traffic spikes Check completed for {ip}")
            # Check for suspicious user agent
            has_suspicious_ua = False
            for ua in data["user_agents"]:
                for pattern in SUSPICIOUS_UA_PATTERNS:
                    if re.search(pattern, ua, re.I):
                        has_suspicious_ua = True
                        logger.warning(f"Suspicious ua found for {ip}")
                        break
            logger.info(f"Suspicious ua Check completed for {ip}")
            # Create the results structure with security indicators
          
            results[ip] = {
                "ip": ip,
                "is_residential": data["is_residential"],
                "traffic_indicators": {
                    "high_request_rate": data["rpm"] > HIGH_RPM_THRESHOLD,
                    "sudden_traffic_spike": is_spiking,
                    "unusual_traffic_distribution": len(data["endpoints_accessed"]) > 8,
                    "missing_headers": not data["headers_present"] or len(data["user_agents"]) == 0,
                    "suspicious_user_agent": has_suspicious_ua
                },
                "packet_indicators": {
                    "ttl_obfuscation": data["ttl_obfuscation"],
                    "error_response_rate": data["response_codes"].get(404, 0) > 5 or 
                                         data["response_codes"].get(403, 0) > 3
                },
                "metadata": {
                    "request_count": data["request_count"],
                    "rpm": round(data["rpm"], 2),
                    "rps": round(data["rps"], 2),
                    "first_seen": data["first_seen"],
                    "last_seen": data["last_seen"], 
                    "ttl_values": list(data["ttl_values"]),
                    "endpoints_accessed": list(data["endpoints_accessed"]),
                    "user_agents": list(data["user_agents"]),
                    "referrers": list(data["referrers"]),
                    "response_codes": dict(data["response_codes"])
                }
            }
            # Add summary flags
            results[ip]["is_suspicious"] = any(results[ip]["traffic_indicators"].values()) or \
                                         any(results[ip]["packet_indicators"].values())
    print("test")
    print("test")
    print("test")
    print("test")
    print(results[ip]["is_suspicious"])
    print("test")
    print("test")
    print("test")
    if(results !={} and time_window >50 ):
        print("generatebotprofile1  ")
        generate_bot_profile(ip,results);
    
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

