import datetime
import json
import logging
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
    return 4

def verify_pow_challenge(challenge, nonce):
    """Verify a proof of work challenge"""
    if not challenge or not nonce:
        return False
        
    difficulty = challenge_store.get(challenge)
    if not difficulty:
        return False
        
    test_hash = hashlib.sha256((challenge + str(nonce)).encode()).hexdigest()
    if test_hash.startswith('0' * difficulty):
        # Clean up the used challenge
        if challenge in challenge_store:
            del challenge_store[challenge]
        return True
        
    return False
def load_datacenter_ips():
    """Load data center IP ranges - simplified version"""
    global dc_ranges
    # Sample data center ranges (AWS, Google Cloud, Azure, etc.)
    # In production, use a comprehensive database or API
    sample_ranges = [
        "3.0.0.0/8",      # AWS
        "13.32.0.0/12",   # AWS CloudFront
        "34.0.0.0/8",     # Google Cloud
        "35.184.0.0/13",  # Google Cloud
        "52.0.0.0/8",     # AWS
        "104.196.0.0/14", # Google Cloud
        "172.217.0.0/16", # Google
        "192.158.28.0/22",# Google
        "13.64.0.0/11",   # Microsoft Azure
        "20.0.0.0/8",     # Microsoft Azure
        "23.192.0.0/11",  # Akamai
        "198.41.128.0/17",# Cloudflare
        "104.16.0.0/12"   # Cloudflare
    ]
    
    for ip_range in sample_ranges:
        try:
            dc_ranges.append(ipaddress.ip_network(ip_range))
        except ValueError:
            logger.error(f"Invalid IP range: {ip_range}")
    
    logger.info(f"Loaded {len(dc_ranges)} data center IP ranges")

def is_datacenter_ip(ip):
    """Check if IP is in a known data center range"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for net in dc_ranges:
            if ip_obj in net:
                return True
        return False
    except ValueError:
        return False

def get_ttl_value(ip):
    """Get TTL value by sending a ping to the IP"""
    try:
        # Try to get TTL using socket
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.settimeout(1)
        s.connect((ip, 0))
        
        # Create ICMP packet: type 8 (echo request), code 0
        packet = struct.pack('!BBHHH', 8, 0, 0, 0, 0)
        s.send(packet)
        
        # Receive response
        resp, addr = s.recvfrom(1024)
        # Extract TTL from IP header (8th byte)
        ttl = resp[8]
        s.close()
        return ttl
    except Exception as e:
        # Fallback to a default value if ping fails
        return None

def analyze_traffic(ip):
    """
    Analyze collected traffic statistics and generate security report
    If IP is provided, analyze only that IP, otherwise analyze all IPs
    """
    print(ip)
    results = {}
    current_time = time.time()
    logger.info(f"Traffic analysis Started for {ip}")
    with data_lock:
        ips_to_analyze = [ip] if ip else ip_stats.keys()
        logger.info(f"data_lock started{ip}")
        print(ips_to_analyze)
        print(ip_stats)
        for ip in ips_to_analyze:
            if ip not in ip_stats:
                continue
            
            
            
            data = ip_stats[ip]
        
            # Skip IPs not seen in the analysis window
            if current_time - data["last_seen"] > ANALYSIS_WINDOW:
                continue
            
            # Calculate metrics
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
    if(results !={}):
        generate_bot_profile(ip,results);
    
    return results



def save_results(results):
    """Save analysis results to log file rather than creating new files"""
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

def pow_routes(app):
    @app.route('/api/pow-challenge')
    def pow_challenge():
        challenge, difficulty = generate_challenge()
        return jsonify({'challenge': challenge, 'difficulty': difficulty})

    @app.route('/api/pow-submit', methods=['POST'])
    def pow_submit():
        data = request.json
        challenge = data.get('challenge')
        nonce = str(data.get('nonce'))

        difficulty = challenge_store.get(challenge)
        if not difficulty:
            return jsonify({'status': 'invalid challenge'}), 400

        test_hash = hashlib.sha256((challenge + nonce).encode()).hexdigest()
        if test_hash.startswith('0' * difficulty):
            return jsonify({'status': 'verified'})
        return jsonify({'status': 'invalid proof'}), 403
