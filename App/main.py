from flask import Flask, request, jsonify, Response, g
import time
import threading
import ipaddress
import json
import re
import os
import logging
from collections import defaultdict, deque
from datetime import datetime
import socket
import struct
import requests
from functools import wraps

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("traffic_analyzer")

# Constants and thresholds
ANALYSIS_WINDOW = 15  # 15 seconds analysis window
HIGH_RPM_THRESHOLD = 60  # More than 1 request per second
SYN_FLOOD_THRESHOLD = 20  # Not detectable in web app context
SUSPICIOUS_UA_PATTERNS = [
    r'^\s*$',  # Empty user agent
    r'(bot|crawl|spider)',  # Known bot patterns
    r'(nmap|nikto|gobuster|dirb)',  # Security tools
    r'(curl|wget|python-requests)',  # Scripting tools
]
TTL_SUSPICIOUS_VALUES = [1, 2, 3, 4, 5, 6, 7, 8, 254, 255]  # Suspicious TTL values

# Global data structures
ip_stats = defaultdict(lambda: {
    "first_seen": 0,
    "last_seen": 0,
    "request_count": 0,
    "rpm": 0,
    "rps": 0,
    "endpoints_accessed": set(),
    "user_agents": set(),
    "referrers": set(),
    "headers_present": True,
    "is_residential": None,
    "ttl_values": set(),
    "ttl_obfuscation": False,
    "last_requests": deque(maxlen=10),  # Store last 10 request times to detect spikes
    "response_codes": defaultdict(int)  # Track HTTP response codes
})

# Thread safety
data_lock = threading.Lock()

# Load data center IP ranges (sample - in production use a comprehensive dataset)
dc_ranges = []

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

def analyze_traffic(ip=None):
    """
    Analyze collected traffic statistics and generate security report
    If IP is provided, analyze only that IP, otherwise analyze all IPs
    """
    results = {}
    current_time = time.time()
    
    with data_lock:
        ips_to_analyze = [ip] if ip else ip_stats.keys()
        
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
            
            # Check for suspicious user agent
            has_suspicious_ua = False
            for ua in data["user_agents"]:
                for pattern in SUSPICIOUS_UA_PATTERNS:
                    if re.search(pattern, ua, re.I):
                        has_suspicious_ua = True
                        break
            
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
    
    return results

def periodic_analyzer():
    """Run periodic analysis of traffic"""
    while True:
        time.sleep(ANALYSIS_WINDOW)
        results = analyze_traffic()
        
        # Log suspicious activities
        suspicious_count = sum(1 for ip, data in results.items() if data["is_suspicious"])
        if suspicious_count > 0:
            logger.warning(f"Detected {suspicious_count} suspicious IPs")
            # Save results to file
            save_results(results)

def save_results(results):
    """Save analysis results to file"""
    if not results:
        return
        
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"traffic_analysis_{timestamp}.json"
    
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)
    
    logger.info(f"Analysis results saved to {filename}")

# Initialize Flask app
app = Flask(__name__)

# Start analyzer thread on app startup
@app.before_first_request
def start_background_tasks():
    load_datacenter_ips()
    analyzer_thread = threading.Thread(target=periodic_analyzer, daemon=True)
    analyzer_thread.start()
    logger.info("Traffic analyzer started")

# Traffic analysis middleware
@app.before_request
def analyze_request():
    # Get client IP
    client_ip = request.remote_addr
    
    # Get request timestamp
    request_time = time.time()
    
    # Extract useful request information
    user_agent = request.headers.get('User-Agent', '')
    referrer = request.headers.get('Referer', '')
    endpoint = request.path
    
    # Try to get TTL value (may require additional privileges)
    ttl = get_ttl_value(client_ip)
    
    # Store request data with thread safety
    with data_lock:
        ip_data = ip_stats[client_ip]
        
        # First request from this IP
        if ip_data["first_seen"] == 0:
            ip_data["first_seen"] = request_time
            ip_data["is_residential"] = not is_datacenter_ip(client_ip)
        
        # Update statistics
        ip_data["last_seen"] = request_time
        ip_data["request_count"] += 1
        ip_data["endpoints_accessed"].add(endpoint)
        ip_data["last_requests"].append(request_time)
        
        # Check headers
        if user_agent:
            ip_data["user_agents"].add(user_agent)
        if referrer:
            ip_data["referrers"].add(referrer)
        
        # Check if important headers are missing
        ip_data["headers_present"] = bool(user_agent and referrer)
        
        # Store TTL if available
        if ttl:
            ip_data["ttl_values"].add(ttl)
            if ttl in TTL_SUSPICIOUS_VALUES:
                ip_data["ttl_obfuscation"] = True
    
    # Store start time for response time tracking
    g.start_time = time.time()

@app.after_request
def after_request(response):
    # Calculate response time
    if hasattr(g, 'start_time'):
        response_time = time.time() - g.start_time
    else:
        response_time = 0
    
    # Get client IP
    client_ip = request.remote_addr
    
    # Store response code in statistics
    with data_lock:
        if client_ip in ip_stats:
            ip_stats[client_ip]["response_codes"][response.status_code] += 1
    
    return response

# Add a route to manually check an IP
@app.route('/check/<ip>')
def check_ip(ip):
    try:
        ipaddress.ip_address(ip)  # Validate IP format
        results = analyze_traffic(ip)
        if ip in results:
            return jsonify(results[ip])
        else:
            return jsonify({"error": "No data for this IP"}), 404
    except ValueError:
        return jsonify({"error": "Invalid IP address"}), 400

# Add a route to get traffic analysis for all IPs
@app.route('/analysis')
def get_analysis():
    results = analyze_traffic()
    return jsonify(results)

# Add a route to check if current request is suspicious
@app.route('/analyze_me')
def analyze_me():
    client_ip = request.remote_addr
    results = analyze_traffic(client_ip)
    if client_ip in results:
        return jsonify(results[client_ip])
    else:
        return jsonify({"error": "No data for your IP yet"}), 404

# Example application route that could be protected
@app.route('/')
def index():
    return "Hello, this is the protected application!"

# Add an endpoint that will analyze and return results
@app.route('/api/check_request', methods=['GET', 'POST'])
def check_request():
    client_ip = request.remote_addr
    
    # Analyze this IP
    results = analyze_traffic(client_ip)
    
    if client_ip in results:
        # Return the analysis results
        return jsonify({
            "syn_flood": False,  # Can't detect in web app context
            "high_rpm": results[client_ip]["traffic_indicators"]["high_request_rate"],
            "script_hits": results[client_ip]["traffic_indicators"]["suspicious_user_agent"] or 
                          results[client_ip]["traffic_indicators"]["missing_headers"],
            "ttl_obfuscation": results[client_ip]["packet_indicators"]["ttl_obfuscation"]
        })
    else:
        # Default response if no data yet
        return jsonify({
            "syn_flood": False,
            "high_rpm": False,
            "script_hits": False,
            "ttl_obfuscation": False
        })

# Decorator function to protect routes with traffic analysis
def traffic_protected(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.remote_addr
        results = analyze_traffic(client_ip)
        
        if client_ip in results and results[client_ip]["is_suspicious"]:
            # Log suspicious activity
            logger.warning(f"Blocked suspicious request from {client_ip}")
            return jsonify({"error": "Access denied due to suspicious activity"}), 403
        
        return f(*args, **kwargs)
    return decorated_function

# Example of a protected route
@app.route('/protected')
@traffic_protected
def protected():
    return "This is a protected route!"

if __name__ == "__main__":
    # Start the Flask app
    app.run(host="0.0.0.0", port=8080, debug=False)