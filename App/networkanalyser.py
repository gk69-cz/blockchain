from collections import defaultdict, deque
from logging.handlers import RotatingFileHandler
from flask import Flask, request, jsonify, g, session
import time
import threading
import ipaddress
import logging
from functools import wraps

from js_threshhold_logic import analyze_traffic, generate_challenge, get_dynamic_difficulty, get_ttl_value, is_datacenter_ip, load_datacenter_ips, pow_routes, save_results, verify_pow_challenge

from shared_data import ip_stats, data_lock, challenge_store, dc_ranges
from shared_data import logger, ANALYSIS_WINDOW, HIGH_RPM_THRESHOLD, SUSPICIOUS_UA_PATTERNS, TTL_SUSPICIOUS_VALUES


pow_script = """
<script>
function solvePow(challenge, difficulty) {
    let nonce = 0;
    while (true) {
        const hash = sha256(challenge + nonce);  
        if (hash.startsWith('0'.repeat(difficulty))) {
            return nonce;
        }
        nonce++;
    }
}

// Start the PoW verification flow when page loads
window.onload = async function() {
    // Fetch challenge
    const challengeResp = await fetch('/api/pow-challenge');
    const challengeData = await challengeResp.json();
    
    // Solve the challenge
    const nonce = await solvePow(challengeData.challenge, challengeData.difficulty);
    
    // Submit the solution
    const submitResp = await fetch('/api/pow-submit', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            challenge: challengeData.challenge,
            nonce: nonce
        })
    });
    
    // Check the result
    const submitData = await submitResp.json();
    if (submitData.status === 'verified') {
        // PoW verified, now start the analyzer
        await fetch('/api/start-analyzer', {
            method: 'GET'
        });
    }
}
</script>
"""

# Remove any existing handlers
if logger.handlers:
    logger.handlers.clear()

# Add a rotating file handler
file_handler = RotatingFileHandler(
    'traffic_analyzer.log',
    maxBytes=10*1024*1024,  # 10MB
    backupCount=5
)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Add console handler if you still want console output
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Initialize Flask app
app = Flask(__name__)

# Run setup code with app context
@app.before_request
def ensure_initialized():
    # Use a flag in app config to check if initialization has been done
    if not app.config.get('INITIALIZED', False):
        load_datacenter_ips()
        
        # Check if PoW verification is needed
        if app.config.get('REQUIRE_POW', True):
            # Set up a flag indicating PoW is required
            app.config['POW_REQUIRED'] = True
            logger.info("PoW verification required before starting analyzer")
        else:
            # Start analyzer thread directly if PoW is not required
            analyzer_thread = threading.Thread(target=periodic_analyzer(client_ip), daemon=True)
            analyzer_thread.start()
            logger.info("Traffic analyzer started without PoW requirement")
            
        app.config['INITIALIZED'] = True
        
        


# Traffic analysis middleware
@app.before_request
def analyze_request():
    # Get client IP
    client_ip = request.remote_addr
    
    
    # Get request timestamp
    request_time = time.time()
    
    # Extract useful request information
    user_agent = request.headers.get('User-Agent', '')
    print("User-Agent")
    print(user_agent)
    print("User-Agent")
    referrer = request.headers.get('Referer', '')
    endpoint = request.path
    
    if request.headers.get('X-Forwarded-For'):
            # X-Forwarded-For can contain multiple IPs - the leftmost is typically the client
        forwarded_ips = request.headers.get('X-Forwarded-For').split(',')
        client_ip = forwarded_ips[0].strip()
    elif request.headers.get('X-Real-IP'):
        client_ip = request.headers.get('X-Real-IP')
        
     # Debug print to see all request information
    print(f"==== REQUEST INFO ====")
    print(f"Original remote_addr: {request.remote_addr}")
    print(f"Detected client_ip: {client_ip}")
    print(f"Headers: {dict(request.headers)}")
    print(f"==== END REQUEST INFO ====")
    
    
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

@app.route('/api/start-analyzer', methods=['GET'])
def start_analyzer_endpoint():
    # Check if PoW has been verified from session
    
    client_ip = request.remote_addr
    session_id = request.cookies.get('session_id', client_ip)
    
    # Get PoW verification status from session or app config
    is_verified = session.get('pow_verified', False) if 'session' in globals() else False
    
    # Alternatively, check from a verified clients list
    verified_clients = getattr(app, 'verified_clients', set())
    if client_ip in verified_clients or is_verified:
        # Start analyzer thread if not already started
        if not app.config.get('ANALYZER_STARTED', False):
            analyzer_thread = threading.Thread(target=periodic_analyzer(client_ip), daemon=True)
            analyzer_thread.start()
            logger.info("Traffic analyzer started after PoW v")
            app.config['ANALYZER_STARTED'] = True
            return jsonify({'status': 'analyzer started'})
        return jsonify({'status': 'analyzer already running'})
    
    return jsonify({'status': 'verification required'}), 403

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
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Protected Application</title>
        <script src="https://cdn.jsdelivr.net/npm/js-sha256@0.9.0/build/sha256.min.js"></script>
        {pow_script}
    </head>
    <body>
        <h1>Hello, this is the protected application!</h1>
        <p>PoW verification is running automatically in the background...</p>
    </body>
    </html>
    """


# Modify your pow_submit route to mark verification and start analyzer
@app.route('/api/pow-submit', methods=['POST'])
def pow_submit():
    data = request.json
    challenge = data.get('challenge')
    nonce = str(data.get('nonce'))
    
    if verify_pow_challenge(challenge, str(nonce)):
        # Mark this client as verified
        client_ip = request.remote_addr
        if not hasattr(app, 'verified_clients'):
            app.verified_clients = set()
        app.verified_clients.add(client_ip)
        
        # Start the analyzer if not already started
        if not app.config.get('ANALYZER_STARTED', False):
            analyzer_thread = threading.Thread(target=periodic_analyzer(client_ip), daemon=True)
            analyzer_thread.start()
            logger.info("Traffic analyzer started after PoW verification 500 ")
            app.config['ANALYZER_STARTED'] = True
            
        return jsonify({'status': 'verified'})
    return jsonify({'status': 'invalid proof'}), 403

@app.route('/api/pow-challenge')
def pow_challenge():
        challenge, difficulty = generate_challenge()
        return jsonify({'challenge': challenge, 'difficulty': difficulty})
  
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
def periodic_analyzer(session_id):
    """Run periodic analysis of traffic"""
    while True:
        time.sleep(ANALYSIS_WINDOW)
        logger.info(f"Periodic analyzer is Running for {session_id}")
        results = analyze_traffic(session_id)
        
        # Log suspicious activities
        suspicious_count = sum(1 for session_id, data in results.items() if data["is_suspicious"])
        if suspicious_count > 0:
            logger.warning(f"Detected {suspicious_count} suspicious IP {session_id}")
            # Save results to file
            save_results(results)
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
    app.secret_key = "philipintepari"
    app.run(host="0.0.0.0", port=8080, debug=False)