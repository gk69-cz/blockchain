from collections import defaultdict, deque
import json
from logging.handlers import RotatingFileHandler
import os
from flask import Flask, render_template, request, jsonify, g, session
import time
import threading
import ipaddress
import logging
from functools import wraps

from ipblocker import schedule_extraction
from js_threshhold_logic import analyze_traffic, generate_challenge, get_dynamic_difficulty, get_ttl_value, is_datacenter_ip, load_datacenter_ips, pow_routes, save_results, verify_pow_challenge

from shared_data import SUSPICIOUS_HEADERS, SUSPICIOUS_USER_AGENTS, ip_stats, data_lock, challenge_store, dc_ranges
from shared_data import logger, ANALYSIS_WINDOW, HIGH_RPM_THRESHOLD, SUSPICIOUS_UA_PATTERNS, TTL_SUSPICIOUS_VALUES



pow_script = """
<script>
// SHA-256 function is provided by the imported js-sha256 library

function updateStatus(message) {
    document.getElementById('status').innerText = message;
}

async function solvePow(challenge, difficulty) {
    updateStatus('Solving proof of work challenge (difficulty: ' + difficulty + ')...');
    
    let nonce = 0;
    const startTime = Date.now();
    
    while (true) {
        const hash = sha256(challenge + nonce);
        if (hash.startsWith('0'.repeat(difficulty))) {
            const timeTaken = ((Date.now() - startTime) / 1000).toFixed(2);
            updateStatus('Solution found! Nonce: ' + nonce + ' (took ' + timeTaken + ' seconds)');
            return nonce;
        }
        
        nonce++;
        
        // Update status every 1000 attempts
        if (nonce % 1000 === 0) {
            updateStatus('Still working... Tried ' + nonce + ' solutions');
            // Allow UI to update
            await new Promise(resolve => setTimeout(resolve, 0));
        }
    }
}

// Start the PoW verification flow when page loads
window.onload = async function() {
    try {
        // Fetch challenge
        updateStatus('Requesting challenge from server...');
        const challengeResp = await fetch('/api/pow-challenge');
        const challengeData = await challengeResp.json();
        
        updateStatus('Challenge received. Beginning computation...');
        
        // Solve the challenge
        const nonce = await solvePow(challengeData.challenge, challengeData.difficulty);
        
        // Submit the solution
        updateStatus('Submitting solution to server...');
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
            updateStatus('Verification successful! Redirecting...');
            // Wait a moment to show the success message
            setTimeout(() => {
                // Reload the page to access the protected content
                window.location.reload();
            }, 1500);
        } else {
            updateStatus('Verification failed: ' + submitData.message);
        }
    } catch (error) {
        updateStatus('Error during verification: ' + error.message);
        console.error('PoW error:', error);
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
    
    if is_suspicious(user_agent, request.headers):
        print("Suspicious request detected.")
    else:
        print("Request seems fine.")
    if request.headers.get('X-Forwarded-For'):
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
        
        # Check if important headers are missing or invalid
        ip_data["headers_present"] = bool(user_agent and not(is_suspicious(user_agent, request.headers)))
        print(ip_data["headers_present"])
        # Store TTL if available
        if ttl:
            ip_data["ttl_values"].add(ttl)
            if ttl in TTL_SUSPICIOUS_VALUES:
                ip_data["ttl_obfuscation"] = True
    print("----------------")           
    print(ip_data["headers_present"])
    print("----------------")    
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

def is_suspicious(user_agent, headers):
    print("Checking if user agent or headers are suspicious...")
    ua = (user_agent or "").lower()

    # Partial match: check if any suspicious string appears in the UA
    for bad_ua in SUSPICIOUS_USER_AGENTS:
        if bad_ua and bad_ua in ua:
            print(f"Suspicious user agent detected: {ua} contains {bad_ua}")
            return True
        if not bad_ua and ua.strip() == "":
            print("Suspicious user agent detected: empty UA")
            return True  # Empty UA

    # Check for suspicious headers presence or emptiness
    for header in SUSPICIOUS_HEADERS:
        if header in headers:
            val = headers[header]
            if val is None or val.strip() == "":
                print(f"Suspicious header detected: {header} is empty or missing")
                return True
    print("No suspicious user agent or headers detected.")
    return False


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



# Modify your pow_submit route to mark verification and start analyzer
@app.route('/api/pow-submit', methods=['POST'])
def pow_submit():
    data = request.json
    challenge = data.get('challenge')
    nonce = str(data.get('nonce'))

    if verify_pow_challenge(challenge, str(nonce)):
        # Mark this client as verified
        client_ip = request.remote_addr
        print(client_ip + 'verified pow')
        
        if not hasattr(app, 'verified_clients'):
            app.verified_clients = set()
        app.verified_clients.add(client_ip)
            
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
        
@app.route("/bot-details")
def bot_details():
    json_path = os.path.join(os.path.dirname(__file__), "bot_profiles.json")
    try:
        with open(json_path, "r") as f:
            data = json.load(f)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
def periodic_analyzer(client_ip):
    """Run periodic analysis of traffic"""
    while True:
        try:
            time.sleep(ANALYSIS_WINDOW)
            logger.info(f"Periodic analyzer is running")
            
            # Analyze specific IP if provided, otherwise analyze all IPs
            if client_ip:
                results = analyze_traffic(client_ip)
                if client_ip in results and results[client_ip]["is_suspicious"]:
                    logger.warning(f"Detected suspicious activity from {client_ip}")
                    save_results({client_ip: results[client_ip]})
            else:
                results = analyze_traffic()
                suspicious_count = sum(1 for ip, data in results.items() if data["is_suspicious"])
                if suspicious_count > 0:
                    logger.warning(f"Detected {suspicious_count} suspicious IPs")
                    save_results(results)
        except Exception as e:
            logger.error(f"Error in periodic analyzer: {e}")
            
            
            
# Decorator function to do the pow analysis            
def pow_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.remote_addr
        
        # Check if PoW has been verified for this client
        if not hasattr(app, 'verified_clients'):
            app.verified_clients = set()
            
        if client_ip not in app.verified_clients:
            # Client hasn't been verified, show PoW page
            return f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Proof of Work Required</title>
                <script src="https://cdn.jsdelivr.net/npm/js-sha256@0.9.0/build/sha256.min.js"></script>
                {pow_script}
            </head>
            <body>
                <h1>Please wait, verifying...</h1>
                <p>Proof of Work verification is required before you can access this page.</p>
                <p>This verification helps protect against DDoS attacks.</p>
                <div id="status">Computing proof of work...</div>
            </body>
            </html>
            """
        
        # If we get here, the client has been verified
        return f(*args, **kwargs)
    return decorated_function

# function to connect with other applications


@app.route('/api/analyze', methods=['GET', 'POST'])
def analyze_request_api():
    # process the request and extract client IP
    client_ip = request.remote_addr
    
    # Track request processing time
    g.start_time = time.time()
    
    # Extract useful request information
    user_agent = request.headers.get('User-Agent', '')
    referrer = request.headers.get('Referer', '')
    endpoint = request.path
    
    # Get the actual IP if behind a proxy
    if request.headers.get('X-Forwarded-For'):
        forwarded_ips = request.headers.get('X-Forwarded-For').split(',')
        client_ip = forwarded_ips[0].strip()
    elif request.headers.get('X-Real-IP'):
        client_ip = request.headers.get('X-Real-IP')
    print(f"Client IP: {client_ip}")
    print(f"User-Agent: {user_agent}")
    print('----------End Of initial inference---------------')
    print('----------Start Of Part one---------------')
    # PART 1: Check PoW verification
    pow_status = {}
    if not hasattr(app, 'verified_clients'):
        app.verified_clients = set()
    
    if client_ip not in app.verified_clients:
        # Client needs to complete PoW
        print('----------doing Pow---------------')
        challenge, difficulty = generate_challenge();
        print(f"Generated challenge: {challenge} with difficulty {difficulty} inside analyze_request_api")
        print('----------done Pow---------------')
        pow_status = {
            'verified': verify_pow_challenge(challenge, str(difficulty)),
            'challenge': challenge,
            'difficulty': difficulty,
            'message': 'Proof of work verification required'
        }
    else:
        # Client already verified
        print('----------done before Pow---------------')
        pow_status = {
            'verified': True,
            'message': 'Proof of work previously verified'
        }
    print('----------End Of Part one---------------')
    # PART 2: Analyze traffic patterns
    # Also check if the current request's headers are suspicious
    headers_suspicious = is_suspicious(user_agent, request.headers)
    
    # Run the full traffic analysis
    results = analyze_traffic(client_ip)
    
    traffic_status = {}
    if client_ip in results:
        is_suspicious_ip = results[client_ip]["is_suspicious"]
        
        # Get specific reasons for suspicious activity
        reasons = []
        
        # Check traffic indicators
        traffic_indicators = results[client_ip]["traffic_indicators"]
        for indicator, value in traffic_indicators.items():
            if value:
                reasons.append(f"traffic:{indicator}")
        
        # Check packet indicators
        packet_indicators = results[client_ip]["packet_indicators"]
        for indicator, value in packet_indicators.items():
            if value:
                reasons.append(f"packet:{indicator}")
        
        traffic_status = {
            'is_suspicious': is_suspicious_ip,
            'current_request_suspicious': headers_suspicious,
            'reasons': reasons if is_suspicious_ip else [],
            'traffic_indicators': traffic_indicators,
            'packet_indicators': packet_indicators,
            'metadata': results[client_ip]["metadata"]
        }
    else:
        # No previous data for this IP
        traffic_status = {
            'is_suspicious': False,
            'current_request_suspicious': headers_suspicious,
            'reasons': ['current_request_suspicious'] if headers_suspicious else [],
            'traffic_indicators': {},
            'packet_indicators': {},
            'metadata': {}
        }
    
    # Calculate response time
    response_time = time.time() - g.start_time
    
    # Determine if access would be granted
    access_granted = pow_status.get('verified', False) and not traffic_status.get('is_suspicious', True) and not headers_suspicious
    
    # Return combined results
    return jsonify({
        'access_granted': access_granted,
        'pow_status': pow_status,
        'traffic_status': traffic_status,
        'client_ip': client_ip,
        'response_time_ms': round(response_time * 1000, 2),
        'request_details': {
            'user_agent': user_agent,
            'referrer': referrer,
            'endpoint': endpoint
        }
    })


# Decorator function to protect routes with traffic analysis
def traffic_protected(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.remote_addr
        results = analyze_traffic(client_ip)
        
        if client_ip in results and results[client_ip]["is_suspicious"]:
            # Get specific reasons for suspicious activity
            reasons = []
            
            # Check traffic indicators
            traffic_indicators = results[client_ip]["traffic_indicators"]
            for indicator, value in traffic_indicators.items():
                if value:
                    reasons.append(f"traffic:{indicator}")
            
            # Check packet indicators
            packet_indicators = results[client_ip]["packet_indicators"]
            for indicator, value in packet_indicators.items():
                if value:
                    reasons.append(f"packet:{indicator}")
            
            # Log detailed suspicious activity
            logger.warning(f"Blocked suspicious request from {client_ip}. Reasons: {', '.join(reasons)}")
            
            # Add detailed info to the response so you can see it
            return jsonify({
                "error": "Access denied due to suspicious activity", 
                "reasons": reasons,
                "details": {
                    "traffic_indicators": traffic_indicators,
                    "packet_indicators": packet_indicators,
                    "metadata": results[client_ip]["metadata"]
                }
            }), 403
        
        return f(*args, **kwargs)
    return decorated_function

@app.route('/protected')
@pow_required
@traffic_protected
def protected():
    return "This is a protected route!"

@app.route("/home")
def home():
    return render_template("home.html")


@app.route('/')
@pow_required
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
    <p><a href="/protected">Go to Protected Page</a></p>
    </html>
    """

if __name__ == "__main__":
    # Start the Flask app
    # schedule_extraction()
    app.run(host="0.0.0.0", port=8080, debug=False)
    
    