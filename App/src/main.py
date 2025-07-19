from collections import defaultdict, deque
import json
from logging.handlers import RotatingFileHandler
import os
from flask import Flask, render_template, request, jsonify, g, session
import time
import threading
import logging
from functools import wraps


from blockchain.blockchain_module import Blockchain
from bots.botprofile import generate_bot_profile, save_bot_profiles, score_save_bot
from server.ipblocker import schedule_extraction
from pow.js_threshhold_logic import analyze_traffic, generate_challenge, get_dynamic_difficulty, get_ttl_value, save_results, verify_pow_challenge

from utils.shared_data import SUSPICIOUS_HEADERS, SUSPICIOUS_USER_AGENTS, ip_stats, data_lock, challenge_store, dc_ranges
from utils.shared_data import logger, ANALYSIS_WINDOW, HIGH_RPM_THRESHOLD, SUSPICIOUS_UA_PATTERNS, TTL_SUSPICIOUS_VALUES

# blockchain 

blockchain = Blockchain(difficulty=3)

# blockchain logics

pow_script = """
<script>
async function updateStatus(message) {
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
        if (nonce % 1000 === 0) {
            updateStatus('Still working... Tried ' + nonce + ' solutions');
            await new Promise(resolve => setTimeout(resolve, 0));
        }
    }
}

window.onload = async function () {
    try {
        updateStatus('Checking for pending transactions...');
     

        const challengeResp = await fetch('/api/pow-challenge');
        const challengeData = await challengeResp.json();

        const nonce = await solvePow(challengeData.challenge, challengeData.difficulty);

        updateStatus('Submitting PoW solution...');
        const submitResp = await fetch('/api/pow-submit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                challenge: challengeData.challenge,
                nonce: nonce
            })
        });

        const submitData = await submitResp.json();
        if (submitData.status !== 'verified') {
            updateStatus('Verification failed: ' + submitData.message);
            return;
        }
        
        const pendingResp = await fetch('api/blockchain/pending');
        const pendingTx = await pendingResp.json();

        if (!pendingTx || pendingTx.length === 0) {
            updateStatus('No pending transactions. Nothing to mine. proceding to next step...');

        }

        if (localStorage.getItem('minedKey')) {
    updateStatus('You have already mined a block. Mining skipped.');
    return;
}

updateStatus('Verification successful. Mining block...');
const mineResp = await fetch('api/blockchain/mine');
const mineText = await mineResp.text();

if (mineText.toLowerCase().includes("mined")) {
    const hexKey = [...crypto.getRandomValues(new Uint8Array(8))]
        .map(b => b.toString(16).padStart(2, '0')).join('');
    localStorage.setItem('minedKey', hexKey);
    updateStatus(mineText + ' Key stored: ' + hexKey);
} else {
    updateStatus('Mining failed: ' + mineText);
}

    } catch (err) {
        updateStatus('Error: ' + err.message);
        console.error('Error:', err);
    }
};
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
# logger.addHandler(file_handler)

# Add console handler if you still want console output
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
# logger.addHandler(console_handler)

# Initialize Flask app
app = Flask(__name__)
# Configuration Defaults
app.config['INITIALIZED'] = False
app.config['REQUIRE_POW'] = True  # Set True if PoW is required

# Setup Logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TrafficAnalyzer")
# to update 
# Run setup code with app context
@app.before_request
# def ensure_initialized():
#     if not app.config.get('INITIALIZED', False):
        
#         # Check if PoW verification is needed
#         if app.config.get('REQUIRE_POW', True):
#             app.config['POW_REQUIRED'] = True
#             app.config['INITIALIZED'] = True
#         else:
#             analyzer_thread = threading.Thread(target=periodic_analyzer(client_ip), daemon=True)
#             analyzer_thread.start()
            
#         app.config['INITIALIZED'] = True

# # Traffic analysis middleware
# @app.before_request
# def analyze_request():
#     # Get client IP
#     client_ip = request.remote_addr
    
#     # Get request timestamp
#     request_time = time.time()
    
#     # Extract useful request information
#     user_agent = request.headers.get('User-Agent', '')
#     referrer = request.headers.get('Referer', '')
#     endpoint = request.path
    
#     if is_suspicious(user_agent, request.headers):
#         # Log suspicious request
#         # logger.warning(f"Suspicious request detected from {client_ip} with user agent: {user_agent}")
#         try:
#             transaction_data = {
#                 "ip": "192.168.1.1",
#                 "headers_present": True,
#                 "ttl_obfuscation": False,
#                 "legitimacy_score": 0.85,
#                 "is_trustworthy": True
#             }
#             result = BlockchainInterface.submit_transaction(transaction_data)
#             print("Transaction result:", result)
#         except ValueError as e:
#             print("Error:", e)
    
#     if request.headers.get('X-Forwarded-For'):
#         forwarded_ips = request.headers.get('X-Forwarded-For').split(',')
#         client_ip = forwarded_ips[0].strip()
#     elif request.headers.get('X-Real-IP'):
#         client_ip = request.headers.get('X-Real-IP')
    
    
#     # Try to get TTL value (may require additional privileges)
#     ttl = get_ttl_value(client_ip)
#     # Store request data with thread safety
#     with data_lock:
#         ip_data = ip_stats[client_ip]
        
#         # First request from this IP
#         if ip_data["first_seen"] == 0:
#             ip_data["first_seen"] = request_time
#             ip_data["is_residential"] = True
        
#         # Update statistics
#         ip_data["last_seen"] = request_time
#         ip_data["request_count"] += 1
#         ip_data["endpoints_accessed"].add(endpoint)
#         ip_data["last_requests"].append(request_time)
        
#         # Check headers
#         if user_agent:
#             ip_data["user_agents"].add(user_agent)
#         if referrer:
#             ip_data["referrers"].add(referrer)
        
#         # Check if important headers are missing or invalid
#         ip_data["headers_present"] = bool(user_agent and not(is_suspicious(user_agent, request.headers)))
      
#         # Store TTL if available
#         if ttl:
#             ip_data["ttl_values"].add(ttl)
#             if ttl in TTL_SUSPICIOUS_VALUES:
#                 ip_data["ttl_obfuscation"] = True  
#         # print(ip_data)
        # generate_bot_profile(client_ip,ip_data)  
#     g.start_time = time.time()
    
#  to update finished        


def start_global_analyzer():
    stop_event = threading.Event()
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    if blockchain.check_ip_exists(client_ip):
            logger.info(f"Analyzer already running for IP: {client_ip}")
            return 
    else:
        thread = threading.Thread(target=periodic_analyzer, args=(client_ip, stop_event), daemon=True)
        thread.start()
        logger.info("Global background analyzer started.")
    
@app.before_request
def unified_before_request():
    if not app.config['INITIALIZED']:
        if app.config.get('REQUIRE_POW', True):
            app.config['POW_REQUIRED'] = True
            logger.info("PoW required. No analyzer started.")
        else:
            start_global_analyzer()
        app.config['INITIALIZED'] = True
        logger.info("Application initialized.")

    # Get client IP
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    request_time = time.time()
    user_agent = request.headers.get('User-Agent', '')
    referrer = request.headers.get('Referer', '')
    endpoint = request.path

    suspicious_request = is_suspicious(user_agent, request.headers)

    if suspicious_request:
        logger.warning(f"Suspicious request detected from {client_ip}. User-Agent: {user_agent}")
        try:
            transaction_data = {
                "ip": client_ip,
                "headers_present": False,
                "ttl_obfuscation": False,
                "legitimacy_score": 0.0,
                "is_trustworthy": False
            }
            blockchain.add_transaction(transaction_data)
            logger.info(f"Suspicious transaction submitted to blockchain for {client_ip}")
        except ValueError as e:
            logger.error(f"Failed to submit suspicious transaction for {client_ip}: {e}")

        

    ttl = get_ttl_value(client_ip)

    with data_lock:
        stats = ip_stats.setdefault(client_ip, {
            "first_seen": 0,
            "last_seen": 0,
            "request_count": 0,
            "endpoints_accessed": set(),
            "last_requests": [],
            "user_agents": set(),
            "referrers": set(),
            "headers_present": True,
            "ttl_values": set(),
            "ttl_obfuscation": False,
            "is_residential": True
        })

        if stats["first_seen"] == 0:
            stats["first_seen"] = request_time
            logger.info(f"New IP seen: {client_ip}")

        stats["last_seen"] = request_time
        stats["request_count"] += 1
        stats["endpoints_accessed"].add(endpoint)
        stats["last_requests"].append(request_time)
        if user_agent:
            stats["user_agents"].add(user_agent)
        if referrer:
            stats["referrers"].add(referrer)

        stats["headers_present"] = bool(user_agent and not suspicious_request)

        if ttl:
            stats["ttl_values"].add(ttl)
            if ttl in TTL_SUSPICIOUS_VALUES:
                stats["ttl_obfuscation"] = True

        logger.debug(f"Stats updated for {client_ip}: {stats}")

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
      if "response_codes" not in ip_stats[client_ip]:
        ip_stats[client_ip]["response_codes"] = {}

        ip_stats[client_ip]["response_codes"][response.status_code] = \
            ip_stats[client_ip]["response_codes"].get(response.status_code, 0) + 1

    return response

def is_suspicious(user_agent, headers):
    ua = (user_agent or "").lower()

    # Partial match: check if any suspicious string appears in the UA
    for bad_ua in SUSPICIOUS_USER_AGENTS:
        if bad_ua and bad_ua in ua:
            return True
        if not bad_ua and ua.strip() == "":
            return True  # Empty UA

    # Check for suspicious headers presence or emptiness
    for header in SUSPICIOUS_HEADERS:
        if header in headers:
            val = headers[header]
            if val is None or val.strip() == "":
                return True
    
    return False


@app.route('/api/blockchain/add-transaction', methods=['POST'])
def api_add_transaction():
    """Add a transaction to the blockchain"""
    tx_data = request.get_json()
    try:
        blockchain.add_transaction(tx_data)
        return jsonify({"message": "Transaction added successfullyyyyy"}), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/blockchain/mine', methods=['GET'])
def api_mine():
    """Mine pending transactions into a block"""
    result = blockchain.mine()
    if result:
        return jsonify({
            "message": f"Block #{result['index']} mined successfully",
            "details": result
        }), 201
    else:
        return jsonify({"message": "No transactions to mineee"}), 200


@app.route('/api/blockchain/chain', methods=['GET'])
def api_get_chain():
    """Get full blockchain"""
    chain = blockchain.get_chain()
    return jsonify(chain), 200


@app.route('/api/blockchain/pending', methods=['GET'])
def api_get_pending_transactions():
    """Get all pending transactions"""
    pending = blockchain.get_pending_transactions()
    return jsonify(pending), 200


@app.route('/api/blockchain/search', methods=['POST'])
def api_search_by_ip():
    """Search for transactions using an IP"""
    data = request.get_json()
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "Missing 'ip' field in request"}), 400

    result = blockchain.search_by_ip(ip)
    return jsonify(result), 200

# -----------------------------
# Run Server
# -----------------------------
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
            stop_event = threading.Event()
            analyzer_thread = threading.Thread(target=periodic_analyzer, args=(client_ip, stop_event), daemon=True)
            analyzer_thread.start()
            # # logger.info("Traffic analyzer started after PoW v")
            app.config['ANALYZER_STARTED'] = True
            return jsonify({'status': 'analyzer started'})
        return jsonify({'status': 'analyzer already running'})
    
    return jsonify({'status': 'verification required'}), 403


# Modify your pow_submit route to mark verification and start analyzer
@app.route('/api/pow-submit', methods=['POST'])
def pow_submit():
    data = request.json
    challenge = data.get('challenge')
    nonce = str(data.get('nonce'))
    print(f"Received PoW submission: challenge={challenge}, nonce={nonce}")

    if verify_pow_challenge(challenge, str(nonce)):
        # Mark this client as verified
        client_ip = request.remote_addr
        
        if not hasattr(app, 'verified_clients'):
            app.verified_clients = set()
        app.verified_clients.add(client_ip)
            
        return jsonify({'status': 'verified'})
   
    return jsonify({'status': 'invalid proof'}), 403

@app.route('/api/pow-challenge')
def pow_challenge():
        challenge, difficulty = generate_challenge()
        return jsonify({'challenge': challenge, 'difficulty': difficulty})       
@app.route("/api/bot-details")
def bot_details():
    json_path = os.path.join(os.path.dirname(__file__), "bot_profiles.json")
    try:
        with open(json_path, "r") as f:
            data = json.load(f)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
def periodic_analyzer(client_ip, stop_event):
    while not stop_event.is_set():
        try:
            if client_ip:
                results = analyze_traffic(client_ip)
                if client_ip in results and results[client_ip]["is_suspicious"]:
                    logger.warning(f"Detected suspicious activity from {client_ip}")
                    for ip, data in results.items():
                        if data["is_suspicious"]:
                            try:
                                transaction_data = {
                                    "ip": ip,
                                    "headers_present": results[ip]["traffic_indicators"].get("missing_headers") is False,
                                    "ttl_obfuscation": results[ip]["packet_indicators"].get("ttl_obfuscation", False),
                                    "legitimacy_score": score_save_bot(results[ip]),  # Because it's suspicious (0% legitimate)
                                    "is_trustworthy": False
                                }

                                result = blockchain.add_transaction(transaction_data)
                                logger.info(f"Blockchain transaction submitted for {ip}: {result}")
                                break
                            except Exception:
                                logger.exception("Error in periodic analyzer")
                else:
                    for ip, data in results.items():
                        try:
                                transaction_data = {
                                    "ip": ip,
                                    "headers_present": results[ip]["traffic_indicators"].get("missing_headers") is False,
                                    "ttl_obfuscation": results[ip]["packet_indicators"].get("ttl_obfuscation", False),
                                    "legitimacy_score": score_save_bot(results[ip]),  
                                    "is_trustworthy": False
                                }

                                result = blockchain.add_transaction(transaction_data)
                                logger.info(f"Blockchain transaction submitted for {ip}: {result}")
                                break
                        except Exception:
                                logger.exception("Error in periodic analyzer")
                                logger.info(f"No suspicious activity detected for {client_ip}")
                    # time.sleep(60)  
            else:
                results = analyze_traffic()
                suspicious_count = sum(1 for ip, data in results.items() if data["is_suspicious"])
                if suspicious_count > 0:
                    for ip, data in results.items():
                        if data["is_suspicious"]:
                            try:
                                transaction_data = {
                                    "ip": ip,
                                    "headers_present": results[ip]["traffic_indicators"].get("missing_headers") is False,
                                    "ttl_obfuscation": results[ip]["packet_indicators"].get("ttl_obfuscation", False),
                                    "legitimacy_score": score_save_bot(results[ip]),   # Because it's suspicious (0% legitimate)
                                    "is_trustworthy": False
                                }
                                
                                result = blockchain.add_transaction(transaction_data)
                                logger.info(f"Blockchain transaction submitted for {ip}: {result}")
                            except Exception:
                                logger.exception("Error in periodic analyzer")
        except Exception:
                logger.exception("Error in periodic analyzer")
        time.sleep(ANALYSIS_WINDOW)
           

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

running_analyzers = {}

# Track running analyzers to avoid multiple threads for same IP
def traffic_protected(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.remote_addr
        # logger.info(f"Received request fromeeeeeeeeeee {client_ip}")
        # Start analyzer thread only if not already running for this IP
        if blockchain.check_ip_exists(client_ip):
            logger.info(f"Analyzer already running for IP: {client_ip}")
            return f(*args, **kwargs)
        else:
            if client_ip not in running_analyzers:
                start_global_analyzer()
                # logger.info(f"Started background analyzer for IP: {client_ip}")

            # Perform immediate analysis to block suspicious traffic
            results = analyze_traffic(client_ip)

            if client_ip in results and results[client_ip]["is_suspicious"]:
                reasons = []

                traffic_indicators = results[client_ip]["traffic_indicators"]
                for indicator, value in traffic_indicators.items():
                    if value:
                        reasons.append(f"traffic:{indicator}")

                packet_indicators = results[client_ip]["packet_indicators"]
                for indicator, value in packet_indicators.items():
                    if value:
                        reasons.append(f"packet:{indicator}")

                # logger.warning(f"Blocked suspicious request from {client_ip}. Reasons: {', '.join(reasons)}")

                return jsonify({
                    "ip": client_ip,
                    "error": "Access denied due to suspicious activity",
                    "reasons": reasons,
                    "details": {
                        "traffic_indicators": traffic_indicators,
                        "packet_indicators": packet_indicators,
                        "metadata": results[client_ip]["metadata"]
                    }
                }), 403

            save_bot_profiles(results)
            score_save_bot(results)

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
    # Initialize rate limiter for per-IP tracking
    # limiter = Limiter(
    #     get_remote_address,
    #     app=app,
    #     default_limits=["100 per minute"]  # global limit per IP
    # )
    app.run(host="0.0.0.0", port=8081, debug=False)
    
    