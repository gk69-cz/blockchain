from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
import datetime
import json
from logging.handlers import RotatingFileHandler
import os
import subprocess
from flask import Flask, render_template, request, jsonify, g, session
import time
import threading
import logging
from logging_fix import setup_logging
from functools import wraps
import atexit

from blockchain.blockchain_module import Blockchain
from bots.botprofile import generate_bot_profile, save_bot_profiles, score_save_bot
from server.ipblocker import schedule_extraction
from pow.js_threshhold_logic import analyze_traffic, generate_challenge, get_dynamic_difficulty, get_ttl_value, save_results, verify_pow_challenge

from utils.shared_data import SUSPICIOUS_HEADERS, SUSPICIOUS_USER_AGENTS, ip_stats, data_lock, challenge_store, dc_ranges
from utils.shared_data import logger, ANALYSIS_WINDOW, HIGH_RPM_THRESHOLD, SUSPICIOUS_UA_PATTERNS, TTL_SUSPICIOUS_VALUES, SYN_FLOOD_THRESHOLD, request_rate_tracker, difficulty_cache

# blockchain 

blockchain = Blockchain(difficulty=4)

TIME_WINDOW = 10  # Time window in seconds to collect requests
executor = ThreadPoolExecutor(max_workers=10)  # Thread pool for parallel analysis
ip_batch_timers = {}  # Track timers for each IP
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
        // Check if we already have a valid auth pair
if (sessionStorage.getItem('authPair')) {
    const pair = JSON.parse(sessionStorage.getItem('authPair'));
    console.log("Found auth pair in sessionStorage:", pair);

    try {
        const validResp = await fetch('/api/auth/validate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(pair)
        });
        const validData = await validResp.json();

        if (validData.valid) {
            console.log("Auth pair is still valid (age:", validData.age_seconds, "s). Skipping PoW and blockchain search.");
        
            // go directly to protected route
            setTimeout(() => {
                window.location.href = '/protected';
            }, 1000);
            return; // stop execution here
        } else {
            console.log("Auth pair expired (age:", validData.age_seconds, "s). Proceeding with PoW and blockchain search...");
            updateStatus("Auth expired. Running PoW + blockchain checks...");
        }
    } catch (err) {
        console.error("Error validating auth pair:", err);
        updateStatus("Error validating auth pair, running PoW...");
    }
} else {
    console.log("No auth pair found. Proceeding with PoW and blockchain search...");
}

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
            updateStatus('No pending transactions. Nothing to mine. proceeding to next step...');
        }

        if (sessionStorage.getItem('authPair')) {
    updateStatus('You already have an auth pair. Checking IP records...');
            updateStatus('You have already mined a block. Checking IP records...');
            const clientIpResp = await fetch('https://api.ipify.org?format=json');
            const clientIpData = await clientIpResp.json();
            const realIp = clientIpData.ip;
            try {
                const resp = await fetch('/api/blockchain/search', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip: realIp })
                });

                const result = await resp.json();
                if (result && result.length > 0) {
                    updateStatus('Search successful: IP found in blockchain records.');
                    console.log(result);
                } else {
                    updateStatus('No records found for this IP.');
                     setTimeout(() => {
                        window.location.href = '/protected';
                    }, 1500);
                }
            } catch (err) {
                updateStatus('Error checking IP: ' + err.message);
            }

        }


        updateStatus('Verification successful. Starting continuous mining for 15 seconds...');
        
        // Continuous mining for 15 seconds
        const miningStartTime = Date.now();
        const miningDuration = 15000; // 15 seconds
        let miningAttempts = 0;
        let lastMineResult = '';

        while (Date.now() - miningStartTime < miningDuration) {
            try {
                miningAttempts++;
                const timeRemaining = Math.ceil((miningDuration - (Date.now() - miningStartTime)) / 1000);
                updateStatus(`Mining attempt ${miningAttempts}... ${timeRemaining} seconds remaining`);
                
                const mineResp = await fetch('api/blockchain/usermine');
                const mineText = await mineResp.text();
                lastMineResult = mineText;

                if (mineText.toLowerCase().includes("mined")) {
                    
                    const hexKey = [...crypto.getRandomValues(new Uint8Array(8))]
                        .map(b => b.toString(16).padStart(2, '0')).join('');
                    const authResp = await fetch('/api/auth/generate');
                    const authData = await authResp.json();
                    sessionStorage.setItem('authPair', JSON.stringify(authData));
                    updateStatus(`Auth pair generated & stored: ${JSON.stringify(authData)}`);
                    break; 
                }

                // Small delay between requests to prevent overwhelming the server
                await new Promise(resolve => setTimeout(resolve, 100));
                
            } catch (err) {
                console.error('Mining attempt failed:', err);
                updateStatus(`Mining attempt ${miningAttempts} failed: ${err.message}`);
            }
        }

        // Final status update
        if (!localStorage.getItem('minedKey')) {
            updateStatus(`Mining completed after ${miningAttempts} attempts. Final result: ${lastMineResult}`);
        }

    } catch (err) {
        updateStatus('Error: ' + err.message);
        console.error('Error:', err);
    }
};
</script>
"""


logger = setup_logging()

BATCH_SIZE = 20
ANALYSIS_WINDOW = 60  
BLOCK_DURATION = 300

# Simple dictionaries to track IPs
ip_requests = {}  
blocked_ips = {} 
analysis_results = {}  


def load_ip_data():
    try:
        if os.path.exists('ip_tracking.json'):
            with open('ip_tracking.json', 'r') as f:
                data = json.load(f)
                return data.get('ip_requests', {}), data.get('blocked_ips', {}), data.get('analysis_results', {})
    except:
        pass
    return {}, {}, {}

def track_request_rate():
    """Track request rates for difficulty adjustment"""
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    current_time = int(time.time())
    
    if client_ip not in request_rate_tracker:
        request_rate_tracker[client_ip] = []
    
    # Add current request
    request_rate_tracker[client_ip].append(current_time)
    
    # Clean old requests (keep only last 5 minutes)
    cutoff_time = current_time - 300
    request_rate_tracker[client_ip] = [t for t in request_rate_tracker[client_ip] if t > cutoff_time]

def save_ip_data():
    try:
        data = {
            'ip_requests': ip_requests,
            'blocked_ips': blocked_ips,
            'last_updated': datetime.datetime.now().isoformat()
        }
        with open('ip_tracking.json', 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        logger.error(f"Failed to save IP data: {e}")

# Load data on startup
ip_requests, blocked_ips, analysis_results = load_ip_data()

def is_ip_blocked(client_ip):
    if client_ip in blocked_ips:
        block_until = blocked_ips[client_ip]
        if time.time() < block_until:
            return True, int(block_until - time.time())
        else:
            del blocked_ips[client_ip]
            save_ip_data()
    return False, 0

def add_request_to_batch(client_ip, user_agent, headers):
    current_time = time.time()
    # Initialize IP if not exists
    if client_ip not in ip_requests:
        ip_requests[client_ip] = []
    
    cutoff_time = current_time - ANALYSIS_WINDOW
    ip_requests[client_ip] = [req for req in ip_requests[client_ip] 
                              if req['timestamp'] > cutoff_time]
    
    # Add current request with headers for is_suspicious function
    request_data = {
        'timestamp': current_time,
        'user_agent': user_agent,
        'path': request.path,
        'method': request.method,
        'referer': headers.get('Referer', ''),
        'accept': headers.get('Accept', ''),
        'accept_language': headers.get('Accept-Language', ''),
        'accept_encoding': headers.get('Accept-Encoding', '')
    }
    ip_requests[client_ip].append(request_data)
    
    # Check if batch is ready for analysis
    batch_size = len(ip_requests[client_ip])
    logger.info(f"[BATCH TRACKING] {client_ip}: {batch_size}/{BATCH_SIZE} requests")
    
    # Schedule analysis if timer not already running for this IP
    if client_ip not in ip_batch_timers or not ip_batch_timers[client_ip].is_alive():
        timer = threading.Timer(TIME_WINDOW, lambda: schedule_batch_analysis(client_ip))
        timer.daemon = True
        timer.start()
        ip_batch_timers[client_ip] = timer
        logger.info(f"[TIMER] Started {TIME_WINDOW}s timer for {client_ip}")
    
   
    if batch_size >= BATCH_SIZE:
        logger.info(f"[IMMEDIATE] {client_ip} hit batch size limit, analyzing now")
        # Cancel timer since we're analyzing immediately
        if client_ip in ip_batch_timers:
            ip_batch_timers[client_ip].cancel()
            del ip_batch_timers[client_ip]
        return analyze_ip_batch(client_ip)
    return False 


def schedule_batch_analysis(client_ip):
    """Schedule batch analysis in a separate thread"""
    logger.info(f"[SCHEDULER] Time window expired for {client_ip}, scheduling analysis")
    
    # Remove timer reference
    if client_ip in ip_batch_timers:
        del ip_batch_timers[client_ip]
    
    # Only analyze if there are requests
    if client_ip in ip_requests and len(ip_requests[client_ip]) > 0:
        # Submit to thread pool for parallel processing
        future = executor.submit(analyze_ip_batch_threaded, client_ip)
        logger.info(f"[THREAD] Submitted analysis for {client_ip} to thread pool")
    else:
        logger.info(f"[SCHEDULER] No requests to analyze for {client_ip}")


def analyze_ip_batch_threaded(client_ip):
    """Thread-safe wrapper for batch analysis"""
    try:
        logger.info(f"[THREAD] Starting threaded analysis for {client_ip}")
        return analyze_ip_batch(client_ip)
    except Exception as e:
        logger.warning(f"[THREAD ERROR] Analysis failed for {client_ip}: {e}")
        return False

def block_ip_simple(client_ip, reason):
    block_until = time.time() + BLOCK_DURATION
    blocked_ips[client_ip] = block_until
    
    # Progressive blocking for repeat offenders
    if client_ip in analysis_results:
        suspicious_ratio = (analysis_results[client_ip]['suspicious_count'] / 
                          max(analysis_results[client_ip]['total_batches'], 1))
        if suspicious_ratio > 0.5:  # More than 50% suspicious batches
            blocked_ips[client_ip] = time.time() + (BLOCK_DURATION * 3)  # Triple block time
            print(f"[EXTENDED BLOCK] {client_ip} - Repeat offender")
    
    logging.critical(f"[BLOCKED] {client_ip} - {reason} - Until: {datetime.datetime.fromtimestamp(blocked_ips[client_ip])}")
    save_ip_data()
    
def analyze_ip_batch(client_ip):
    """Analyze batch of requests from IP using existing is_suspicious function"""
    try:
        # Create a copy of requests to avoid race conditions
        with data_lock:  # Use your existing data_lock
            if client_ip not in ip_requests or not ip_requests[client_ip]:
                print(f"[ANALYSIS] No requests found for {client_ip}")
                return False
                
            requests_batch = ip_requests[client_ip].copy()
            # Clear the batch after copying
            ip_requests[client_ip] = []
        
        total_requests = len(requests_batch)    
        logging.warning(f"[BATCH ANALYSIS] Analyzing {total_requests} requests from {client_ip}")
        
        # Using existing is_suspicious function
        suspicious_count = 0
        for req in requests_batch:
            mock_headers = {
                'User-Agent': req.get('user_agent', ''),
                'Referer': req.get('referer', ''),
                'Accept': req.get('accept', ''),
                'Accept-Language': req.get('accept_language', ''),
                'Accept-Encoding': req.get('accept_encoding', '')
            }   
            if is_suspicious(req.get('user_agent', ''), mock_headers):
                suspicious_count += 1
                
        suspicious_ratio = suspicious_count / total_requests
        is_batch_suspicious = suspicious_ratio > 0.5
        
        print(f"[ANALYSIS] {client_ip} - Suspicious: {suspicious_count}/{total_requests} ({suspicious_ratio:.1%})")
        
        # Additional check: Request frequency (too fast)
        if total_requests >= 50:  # Lower threshold for time-based analysis
            timestamps = [req['timestamp'] for req in requests_batch]
            time_span = max(timestamps) - min(timestamps)
            if time_span < 20:  # Very rapid requests
                is_batch_suspicious = True
                logging.critical(f"[ANALYSIS] {client_ip} - Rapid fire: {total_requests} in {time_span:.2f}s")
        
        # Update analysis results (thread-safe)
        with data_lock:
            if client_ip not in analysis_results:
                analysis_results[client_ip] = {'suspicious_count': 0, 'total_batches': 0}
            
            analysis_results[client_ip]['total_batches'] += 1
            if is_batch_suspicious:
                analysis_results[client_ip]['suspicious_count'] += 1
        
        # Block logic
        if is_batch_suspicious:
            block_ip_simple(client_ip, f"Time-based batch analysis: {suspicious_count}/{total_requests} suspicious requests")
            
            # Add to blockchain
            try:
                transaction_data = {
                    "ip": client_ip,
                    "batch_size": total_requests,
                    "suspicious_requests": suspicious_count,
                    "suspicious_ratio": suspicious_ratio,
                    "analysis_type": "time_based_batch_analysis",
                    "headers_present": suspicious_count < total_requests,
                    "ttl_obfuscation": False,
                    "legitimacy_score": 1.0 - suspicious_ratio,
                    "is_trustworthy": False
                }
                blockchain.add_transaction(transaction_data)
                logging.info(f"[BLOCKCHAIN] Added suspicious time-based batch transaction for {client_ip}")
            except Exception as e:
                logging.critical(f"[ERROR] Failed to add blockchain transaction: {e}")
        else:
            # Add positive transaction for clean batch
            try:
                transaction_data = {
                    "ip": client_ip,
                    "batch_size": total_requests,
                    "suspicious_requests": suspicious_count,
                    "suspicious_ratio": suspicious_ratio,
                    "analysis_type": "time_based_batch_analysis",
                    "headers_present": True,
                    "ttl_obfuscation": False,
                    "legitimacy_score": 1.0 - suspicious_ratio,
                    "is_trustworthy": True
                }
                blockchain.add_transaction(transaction_data)
                logging.info(f"[BLOCKCHAIN] Added clean time-based batch transaction for {client_ip}")
            except Exception as e:
                logging.critical(f"[ERROR] Failed to add blockchain transaction: {e}")
        
        save_ip_data()
        return is_batch_suspicious
        
    except Exception as e:
        logging.critical(f"[ERROR] Batch analysis failed for {client_ip}: {e}")
        return True


# Add console handler if you still want console output
console_handler = logging.StreamHandler()
# logger.addHandler(console_handler)

# Initialize Flask app
app = Flask(__name__)
# Configuration Defaults
app.config['INITIALIZED'] = False
app.config['REQUIRE_POW'] = True  # Set True if PoW is required


def start_global_analyzer():
    stop_event = threading.Event()
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    user_agent = request.headers.get('User-Agent', '').lower()
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
    batch_response = batch_rate_limiter()
    if batch_response:
        return batch_response
    # Get client IP
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    
    logger.info(f"Received request from {client_ip}")
    track_request_rate()
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
    analyze_traffic(client_ip)


@app.before_request
def batch_rate_limiter():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    user_agent = request.headers.get('User-Agent', '')
    print(f"[TIME-BASED] Received request from {client_ip}")
    
    # Check if IP is blocked
    is_blocked, remaining_time = is_ip_blocked(client_ip)
    if is_blocked:
        print(f"[BLOCKED REQUEST] {client_ip} - {remaining_time}s remaining")
        logging.critical(f"[BLOCKED REQUEST] {client_ip} - {remaining_time}s remaining")
        return jsonify({
            "error": "IP temporarily blocked",
            "ip": client_ip,
            "remaining_seconds": remaining_time,
            "message": "Please wait before making more requests"
        }), 429
    
    # Add request to time-based batch (non-blocking)
    # This will return True only if immediate blocking is needed
    immediate_block = add_request_to_batch(client_ip, user_agent, request.headers)
    if immediate_block:
        print(f"[IMMEDIATE BLOCK] {client_ip} - Blocking due to rapid requests")
        return jsonify({
            "error": "Too many rapid requests",
            "ip": client_ip,
            "message": "Please slow down your requests"
        }), 429

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

    # Checking if any suspicious string appears in the UA
    for bad_ua in SUSPICIOUS_USER_AGENTS:
        if bad_ua and bad_ua in ua:
            return True
        if not bad_ua and ua.strip() == "":
            return True  # Empty UA

    # Check for suspicious headers presence or if header is empty
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

@app.route('/api/blockchain/usermine', methods=['GET'])
def api_usermine():
    """Mine pending transactions into a block"""
    result = blockchain.usermine()
    if result:
        return jsonify({
            "message": f"Preminined ip block success",
            "details": result
        }), 201
    else:
        return jsonify({"message": "No transactions to mineee"}), 200

@app.route('/api/blockchain/chain', methods=['GET'])
def api_get_chain():
    """Get full blockchain"""
    chain = blockchain.get_chain()
    return jsonify(chain), 200

@app.route('/api/blockchain/userblocks', methods=['GET'])
def api_get_userblocks():
    """Get user mined blocks"""
    blocks = blockchain.get_user_mined_data()
    return jsonify(blocks), 200

@app.route('/api/blockchain/pending', methods=['GET'])
def api_get_pending_transactions():
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

@app.route('/api/blockchain/search-ip', methods=['POST'])
def api_search_ip():
    data = request.get_json()
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "Missing 'ip' field in request"}), 400

    result = blockchain.search_by_ip(ip)
    return jsonify(result), 200

# for quick action
@app.route('/api/analyze-block', methods=['GET'])
def api_analyze_now():
   client_ip = request.remote_addr
   result = blockchain.search_by_ip(client_ip)

def detect_syn_flood(threshold=100):
    while True:
        try:
            # Count connections in SYN_RECV state
            result = subprocess.run(
                ["netstat", "-ant"], capture_output=True, text=True
            )
            syn_recv_count = sum(1 for line in result.stdout.splitlines() if "SYN_RECV" in line)
            if syn_recv_count > threshold:
                logger.warning(f"Possible SYN flood detected! SYN_RECV count: {syn_recv_count}")
        except Exception as e:
            logger.error(f"SYN flood detection error: {e}")
        time.sleep(5)  # Check every 5 seconds

# Start SYN flood detection in a background thread
threading.Thread(target=detect_syn_flood, daemon=True).start()

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
            # logger.info("Traffic analyzer started after PoW v")
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
    INACTIVITY_TIMEOUT = 200
    while not stop_event.is_set():
        try:
            now = time.time()
            with data_lock:
                last_seen = ip_stats.get(client_ip, {}).get("last_seen", 0)

            # Stop analyzer if client inactive too long
            if last_seen and (now - last_seen > INACTIVITY_TIMEOUT):
                logger.info(f"Stopping analyzer for {client_ip} due to inactivity ({INACTIVITY_TIMEOUT}s)")
                running_analyzers.pop(client_ip, None)  # allow restart later
                break
            if client_ip:
                logger.info(f"Running periodic analyzer for IP: {client_ip}")
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
                                    "legitimacy_score": score_save_bot(results[ip]),  
                                    "is_trustworthy": not bool(data["is_suspicious"])
                                }
                                logger.info(f"Blockchain transaction banger")
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
                                    "is_trustworthy": not bool(data["is_suspicious"])

                                }
                                logger.info(f"Blockchain transaction banger2 data: {data}")
                                result = blockchain.add_transaction(transaction_data)
                                logger.info(f"Blockchain transaction submitted for {ip}: {result}")
                                break
                        except Exception:
                                logger.exception("Error in periodic analyzer")
                                logger.info(f"No suspicious activity detected for {client_ip}")
                    # time.sleep(60)  
            else:
                logger.info("Error in periodic analyzer5656")
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
                                    "is_trustworthy": bool(data["is_suspicious"])

                                }
                                logger.info(f"Blockchain transaction banger3 ")
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
        print(f"Client IP powdone: {client_ip}")
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
        # Start analyzer thread only if not already running for this IP
        if blockchain.check_ip_exists(client_ip):
            logger.info(f"Analyzer already running for IP: {client_ip}")
            return f(*args, **kwargs)
        else:
            if client_ip not in running_analyzers:
                start_global_analyzer()
                logger.info(f"Started background analyzer for IP: {client_ip}")
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
 
# after line ~950 (before cleanup_resources or near other routes)

@app.route('/api/auth/generate', methods=['GET'])
def generate_auth_pair():
    import secrets
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    presigned_key = secrets.token_hex(8)
    authtoken = secrets.token_hex(8)
    timestamp = datetime.datetime.utcnow().isoformat()

    data = {"presigned_key": presigned_key, "authtoken": authtoken, "timestamp": timestamp, "ip": client_ip}

    # Save in server JSON file
    try:
        with open("auth_pairs.json", "a") as f:
            f.write(json.dumps(data) + "\n")
    except Exception as e:
        logger.error(f"Failed to save auth pair: {e}")

    # Save also in session
    session['auth_pair'] = data
    return jsonify(data), 200


@app.route('/api/auth/validate', methods=['POST'])
def validate_auth_pair():
    req = request.get_json()
    presigned_key = req.get("presigned_key")
    authtoken = req.get("authtoken")

    stored = session.get("auth_pair")
    if not stored:
        return jsonify({"valid": False, "reason": "No auth pair in session"}), 400

    # Expiry window (e.g., 5 minutes)
    expiry_seconds = 300
    ts = datetime.datetime.fromisoformat(stored["timestamp"])
    age = (datetime.datetime.utcnow() - ts).total_seconds()

    if stored["presigned_key"] == presigned_key and stored["authtoken"] == authtoken and age <= expiry_seconds:
        return jsonify({"valid": True, "age_seconds": age}), 200
    else:
        return jsonify({"valid": False, "age_seconds": age}), 200


@app.route('/api/blockchain/backtrace', methods=['POST'])
def backtrace_blockchain():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    data = request.get_json() or {}
    ip = data.get("ip", client_ip)

    # Perform blockchain lookup for IP
    result = blockchain.search_by_ip(ip)
    return jsonify({"queried_ip": ip, "results": result}), 200

@app.route('/api/analyze-now', methods=['GET'])
def api_deep_analyze():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    user_agent = request.headers.get('User-Agent', '').lower()
    
    try:
        logging.info(f"Starting deep analysis for IP: {client_ip} (may take time)")
        syn_flood_threshold = 100
        result = subprocess.run(
            ["netstat", "-ant"], capture_output=True, text=True
        )
        syn_recv_count = sum(1 for line in result.stdout.splitlines() if "SYN_RECV" in line)
        if syn_recv_count > syn_flood_threshold:
            logging.warning(f"SYN flood detected during analyze-now! SYN_RECV count: {syn_recv_count}")
            transaction_data = {
                "ip": client_ip,
                "attack_type": "SYN_FLOOD",
                "syn_recv_count": syn_recv_count,
                "headers_present": False,
                "ttl_obfuscation": False,
                "legitimacy_score": 0.0,
                "is_trustworthy": False
            }
            result = blockchain.add_transaction(transaction_data)
            logger.info(f"SYN flood transaction submitted for {client_ip}: {result}")

        # Run full analysis (blocking call)
        results = analyze_traffic(client_ip)

        if client_ip in results:
            analysis_result = results[client_ip]
            verdict = analysis_result.get("is_suspicious", False)
            print(f"Deep analysis complete for {client_ip}. Verdict: {'SUSPICIOUS' if verdict else 'CLEAN'}")
            logger.info(f"Deep analysis complete for {client_ip}. Verdict: {'SUSPICIOUS' if verdict else 'CLEAN'}")
            transaction_data = {
                                    "ip": client_ip,
                                    "headers_present": results[client_ip]["traffic_indicators"].get("missing_headers") is False,
                                    "ttl_obfuscation": results[client_ip]["packet_indicators"].get("ttl_obfuscation", False),
                                    "legitimacy_score": score_save_bot(results[client_ip]),  
                                    "is_trustworthy": not bool(analysis_result["is_suspicious"])
                    }
            logger.info(f"Blockchain transaction ")
            result = blockchain.add_transaction(transaction_data)
            logger.info(f"Blockchain transaction submitted for {client_ip}: {result}")
            blockchain.usermine()
            return jsonify({
                "ip": client_ip,
                "user_agent": user_agent,
                "analysis": analysis_result,
                "is_suspicious": verdict
            }), 200
        else:
            return jsonify({
                "ip": client_ip,
                "error": "No analysis data found for IP."
            }), 404

    except Exception as e:
        logger.exception(f"Deep analysis failed for {client_ip}: {e}")
        return jsonify({"error": str(e)}), 500
    
@app.route('/protected')
# @pow_required
# @traffic_protected
def protected():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    logger.info(f"[BLOCKCHAIN] -> Access attempt from {client_ip}")

    result = blockchain.search_by_ip(client_ip)
    print(f"Blockchain search result for {client_ip}: {result}")
    if result["found"]:
        # Get last transaction recorded for this IP
        last_tx = result["results"][-1]["transaction"]

        if last_tx.get("is_trustworthy", False):
            logger.info(f"[BLOCKCHAIN] -> {client_ip} found as TRUSTED in blockchain. Access granted.")
            return f"Access granted: trusted IP {client_ip}"
        else:
            logger.warning(f"[BLOCKCHAIN] -> {client_ip} found as UNTRUSTWORTHY in blockchain. Access denied.")
            return f"Access denied: untrustworthy IP {client_ip}", 403
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

def cleanup_resources():
    """Clean up resources on shutdown"""
    executor.shutdown(wait=True)
    for timer in ip_batch_timers.values():
        if timer.is_alive():
            timer.cancel()
def start_cleanup_thread():
    """Start background cleanup thread"""
    def cleanup_worker():
        while True:
            try:
                cleanup_expired_challenges()
                time.sleep(60)  # Run every minute
            except Exception as e:
                logger.error(f"Cleanup thread error: {e}")
    
    cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
    cleanup_thread.start()
    logger.info("Started cleanup thread")
def cleanup_expired_challenges():
    """Remove expired challenges periodically"""
    current_time = int(time.time())
    expired_challenges = [
        challenge for challenge, data in challenge_store.items()
        if current_time > data['expires']
    ]
    
    for challenge in expired_challenges:
        del challenge_store[challenge]
    
    if expired_challenges:
        logger.info(f"Cleaned up {len(expired_challenges)} expired challenges")    
                
if __name__ == "__main__":
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24))
    schedule_extraction()
    start_cleanup_thread() 
    atexit.register(cleanup_resources)
    app.run(host="0.0.0.0", port=8081, debug=False)
    
    