# bot_profile.py
import json
import os
from uuid import uuid4
from collections import defaultdict, deque
import threading

BOT_PROFILES_FILE = "bot_profiles.json"
BLOCK_PROFILES_FILE = 'blockchain.json'
BOT_FILE = 'bot_profiles.json'
TO_BLOCK_FILE = 'to_block.json'

file_lock = threading.Lock()
number = 1
def load_bot_profiles():
    if not os.path.exists(BOT_PROFILES_FILE):
        return {}
    try:
        with file_lock, open(BOT_PROFILES_FILE, 'r') as f:
            profiles = json.load(f)
            print(profiles)
            # Convert sets back from lists (JSON doesn't support sets)
            for ip, profile in profiles.items():
                if 'user_agents' in profile:
                    profile['user_agents'] = set(profile['user_agents'])
                if 'referrers' in profile:
                    profile['referrers'] = set(profile['referrers'])
                if 'ttl_values' in profile:
                    profile['ttl_values'] = set(profile['ttl_values'])
                if 'last_requests' in profile:
                    profile['last_requests'] = deque(profile['last_requests'], maxlen=10)
            
            return profiles
    except (json.JSONDecodeError, IOError) as e:
        print(f"Error loading bot profiles: {e}")
        return {}

def save_bot_profiles(profiles):
    
    try:
        # Convert sets to lists for JSON serialization
        serializable_profiles = {}
        for ip, profile in profiles.items():
            serializable_profile = profile.copy()
            if 'endpoints_accessed' in profile:
                serializable_profile['endpoints_accessed'] = list(profile['endpoints_accessed'])
            if 'user_agents' in profile:
                serializable_profile['user_agents'] = list(profile['user_agents'])
            if 'referrers' in profile:
                serializable_profile['referrers'] = list(profile['referrers'])
            if 'ttl_values' in profile:
                serializable_profile['ttl_values'] = list(profile['ttl_values'])
            if 'last_requests' in profile:
                serializable_profile['last_requests'] = list(profile['last_requests'])
            
            serializable_profiles[ip] = serializable_profile
            
        with file_lock, open(BOT_PROFILES_FILE, 'w') as f:
            json.dump(serializable_profiles, f, indent=2)
    except IOError as e:
        print(f"Error saving bot profiles: {e}")

def generate_bot_profile(ip, data):
    
    print(f"Generating bot profile for IP: {ip}")
    # Load existing profiles
    profiles = load_bot_profiles()
    
    # Extract data for this IP
    ip_data = data[ip]
    meta = ip_data["metadata"]
    packet = ip_data.get("packet_indicators", {})
    traffic = ip_data.get("traffic_indicators", {})
    
    # Create a new profile if IP doesn't exist in our records
    if ip not in profiles:
        profiles[ip] = {
            "ip": ip,
            "id": f"bot-{uuid4().hex[:8]}",
            "first_seen": meta.get("first_seen", 0),
            "last_seen": meta.get("last_seen", 0),
            "request_count": meta.get("request_count", 0),
            "rpm": meta.get("rpm", 0),
            "rps": meta.get("rps", 0),
            "endpoints_accessed": set(meta.get("endpoints_accessed", [])),
            "user_agents": set(meta.get("user_agents", [])),
            "referrers": set(meta.get("referrers", [])),
            "headers_present": not traffic.get("missing_headers", False),
            "is_residential": ip_data.get("is_residential", None),
            "ttl_values": set(meta.get("ttl_values", [])),
            "ttl_obfuscation": packet.get("ttl_obfuscation", False),
            "last_requests": deque(maxlen=10),
            "response_codes": defaultdict(int, meta.get("response_codes", {})),
            "is_suspicious": ip_data.get("is_suspicious", False)  # Add the is_suspicious flag
        }
    else:
        # Update existing profile with new data
        profile = profiles[ip]
        profile["last_seen"] = meta.get("last_seen", profile["last_seen"])
        profile["request_count"] = meta.get("request_count", profile["request_count"])
        profile["rpm"] = meta.get("rpm", profile["rpm"])
        profile["rps"] = meta.get("rps", profile["rps"])
        
       # Make sure all relevant fields are sets
        profile["endpoints_accessed"] = set(profile.get("endpoints_accessed", []))
        profile["user_agents"] = set(profile.get("user_agents", []))
        profile["referrers"] = set(profile.get("referrers", []))
        profile["ttl_values"] = set(profile.get("ttl_values", []))

        # Now safely update
        if "endpoints_accessed" in meta:
            profile["endpoints_accessed"].update(meta["endpoints_accessed"])
        if "user_agents" in meta:
            profile["user_agents"].update(meta["user_agents"])
        if "referrers" in meta:
            profile["referrers"].update(meta["referrers"])
        if "ttl_values" in meta:
            profile["ttl_values"].update(meta["ttl_values"])
            
        # Update other fields
        profile["headers_present"] = not traffic.get("missing_headers", profile["headers_present"])
        profile["ttl_obfuscation"] = packet.get("ttl_obfuscation", profile["ttl_obfuscation"])
        
        # Update response codes by adding new counts
        for code, count in meta.get("response_codes", {}).items():
            if code not in profile["response_codes"]:
                profile["response_codes"][code] = 0
                profile["response_codes"][code] += count
            
        # Update suspicious flag - if it's ever been suspicious, keep it marked
        if ip_data.get("is_suspicious", False):
            profile["is_suspicious"] = True
    
    # Save updated profiles
    save_bot_profiles(profiles)
    score_save_bot(profiles)
    return profiles[ip]

def score_save_bot(bot):
    print("Scoring bot profile...")
    print(bot)
    score = 0

    metadata = bot.get("metadata", {})
    packet_indicators = bot.get("packet_indicators", {})
    traffic_indicators = bot.get("traffic_indicators", {})

    # 1. RPM
    rpm = metadata.get("rpm", 0)
    if rpm <= 2:
        score += 1
    elif rpm > 5:
        score -= 1

    # 2. User-Agent
    user_agents = metadata.get("user_agents", [])
    if any("Mozilla" in ua or "Chrome" in ua or "Safari" in ua for ua in user_agents):
        score += 1
    if all("curl" in ua.lower() for ua in user_agents):
        score -= 1
    if any(ua.lower() in ["nmap", "nikto", "gobuster", "dirb"] for ua in user_agents):
        score -= 2
    # if any(ua.lower() in ["python-requests", "python", "requests"] for ua in user_agents):
    #     score -= 1
    if any(ua.lower() in ["bot", "crawl", "spider"] for ua in user_agents):
        score -= 1
    if len(user_agents) == 0:
        score -= 1

    # 3. Headers
    headers_present = not traffic_indicators.get("missing_headers", False)
    if headers_present:
        score += 1
    else:
        score -= 1

    # 4. TTL Obfuscation
    ttl_obfuscation = packet_indicators.get("ttl_obfuscation", None)
    if ttl_obfuscation is False:
        score += 1
    else:
        score -= 1

    # 5. Response Codes
    codes = metadata.get("response_codes", {})
    if sum(codes.get(200, 0) for _ in [200]) >= 1:
        score += 1
    if sum(codes.get(code, 0) for code in [403, 404, 500]) >= 2:
        score -= 1

    # 6. Is Residential
    if bot.get("is_residential", False):
        score += 1
    else:
        score -= 1

    # 7. Is Suspicious
    if bot.get("is_suspicious", False):
        score -= 2
    else:
        score += 2

    # 8. Referrer Check
    referrers = metadata.get("referrers", [])
    ip = bot.get("ip", "unknown_ip")
    if all(ip in ref for ref in referrers):
        score += 1
    else:
        score -= 1

    # 9. TTL Values Consistency
    ttl_values = metadata.get("ttl_values", [])
    if len(set(ttl_values)) == 1 and ttl_values:
        score += 1
    else:
        score -= 1

    # Clamp score between 0 and 10
    final_score = max(0, min(10, score))

    # Prepare result
    result = {
        "ip": ip,
        "headers_present": headers_present,
        "ttl_obfuscation": ttl_obfuscation,
        "legitimacy_score": final_score,
        "is_trustworthy": final_score >= 5
    }

    print("Transaction result:", result)

    # Save result
    with file_lock, open(BLOCK_PROFILES_FILE, 'w') as f:
        json.dump(result, f, indent=2)

    print(f"Bot profile for {ip} scored: {final_score} and saved.")
    return final_score

