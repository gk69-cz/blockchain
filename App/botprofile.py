# bot_profile.py
import json
import os
from uuid import uuid4
from collections import defaultdict, deque
import threading

# File to store bot profiles
BOT_PROFILES_FILE = "bot_profiles.json"
BOT_FILE = 'bot_profiles.json'
TO_BLOCK_FILE = 'to_block.json'
# Lock for thread-safe file operations
file_lock = threading.Lock()

def load_bot_profiles():
    if not os.path.exists(BOT_PROFILES_FILE):
        return {}
    try:
        with file_lock, open(BOT_PROFILES_FILE, 'r') as f:
            profiles = json.load(f)
            
            # Convert sets back from lists (JSON doesn't support sets)
            for ip, profile in profiles.items():
                if 'endpoints_accessed' in profile:
                    profile['endpoints_accessed'] = set(profile['endpoints_accessed'])
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
        
        # Update sets by merging
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
    
    print(f"Bot profile for {ip} {'created' if ip not in profiles else 'updated'}")
    return profiles[ip]

