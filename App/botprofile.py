# bot_profile.py
from uuid import uuid4
import random
from collections import defaultdict, deque

def generate_bot_profile(ip, data):
    meta = data[ip]["metadata"]
    packet = data[ip].get("packet_indicators", {})
    traffic = data[ip].get("traffic_indicators", {})

    bot_profile = defaultdict(lambda: {
        "ip":ip,
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
        "is_residential": data[ip].get("is_residential", None),
        "ttl_values": set(meta.get("ttl_values", [])),
        "ttl_obfuscation": packet.get("ttl_obfuscation", False),
        "last_requests": deque(maxlen=10),  
        "response_codes": defaultdict(int, meta.get("response_codes", {}))
    })
    print(bot_profile)
    return bot_profile[ip]

