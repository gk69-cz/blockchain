import json
import logging
import threading
import requests
from collections import defaultdict, deque

# Configure logging
log_file = 'traffic_analyzer.log'
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("traffic_analyzer")
logger.setLevel(logging.INFO)

# Constants and thresholds
ANALYSIS_WINDOW = 15  
HIGH_RPM_THRESHOLD = 90  
SYN_FLOOD_THRESHOLD = 20  
SUSPICIOUS_UA_PATTERNS = [
    r'^\s*$',  # Empty user agent
    r'(bot|crawl|spider)',  # Known bot patterns
    r'(nmap|nikto|gobuster|dirb)',  # Security tools
    r'(curl|wget|python-requests)',  # Scripting tools
]
TTL_SUSPICIOUS_VALUES = [
    0,     # Invalid
    1, 2, 3, 4, 5,     # Unusually low - could indicate crafted packets
    6, 7, 8, 9, 10,    # Below typical hop limits
    32, 36,            # Rare but occasionally used in obfuscated attacks
    100,               # Not typical for major OS defaults
    192, 200, 222,     # Often seen in spoofed packets
    255                # Possible router or forged header
]


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
    "last_requests": deque(maxlen=10),  
    "response_codes": defaultdict(int)  
})

# Thread safety
data_lock = threading.Lock()
with open('suspheader.json', 'r') as f:
    SUSPICIOUS_DATA = json.load(f)

SUSPICIOUS_USER_AGENTS = SUSPICIOUS_DATA["user_agents"]
SUSPICIOUS_HEADERS = SUSPICIOUS_DATA["headers"]

# Global stores
challenge_store = {}
dc_ranges = []

