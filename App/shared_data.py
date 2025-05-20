import json
import logging
import threading
from collections import defaultdict, deque

# Configure logging
log_file = 'traffic_analyzer.log'
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("traffic_analyzer")
logger.setLevel(logging.INFO)

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
with open('suspheader.json', 'r') as f:
    SUSPICIOUS_DATA = json.load(f)

SUSPICIOUS_USER_AGENTS = SUSPICIOUS_DATA["user_agents"]
SUSPICIOUS_HEADERS = SUSPICIOUS_DATA["headers"]

# Global stores
challenge_store = {}
dc_ranges = []