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
    r'^\s*$', 
    r'(bot|crawl|spider)', 
    r'(nmap|nikto|gobuster|dirb)', 
    r'(curl|wget)', 
    # r'(curl|wget|python-requests)',  
]
TTL_SUSPICIOUS_VALUES = [
    0,     
    1, 2, 3, 4, 5,     
    6, 7, 8, 9, 10,    
    32, 36,            
    100,              
    192, 200, 222,     
    255                
]

SUSPICIOUS_USER_AGENTS = [
    "sqlmap",           # SQL injection testing tool
    "nmap",             # Network mapping tool
    "nikto",            # Web vulnerability scanner
    "curl",             # Command line HTTP client
    "libwww-perl",      # Perl HTTP library
    "httrack",          # Website copier
    "wget",             # File downloader
    "masscan",          # Port scanner
    "zmeu",             # Vulnerability scanner
    "acunetix",         # Web vulnerability scanner
    "netsparker",       # Web application security scanner
    "java",             # Generic Java HTTP client
    "winhttp",          # Windows HTTP API
    "axios",            # JavaScript HTTP client
    "go-http-client",   # Go HTTP client
    "okhttp",           # Android/Java HTTP client
    "ApacheBench",
    "WindowsPowerShell",# Apache HTTP server benchmarking tool
    ""                  # Empty user agent
]

# Suspicious Headers (consolidated from suspheader.json)
# Sources:
# - RFC 7239: https://tools.ietf.org/html/rfc7239
# - Common proxy headers: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
# - Security analysis: https://www.acunetix.com/blog/articles/http-security-headers/
SUSPICIOUS_HEADERS = [
    "X-Forwarded-For",      # Proxy/load balancer header
    "X-Real-IP",            # Real client IP header
    "X-Originating-IP",     # Original client IP header
    "X-Requested-With",     # AJAX request identifier
    "Referer",              # Referring page URL
    "User-Agent",           # Client application identifier
    "Accept-Language",      # Client language preferences
    "Authorization",        # Authentication credentials
    "Cookie"                # Session/state information
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

# Global stores
challenge_store = {}
dc_ranges = []