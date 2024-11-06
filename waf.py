# waf.py
import re
import time
from collections import defaultdict
from datetime import datetime

# Basic WAF rules
sql_injection_patterns = [
    r"(?i)\b(SELECT|UNION|INSERT|DELETE|UPDATE|DROP|ALTER|FROM|WHERE)\b",
    r"(--|\bOR\b|\bAND\b)[\s\']+\d=\d",  # SQL injection with conditional expressions
]
xss_patterns = [
    r"<script.*?>.*?</script>",  # script tags
    r"on\w*=['\"]?javascript:",  # event handlers with JavaScript
]
path_traversal_patterns = [
    r"\.\./",  # parent directory traversal
    r"/etc/passwd",  # attempting to access sensitive files
]

BLACKLISTED_IPS = {"192.168.1.100", "203.0.113.45"}
WHITELISTED_IPS = {"127.0.0.1"}

def is_ip_blacklisted(ip):
    return ip in BLACKLISTED_IPS

def is_ip_whitelisted(ip):
    return ip in WHITELISTED_IPS


# Define rate limiting parameters
RATE_LIMIT = 5  # Max requests per IP
TIME_WINDOW = 60  # Time window in seconds
ip_request_times = defaultdict(list)  # Dictionary to track requests by IP
MAX_REQUEST_LENGTH = 500  # Example threshold for request size

def log_attack(ip, attack_type, data, user_agent):
    with open("waf_log.txt", "a") as log_file:
        timestamp = datetime.now().isoformat()
        log_file.write(
            f"Time: {timestamp} | IP: {ip} | Attack: {attack_type} | "
            f"User-Agent: {user_agent} | Data: {data}\n"
        )
    print(f"Blocked {attack_type} from {ip} with User-Agent: {user_agent}")

def is_anomalous_request(data):
    # Check if the request length exceeds the defined maximum
    if len(data) > MAX_REQUEST_LENGTH:
        return "Anomalous request length"
    # Future expansion: Add checks for unusual characters or patterns
    return None

def is_malicious_request(data):
    # Check for SQL injection
    for pattern in sql_injection_patterns:
        if re.search(pattern, data):
            return "SQL Injection"
    # Check for XSS
    for pattern in xss_patterns:
        if re.search(pattern, data):
            return "XSS"
    # Check for Path Traversal
    for pattern in path_traversal_patterns:
        if re.search(pattern, data):
            return "Path Traversal"
    return None

def log_attack(ip, attack_type, data):
    with open("waf_log.txt", "a") as log_file:
        log_file.write(f"IP: {ip} | Attack: {attack_type} | Data: {data}\n")
    print(f"Blocked {attack_type} from {ip}: {data}")

def is_rate_limited(ip):
    # Get current time
    current_time = time.time()
    # Filter out requests older than TIME_WINDOW
    ip_request_times[ip] = [
        timestamp for timestamp in ip_request_times[ip] if current_time - timestamp < TIME_WINDOW
    ]
    # Check if the IP exceeds the rate limit
    if len(ip_request_times[ip]) >= RATE_LIMIT:
        return True
    # Otherwise, log the current request time
    ip_request_times[ip].append(current_time)
    return False
