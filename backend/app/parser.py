import re
import html
from urllib.parse import unquote
from datetime import datetime
from typing import Dict, Any, Optional, Tuple

# Normalize text for matching (URL-decode, HTML-decode, lowercase)
def normalize_for_matching(text: str) -> str:
    if not text:
        return ""
    # Double-unquoting handles double-encoded characters like %252e -> %2e -> .
    decoded = unquote(text)
    double_decoded = unquote(decoded)
    unescaped = html.unescape(double_decoded)
    return unescaped.lower()

# Parse datetime strings to standard datetime objects
def parse_nginx_time(time_str: str) -> Optional[datetime]:
    # Nginx format: 23/May/2025:14:33:01 +0000
    try:
        # Strip timezone offset for simplicity in parsing if needed, but let's parse offset
        # %d/%b/%Y:%H:%M:%S %z
        return datetime.strptime(time_str, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        try:
            # Fallback without timezone
            return datetime.strptime(time_str.split()[0], "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            return None

def parse_auth_time(time_str: str) -> Optional[datetime]:
    # Linux auth log format usually: May 23 14:33:01 or 2025-05-23T14:33:01+00:00
    # Let's try ISO format first, then standard syslog format
    try:
        return datetime.fromisoformat(time_str.replace("Z", "+00:00"))
    except ValueError:
        try:
            # Syslog format: May 23 14:33:01 (assumes current year)
            current_year = datetime.utcnow().year
            dt = datetime.strptime(f"{current_year} {time_str}", "%Y %b %d %H:%M:%S")
            return dt
        except ValueError:
            return None

# Regex patterns for Nginx
# Example: 203.0.113.42 - - [23/May/2025:14:33:01 +0000] "GET /api/users?id=1 HTTP/1.1" 400 512
NGINX_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+[^"]*"\s+(?P<status>\d+)\s+(?P<bytes>\d+)'
)

# Regex patterns for Linux Auth Logs
# Example: May 23 14:33:01 server sshd[12345]: Failed password for invalid user admin from 203.0.113.42 port 54321 ssh2
# Example: May 23 14:33:01 server sshd[12345]: Accepted password for root from 192.168.1.100 port 12345 ssh2
# Example: May 23 14:33:01 server sudo: pam_unix(sudo:auth): authentication failure; logname=uid=0 euid=0 ruser=yash rhost=
# Example: May 23 14:33:01 server su: pam_unix(su:auth): authentication failure; logname=uid=0 euid=0 ruser=yash rhost=
AUTH_FAILED_USER_IP = re.compile(r'failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+)')
AUTH_ACCEPTED_USER_IP = re.compile(r'accepted password for (?P<user>\S+) from (?P<ip>\S+)')
SUDO_FAILURE = re.compile(r'sudo:.*authentication failure')
SU_FAILURE = re.compile(r'su:.*failed su')
ROOT_AUTH_FAILURE = re.compile(r'authentication failure for root')

def parse_nginx_log(line: str) -> Optional[Dict[str, Any]]:
    match = NGINX_PATTERN.match(line)
    if not match:
        return None
    
    gd = match.groupdict()
    timestamp = parse_nginx_time(gd["time"])
    
    # Payload details
    payload = {
        "method": gd["method"],
        "path": gd["path"],
        "status": int(gd["status"]),
        "bytes": int(gd["bytes"]),
        "user_agent": None,
        "referrer": None
    }
    
    # Try parsing query parameters or body if present, but standard nginx matches request path
    return {
        "timestamp": timestamp,
        "source_ip": gd["ip"] if gd["ip"] != "-" else None,
        "destination_ip": None,
        "username": gd["user"] if gd["user"] != "-" else None,
        "action": f"HTTP_{gd['method']}_{gd['status']}",
        "payload": payload,
        "parser_confidence": 1.0
    }

def parse_auth_log(line: str) -> Optional[Dict[str, Any]]:
    # Extract timestamp from beginning (first 15 chars or up to hostname/service)
    # Common formats:
    # "May 23 14:33:01 server ..." (Syslog)
    # "2026-05-23T14:33:01.123456+00:00 server ..." (RFC 5424)
    # Let's search for timestamp pattern
    timestamp = None
    log_content = line
    
    # Try ISO timestamp match at start
    iso_match = re.match(r'^(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z))', line)
    if iso_match:
        timestamp = parse_auth_time(iso_match.group("time"))
        log_content = line[iso_match.end():].strip()
    else:
        # Try syslog style (e.g. "May 23 14:33:01")
        syslog_match = re.match(r'^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})', line)
        if syslog_match:
            timestamp = parse_auth_time(syslog_match.group("time"))
            log_content = line[syslog_match.end():].strip()
            
    # Remove hostname and process name if present
    # E.g. "myhost sshd[123]: Failed password..." -> "sshd[123]: Failed password..."
    # E.g. "sshd[123]: Failed password..." -> "Failed password..."
    log_content = re.sub(r'^[a-zA-Z0-9_\-\.]+\s+', '', log_content) # remove hostname
    log_content = re.sub(r'^[a-zA-Z0-9_\-\.]+\[\d+\]:\s*', '', log_content) # remove process[pid]:
    log_content = re.sub(r'^[a-zA-Z0-9_\-\.]+:\s*', '', log_content) # remove process:
    
    # Analyze event logic
    source_ip = None
    username = None
    action = "UNKNOWN"
    
    # Check failed ssh password
    m_fail = AUTH_FAILED_USER_IP.search(log_content.lower())
    m_accept = AUTH_ACCEPTED_USER_IP.search(log_content.lower())
    if m_fail:
        source_ip = m_fail.group("ip")
        username = m_fail.group("user")
        action = "LOGIN_FAILED"
    elif m_accept:
        source_ip = m_accept.group("ip")
        username = m_accept.group("user")
        action = "LOGIN_SUCCESS"
    elif SUDO_FAILURE.search(line.lower()) or SU_FAILURE.search(line.lower()) or ROOT_AUTH_FAILURE.search(line.lower()):
        action = "PRIV_ESC_FAILED"
        user_match = re.search(r'ruser=(?P<user>\S+)', line)
        if user_match:
            username = user_match.group("user")
        else:
            user_match_2 = re.search(r'for user (?P<user>\S+)', line)
            if user_match_2:
                username = user_match_2.group("user")
    elif "session opened for user root" in line.lower() or "sudo:.*pam_unix.*session opened" in line.lower():
        action = "PRIV_ESC_SUCCESS"
        username = "root"
        
    confidence = 1.0 if action != "UNKNOWN" else 0.5
    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": None,
        "username": username,
        "action": action,
        "payload": {"raw_message": log_content},
        "parser_confidence": confidence
    }

def parse_log_line(line: str, source_type: str) -> Dict[str, Any]:
    """
    Parses a single log line according to its source type.
    Falls back to a low-confidence generic event if parser fails.
    """
    event = None
    if source_type == "nginx":
        event = parse_nginx_log(line)
    elif source_type in ["auth", "syslog"]:
        event = parse_auth_log(line)
        
    if event:
        return event
        
    # Fallback for unrecognized formats or 'custom'
    return {
        "timestamp": datetime.utcnow(),
        "source_ip": None,
        "destination_ip": None,
        "username": None,
        "action": "RAW_LOG",
        "payload": {"raw": line},
        "parser_confidence": 0.0
    }
