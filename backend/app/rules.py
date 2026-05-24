import re
from datetime import datetime, timedelta
from collections import defaultdict
from typing import List, Dict, Any, Tuple, Optional
from app.parser import normalize_for_matching
from app.database import db

# Pattern Rule definitions
RULE_METADATA = {
    "LOG4SHELL": {
        "severity": "CRITICAL",
        "score": 99,
        "confidence": 0.99,
        "patterns": [
            re.compile(r'\$\{jndi:', re.IGNORECASE),
            re.compile(r'\$\{.*?j.*?n.*?d.*?i.*?:', re.IGNORECASE),
            re.compile(r'%24%7bjndi', re.IGNORECASE),
        ],
        "match_on_normalized": True
    },
    "SSRF": {
        "severity": "CRITICAL",
        "score": 95,
        "confidence": 0.98,
        "patterns": [
            re.compile(r'169\.254\.169\.254'),
            re.compile(r'metadata\.google\.internal'),
            re.compile(r'metadata\.azure\.internal'),
            re.compile(r'(?:^|[^.\d])127\.0\.0\.1'),
            re.compile(r'(?:^|[/=@])localhost(?:[:/]|$)', re.IGNORECASE),
            re.compile(r'(?<![.\d])0\.0\.0\.0'),
            re.compile(r'\[::1\]'),
            re.compile(r'0x7f[0-9a-f]{6}', re.IGNORECASE),
            re.compile(r'0177\.0\.'),
        ],
        "match_on_normalized": True
    },
    "CMD_INJECTION": {
        "severity": "HIGH",
        "score": 82,
        "confidence": 0.87,
        "patterns": [
            re.compile(r'[|;&`]\s*(?:ls|id|whoami|cat|wget|curl|chmod|bash|sh|python|perl|nc|ncat)\b', re.IGNORECASE),
            re.compile(r'\$\((?:id|whoami|ls|cat|wget|curl)\)'),
            re.compile(r'`(?:id|whoami|ls|cat)`'),
            re.compile(r'/(?:bin|usr/bin)/(?:bash|sh|python|perl|nc)\b'),
            re.compile(r'(?:c99|r57|webshell|shell\.php|cmd\.php)', re.IGNORECASE),
        ],
        "match_on_normalized": True
    },
    "PRIV_ESC": {
        "severity": "CRITICAL",
        "score": 90,
        "confidence": 0.95,
        "patterns": [
            re.compile(r'sudo:.*authentication failure'),
            re.compile(r'su:.*failed su'),
            re.compile(r'authentication failure for root')
        ],
        # Auth log patterns are specific, match on raw
        "match_on_normalized": False 
    },
    "SQLI": {
        "severity": "HIGH",
        "score": 80,
        "confidence": 0.90,
        "patterns": [
            re.compile(r'\bunion\s+select\b'),
            re.compile(r'\bor\s+1\s*=\s*1\b'),
            re.compile(r"'\s+or\s+'1'\s*=\s*'1"),
            re.compile(r'\bsleep\s*\('),
            re.compile(r'\bbenchmark\s*\('),
            re.compile(r'\binformation_schema\b'),
            re.compile(r'\bdrop\s+table\b')
        ],
        "match_on_normalized": True
    },
    "XSS": {
        "severity": "MEDIUM",
        "score": 65,
        "confidence": 0.85,
        "patterns": [
            re.compile(r'<script[\s>]'),
            re.compile(r'javascript:'),
            re.compile(r'onerror\s*='),
            re.compile(r'onload\s*='),
            re.compile(r'<iframe[\s>]')
        ],
        "match_on_normalized": True
    },
    "PATH_TRAVERSAL": {
        "severity": "MEDIUM",
        "score": 60,
        "confidence": 0.88,
        "patterns": [
            re.compile(r'\.\./|\.\.\\'),
            re.compile(r'%252e%252e'),
            re.compile(r'\.\.%2f'),
            re.compile(r'etc/passwd'),
            re.compile(r'proc/self/environ'),
            re.compile(r'win\.ini'),
            re.compile(r'boot\.ini')
        ],
        "match_on_normalized": True
    }
}

# Run Pattern Rules against a single parsed event
def check_pattern_rules(raw_content: str) -> Optional[Tuple[str, Dict[str, Any], str]]:
    """
    Checks raw_content against pattern rules.
    Returns (threat_type, rule_metadata, matched_pattern_text) or None.
    """
    normalized_content = normalize_for_matching(raw_content)
    
    for threat_type, meta in RULE_METADATA.items():
        content_to_check = normalized_content if meta["match_on_normalized"] else raw_content
        for pattern in meta["patterns"]:
            match = pattern.search(content_to_check)
            if match:
                return threat_type, meta, match.group(0)
                
    return None

# Correlation rule: Brute force detection
def check_brute_force_correlation(session_id: str, current_events: List[Dict[str, Any]], window_minutes: int = 5, threshold: int = 10) -> List[Dict[str, Any]]:
    """
    Queries the database for LOGIN_FAILED and PRIV_ESC_FAILED actions in the last 5 minutes.
    Groups them by IP, and raises BRUTE_FORCE threats if above threshold.
    """
    # 1. Gather all LOGIN_FAILED and PRIV_ESC_FAILED events in session from last 5 minutes
    cutoff_time = datetime.utcnow() - timedelta(minutes=window_minutes)
    
    # Query database
    try:
        db_events = db.get_recent_failed_events(session_id, cutoff_time)
    except Exception as e:
        print(f"Error querying database for recent failed events: {e}")
        db_events = []
        
    # Fallback/merge with current_events to be completely safe
    # This ensures that even if DB operations are async/lagged, we don't miss current batch events
    event_map = {e["id"]: e for e in db_events}
    for event in current_events:
        if event.get("action") in ["LOGIN_FAILED", "PRIV_ESC_FAILED"] and event.get("source_ip"):
            if event["id"] not in event_map:
                # Check timestamp
                ts = event.get("timestamp")
                if isinstance(ts, str):
                    try:
                        ts_dt = datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
                    except ValueError:
                        ts_dt = datetime.utcnow()
                elif isinstance(ts, datetime):
                    ts_dt = ts
                else:
                    ts_dt = datetime.utcnow()
                
                if ts_dt >= cutoff_time:
                    # Convert event to dict with string timestamp for uniform processing
                    event_copy = dict(event)
                    event_copy["timestamp"] = ts_dt.isoformat()
                    event_map[event["id"]] = event_copy
                    
    # Group by IP
    by_ip = defaultdict(list)
    for event in event_map.values():
        ip = event.get("source_ip")
        if ip:
            ts = event.get("timestamp")
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
                except ValueError:
                    ts = datetime.utcnow()
            elif not ts:
                ts = datetime.utcnow()
            by_ip[ip].append((ts, event["id"]))
            
    detected_brute_forces = []
    
    # 2. Apply window threshold check for each IP
    for ip, events_info in by_ip.items():
        events_info.sort(key=lambda x: x[0])
        for i, (ts, event_id) in enumerate(events_info):
            window_end = ts + timedelta(minutes=window_minutes)
            matching_events = [e for e in events_info[i:] if e[0] <= window_end]
            
            if len(matching_events) >= threshold:
                # Found brute force!
                event_ids = [e[1] for e in matching_events]
                detected_brute_forces.append({
                    "source_ip": ip,
                    "event_ids": event_ids,
                    "count": len(matching_events)
                })
                break # One threat per IP per run
                
    return detected_brute_forces

def process_rules(session_id: str, parsed_events_with_logs: List[Tuple[Dict[str, Any], Dict[str, Any]]]) -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """
    Takes parsed events and their raw logs.
    Runs patterns and correlations.
    Inserts matched threats and links event relations.
    Returns list of (parsed_event, raw_log) that did NOT match any rules (for LLM routing).
    """
    unmatched_events = []
    matched_event_ids = set()
    
    # 1. Run pattern rules first
    for event, raw_log in parsed_events_with_logs:
        raw_content = raw_log["raw_content"]
        match_result = check_pattern_rules(raw_content)
        
        if match_result:
            threat_type, meta, pattern_text = match_result
            source_ip = event.get("source_ip")
            
            # Check duplicate suppression
            if not db.is_duplicate_threat(session_id, threat_type, source_ip):
                summary = f"Deterministic rule matched {threat_type} pattern in log entry."
                # Create threat
                threat = db.create_threat(
                    session_id=session_id,
                    threat_type=threat_type,
                    severity=meta["severity"],
                    severity_score=meta["score"],
                    confidence=meta["confidence"],
                    source_ip=source_ip,
                    summary=summary,
                    classification_source="rule",
                    attack_pattern=pattern_text
                )
                # Link threat to event
                db.create_threat_event(threat["id"], event["id"])
                
            matched_event_ids.add(event["id"])
            # Update raw log status to processed
            db.update_raw_log(raw_log["id"], raw_log["redacted_content"], raw_log["redaction_applied"], "processed")
        else:
            unmatched_events.append((event, raw_log))
            
    # 2. Run brute force correlation rules
    all_events_in_batch = [e for e, _ in parsed_events_with_logs]
    brute_forces = check_brute_force_correlation(session_id, all_events_in_batch)
    
    for bf in brute_forces:
        ip = bf["source_ip"]
        event_ids = bf["event_ids"]
        
        # Suppress duplicate brute force threats
        if not db.is_duplicate_threat(session_id, "BRUTE_FORCE", ip):
            summary = f"Detected {bf['count']} authentication failures from IP {ip} in under 5 minutes."
            threat = db.create_threat(
                session_id=session_id,
                threat_type="BRUTE_FORCE",
                severity="HIGH",
                severity_score=75,
                confidence=0.92,
                source_ip=ip,
                summary=summary,
                classification_source="rule",
                attack_pattern="SSH_BRUTE_FORCE"
            )
            # Link all matching events
            for ev_id in event_ids:
                db.create_threat_event(threat["id"], ev_id)
                matched_event_ids.add(ev_id)
                
            # Update all raw logs associated with these events to processed
            for event, raw_log in parsed_events_with_logs:
                if event["id"] in event_ids:
                    db.update_raw_log(raw_log["id"], raw_log["redacted_content"], raw_log["redaction_applied"], "processed")
                    
    # Filter the unmatched events list: remove events that were matched by brute force correlation
    final_unmatched = []
    for event, raw_log in unmatched_events:
        if event["id"] not in matched_event_ids:
            final_unmatched.append((event, raw_log))
            
    return final_unmatched
