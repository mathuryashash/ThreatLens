import os
import uuid
import ipaddress
import threading
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from app.config import settings

def clean_ip(ip: Optional[str]) -> Optional[str]:
    if not ip:
        return None
    ip = ip.strip()
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        return None

# In-memory Mock Database for Offline fallback
class MockDatabase:
    def __init__(self):
        self.lock = threading.Lock()
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.raw_logs: Dict[str, Dict[str, Any]] = {}
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self.parsed_events: Dict[str, Dict[str, Any]] = {}
        self.threats: Dict[str, Dict[str, Any]] = {}
        self.threat_events: List[Dict[str, str]] = []  # List of dicts with threat_id and event_id

    def create_session(self) -> Dict[str, Any]:
        with self.lock:
            session_id = str(uuid.uuid4())
            created_at = datetime.utcnow()
            expires_at = created_at + timedelta(hours=24)
            session = {
                "id": session_id,
                "created_at": created_at.isoformat(),
                "expires_at": expires_at.isoformat(),
                "max_logs": 500,
                "used_logs": 0,
                "max_explain_calls": 10,
                "used_explain_calls": 0,
                "last_seen_at": created_at.isoformat()
            }
            self.sessions[session_id] = session
            return session

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            return self.sessions.get(session_id)

    def increment_session_logs(self, session_id: str, count: int) -> int:
        with self.lock:
            if session_id in self.sessions:
                self.sessions[session_id]["used_logs"] = max(0, self.sessions[session_id]["used_logs"] + count)
                return self.sessions[session_id]["used_logs"]
            return 0

    def increment_session_explain(self, session_id: str) -> int:
        with self.lock:
            if session_id in self.sessions:
                session = self.sessions[session_id]
                current = session.get("used_explain_calls") or 0
                max_explain = session.get("max_explain_calls") or 10
                if current >= max_explain:
                    return -1
                session["used_explain_calls"] += 1
                return session["used_explain_calls"]
            return 0

    def create_raw_log(self, session_id: str, source_type: str, raw_content: str) -> Dict[str, Any]:
        log_id = str(uuid.uuid4())
        log = {
            "id": log_id,
            "session_id": session_id,
            "source_type": source_type,
            "raw_content": raw_content,
            "redacted_content": None,
            "redaction_applied": False,
            "processing_status": "queued",
            "processing_error": None,
            "ingested_at": datetime.utcnow().isoformat(),
            "processed_at": None
        }
        self.raw_logs[log_id] = log
        return log

    def update_raw_log(self, log_id: str, redacted_content: str, redaction_applied: bool, processing_status: str, processing_error: str = None) -> None:
        if log_id in self.raw_logs:
            self.raw_logs[log_id].update({
                "redacted_content": redacted_content,
                "redaction_applied": redaction_applied,
                "processing_status": processing_status,
                "processing_error": processing_error,
                "processed_at": datetime.utcnow().isoformat() if processing_status == "processed" else None
            })

    def create_job(self, session_id: str, total_logs: int) -> Dict[str, Any]:
        job_id = str(uuid.uuid4())
        job = {
            "id": job_id,
            "session_id": session_id,
            "total_logs": total_logs,
            "processed_logs": 0,
            "failed_logs": 0,
            "status": "queued",
            "error": None,
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "completed_at": None
        }
        self.jobs[job_id] = job
        return job

    def update_job(self, job_id: str, processed_logs: int, failed_logs: int, status: str, error: str = None) -> None:
        if job_id in self.jobs:
            now = datetime.utcnow().isoformat()
            self.jobs[job_id].update({
                "processed_logs": processed_logs,
                "failed_logs": failed_logs,
                "status": status,
                "error": error,
                "updated_at": now,
                "completed_at": now if status in ["completed", "failed"] else None
            })

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        return self.jobs.get(job_id)

    def create_parsed_event(self, raw_log_id: str, session_id: str, timestamp: Optional[datetime], source_ip: Optional[str], destination_ip: Optional[str], username: Optional[str], action: Optional[str], payload: Dict[str, Any], parser_confidence: float) -> Dict[str, Any]:
        event_id = str(uuid.uuid4())
        event = {
            "id": event_id,
            "raw_log_id": raw_log_id,
            "session_id": session_id,
            "timestamp": timestamp.isoformat() if timestamp else None,
            "source_ip": clean_ip(source_ip),
            "destination_ip": clean_ip(destination_ip),
            "username": username,
            "action": action,
            "payload": payload,
            "parser_confidence": parser_confidence,
            "created_at": datetime.utcnow().isoformat()
        }
        self.parsed_events[event_id] = event
        return event

    def is_duplicate_threat(self, session_id: str, threat_type: str, source_ip: Optional[str], window_minutes: int = 5) -> bool:
        cutoff = datetime.utcnow() - timedelta(minutes=window_minutes)
        cleaned_source_ip = clean_ip(source_ip)
        for threat in self.threats.values():
            if (threat["session_id"] == session_id and 
                threat["threat_type"] == threat_type and 
                threat["source_ip"] == cleaned_source_ip):
                detected_at = datetime.fromisoformat(threat["detected_at"].replace("Z", "+00:00"))
                # Make naive for comparison
                detected_at_naive = detected_at.replace(tzinfo=None)
                if detected_at_naive >= cutoff:
                    return True
        return False

    def get_recent_failed_events(self, session_id: str, since: datetime) -> List[Dict[str, Any]]:
        results = []
        for event in self.parsed_events.values():
            if event["session_id"] == session_id and event["action"] in ["LOGIN_FAILED", "PRIV_ESC_FAILED"]:
                ts_str = event.get("timestamp")
                if ts_str:
                    try:
                        event_dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).replace(tzinfo=None)
                        if event_dt >= since:
                            results.append(event)
                    except ValueError:
                        pass
        return results

    def create_threat(self, session_id: str, threat_type: str, severity: str, severity_score: int, confidence: float, source_ip: Optional[str], summary: str, classification_source: str, attack_pattern: Optional[str] = None, model_name: Optional[str] = None, raw_ai_response: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        threat_id = str(uuid.uuid4())
        threat = {
            "id": threat_id,
            "session_id": session_id,
            "threat_type": threat_type,
            "severity": severity,
            "severity_score": severity_score,
            "confidence": confidence,
            "source_ip": source_ip,
            "geo_country": None,
            "geo_city": None,
            "is_private_ip": self._is_private_ip_helper(source_ip),
            "summary": summary,
            "explanation": None,
            "classification_source": classification_source,
            "attack_pattern": attack_pattern,
            "model_name": model_name,
            "prompt_version": settings.LLM_PROMPT_VERSION,
            "false_positive": False,
            "raw_ai_response": raw_ai_response,
            "detected_at": datetime.utcnow().isoformat()
        }
        self.threats[threat_id] = threat
        return threat

    def create_threat_event(self, threat_id: str, event_id: str) -> None:
        self.threat_events.append({"threat_id": threat_id, "event_id": event_id})

    def get_threats(self, session_id: str, severity: Optional[str] = None, limit: int = 50, since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        results = []
        for threat in self.threats.values():
            if threat["session_id"] != session_id:
                continue
            if severity and threat["severity"] != severity:
                continue
            if since:
                detected_at = datetime.fromisoformat(threat["detected_at"].replace("Z", "+00:00")).replace(tzinfo=None)
                if detected_at <= since:
                    continue
            results.append(threat)
        
        # Order by detected_at DESC
        results.sort(key=lambda x: x["detected_at"], reverse=True)
        return results[:limit]

    def get_threat(self, threat_id: str) -> Optional[Dict[str, Any]]:
        return self.threats.get(threat_id)

    def get_threat_logs(self, threat_id: str) -> List[str]:
        event_ids = [row["event_id"] for row in self.threat_events if row["threat_id"] == threat_id]
        raw_log_ids = [self.parsed_events[ev_id]["raw_log_id"] for ev_id in event_ids if ev_id in self.parsed_events]
        return [
            self.raw_logs[log_id]["redacted_content"]
            for log_id in raw_log_ids
            if log_id in self.raw_logs and self.raw_logs[log_id].get("redacted_content")
        ]


    def update_threat_explanation(self, threat_id: str, explanation: str, mitre_tactic: str, recommended_actions: List[str]) -> None:
        if threat_id in self.threats:
            # We store recommended actions as string or list, wait, let's keep it structured.
            # In Supabase explanation column is TEXT, but we can store explanation text and mitre_tactic in details,
            # or extend the schema fields. In DATABASE_SCHEMA.md:
            # threats.explanation is TEXT. Let's save a structured JSON or raw text.
            # Wait! In Supabase we have threats.explanation as TEXT.
            # To store explanation, mitre_tactic, recommended_actions, we can either store explanation as a string,
            # or store explanation + mitre_tactic + recommended_actions in explanation column serialized,
            # or add a payload field, or just save the explanation text.
            # Let's check API_SPEC.md:
            # GET /api/threats returns threat object with "explanation": null.
            # POST /api/explain returns {"explanation": "...", "mitre_tactic": "...", "recommended_actions": [...]}
            # To cache it in the threats table, let's check:
            # "explanation is cached — written once on first /api/explain call"
            # Let's save a serialized JSON string in the explanation column, e.g.:
            # {"explanation": "...", "mitre_tactic": "...", "recommended_actions": [...]}
            # This is brilliant, as it allows us to store the entire cached explain response in the single "explanation" TEXT field!
            import json
            serialized = json.dumps({
                "explanation": explanation,
                "mitre_tactic": mitre_tactic,
                "recommended_actions": recommended_actions
            })
            self.threats[threat_id]["explanation"] = serialized

    def _is_private_ip_helper(self, ip: Optional[str]) -> bool:
        if not ip:
            return False
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False


mock_db = MockDatabase()

# Real Supabase DB client class (only imported/initialized if configured)
class SupabaseDatabase:
    def __init__(self):
        from supabase import create_client, Client
        self.client: Client = create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_ROLE_KEY)

    def create_session(self) -> Dict[str, Any]:
        # INSERT INTO sessions DEFAULT VALUES RETURNING *
        res = self.client.table("sessions").insert({}).execute()
        return res.data[0]

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        res = self.client.table("sessions").select("*").eq("id", session_id).execute()
        return res.data[0] if res.data else None

    def increment_session_logs(self, session_id: str, count: int) -> int:
        for _ in range(3):
            session = self.get_session(session_id)
            if not session:
                return 0
            current = session.get("used_logs") or 0
            new_used = max(0, current + count)
            res = self.client.table("sessions").update({"used_logs": new_used}).eq("id", session_id).eq("used_logs", current).execute()
            if res.data:
                return res.data[0].get("used_logs", new_used)
        session = self.get_session(session_id)
        return (session.get("used_logs") or 0) if session else 0

    def increment_session_explain(self, session_id: str) -> int:
        for _ in range(3):
            session = self.get_session(session_id)
            if not session:
                return 0
            current = session.get("used_explain_calls") or 0
            new_used = current + 1
            res = self.client.table("sessions").update({"used_explain_calls": new_used}).eq("id", session_id).eq("used_explain_calls", current).execute()
            if res.data:
                return res.data[0].get("used_explain_calls", new_used)
        session = self.get_session(session_id)
        return (session.get("used_explain_calls") or 0) if session else 0

    def create_raw_log(self, session_id: str, source_type: str, raw_content: str) -> Dict[str, Any]:
        res = self.client.table("raw_logs").insert({
            "session_id": session_id,
            "source_type": source_type,
            "raw_content": raw_content,
            "processing_status": "queued"
        }).execute()
        return res.data[0]

    def update_raw_log(self, log_id: str, redacted_content: str, redaction_applied: bool, processing_status: str, processing_error: str = None) -> None:
        update_data = {
            "redacted_content": redacted_content,
            "redaction_applied": redaction_applied,
            "processing_status": processing_status,
            "processing_error": processing_error
        }
        if processing_status == "processed":
            update_data["processed_at"] = datetime.utcnow().isoformat()
        self.client.table("raw_logs").update(update_data).eq("id", log_id).execute()

    def create_job(self, session_id: str, total_logs: int) -> Dict[str, Any]:
        res = self.client.table("ingestion_jobs").insert({
            "session_id": session_id,
            "total_logs": total_logs,
            "processed_logs": 0,
            "failed_logs": 0,
            "status": "queued"
        }).execute()
        return res.data[0]

    def update_job(self, job_id: str, processed_logs: int, failed_logs: int, status: str, error: str = None) -> None:
        update_data = {
            "processed_logs": processed_logs,
            "failed_logs": failed_logs,
            "status": status,
            "error": error,
            "updated_at": datetime.utcnow().isoformat()
        }
        if status in ["completed", "failed"]:
            update_data["completed_at"] = datetime.utcnow().isoformat()
        self.client.table("ingestion_jobs").update(update_data).eq("id", job_id).execute()

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        res = self.client.table("ingestion_jobs").select("*").eq("id", job_id).execute()
        return res.data[0] if res.data else None

    def create_parsed_event(self, raw_log_id: str, session_id: str, timestamp: Optional[datetime], source_ip: Optional[str], destination_ip: Optional[str], username: Optional[str], action: Optional[str], payload: Dict[str, Any], parser_confidence: float) -> Dict[str, Any]:
        res = self.client.table("parsed_events").insert({
            "raw_log_id": raw_log_id,
            "session_id": session_id,
            "timestamp": timestamp.isoformat() if timestamp else None,
            "source_ip": clean_ip(source_ip),
            "destination_ip": clean_ip(destination_ip),
            "username": username,
            "action": action,
            "payload": payload,
            "parser_confidence": parser_confidence
        }).execute()
        return res.data[0]

    def is_duplicate_threat(self, session_id: str, threat_type: str, source_ip: Optional[str], window_minutes: int = 5) -> bool:
        cutoff = (datetime.utcnow() - timedelta(minutes=window_minutes)).isoformat()
        cleaned_source_ip = clean_ip(source_ip)
        query = self.client.table("threats").select("id").eq("session_id", session_id).eq("threat_type", threat_type)
        if cleaned_source_ip is None:
            query = query.is_("source_ip", "null")
        else:
            query = query.eq("source_ip", cleaned_source_ip)
        res = query.gte("detected_at", cutoff).limit(1).execute()
        return len(res.data) > 0

    def get_recent_failed_events(self, session_id: str, since: datetime) -> List[Dict[str, Any]]:
        res = self.client.table("parsed_events")\
            .select("*")\
            .eq("session_id", session_id)\
            .in_("action", ["LOGIN_FAILED", "PRIV_ESC_FAILED"])\
            .gte("timestamp", since.isoformat())\
            .execute()
        return res.data

    def create_threat(self, session_id: str, threat_type: str, severity: str, severity_score: int, confidence: float, source_ip: Optional[str], summary: str, classification_source: str, attack_pattern: Optional[str] = None, model_name: Optional[str] = None, raw_ai_response: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        cleaned_source_ip = clean_ip(source_ip)
        res = self.client.table("threats").insert({
            "session_id": session_id,
            "threat_type": threat_type,
            "severity": severity,
            "severity_score": severity_score,
            "confidence": confidence,
            "source_ip": cleaned_source_ip,
            "is_private_ip": self._is_private_ip_helper(cleaned_source_ip),
            "summary": summary,
            "classification_source": classification_source,
            "attack_pattern": attack_pattern,
            "model_name": model_name,
            "prompt_version": settings.LLM_PROMPT_VERSION,
            "raw_ai_response": raw_ai_response
        }).execute()
        return res.data[0]

    def create_threat_event(self, threat_id: str, event_id: str) -> None:
        self.client.table("threat_events").insert({
            "threat_id": threat_id,
            "event_id": event_id
        }).execute()

    def get_threats(self, session_id: str, severity: Optional[str] = None, limit: int = 50, since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        query = self.client.table("threats").select("*").eq("session_id", session_id)
        if severity:
            query = query.eq("severity", severity)
        if since:
            since_str = since.isoformat()
            if not since_str.endswith("Z") and "+" not in since_str and "-" not in since_str:
                since_str += "Z"
            query = query.gt("detected_at", since_str)
        
        res = query.order("detected_at", desc=True).limit(limit).execute()
        return res.data

    def get_threat(self, threat_id: str) -> Optional[Dict[str, Any]]:
        res = self.client.table("threats").select("*").eq("id", threat_id).execute()
        return res.data[0] if res.data else None

    def get_threat_logs(self, threat_id: str) -> List[str]:
        try:
            te_res = self.client.table("threat_events").select("event_id").eq("threat_id", threat_id).execute()
            if not te_res.data:
                return []
            event_ids = [row["event_id"] for row in te_res.data]
            
            ev_res = self.client.table("parsed_events").select("raw_log_id").in_("id", event_ids).execute()
            if not ev_res.data:
                return []
            raw_log_ids = [row["raw_log_id"] for row in ev_res.data if row.get("raw_log_id")]
            
            if not raw_log_ids:
                return []
            rl_res = self.client.table("raw_logs").select("redacted_content").in_("id", raw_log_ids).execute()
            if not rl_res.data:
                return []
            return [row["redacted_content"] for row in rl_res.data if row.get("redacted_content")]
        except Exception as e:
            print(f"Error fetching logs for threat {threat_id}: {e}")
            return []


    def update_threat_explanation(self, threat_id: str, explanation: str, mitre_tactic: str, recommended_actions: List[str]) -> None:
        import json
        serialized = json.dumps({
            "explanation": explanation,
            "mitre_tactic": mitre_tactic,
            "recommended_actions": recommended_actions
        })
        self.client.table("threats").update({"explanation": serialized}).eq("id", threat_id).execute()

    def _is_private_ip_helper(self, ip: Optional[str]) -> bool:
        if not ip:
            return False
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False


# Export DB functions dynamically
def get_db():
    allow_mock = getattr(settings, "ALLOW_MOCK_DB", False)
    if settings.is_db_configured:
        try:
            return SupabaseDatabase()
        except Exception as e:
            if allow_mock:
                print(f"Warning: Failed to initialize Supabase client: {e}. Falling back to in-memory db.")
                return mock_db
            else:
                print(f"Error: Failed to initialize Supabase client: {e}. Mock DB fallback is disabled.")
                raise RuntimeError(f"Database connection failed: {e}")
    else:
        if allow_mock:
            print("Warning: Database credentials not configured. Running in Mock/Offline mode.")
            return mock_db
        else:
            raise RuntimeError("Database not configured and Mock DB fallback is disabled.")

db = get_db()
