import os
import json
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, BackgroundTasks, HTTPException, Request, Depends, status, Query
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.config import settings
from app.schemas import (
    SessionCreateResponse, IngestRequest, IngestResponse,
    JobStatusResponse, ThreatResponse, ExplainRequest, ExplainResponse,
    SessionQuotaResponse
)
from app.database import db
from app.parser import parse_log_line
from app.redactor import redact_content
from app.rules import process_rules
from app.llm import get_llm_client

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="ThreatLens API", version="1.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Global Semaphore to limit concurrent LLM calls across all background tasks
llm_semaphore = asyncio.Semaphore(5)

@app.on_event("startup")
def startup_event():
    # Mark any "queued" or "processing" jobs from previous runs as "failed" on server startup
    try:
        if hasattr(db, "client") and hasattr(db, "get_session"):
            # Supabase database stale job cleanup
            db.client.table("ingestion_jobs")\
                .update({"status": "failed", "error": "Server restarted during job execution"})\
                .in_("status", ["queued", "processing"])\
                .execute()
            print("Cleanup: Marked stale/interrupted ingestion jobs as failed.")
        else:
            # Mock database stale job cleanup
            db.cleanup_stale_jobs()
    except Exception as e:
        print(f"Failed to clean up stale jobs on startup: {e}")

# ============================================================
# API Endpoints
# ============================================================

@app.get("/api/health")
def health_check():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}

@app.post("/api/session", response_model=SessionCreateResponse)
@limiter.limit("20/minute")
def create_session(request: Request):
    session = db.create_session()
    return {
        "session_id": session["id"],
        "expires_at": session["expires_at"],
        "max_logs": session["max_logs"],
        "max_explain_calls": session["max_explain_calls"]
    }

@app.get("/api/session/{session_id}/quota", response_model=SessionQuotaResponse)
@limiter.limit("60/minute")
def get_session_quota(request: Request, session_id: str):
    session = get_valid_session(session_id)
    return {
        "max_logs": session.get("max_logs") or 500,
        "used_logs": session.get("used_logs") or 0,
        "max_explain_calls": session.get("max_explain_calls") or 10,
        "used_explain_calls": session.get("used_explain_calls") or 0
    }

# Custom body size limit middleware (3MB max)
class LimitUploadSizeMiddleware:
    def __init__(self, app, max_size: int = 3 * 1024 * 1024):
        self.app = app
        self.max_size = max_size

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Check content-length header first
        content_length = 0
        for header, value in scope.get("headers", []):
            if header == b"content-length":
                try:
                    content_length = int(value)
                except ValueError:
                    await self._send_json_error(send, 400, "bad_request", "Malformed Content-Length header")
                    return
                break

        if content_length > self.max_size:
            await self._send_json_error(send, 413, "request_too_large", "Upload size exceeds 3MB limit")
            return

        # Create a custom receive that counts bytes
        total_size = 0
        body_overflow = False

        async def custom_receive():
            nonlocal total_size, body_overflow
            if body_overflow:
                return {"type": "http.disconnect"}

            message = await receive()
            if message["type"] == "http.request":
                chunk_size = len(message.get("body", b""))
                total_size += chunk_size
                if total_size > self.max_size:
                    body_overflow = True
                    await self._send_json_error(send, 413, "request_too_large", "Upload size exceeds 3MB limit")
                    return {"type": "http.disconnect"}
            return message

        await self.app(scope, custom_receive, send)

    async def _send_json_error(self, send, status_code: int, error_code: str, detail: str):
        try:
            await send({
                "type": "http.response.start",
                "status": status_code,
                "headers": [
                    (b"content-type", b"application/json"),
                ]
            })
            await send({
                "type": "http.response.body",
                "body": json.dumps({"error": error_code, "detail": detail}).encode("utf-8"),
                "more_body": False
            })
        except Exception:
            pass

app.add_middleware(LimitUploadSizeMiddleware, max_size=3 * 1024 * 1024)

# Configure CORS
origins = [settings.FRONTEND_ORIGIN]
if settings.DEBUG:
    origins += [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3001",
        "http://localhost:3002",
        "http://127.0.0.1:3002",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

# Helper: check session validity
def get_valid_session(session_id: str) -> Dict[str, Any]:
    session = db.get_session(session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "session_not_found", "detail": "Session ID does not exist"}
        )
        
    # Check expiry
    expires_at_raw = session.get("expires_at")
    if not expires_at_raw:
        expires_at = datetime.utcnow() + timedelta(hours=24)
    elif isinstance(expires_at_raw, datetime):
        expires_at = expires_at_raw
    else:
        try:
            expires_at = datetime.fromisoformat(expires_at_raw.replace("Z", "+00:00")).replace(tzinfo=None)
        except Exception:
            # Fallback to a future date to prevent random crashes on parse errors
            expires_at = datetime.utcnow() + timedelta(hours=24)
            
    if expires_at < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "session_expired", "detail": "Session has expired. Please reset."}
        )
    return session

# Async worker processing loop
async def process_log_ingest_job(job_id: str, session_id: str, source_type: str, logs: List[str]):
    try:
        # 1. Update job status to processing
        db.update_job(job_id, processed_logs=0, failed_logs=0, status="processing")
        
        llm_client = get_llm_client()
        
        parsed_events_with_logs = []
        processed_count = 0
        failed_count = 0
        
        # 2. Parse, redact, and store logs + events
        for line in logs:
            try:
                # Insert raw_log entry
                raw_log = db.create_raw_log(session_id, source_type, line)
                
                # Parse
                parsed_data = parse_log_line(line, source_type)
                
                # Redact
                redacted = redact_content(line)
                
                # Update raw log with redacted copy
                db.update_raw_log(
                    raw_log["id"], 
                    redacted_content=redacted, 
                    redaction_applied=True, 
                    processing_status="processing"
                )
                raw_log["redacted_content"] = redacted
                raw_log["redaction_applied"] = True
                raw_log["processing_status"] = "processing"
                
                # Create parsed_event record
                event = db.create_parsed_event(
                    raw_log_id=raw_log["id"],
                    session_id=session_id,
                    timestamp=parsed_data["timestamp"],
                    source_ip=parsed_data["source_ip"],
                    destination_ip=parsed_data["destination_ip"],
                    username=parsed_data["username"],
                    action=parsed_data["action"],
                    payload=parsed_data["payload"],
                    parser_confidence=parsed_data["parser_confidence"]
                )
                
                parsed_events_with_logs.append((event, raw_log))
                processed_count += 1
            except Exception as e:
                print(f"Failed parsing log line: {e}")
                failed_count += 1
                
            # Update job progress in database
            db.update_job(job_id, processed_logs=processed_count, failed_logs=failed_count, status="processing")
            
        # 3. Run deterministic and correlation rules
        # Returns list of events (event, raw_log) that did not trigger any rules
        unmatched_logs = process_rules(session_id, parsed_events_with_logs)
        
        # 4. Batch remaining unmatched logs and send to LLM
        # Batch size is 20 lines
        batch_size = 20
        unmatched_batches = [unmatched_logs[i:i + batch_size] for i in range(0, len(unmatched_logs), batch_size)]
        
        async def process_llm_batch(batch):
            nonlocal processed_count, failed_count
            
            # Extract log content for prompt
            raw_lines = [r["redacted_content"] for _, r in batch]
            
            async with llm_semaphore:
                try:
                    findings = await llm_client.classify_logs(raw_lines)
                    
                    # Store threat findings
                    for finding in findings:
                        source_ip = finding["source_ip"]
                        
                        # Validate source_ip matches one in our parsed events to prevent LLM hallucinations
                        valid_ip = None
                        if source_ip:
                            for event, _ in batch:
                                if event.get("source_ip") == source_ip:
                                    valid_ip = source_ip
                                    break
                                    
                        # Check duplicate suppression
                        threat_type = finding["threat_type"]
                        if not db.is_duplicate_threat(session_id, threat_type, valid_ip):
                            threat = db.create_threat(
                                session_id=session_id,
                                threat_type=threat_type,
                                severity=finding["severity"],
                                severity_score=finding["severity_score"],
                                confidence=finding["confidence"],
                                source_ip=valid_ip,
                                summary=finding["summary"],
                                classification_source="ai",
                                model_name=getattr(llm_client, "model", "llama3-8b-8192"),
                                raw_ai_response=finding
                            )
                            
                            # Link related event indices
                            for idx in finding.get("related_event_indices", []):
                                if 0 <= idx < len(batch):
                                    linked_event = batch[idx][0]
                                    db.create_threat_event(threat["id"], linked_event["id"])
                                    
                    # Mark all raw logs in this batch as processed
                    for _, raw_log in batch:
                        db.update_raw_log(raw_log["id"], raw_log["redacted_content"], raw_log["redaction_applied"], "processed")
                        
                except Exception as e:
                    print(f"LLM Classification batch failed: {e}")
                    failed_count += len(batch)
                    # Mark all raw logs in this batch as failed
                    for _, raw_log in batch:
                        db.update_raw_log(raw_log["id"], raw_log["redacted_content"], raw_log["redaction_applied"], "failed", str(e))
                        
            # Update job progress
            db.update_job(job_id, processed_logs=processed_count, failed_logs=failed_count, status="processing")
            
        # Run LLM classification concurrent batch tasks
        if unmatched_batches:
            await asyncio.gather(*(process_llm_batch(batch) for batch in unmatched_batches))
            
        # 5. Complete job
        final_status = "completed" if failed_count < len(logs) else "failed"
        db.update_job(job_id, processed_logs=processed_count, failed_logs=failed_count, status=final_status)
        
    except Exception as e:
        print(f"Job processing general crash: {e}")
        db.update_job(job_id, processed_logs=0, failed_logs=len(logs), status="failed", error=str(e))
@app.post("/api/ingest", response_model=IngestResponse)
@limiter.limit("20/minute")
def ingest_logs(request: Request, payload: IngestRequest, bg_tasks: BackgroundTasks):
    # Validate session
    session = get_valid_session(payload.session_id)
    
    # Validate source_type
    allowed_sources = ["nginx", "auth", "syslog", "custom"]
    if payload.source_type not in allowed_sources:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_source_type", "detail": f"Source type must be one of: {allowed_sources}"}
        )
        
    # Validate line counts (cap 500 lines)
    if len(payload.logs) > 500:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "too_many_lines", "detail": "Cannot ingest more than 500 lines per batch"}
        )

    # Validate individual line lengths defensively (cap 8KB per line)
    for line in payload.logs:
        if len(line) > 8192:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "line_too_long", "detail": "Log line exceeds maximum limit of 8KB"}
            )
        
    # Increment logs quota atomically
    new_used = db.increment_session_logs(payload.session_id, len(payload.logs))
    if new_used == -1:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"error": "quota_exceeded", "detail": "Session log limit exceeded. Limit is 500 logs."}
        )
    
    # Create job
    job = db.create_job(payload.session_id, len(payload.logs))
    
    # Dispatch background worker task
    bg_tasks.add_task(
        process_log_ingest_job,
        job_id=job["id"],
        session_id=payload.session_id,
        source_type=payload.source_type,
        logs=payload.logs
    )
    
    remaining_quota = session["max_logs"] - new_used
    
    return {
        "status": "queued",
        "job_id": job["id"],
        "ingested_count": len(payload.logs),
        "remaining_quota": max(0, remaining_quota)
    }

@app.get("/api/jobs/{job_id}", response_model=JobStatusResponse)
@limiter.limit("60/minute")
def get_job_status(request: Request, job_id: str, session_id: str):
    # Validate session
    get_valid_session(session_id)
    
    job = db.get_job(job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "threat_not_found", "detail": "Job not found"}
        )
        
    # Verify owner
    if job["session_id"] != session_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "session_mismatch", "detail": "Forbidden: Session ID mismatch for this job"}
        )
        
    percent = 0
    if job["total_logs"] > 0:
        percent = int(((job["processed_logs"] + job["failed_logs"]) / job["total_logs"]) * 100)
        
    return {
        "job_id": job["id"],
        "status": job["status"],
        "total_logs": job["total_logs"],
        "processed_logs": job["processed_logs"],
        "failed_logs": job["failed_logs"],
        "percent_complete": min(100, percent)
    }

@app.get("/api/threats", response_model=ThreatResponse)
@limiter.limit("60/minute")
def get_threats(request: Request, session_id: str, severity: Optional[str] = None, limit: int = Query(default=50, ge=1, le=200), since: Optional[str] = None):
    # Validate session
    get_valid_session(session_id)
    
    # Parse since time
    since_dt = None
    if since:
        try:
            # ISO timestamp string
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            pass
            
    threats_data = db.get_threats(session_id, severity, limit, since_dt)
    
    # Calculate counts by severity from already-fetched page (avoids second full-table query)
    by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for t in threats_data:
        sev = t.get("severity")
        if sev in by_sev:
            by_sev[sev] += 1
            
    next_cursor = None
    if threats_data:
        next_cursor = threats_data[-1]["detected_at"]
        
    # Format database rows to schema format
    formatted_threats = []
    for t in threats_data:
        # explanation text is stored as a serialized JSON containing fields
        # if not null, extract explanation text
        explanation_text = None
        if t.get("explanation"):
            try:
                explanation_data = json.loads(t["explanation"])
                explanation_text = explanation_data.get("explanation")
            except (json.JSONDecodeError, KeyError, TypeError) as e:
                print(f"Warning: malformed cached explanation: {e}")
                explanation_text = t["explanation"]
                
        # Fetch related raw log lines as evidence
        evidence_logs = []
        try:
            evidence_logs = db.get_threat_logs(t["id"])
        except Exception as e:
            print(f"Error loading evidence for threat {t['id']}: {e}")

        formatted_threats.append({
            "id": t["id"],
            "session_id": t["session_id"],
            "threat_type": t["threat_type"],
            "severity": t["severity"],
            "severity_score": t["severity_score"],
            "confidence": t["confidence"],
            "source_ip": t["source_ip"],
            "geo_country": t["geo_country"],
            "geo_city": t["geo_city"],
            "is_private_ip": t["is_private_ip"] or False,
            "summary": t["summary"],
            "explanation": explanation_text,
            "classification_source": t["classification_source"],
            "attack_pattern": t["attack_pattern"],
            "model_name": t["model_name"],
            "evidence": evidence_logs,
            "detected_at": t["detected_at"]
        })
        
    return {
        "threats": formatted_threats,
        "total": len(formatted_threats),
        "by_severity": by_sev,
        "next_cursor": next_cursor
    }

@app.post("/api/explain", response_model=ExplainResponse)
@limiter.limit("20/minute")
async def explain_threat(request: Request, payload: ExplainRequest):
    # Validate session
    session = get_valid_session(payload.session_id)
    
    # Fetch threat
    threat = db.get_threat(payload.threat_id)
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "threat_not_found", "detail": "Threat not found"}
        )
        
    # Verify owner
    if threat["session_id"] != payload.session_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "session_mismatch", "detail": "Forbidden: Threat belongs to another session"}
        )
        
    # Check cached explanation
    if threat.get("explanation"):
        try:
            explanation_data = json.loads(threat["explanation"])
            return {
                "threat_id": threat["id"],
                "explanation": explanation_data["explanation"],
                "mitre_tactic": explanation_data["mitre_tactic"],
                "recommended_actions": explanation_data["recommended_actions"],
                "cached": True
            }
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            print(f"Warning: malformed cached explanation: {e}")
            # Fallback if serialization failed
            
    # Check explanation quota
    used_explain = session.get("used_explain_calls") or 0
    max_explain = session.get("max_explain_calls") or 10
    if used_explain >= max_explain:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"error": "explain_quota_exceeded", "detail": f"Session explanation quota exceeded (limit: {max_explain})"}
        )

    # Increment quota BEFORE the LLM call to prevent TOCTOU race where two
    # concurrent requests both pass the check above and both proceed to call
    # the LLM. If the LLM call later fails the quota stays consumed (accepted trade-off).
    try:
        new_explain = db.increment_session_explain(payload.session_id)
        if new_explain == -1:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={"error": "explain_quota_exceeded", "detail": f"Session explanation quota exceeded (limit: {max_explain})"}
            )
    except HTTPException:
        raise
    except Exception as db_err:
        print(f"Failed to increment session explain count: {db_err}")

    # Call LLM client
    llm_client = get_llm_client()

    # Fetch related redacted log lines via database abstraction layer
    related_logs = []
    try:
        related_logs = db.get_threat_logs(threat["id"])
    except Exception as e:
        print(f"Error fetching related logs for threat {threat['id']}: {e}")

    # Fallback to summary if no logs linked
    if not related_logs:
        related_logs = [threat.get("summary", "Suspicious log event")]

    try:
        explain_res = await llm_client.explain_threat(threat, related_logs)

        explanation = explain_res.get("explanation") or "Security event detected indicating suspicious pattern."
        mitre_tactic = explain_res.get("mitre_tactic") or "Suspicious Activity"
        recommended_actions = explain_res.get("recommended_actions") or [
            "Investigate activity from the source IP address",
            "Audit system authentication logs and firewall rules"
        ]

        # Save to database (wrapped defensively to prevent write errors from crashing the endpoint)
        try:
            db.update_threat_explanation(
                threat_id=threat["id"],
                explanation=explanation,
                mitre_tactic=mitre_tactic,
                recommended_actions=recommended_actions
            )
        except Exception as db_err:
            print(f"Failed to cache explanation to database: {db_err}")

        return {
            "threat_id": threat["id"],
            "explanation": explanation,
            "mitre_tactic": mitre_tactic,
            "recommended_actions": recommended_actions,
            "cached": False
        }
    except Exception as e:
        print(f"Failed to generate threat explanation: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "classification_failed", "detail": "Explanation service unavailable"}
        )

