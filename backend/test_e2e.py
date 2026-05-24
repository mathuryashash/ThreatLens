import sys
import os
import asyncio
from datetime import datetime

# Add backend directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.database import db
from app.main import process_log_ingest_job
from app.llm import get_llm_client

async def run_e2e_test():
    print("Starting direct E2E pipeline verification test...")
    
    # 1. Clear database state
    if hasattr(db, "sessions"):
        db.sessions.clear()
        db.raw_logs.clear()
        db.jobs.clear()
        db.parsed_events.clear()
        db.threats.clear()
        db.threat_events.clear()
        
    # 2. Create session
    session = db.create_session()
    session_id = session["id"]
    print(f"Session created: {session_id}")
    
    # 3. Define test logs (mixed attacks)
    logs = [
        # SQLi Access Log
        '198.51.100.12 - - [23/May/2026:14:35:10 +0000] "GET /api/users?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 400 512 "-" "Mozilla/5.0"',
        # SSRF Access Log
        '203.0.113.99 - - [23/May/2026:14:36:20 +0000] "GET /api/proxy?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
        # 10 Failed logins for Brute Force
        'May 23 14:33:01 server sshd[12345]: Failed password for invalid user admin from 203.0.113.42 port 54321 ssh2',
        'May 23 14:33:02 server sshd[12345]: Failed password for invalid user admin from 203.0.113.42 port 54322 ssh2',
        'May 23 14:33:03 server sshd[12345]: Failed password for invalid user admin from 203.0.113.42 port 54323 ssh2',
        'May 23 14:33:04 server sshd[12345]: Failed password for invalid user admin from 203.0.113.42 port 54324 ssh2',
        'May 23 14:33:05 server sshd[12345]: Failed password for invalid user admin from 203.0.113.42 port 54325 ssh2',
        'May 23 14:33:06 server sshd[12345]: Failed password for invalid user admin from 203.0.113.42 port 54326 ssh2',
        'May 23 14:33:07 server sshd[12345]: Failed password for invalid user admin from 203.0.113.42 port 54327 ssh2',
        'May 23 14:33:08 server sshd[12345]: Failed password for invalid user admin from 203.0.113.42 port 54328 ssh2',
        'May 23 14:33:09 server sshd[12345]: Failed password for invalid user admin from 203.0.113.42 port 54329 ssh2',
        'May 23 14:33:10 server sshd[12345]: Failed password for invalid user admin from 203.0.113.42 port 54330 ssh2',
        # Unknown log pattern to route to LLM
        '203.0.113.42 - - [23/May/2026:14:39:00 +0000] "GET /wp-login.php HTTP/1.1" 200 2345 "-" "Mozilla/5.0" (routes to AI)'
    ]
    
    # 4. Create Job
    job = db.create_job(session_id, len(logs))
    job_id = job["id"]
    print(f"Ingestion job created: {job_id}")
    
    # 5. Execute log ingestion job worker
    print("Running background processor...")
    await process_log_ingest_job(job_id, session_id, "nginx", logs)
    
    # 6. Verify Job completion
    job_status = db.get_job(job_id)
    assert job_status["status"] == "completed", f"Job failed: {job_status.get('error')}"
    assert job_status["processed_logs"] == len(logs)
    print("Job status verified: completed successfully!")
    
    # 7. Fetch threats
    threats = db.get_threats(session_id)
    print(f"Detected threats: {len(threats)}")
    for t in threats:
        print(f" - [{t['severity']}] {t['threat_type']}: {t['summary']} (Source: {t['classification_source']})")
        
    threat_types = [t["threat_type"] for t in threats]
    assert "SQLI" in threat_types, "SQL Injection was not detected!"
    assert "SSRF" in threat_types, "Server-Side Request Forgery was not detected!"
    assert "BRUTE_FORCE" in threat_types, "Brute force was not detected!"
    # Verify AI classified threat
    assert "RECON" in threat_types or "SUSPICIOUS" in threat_types, "AI classifier did not detect suspicious WP probe!"
    
    # 8. Test Explain Threat (First call - generates explanation)
    sqli_threat = next(t for t in threats if t["threat_type"] == "SQLI")
    threat_id = sqli_threat["id"]
    print(f"Explaining threat: {threat_id} ({sqli_threat['threat_type']})")
    
    # Gather logs for the threat
    event_ids = [row["event_id"] for row in db.threat_events if row["threat_id"] == threat_id]
    raw_log_ids = [db.parsed_events[ev_id]["raw_log_id"] for ev_id in event_ids]
    related_logs = [db.raw_logs[log_id]["redacted_content"] for log_id in raw_log_ids]
    
    llm_client = get_llm_client()
    explain_res = await llm_client.explain_threat(sqli_threat, related_logs)
    
    assert "explanation" in explain_res
    assert "mitre_tactic" in explain_res
    assert "recommended_actions" in explain_res
    print("Threat explanation generated successfully:")
    print(f" - MITRE Tactic: {explain_res['mitre_tactic']}")
    print(f" - Explanation: {explain_res['explanation']}")
    
    # Cache explanation in db
    db.update_threat_explanation(threat_id, explain_res["explanation"], explain_res["mitre_tactic"], explain_res["recommended_actions"])
    
    # Try getting it again to check cache
    threat_updated = db.get_threat(threat_id)
    assert threat_updated["explanation"] is not None
    print("Threat explanation caching verified successfully!")
    
    print("\nSUCCESS: All direct E2E pipeline verification tests passed successfully!")

if __name__ == "__main__":
    asyncio.run(run_e2e_test())
