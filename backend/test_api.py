import requests
import time
import sys

BASE_URL = "http://127.0.0.1:8000"

def run_tests():
    print("==================================================")
    print("ThreatLens API Integration Tests via 'requests'")
    print("==================================================\n")
    
    # 1. Test GET /api/health
    print("[Test 1] Validating Health Check (GET /api/health)...")
    try:
        response = requests.get(f"{BASE_URL}/api/health")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        assert data.get("status") == "ok", f"Expected status 'ok', got {data.get('status')}"
        print("✓ Health Check Passed successfully.\n")
    except Exception as e:
        print(f"✗ Health Check Failed: {e}\n")
        sys.exit(1)

    # 2. Test POST /api/session
    print("[Test 2] Creating New Session (POST /api/session)...")
    session_id = None
    try:
        response = requests.post(f"{BASE_URL}/api/session")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        session_id = data.get("session_id")
        assert session_id is not None, "session_id was not returned"
        print(f"✓ Session Created successfully. ID: {session_id}")
        print(f"  Max Logs Quota: {data.get('max_logs')} | Max Explain Quota: {data.get('max_explain_calls')}\n")
    except Exception as e:
        print(f"✗ Session Creation Failed: {e}\n")
        sys.exit(1)

    # 3. Test POST /api/ingest
    print("[Test 3] Ingesting Attack Logs (POST /api/ingest)...")
    job_id = None
    test_logs = [
        '198.51.100.12 - - [23/May/2026:14:35:10 +0000] "GET /api/users?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 400 512 "-" "Mozilla/5.0"',
        '203.0.113.99 - - [23/May/2026:14:36:20 +0000] "GET /api/proxy?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
        'May 23 14:33:01 server sshd[12345]: Failed password for invalid user admin from 203.0.113.42 port 54321 ssh2'
    ]
    try:
        payload = {
            "session_id": session_id,
            "source_type": "nginx",
            "logs": test_logs
        }
        response = requests.post(f"{BASE_URL}/api/ingest", json=payload)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        job_id = data.get("job_id")
        assert data.get("status") == "queued", f"Expected 'queued', got {data.get('status')}"
        assert job_id is not None, "job_id was not returned"
        print(f"✓ Logs Ingested successfully. Job ID: {job_id}\n")
    except Exception as e:
        print(f"✗ Log Ingestion Failed: {e}\n")
        sys.exit(1)

    # 4. Test GET /api/jobs/{job_id}
    print("[Test 4] Polling Ingestion Job (GET /api/jobs/{job_id})...")
    try:
        completed = False
        attempts = 0
        while not completed and attempts < 10:
            response = requests.get(f"{BASE_URL}/api/jobs/{job_id}?session_id={session_id}")
            assert response.status_code == 200, f"Expected 200, got {response.status_code}"
            data = response.json()
            status = data.get("status")
            print(f"  Polling attempt {attempts+1}: status='{status}', completed={data.get('percent_complete')}%")
            if status in ["completed", "failed"]:
                completed = True
                assert status == "completed", f"Job failed: {data.get('error')}"
            else:
                time.sleep(1.0)
                attempts += 1
        assert completed, "Job did not complete within timeout window"
        print("✓ Job Polling Completed successfully.\n")
    except Exception as e:
        print(f"✗ Job Polling Failed: {e}\n")
        sys.exit(1)

    # 5. Test GET /api/threats
    print("[Test 5] Fetching Threat Feed (GET /api/threats)...")
    threat_id = None
    try:
        response = requests.get(f"{BASE_URL}/api/threats?session_id={session_id}")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        threats = data.get("threats", [])
        assert len(threats) >= 2, f"Expected at least 2 threats, got {len(threats)}"
        
        # Display the threats found
        print(f"✓ Threat Feed Retrieved successfully. Detected {data.get('total')} threats:")
        for t in threats:
            print(f"  - [{t.get('severity')}] {t.get('threat_type')}: {t.get('summary')} (Source: {t.get('classification_source')})")
            if t.get("threat_type") == "SQLI":
                threat_id = t.get("id")
        
        assert threat_id is not None, "Could not find a SQLI threat ID for explanation testing"
        print()
    except Exception as e:
        print(f"✗ Threat Feed Fetch Failed: {e}\n")
        sys.exit(1)

    # 6. Test POST /api/explain (AI explanation and caching)
    print(f"[Test 6] Explaining Threat (POST /api/explain) for Threat ID: {threat_id}...")
    try:
        payload = {
            "session_id": session_id,
            "threat_id": threat_id
        }
        # First call (generates explanation)
        t0 = time.time()
        response = requests.post(f"{BASE_URL}/api/explain", json=payload)
        t_first = time.time() - t0
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        assert data.get("explanation") is not None, "explanation field is null"
        assert data.get("mitre_tactic") is not None, "mitre_tactic field is null"
        assert len(data.get("recommended_actions", [])) > 0, "recommended_actions is empty"
        print(f"✓ Explanation Generated successfully in {t_first:.2f}s.")
        print(f"  MITRE ATT&CK Tactic: {data.get('mitre_tactic')}")
        print(f"  Cached: {data.get('cached')}")
        
        # Second call (must be served from Cache instantly)
        t0 = time.time()
        response_cached = requests.post(f"{BASE_URL}/api/explain", json=payload)
        t_cached = time.time() - t0
        assert response_cached.status_code == 200, f"Expected 200, got {response_cached.status_code}"
        data_cached = response_cached.json()
        assert data_cached.get("cached") is True, f"Expected cached response to be True, got {data_cached.get('cached')}"
        print(f"✓ Explanation Cache Verification Passed. Cached hit resolved in {t_cached*1000:.2f}ms.\n")
    except Exception as e:
        print(f"✗ Threat Explanation / Caching Failed: {e}\n")
        sys.exit(1)

    print("==================================================")
    print("ALL API INTEGRATION TESTS PASSED SUCCESSFULLY!")
    print("==================================================")

if __name__ == "__main__":
    run_tests()
