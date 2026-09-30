"""
Regression tests from the QA loop (hermes/qa-loop).
LLM is always mocked here — no network calls.
"""
import asyncio
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from app.config import settings
from app.database import db, MockDatabase
from app.main import app, process_log_ingest_job

client = TestClient(app)


def _run_job(logs, source_type, llm):
    session = db.create_session()
    job = db.create_job(session["id"], len(logs))
    with patch("app.main.get_llm_client", return_value=llm):
        asyncio.run(process_log_ingest_job(job["id"], session["id"], source_type, logs))
    return session["id"], db.get_job(job["id"])


def _brute_force_lines(n=11, ip="203.0.113.42"):
    # Historical syslog timestamps (well over 5 minutes old) — the realistic upload case.
    return [
        f"Jan  2 03:04:{i:02d} host sshd[1]: Failed password for invalid user admin from {ip} port {5000 + i} ssh2"
        for i in range(n)
    ]


class TestTestEnvironmentIsolation:
    def test_tests_never_use_real_backends(self):
        # conftest must win over backend/.env (load_dotenv doesn't override set vars).
        assert isinstance(db, MockDatabase)
        assert not settings.is_llm_configured

    def test_groq_models_are_configurable_and_not_decommissioned(self):
        from app.llm import GroqClient
        g = GroqClient()
        # llama-3.1-8b-instant / llama-3.3-70b-versatile were retired by Groq (404).
        assert g.model == settings.GROQ_CLASSIFY_MODEL
        assert g.explain_model == settings.GROQ_EXPLAIN_MODEL
        assert "llama-3.1-8b-instant" not in (g.model, g.explain_model)
        assert "llama-3.3-70b-versatile" not in (g.model, g.explain_model)

    def test_groq_classify_sends_configured_model(self):
        from unittest.mock import MagicMock
        from app.llm import GroqClient
        g = GroqClient()
        resp = MagicMock(is_success=True)
        resp.json.return_value = {"choices": [{"message": {"content": '{"findings": []}'}}]}
        with patch.object(g, "client") as http:
            http.post = AsyncMock(return_value=resp)
            assert asyncio.run(g.classify_logs(["x"])) == []
            assert http.post.call_args.kwargs["json"]["model"] == g.model


class TestBruteForceOnHistoricalLogs:
    def test_brute_force_detected_by_rule_not_llm(self):
        llm = AsyncMock()
        llm.classify_logs.return_value = []
        sid, job = _run_job(_brute_force_lines(), "auth", llm)

        threats = db.get_threats(sid)
        bf = [t for t in threats if t["threat_type"] == "BRUTE_FORCE"]
        assert len(bf) == 1
        assert bf[0]["classification_source"] == "rule"
        # every failed login was consumed by the correlation rule -> nothing left for the LLM
        llm.classify_logs.assert_not_called()
        assert job["status"] == "completed"

    def test_brute_force_detected_when_later_failures_follow(self):
        # Mirrors sample_attack_logs.log: SSH brute force at 03:04, sudo failures 6 minutes later.
        later = [
            "Jan  2 03:10:30 host sudo: pam_unix(sudo:auth): authentication failure; logname= uid=1001 euid=0 ruser=dev rhost= user=root",
        ]
        llm = AsyncMock()
        llm.classify_logs.return_value = []
        sid, _ = _run_job(_brute_force_lines() + later, "auth", llm)
        bf = [t for t in db.get_threats(sid) if t["threat_type"] == "BRUTE_FORCE"]
        assert len(bf) == 1 and bf[0]["classification_source"] == "rule"

    def test_below_threshold_goes_to_llm(self):
        llm = AsyncMock()
        llm.classify_logs.return_value = []
        sid, _ = _run_job(_brute_force_lines(n=3), "auth", llm)
        assert not [t for t in db.get_threats(sid) if t["threat_type"] == "BRUTE_FORCE"]
        llm.classify_logs.assert_called_once()


class TestLLMRouting:
    def test_only_unmatched_lines_are_batched_to_llm(self):
        rule_line = '1.2.3.4 - - [23/May/2026:08:05:10 +0000] "GET /a?id=1%20UNION%20SELECT%201 HTTP/1.1" 400 1'
        benign = [
            f'10.0.0.{i} - - [23/May/2026:08:00:00 +0000] "GET /page{i} HTTP/1.1" 200 1' for i in range(25)
        ]
        llm = AsyncMock()
        llm.classify_logs.return_value = []
        _, job = _run_job([rule_line] + benign, "nginx", llm)

        sent = [line for call in llm.classify_logs.call_args_list for line in call.args[0]]
        assert len(sent) == 25
        assert not any("UNION" in s for s in sent)
        # batches of <= 20
        assert sorted(len(c.args[0]) for c in llm.classify_logs.call_args_list) == [5, 20]
        assert job["status"] == "completed"

    def test_llm_failure_counts_do_not_exceed_total(self):
        lines = [f'10.0.0.1 - - [23/May/2026:08:00:00 +0000] "GET /p{i} HTTP/1.1" 200 1' for i in range(5)]
        llm = AsyncMock()
        llm.classify_logs.side_effect = RuntimeError("groq down")
        _, job = _run_job(lines, "nginx", llm)
        assert job["processed_logs"] + job["failed_logs"] == 5
        assert job["failed_logs"] == 5
        assert job["status"] == "failed"


class TestIngestEdgeCases:
    def _sid(self):
        return client.post("/api/session").json()["session_id"]

    def test_mock_db_cleans_stale_jobs_on_startup(self):
        # startup_event calls db.cleanup_stale_jobs() on MockDatabase; it used to be missing.
        m = MockDatabase()
        s = m.create_session()
        job = m.create_job(s["id"], 3)
        m.cleanup_stale_jobs()
        assert m.get_job(job["id"])["status"] == "failed"

    def test_empty_batch_job_completes(self):
        sid = self._sid()
        r = client.post("/api/ingest", json={"session_id": sid, "source_type": "nginx", "logs": []})
        job = client.get(f"/api/jobs/{r.json()['job_id']}", params={"session_id": sid}).json()
        assert job["status"] == "completed"

    def test_session_log_quota_enforced(self):
        sid = self._sid()
        logs = ["plain line"] * 500
        assert client.post("/api/ingest", json={"session_id": sid, "source_type": "custom", "logs": logs}).status_code == 200
        r = client.post("/api/ingest", json={"session_id": sid, "source_type": "custom", "logs": ["one more"]})
        assert r.status_code == 429
        assert r.json()["detail"]["error"] == "quota_exceeded"
