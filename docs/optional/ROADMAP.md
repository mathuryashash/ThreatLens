# Future Roadmap — ThreatLens

This document describes what ThreatLens would look like as a production product beyond the hackathon build.

---

## Post-Hackathon (v1.1 — 2 weeks)

**Real authentication**
- Replace demo session tokens with actual user accounts (Supabase Auth or Clerk)
- Email/password + Google OAuth
- Full Supabase RLS policies isolating data per user

**Durable job queue**
- Replace FastAPI `BackgroundTasks` with Celery + Redis
- Crash-safe job processing with retry logic
- Dead letter queue for permanently failed jobs

**Supabase Realtime**
- Replace 3s polling with WebSocket push
- Only safe to enable after full RLS verification
- Frontend subscribes to `threats` table filtered by user_id

---

## v1.2 — Production Grade (1 month)

**More log parsers**
- Apache combined log format
- AWS CloudTrail JSON
- Windows Event Log XML
- Kubernetes audit logs
- Generic JSON log format

**Better rule coverage**
- Log4Shell detection (JNDI injection)
- RCE via command injection patterns
- XXE patterns
- LDAP injection
- Mass assignment detection in HTTP bodies

**Webhook alerting**
- Slack notification on CRITICAL threats
- PagerDuty integration
- Email alerts with threat summary
- Configurable severity thresholds per integration

---

## v2.0 — Correlation Engine (2-3 months)

**Cross-event correlation**
- LLM-powered correlation across time windows
- Attack chain reconstruction (recon → exploit → exfil)
- Campaign detection: same IP appearing in multiple attack types

**MITRE ATT&CK mapping**
- Full tactic/technique mapping per threat type
- Visual kill chain display
- Coverage gap analysis

**Hybrid classification**
- Rule detection + AI enrichment combined
- `classification_source='hybrid'`
- AI adds confidence adjustment, context, and MITRE mapping to rule-matched threats

---

## v2.5 — Multi-Tenant SaaS (3-6 months)

**Organization accounts**
- Teams with multiple users
- Role-based access (admin, analyst, viewer)
- Shared log ingestion pipelines

**Persistent history**
- Sessions don't expire — full audit trail
- Historical trend charts (threats per day, top attacking IPs)
- Export reports as PDF/CSV

**Saved dashboards**
- Custom filters and views
- Bookmark specific threat investigations
- Annotate threats with analyst notes

---

## v3.0 — SIEM Integrations (6+ months)

**Log source connectors**
- Syslog receiver (UDP/TCP)
- S3 bucket polling for log files
- CloudWatch Logs integration
- Splunk forwarding compatibility

**Remediation integrations**
- AWS WAF rule suggestions (1-click add IP to deny list)
- Cloudflare firewall rule generation
- Export to SOAR playbooks (Tines, Torq)

**Compliance reporting**
- SOC 2 audit evidence export
- PCI-DSS log retention compliance checks
- GDPR access log reports

---

## Things That Would NOT Be Added

- Automated network blocking (too high blast radius for an advisory tool)
- Antivirus or malware execution (out of scope for log analysis)
- Vulnerability scanning (different tool class)
- Packet capture analysis (PCAP is a different pipeline)

---

## Technical Debt from Hackathon Build

| Item | Priority | Effort |
|------|----------|--------|
| Replace BackgroundTasks with Celery | HIGH | 2 days |
| Add Supabase RLS policies | HIGH | 1 day |
| Add real user authentication | HIGH | 3 days |
| Replace localStorage session with secure cookie | MEDIUM | 1 day |
| Add proper database migrations (Alembic) | MEDIUM | 1 day |
| Add unit test suite | MEDIUM | 3 days |
| GeminiClient full implementation | LOW | 1 day |
| Virtual scrolling for large threat lists | LOW | 0.5 days |
