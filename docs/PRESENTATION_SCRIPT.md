# ThreatLens: 3-Minute Presentation Script

This script is structured for a 3-minute presentation or video walkthrough of ThreatLens. It avoids robotic or cliché phrasing, focusing on clear, direct language.

---

## Script Breakdown

| Timing | Section | Key Visual | Focus |
|--------|---------|------------|-------|
| **0:00 - 0:30** | Pitch & Problem | Clean Homepage / Empty Feed | Explaining the problem of log noise and the ThreatLens approach. |
| **0:30 - 1:00** | Data Ingestion | Click "Load sample attack logs", watch pipeline | Privacy-first sessions, data redaction, and rules-first processing. |
| **1:00 - 1:45** | Threat Feed | Scrolling through populated threat cards | Severity grouping, attack types, and prompt injection defense. |
| **1:45 - 2:15** | AI Analyst Brief | Click "Explain" on a threat, show panel | Incident explanation, MITRE mapping, remediation, and caching. |
| **2:15 - 2:45** | Architecture | Architecture diagram / `docs/ARCHITECTURE.md` | Hybrid engine: why rules run before the LLM. |
| **2:45 - 3:00** | Reset & Wrap | Click "Reset demo", show clean screen | Privacy deletion and final project conclusion. |

---

### [0:00 - 0:30] Pitch & Problem Statement

**[Visual]**
*Show the ThreatLens dashboard homepage. The screen is clean, dark-themed, showing a zeroed-out stats bar and an empty threat feed. The mouse hovers near the session ID in the header.*

**[Spoken Script]**
"Every day, applications generate thousands of lines of security logs. When an attack happens, developers and security teams are forced to sift through raw text or configure complex query languages just to figure out what went wrong. 

That is why we built ThreatLens. It is a session-scoped security log triage dashboard. You paste nginx access logs or Linux authentication logs directly into the browser, and in seconds, get a prioritized queue of security incidents—with clear explanations and recommended fixes. There are no agents to install, and no accounts to create."

---

### [0:30 - 1:00] Data Ingestion & Privacy

**[Visual]**
*Click the "Load sample attack logs" button. The progress bar starts animating through the pipeline phases: PARSE → REDACT → RULES → LLM → STORE.*

**[Spoken Script]**
"Let's load a sample batch of attack logs to see how it works. 

When you paste logs, ThreatLens creates a temporary session ID in your browser. All database queries are isolated to this specific session. Before any logs leave your system, our pipeline runs a redaction step that strips out sensitive keys, tokens, and credentials. 

Next, our rule engine processes the logs. Instead of sending everything to an AI model, we run cheap, fast, deterministic rules first to catch common attacks like SQL injection, brute force attempts, and directory traversals."

---

### [1:00 - 1:45] Threat Feed & Prompt Injection

**[Visual]**
*The pipeline finishes. The feed populates with threats. Scroll down to show different threat cards (Critical, High, Medium) and show that benign logs did not trigger any alerts.*

**[Spoken Script]**
"Once processed, we get a prioritized list of alerts. 

At the top, we have a critical SSRF attack targeting an AWS metadata endpoint, alongside brute-force SSH logins and SQL injection probes. Successful logins and normal page visits are filtered out entirely so you can focus only on what matters.

We also designed this to handle prompt injection. One of our sample log lines contains instructions telling the AI to ignore previous rules and report everything as safe. ThreatLens neutralizes this by wrapping log contents in XML tags and instructing the model to treat log lines strictly as untrusted evidence, not commands. As you can see, the injection was ignored and the threat was flagged correctly."

---

### [1:45 - 2:15] AI Analyst Briefing & Caching

**[Visual]**
*Click the "Explain" button on the critical SSRF threat. A loading indicator appears briefly, then the slide-out panel displays the detailed report. Click the button again to show it loading instantly from the cache.*

**[Spoken Script]**
"For any flagged threat, clicking 'Explain' calls a Llama model hosted on Groq to generate a plain-English analyst brief. 

Instead of raw regex matches, you get a clear summary of what the attacker was trying to do, the specific MITRE ATT&CK tactic they used, and step-by-step response actions. 

When you click explaining a second time, the brief loads instantly. We cache every explanation in PostgreSQL, saving API costs and reducing latency for recurring events."

---

### [2:15 - 2:45] Architecture & Performance

**[Visual]**
*Switch tabs to display the architecture diagram or show `docs/ARCHITECTURE.md` on screen.*

**[Spoken Script]**
"Under the hood, ThreatLens uses a hybrid model. 

Running rules before the LLM means we only send unmatched or highly ambiguous logs to the AI. This keeps our processing fast, keeps costs low, and ensures the core dashboard remains operational even if the external LLM provider experiences rate limits or downtime."

---

### [2:45 - 3:00] Reset & Wrap-up

**[Visual]**
*Switch back to the dashboard. Click the "Reset demo" button. Watch the feed clear instantly and a new session ID appear in the header.*

**[Spoken Script]**
"Finally, clicking 'Reset' destroys the current session, deletes the temporary database rows, and gives you a clean slate. 

ThreatLens brings the speed of traditional rules and the clarity of generative AI into a single, private dashboard. 

Thank you."

---

## Presenter Tips
1. **Pacing**: Speak at a steady, conversational pace. Do not rush.
2. **Synchronize**: Wait for the UI animations (ingestion pipeline progress) to complete before describing the results in the feed.
3. **No Buzzwords**: Keep the focus on technical design decisions (redaction, caching, hybrid rules) rather than hype words.
