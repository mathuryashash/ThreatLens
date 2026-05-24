# System Architecture — ThreatLens

## High-Level Component Diagram

```mermaid
flowchart LR
    subgraph Client
        A[User Browser\nNext.js 16]
    end

    subgraph Vercel
        B[Next.js App\nApp Router SSR]
    end

    subgraph Railway
        C[FastAPI Backend]
        D[Rule Engine]
        E[Groq LLM Client]
        F[Parser + Redactor]
    end

    subgraph Supabase
        G[(PostgreSQL)]
    end

    subgraph Groq_API
        H[llama-3.1-8b-instant\nClassifier]
        I[llama-3.3-70b-versatile\nExplainer]
    end

    A -->|HTTP| B
    B -->|API calls| C
    C --> F
    F --> D
    F --> E
    D -->|write threats| G
    E --> H
    E --> I
    H -->|write threats| G
    C -->|read threats| G
    B -->|poll /api/threats every 3s| C
```

---

## Data Flow Diagram

```mermaid
flowchart TD
    U[User] -->|upload logs| FE[Next.js Frontend]
    FE -->|POST /api/ingest| BE[FastAPI]
    BE -->|store| RL[(raw_logs)]
    BE -->|store| JOB[(ingestion_jobs)]
    BE -->|return job_id| FE

    RL -->|async background| PARSE[Parser]
    PARSE -->|normalize + match| RULE[Rule Engine]
    PARSE -->|redact copy| REDACT[Redacted Content]

    RULE -->|match found| T1[(threats - rule)]
    REDACT -->|no rule match| GROQ[Groq Classifier]
    GROQ -->|findings| T2[(threats - ai)]

    FE -->|GET /api/threats?since=...| BE
    BE -->|read| T1
    BE -->|read| T2
    BE -->|return threats| FE

    FE -->|user clicks explain| BE2[FastAPI /explain]
    BE2 -->|check cache| T3[(threats.explanation)]
    T3 -->|null → call Groq| GROQ2[Groq Explainer]
    GROQ2 -->|cache + return| FE
    T3 -->|cached → return| FE
```

---

## Processing Pipeline (Per Log Batch)

```mermaid
flowchart LR
    RAW[raw_content\nimmutable] --> NORM[normalize_for_matching\nURL-decode, HTML-decode, lowercase]
    RAW --> REDACT[redact secrets\n→ redacted_content]

    NORM --> RULE{Rule Engine}
    RULE -->|pattern match| THREAT_RULE[threat\nclassification_source=rule]
    RULE -->|no match| BATCH[batch unmatched logs]

    REDACT --> BATCH
    BATCH --> GROQ[Groq Llama 8B\nclassify]
    GROQ --> VALIDATE[validate + sanitize\nJSON response]
    VALIDATE -->|ok| THREAT_AI[threat\nclassification_source=ai]
    VALIDATE -->|fail| FAILED[mark batch failed\nincrement failed_logs\ncontinue job]
```

---

## Polling Loop (Frontend)

```mermaid
sequenceDiagram
    participant FE as Next.js
    participant BE as FastAPI
    participant DB as Supabase

    FE->>BE: GET /api/threats?session_id=X
    BE->>DB: SELECT threats WHERE session_id=X ORDER BY detected_at DESC
    DB-->>BE: threats[]
    BE-->>FE: { threats[], total, by_severity }
    FE->>FE: update feed + since cursor

    loop every 3 seconds
        FE->>BE: GET /api/threats?session_id=X&since=T
        BE->>DB: SELECT threats WHERE session_id=X AND detected_at > T
        DB-->>BE: new_threats[]
        BE-->>FE: { threats: new_threats[] }
        FE->>FE: append to feed
    end
```

---

## Explain Flow

```mermaid
sequenceDiagram
    participant FE as Next.js
    participant BE as FastAPI
    participant DB as Supabase
    participant GR as Groq

    FE->>BE: POST /api/explain { session_id, threat_id }
    BE->>DB: fetch threat (check session_id match + quota)
    alt explanation cached
        DB-->>BE: threat.explanation != null
        BE-->>FE: { explanation, mitre_tactic, recommended_actions, cached: true }
    else not cached
        BE->>GR: Llama 70B explain prompt
        GR-->>BE: explanation + mitre + actions
        BE->>DB: UPDATE threats SET explanation=...
        BE-->>FE: { explanation, mitre_tactic, recommended_actions, cached: false }
    end
```

---

## Component Responsibilities

| Component | Responsibility |
|-----------|---------------|
| Next.js App Router | Session init, log upload UI, polling loop, threat feed render, explain panel |
| FastAPI | Request validation, async processing orchestration, quota enforcement, CORS |
| Parser | Extract IP, timestamp, username, action from nginx/auth log lines |
| Redactor | Replace secrets in a copy of raw_content before LLM sees it |
| Rule Engine | Pattern + correlation matching on normalized text; writes rule-sourced threats |
| Groq Client | Batch classification + single-threat explanation; JSON validation; semaphore |
| Supabase | Persistent storage; threat/event linking; session lifecycle |

---

## Polling vs Realtime Decision

**MVP uses polling every 3 seconds.**

| Approach | Status | Reason |
|----------|--------|--------|
| Polling (3s) | **Official MVP** | Simple, reliable, no RLS required |
| Supabase Realtime | Post-MVP only | Requires verified session-level RLS before enabling; browser subscriptions must not leak cross-session data |

The `since=ISO_TIMESTAMP` cursor on `/api/threats` makes polling efficient — only new threats are fetched on each tick.

---

## Deployment Topology

```
┌─────────────────────────────────────────────────┐
│  Vercel (free)                                  │
│  ┌────────────────────────────────────────────┐ │
│  │  Next.js 16 App                            │ │
│  │  NEXT_PUBLIC_API_URL = Railway URL         │ │
│  └────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────┘
              │ HTTPS API calls
┌─────────────────────────────────────────────────┐
│  Railway (free)                                 │
│  ┌────────────────────────────────────────────┐ │
│  │  FastAPI (uvicorn)                         │ │
│  │  CORS: FRONTEND_ORIGIN only               │ │
│  │  GROQ_API_KEY (env var)                   │ │
│  │  SUPABASE_SERVICE_ROLE_KEY (env var)      │ │
│  └────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────┘
              │ Supabase client
┌─────────────────────────────────────────────────┐
│  Supabase (free)                                │
│  ┌────────────────────────────────────────────┐ │
│  │  PostgreSQL                                │ │
│  │  service_role_key: backend only           │ │
│  │  anon_key: frontend read-only (future)    │ │
│  └────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────┘
```
