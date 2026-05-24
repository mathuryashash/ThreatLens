# UI/UX Specification — ThreatLens

## Page Structure

Single page application. One route: `/`. No navigation.

```
┌──────────────────────────────────────────────────────────┐
│  [Logo + Title]            [Session ID badge] [Reset]     │
├──────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌───────────────────────────────┐  │
│  │  Upload Panel   │  │  Stats Cards                  │  │
│  │                 │  │  [CRITICAL 2] [HIGH 4] [MED 3]│  │
│  │  [Log textarea] │  └───────────────────────────────┘  │
│  │  [Source type]  │                                      │
│  │  [Analyze btn]  │  ┌───────────────────────────────┐  │
│  │  [Sample logs]  │  │  Threat Feed                  │  │
│  │  [Progress bar] │  │  ┌─────────────────────────┐  │  │
│  └─────────────────┘  │  │ [CRITICAL] SSRF          │  │  │
│                       │  │ 169.254.169.254 attempt  │  │  │
│                       │  │ 203.0.113.99 · 14:35:00  │  │  │
│                       │  │            [Explain ▶]   │  │  │
│                       │  └─────────────────────────┘  │  │
│                       │  ┌─────────────────────────┐  │  │
│                       │  │ [HIGH]    BRUTE_FORCE    │  │  │
│                       │  │ 15 SSH failures from IP  │  │  │
│                       │  │            [Explain ▶]   │  │  │
│                       │  └─────────────────────────┘  │  │
│                       └───────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

---

## Components

### Header

- Left: product name "ThreatLens" + shield icon
- Right: truncated session ID (`sess-...abcd`) as muted text badge, "Reset demo" button
- Background: dark (slate-900 or similar)

### Upload Panel

**Log textarea**
- Placeholder: `Paste nginx access logs or Linux auth logs here...`
- Min height: 200px
- Monospace font
- Resize: vertical only

**Source type selector**
- Segmented control or `<select>`: `nginx` | `auth` | `custom`
- Default: `nginx`

**Action buttons** (stacked or side by side)
- Primary: **"Analyze"** — disabled while session is loading or job is in progress
- Secondary: **"Load sample attack logs"** — outline style
- Both disabled during active job

**Progress bar**
- Shows only while a job is `queued` or `processing`
- Displays: "Processing {processed}/{total} logs..."
- Disappears when job reaches `completed` or `failed`
- On `failed`: show "Some logs could not be processed" warning (non-blocking)

**Empty state**: nothing shown in the upload panel when no job is active

---

### Stats Cards

Four cards in a row (or 2×2 on narrow screens):

| Card | Color | Value |
|------|-------|-------|
| CRITICAL | Red (red-500) | count of severity='CRITICAL' |
| HIGH | Orange (orange-500) | count of severity='HIGH' |
| MEDIUM | Yellow (yellow-500) | count of severity='MEDIUM' |
| LOW | Blue (blue-400) | count of severity='LOW' |

All values are derived from the in-memory threats array — no API call.

---

### Threat Feed

**Container**: scrollable list, newest threats at top.

**Empty state**: 
```
No threats detected.
Upload logs or load sample attack logs to get started.
```

**Loading state**: spinner while first poll hasn't returned yet after ingest.

**Threat Card**:
```
┌─────────────────────────────────────────────────┐
│  [CRITICAL badge]  SSRF                         │
│  AWS metadata endpoint access attempt            │
│  203.0.113.99  ·  rule  ·  2025-05-23 14:35:00  │
│                              [Explain ▶]         │
└─────────────────────────────────────────────────┘
```

- **Severity badge**: pill-shaped, colored by severity (see below)
- **Threat type**: bold, e.g. "SSRF", "SQLI", "BRUTE_FORCE"
- **Summary**: one line, 20 words max — as returned by API
- **Source IP**: monospace
- **Classification source**: small muted text — "rule" or "ai"
- **Timestamp**: `YYYY-MM-DD HH:MM:SS` in local time
- **Explain button**: text button with arrow — only visible if explain quota > 0

**Severity colors**:
| Severity | Badge color | Text |
|----------|------------|------|
| CRITICAL | red-600 bg | white |
| HIGH | orange-500 bg | white |
| MEDIUM | yellow-400 bg | black |
| LOW | blue-400 bg | white |
| INFO | gray-400 bg | white |

---

### Explain Panel

Appears as a slide-over from the right (or a modal on smaller screens). Opens when "Explain" is clicked.

**Loading state**: spinner + "Getting AI explanation..."

**Loaded state**:
```
┌─────────────────────────────────────────────────┐
│  SSRF — CRITICAL          [Cached ✓]  [✕ Close] │
├─────────────────────────────────────────────────┤
│  MITRE: Initial Access                           │
│                                                 │
│  Explanation                                    │
│  The attacker sent a request to the AWS         │
│  metadata endpoint (169.254.169.254) via the    │
│  /proxy endpoint. This is a classic SSRF attack │
│  targeting cloud credential exposure...          │
│                                                 │
│  Recommended Actions                            │
│  • Block outbound requests to 169.254.x.x       │
│  • Audit /proxy for SSRF mitigations            │
│  • Check if any 200 responses preceded this     │
│  • Review IAM role permissions on this instance │
└─────────────────────────────────────────────────┘
```

- "Cached ✓" indicator shown if `cached: true` in API response
- MITRE tactic rendered as a colored pill
- Explanation in paragraph form
- Recommended actions as a bulleted list
- All text content must be rendered as plain text — never HTML-rendered

**Error state**: "Could not generate explanation. Try again." with retry button.

---

## Severity Color Reference (Tailwind)

```
CRITICAL → bg-red-600 text-white
HIGH     → bg-orange-500 text-white
MEDIUM   → bg-yellow-400 text-black
LOW      → bg-blue-400 text-white
INFO     → bg-gray-400 text-white
```

---

## User Flow

```
Load page
  → session auto-created (or restored from localStorage)
  → empty threat feed

Click "Load sample attack logs"
  → POST /api/ingest with sample logs
  → progress bar appears
  → job polls complete
  → threat feed populates (via 3s polling)
  → stats cards update

Click "Explain" on a threat
  → POST /api/explain
  → explain panel slides in
  → explanation + MITRE + recommended actions shown

Click "Explain" again (same threat)
  → instant return, "Cached ✓" shows

Click "Reset demo"
  → new session created
  → threat feed clears
  → stats reset to 0
```

---

## Error States

| Scenario | UI Response |
|----------|-------------|
| Ingest fails (quota exceeded) | Toast: "Session quota reached (500 logs max)" |
| Ingest fails (server error) | Toast: "Upload failed. Try again." |
| Explain fails (quota) | Button disabled after 10 calls; tooltip: "Explanation quota used" |
| Explain fails (server error) | Panel shows: "Could not generate explanation" + retry button |
| Network offline | Toast: "Connection lost. Retrying..." |
| Session expired | Auto-create new session; clear feed; toast: "Session expired — starting fresh" |

---

## Accessibility Notes

- Severity badges have sufficient color contrast (white on red/orange/blue)
- Yellow MEDIUM badge uses black text for contrast
- All interactive elements have focus rings
- Explain panel is keyboard-dismissible (Escape)
- Threat feed items are readable without color (type label always shown as text)
