# ADR 0004 — Use Session IDs for Demo Isolation Instead of User Authentication

**Status**: Accepted

## Context

The application needs some form of isolation so that User A's logs and threats are not visible to User B. Building full user authentication (email/password, OAuth, JWT, refresh tokens) is significant scope for a 48-hour hackathon.

## Decision

Use server-generated UUIDv4 session tokens stored in browser `localStorage`. Sessions are created automatically on first load. All data is scoped to `session_id`. Sessions expire after 24 hours.

This is explicitly not authentication — it is namespace isolation for demo purposes.

## Alternatives Considered

**Supabase Auth**: Full auth with email/password and OAuth. Correct for production, but 4–8 hours of additional scope in a 48-hour build. Out of scope.

**No isolation**: Single shared database visible to all users. Unacceptable — users' logs would be visible to everyone.

**Cookie-based session**: Similar security properties to localStorage for a same-origin app with no XSS vulnerabilities. Either would work; localStorage is simpler to implement and inspect during development.

## Consequences

- Zero authentication overhead in the build
- Session IDs are not cryptographically bound to a user — anyone with the UUID can see that session's data
- Session ID in localStorage is accessible to any XSS on the origin (acceptable: no XSS in this app + demo scope)
- Must be communicated honestly to judges: "Session IDs are demo-scoped namespace tokens, not authentication credentials"
- Production version would replace this with Supabase Auth + proper RLS (see ROADMAP.md)
