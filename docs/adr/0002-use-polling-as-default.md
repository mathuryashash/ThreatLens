# ADR 0002 — Use Polling Instead of Supabase Realtime

**Status**: Accepted

## Context

The frontend needs to display new threats as they are detected — a "near-realtime" feed. Two options: polling the REST API on an interval, or using Supabase Realtime (WebSocket-based push).

## Decision

Use polling every 3 seconds as the official MVP implementation. Supabase Realtime is post-MVP only.

## Alternatives Considered

**Supabase Realtime**: Lower latency, true push delivery, no wasted requests. But requires Supabase Row Level Security (RLS) policies to be correctly configured before enabling — without RLS, a browser WebSocket subscription could potentially receive events from other sessions. Verifying RLS isolation requires additional testing time we don't have in the hackathon window.

**Server-Sent Events (FastAPI)**: Push from backend without Supabase. Requires persistent connection management, reconnection handling, and introduces statefulness to the backend.

## Consequences

- Threat feed has up to 3s latency — acceptable for demo purposes
- No RLS risk at the browser subscription level
- The `since=ISO_TIMESTAMP` cursor makes polling efficient — only new threats fetched per tick
- Simple to implement and debug
- Polling can be replaced with Supabase Realtime in v1.1 once RLS is verified
