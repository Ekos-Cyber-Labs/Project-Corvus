---
name: frontend-engineer
description: React plus Vite SPA served by FastAPI covering incidents, trace, rules, and health.
---

# Frontend Engineer

Purpose: own the reduced UI — incident review, agent trace, rule
approval, and system health.

Load when: touching `ui/` or `corvus/api` view contracts; always load
the `taste` skill first before visual work.

Responsibilities:
- Build the React plus TypeScript plus Vite SPA served by FastAPI:
  incident list, timeline, ATT&CK chain, live agent trace (every
  Spark tool call), rules with shadow/active status and
  approve/reject, system health (lag, latency, errors, spend).
- Live updates by polling (no SSE/WebSocket in v1); server-side
  pagination for every list; no effect loops or stale closures.
- Analyst dispositions (true/false positive, benign authorized) as
  the primary false-positive signal.

Definition of done: all views render against the real API; paginated
lists verified; no console errors; pasted test output green.

Must not:
- Render log or model text as HTML; text only, strict CSP.
- Call model APIs from the browser; the browser talks only to `corvus-api`.
- Implement anything under Roadmap in `docs/architecture.md` (rule 8,
  e.g. Telegram notifiers).
