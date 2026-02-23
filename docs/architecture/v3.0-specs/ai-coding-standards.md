# Project Mirror v3.0 AI Coding Standards (Locked)

**Status:** Architecture Locked  
**Posture:** Paranoid-by-Design  
**Phase:** Sprint 1 Execution Ready  
**Engineering Lead:** Prashant Deoli  
**Date:** February 23, 2026

## 1) Executive Summary

Project Mirror v3.0 operates with an Assume-Breach mindset. Security is enforced as **mechanical invariants** in code, not optional policy. All implementation and AI-assisted generation must preserve fail-closed behavior and deny-by-default boundaries.

## 2) Core Implementation Modules (Answer Key)

### A. Fortress Shell (Electron Container)

- `nodeIntegration: false`
- `contextIsolation: true`
- `sandbox: true`
- Fail-closed startup assertion if any invariant is compromised.
- Default-deny handlers for permission requests, downloads, and new windows.

### B. Interception Engine (Playwright Crawler)

- Non-persistent context with `serviceWorkers: 'block'`.
- Aborts mutating methods: `POST`, `PUT`, `PATCH`, `DELETE`.
- Recursive in-memory redaction replacing values with JS type strings.
- Resource guardrails: 2MB per-response cap and 100MB total session cap.

### C. L3 Cryptographically Gated Override

- Requires `--admin-override --token=<JWT>`.
- RS256 JWT verification against hardcoded public key.
- Appends immutable audit entries with SHA-256 token fingerprint in `audit.log`.
- Emits persistent elevated-mode terminal banner.
- Any verification error must fail closed (`process.exit(1)`).

### D. AI Output Guardrails (Fail-Closed Generation)

- Validate LLM JSON with strict Zod schema (`.strict()`).
- Reject unknown fields and malformed payloads with fail-closed exit.
- Generated Express scaffold must include `app.use(helmet())`.
- Generated server must bind only to `127.0.0.1`.

## 3) Verification & Testing Protocol

Primary audit command:

```bash
node --test tests/security.integration.test.js
```

Verification checklist:

- [ ] Electron: Node APIs remain inaccessible from renderer boundaries.
- [ ] Crawler: Mutating requests are aborted via `route.abort()`.
- [ ] Override: L3 activation fails without valid RS256 token.
- [ ] AI Validator: Strict schema rejects unrecognized keys (e.g. `exec`).

## 4) Required AI Assistant System Prompt

Use this exact context when generating code:

> "You are an expert Security Engineer for Project Mirror v3.0. Adhere strictly to the 'Paranoid-by-Design' appendix. All code must prioritize fail-closed logic, zero-trust input validation via Zod, and absolute isolation in Electron. Refer to the docs/architecture/v3.0-specs/ai-coding-standards.md for validated code snippets before generating any new logic."

## 5) Final Approval

This architecture and implementation phase is officially **Locked**. Sprint 1 feature development is **Green-Lit**.
