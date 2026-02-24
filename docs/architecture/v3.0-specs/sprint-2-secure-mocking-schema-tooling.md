# Sprint 2 Epic: Secure Mocking & Schema Tooling

## Epic Scope

This epic consolidates three security-first capabilities:

1. Zero-persistence Ghost Mocking Engine
2. Live Schema Introspection Dashboard
3. Fail-Closed Backend Scaffolding

## Security Invariants

- All mock responses are fulfilled from in-memory objects only (no filesystem persistence).
- Sensitive mock payloads require authenticated L3 override; otherwise values must be redacted.
- Schema introspection is redacted-by-default and only exposes real values in override mode.
- Generated server code must include `helmet()` and bind exclusively to `127.0.0.1`.
- Schema parsing must be strict and fail closed on unknown keys.

## Live Schema Introspection UI Technical Constraints

- Electron renderer/main communication must use `preload.js` + `contextBridge` only.
- Never expose `ipcRenderer` directly to renderer code; expose only whitelisted subscription methods.
- Renderer must support:
  - `onSchemaIntercepted` (incoming redacted schema payloads)
  - `onSecurityStateChanged` (safe/danger banner state updates)
- Dashboard banner behavior:
  - Safe mode: `REDACTED VIEW ACTIVE`
  - Danger mode: `RAW VALUES VISIBLE - L3 OVERRIDE ACTIVE`
- Zero-leakage policy: do not log intercepted schemas in browser console.

## Governance Rules

- Every PR must pass `node --test tests/security.integration.test.js`.
- Any use of AI assistants must include prompt context and validated reference snippet in the PR body.
- Any code path that weakens deny-by-default or fail-closed behavior is rejected.

## Operational Instructions for Codex Assistants

Initialize AI sessions with this mandate:

> "You are an expert Security Engineer reviewing Sprint 2 tasks for Project Mirror v3.0. You must strictly enforce zero-persistence for all mocking logic and redacted-by-default views for the Introspection UI. Any suggestion to use fs for sensitive data or 0.0.0.0 for server binding must be rejected. Refer to our Sprint 2 architecture specs for validated schema validation patterns."

## Ownership

- QA Automation Engineer: Playwright route interception + ghost fulfillment
- Front-End Engineer: schema tree UI and override-mode banners
- Backend/AI Specialist: secure scaffolding generation + strict schema checks

## Backend Scaffolder v3 Contract

- Module: `sprint2/backend-scaffolder-v3.js`
- Input is untrusted and must be validated with strict Zod object schemas (`.strict()`).
- Any unrecognized or malicious keys (e.g. `exec`, `spawn`) must hard-fail using `CRITICAL_SCHEMA_VALIDATION_FAILURE` and `process.exit(1)`.
- Generation is all-or-nothing: invalid schemas must not write partial files.
- Generated file must include:
  - `const helmet = require('helmet');`
  - `app.use(helmet());`
  - `app.listen(PORT, '127.0.0.1', ...)`
- Generated skeleton must remain minimal and avoid non-approved dependencies beyond `express`, `helmet`, and `zod`.

Required AI prompt context for backend scaffolder work:

> "Act as a Senior Backend Security Specialist for Project Mirror v3.0. Your task is to write a Node.js utility that transforms a redacted JSON schema into a production-hardened Express.js server. Requirements: 1. Use z.object().strict() for all schema parsing to prevent property injection. 2. The generated code string must start with const helmet = require('helmet'); app.use(helmet());. 3. The app.listen call must be hardcoded to 3000, '127.0.0.1'. 4. If the input JSON fails validation, the utility must emit a fatal error and process.exit(1)."
