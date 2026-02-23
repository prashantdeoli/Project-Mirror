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
