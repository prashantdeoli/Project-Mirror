# Project Mirror v4.0 Architecture Plan

**Phase:** v4.0 Architecture Planning  
**Security Posture:** Proactive-by-Design / Self-Correcting

## Modules

1. **Heuristic Redaction Engine**
   - Semantic masking for PII/JWT/API-key/card patterns.
   - Fail-closed fallback to `[CONFIDENTIAL_<TYPE>]` when confidence < 95%.
   - No third-party parsing libraries.

2. **Self-Healing Invariants**
   - Runtime drift automatically remediated to canonical policy state.
   - Every auto-heal action appends `LEVEL_4_CRITICAL_AUTO_FIX` to `audit.log`.
   - If remediation cannot restore canonical invariants, process must hard-exit.

3. **Threat-Intelligence Sync**
   - Malformed blocked payloads are structurally fingerprinted.
   - Fingerprints are appended to canonical policy as `knownBadFingerprints`.
   - Publishing is cryptographically gated by L3 RS256 JWT verification.
   - Fingerprint objects are validated with strict Zod schema before append.
   - Unauthorized publish or invalid schema must fail closed and terminate.

4. **Intelligent Dashboard Integration (Context-Isolated IPC)**
   - UI remains a display-only terminal for pre-sanitized backend intelligence.
   - `electron/preload.js` must expose only whitelisted listeners:
     - `onSchemaIntercepted`
     - `onSecurityStateChanged`
     - `onCriticalAutoFix`
   - Dashboard rendering behavior:
     - Smart-masked strings rendered in cyan.
     - Fail-closed `[CONFIDENTIAL_*]` strings rendered in orange warning style.
     - `LEVEL_4_CRITICAL_AUTO_FIX` event displayed via persistent alert banner.

## Operational AI Prompt

> "You are the Lead AI Security Architect for Project Mirror v4.0. Your mandate is to design autonomous, self-healing security modules.
> Strict Requirements:
> 1. All pattern recognition and heuristic data masking must utilize our existing Zod infrastructure (z.string().regex(), etc.) and default to fail-closed redaction upon uncertainty.
> 2. Do not introduce new third-party parsing libraries.
> 3. Any auto-remediation scripts must execute a hard exit (process.exit(1)) if they cannot successfully restore the configuration to the canonical Git-Ops state.
> 4. Ensure every self-healing action writes a cryptographic fingerprint to the immutable audit log."

## Gate

```bash
node --test tests/security.integration.test.js
```

## Threat Publisher Module Contract

- Module: `sprint4/threat-publisher.js`
- Required input object schema:
  - `hash`: 64-char SHA-256 hex string
  - `reason`: non-trivial reason string
  - `timestamp`: ISO datetime string
- Strict validation via `z.object(...).strict()` to prevent feed poisoning.
- Auth gate: valid L3 RS256 token required prior to policy mutation.
- Atomic read-append-write semantics: no audit success event without successful write.
