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
