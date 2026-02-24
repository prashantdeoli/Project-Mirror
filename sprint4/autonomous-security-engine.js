const crypto = require('crypto');
const fs = require('fs');
const { z } = require('zod');

const heuristicInputSchema = z
    .object({
        key: z.string(),
        value: z.unknown(),
    })
    .strict();

const canonicalPolicySchema = z
    .object({
        policyVersion: z.string(),
        redactionMode: z.enum(['type-only', 'full-mask']),
        blockedMethods: z.array(z.enum(['POST', 'PUT', 'PATCH', 'DELETE'])).min(1),
        knownBadFingerprints: z.array(z.string()).optional(),
    })
    .strict();

function strictTypeString(value) {
    if (value === null) return 'null';
    if (Array.isArray(value)) return 'array';
    return typeof value;
}

function heuristicMaskField(untrustedField) {
    const field = heuristicInputSchema.parse(untrustedField);
    const key = field.key.toLowerCase();
    const value = String(field.value ?? '');

    const rules = [
        {
            type: 'jwt',
            confidence: key.includes('token') && value.split('.').length === 3 ? 0.99 : 0.0,
            masked: '[SAFE_JWT_TOKEN]'
        },
        {
            type: 'apiKey',
            confidence: key.includes('api') && key.includes('key') && value.length >= 16 ? 0.97 : 0.0,
            masked: '[SAFE_API_KEY]'
        },
        {
            type: 'creditCard',
            confidence: key.includes('card') && /^\d{13,19}$/.test(value.replace(/\s|-/g, '')) ? 0.99 : 0.0,
            masked: '[SAFE_CARD_TOKEN]'
        },
        {
            type: 'pii',
            confidence: key.includes('email') && value.includes('@') ? 0.96 : 0.0,
            masked: '[SAFE_EMAIL]'
        },
    ];

    const best = rules.sort((a, b) => b.confidence - a.confidence)[0];
    if (!best || best.confidence < 0.95) {
        return {
            classification: 'unknown',
            confidence: best ? best.confidence : 0.0,
            redacted: `[CONFIDENTIAL_${strictTypeString(field.value).toUpperCase()}]`,
            failClosedFallback: true,
        };
    }

    return {
        classification: best.type,
        confidence: best.confidence,
        redacted: best.masked,
        failClosedFallback: false,
    };
}

function auditCriticalAutoFix(details, auditLogPath = 'audit.log') {
    const fingerprint = crypto.createHash('sha256').update(JSON.stringify(details)).digest('hex').substring(0, 16);
    const entry = `${new Date().toISOString()} | LEVEL_4_CRITICAL_AUTO_FIX | Fingerprint: ${fingerprint}\n`;
    fs.appendFileSync(auditLogPath, entry, { flag: 'a' });
    return fingerprint;
}

function selfHealPolicy({ localPolicy, canonicalPolicy, l3Authorized = false, auditLogPath = 'audit.log' }) {
    const canonical = canonicalPolicySchema.parse(canonicalPolicy);
    const local = canonicalPolicySchema.parse(localPolicy);

    const driftDetected = JSON.stringify(local) !== JSON.stringify(canonical);
    if (!driftDetected) {
        return { healed: false, policy: local };
    }

    if (!l3Authorized) {
        auditCriticalAutoFix({ reason: 'UNAUTHORIZED_OVERRIDE_DURING_SELF_HEAL', local, canonical }, auditLogPath);
    }

    const healedPolicy = { ...canonical };
    auditCriticalAutoFix({ reason: 'SELF_HEAL_APPLIED', healedPolicy }, auditLogPath);
    return { healed: true, policy: healedPolicy };
}

function appendKnownBadFingerprint({ payload, policyPath }) {
    const raw = fs.readFileSync(policyPath, 'utf8');
    const policy = canonicalPolicySchema.parse(JSON.parse(raw));
    const fingerprint = crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');

    const next = {
        ...policy,
        knownBadFingerprints: Array.from(new Set([...(policy.knownBadFingerprints || []), fingerprint])),
    };

    fs.writeFileSync(policyPath, JSON.stringify(next, null, 2));
    return fingerprint;
}

module.exports = {
    appendKnownBadFingerprint,
    auditCriticalAutoFix,
    canonicalPolicySchema,
    heuristicMaskField,
    selfHealPolicy,
};
