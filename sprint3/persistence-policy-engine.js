const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const { z } = require('zod');

const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
[INSERT_AUTHORIZED_PUB_KEY]
-----END PUBLIC KEY-----`;

const policySchema = z
    .object({
        policyVersion: z.string(),
        redactionMode: z.enum(['type-only', 'full-mask']),
        blockedMethods: z.array(z.enum(['POST', 'PUT', 'PATCH', 'DELETE'])).min(1),
    })
    .strict();

function failClosedStorageAccessDenied(reason = 'Unauthenticated cryptographic session') {
    console.error('STORAGE_ACCESS_DENIED');
    console.error(reason);
    process.exit(1);
}

function verifyL3TokenAndDeriveKey(token) {
    if (!token) {
        failClosedStorageAccessDenied('Missing L3 token.');
    }

    try {
        jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] });
        return crypto.createHash('sha256').update(token).digest();
    } catch (error) {
        failClosedStorageAccessDenied(error.message);
    }
}

function tokenFingerprint(token) {
    return crypto.createHash('sha256').update(token).digest('hex').substring(0, 16);
}

function encryptJsonPayload(payloadObject, token) {
    const key = verifyL3TokenAndDeriveKey(token);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const plaintext = Buffer.from(JSON.stringify(payloadObject), 'utf8');
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return {
        iv: iv.toString('base64'),
        authTag: authTag.toString('base64'),
        ciphertext: ciphertext.toString('base64'),
    };
}

function decryptJsonPayload(encryptedEnvelope, token) {
    const key = verifyL3TokenAndDeriveKey(token);
    const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        key,
        Buffer.from(encryptedEnvelope.iv, 'base64')
    );
    decipher.setAuthTag(Buffer.from(encryptedEnvelope.authTag, 'base64'));

    const decrypted = Buffer.concat([
        decipher.update(Buffer.from(encryptedEnvelope.ciphertext, 'base64')),
        decipher.final(),
    ]);

    return JSON.parse(decrypted.toString('utf8'));
}

function appendAuditEvent(token, action, auditLogPath = 'audit.log') {
    const fingerprint = tokenFingerprint(token);
    const entry = `${new Date().toISOString()} | ${action} | TokenFingerprint: ${fingerprint}\n`;
    fs.appendFileSync(auditLogPath, entry, { flag: 'a' });
}

function saveEncryptedMockConfig({ token, config, storagePath = 'mock-config.enc' }) {
    if (!token) failClosedStorageAccessDenied('Missing L3 token for save operation.');
    const envelope = encryptJsonPayload(config, token);
    fs.writeFileSync(storagePath, JSON.stringify(envelope));
    appendAuditEvent(token, 'PERSISTENCE_SAVE');
    return storagePath;
}

function loadEncryptedMockConfig({ token, storagePath = 'mock-config.enc' }) {
    if (!token) failClosedStorageAccessDenied('Missing L3 token for load operation.');
    const raw = fs.readFileSync(storagePath, 'utf8');
    const envelope = JSON.parse(raw);
    const config = decryptJsonPayload(envelope, token);
    appendAuditEvent(token, 'PERSISTENCE_LOAD');
    return config;
}

function loadCanonicalPolicy(policyPath) {
    const raw = fs.readFileSync(policyPath, 'utf8');
    const parsed = JSON.parse(raw);
    return policySchema.parse(parsed);
}

function syncPolicyFromRepo({
    repoRoot = process.cwd(),
    relativePolicyPath = 'docs/architecture/v3.0-specs/policy-sync.json',
}) {
    const resolved = path.resolve(repoRoot, relativePolicyPath);
    return loadCanonicalPolicy(resolved);
}

function detectPolicyDrift(localPolicy, canonicalPolicy) {
    return JSON.stringify(localPolicy) !== JSON.stringify(canonicalPolicy);
}

module.exports = {
    appendAuditEvent,
    decryptJsonPayload,
    detectPolicyDrift,
    encryptJsonPayload,
    failClosedStorageAccessDenied,
    loadCanonicalPolicy,
    loadEncryptedMockConfig,
    policySchema,
    saveEncryptedMockConfig,
    syncPolicyFromRepo,
    tokenFingerprint,
    verifyL3TokenAndDeriveKey,
};
