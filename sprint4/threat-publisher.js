const fs = require('fs');
const { z } = require('zod');
const jwt = require('jsonwebtoken');

const threatFingerprintSchema = z
    .object({
        hash: z.string().length(64),
        reason: z.string().min(5),
        timestamp: z.string().datetime(),
    })
    .strict();

function failClosedThreatPublish(message) {
    console.error(message);
    process.exit(1);
}

function publishThreatFingerprint(
    fingerprintData,
    l3Token,
    publicKey,
    policyPath = 'docs/architecture/v3.0-specs/policy-sync.json'
) {
    try {
        if (!l3Token) throw new Error('UNAUTHORIZED_THREAT_PUBLISH: Missing L3 Token');
        jwt.verify(l3Token, publicKey, { algorithms: ['RS256'] });

        const validatedThreat = threatFingerprintSchema.parse(fingerprintData);

        const rawPolicy = fs.readFileSync(policyPath, 'utf8');
        const policy = JSON.parse(rawPolicy);

        if (!Array.isArray(policy.knownBadFingerprints)) {
            policy.knownBadFingerprints = [];
        }

        const alreadyPresent = policy.knownBadFingerprints.some((entry) => entry.hash === validatedThreat.hash);
        if (!alreadyPresent) {
            policy.knownBadFingerprints.push(validatedThreat);
            fs.writeFileSync(policyPath, JSON.stringify(policy, null, 2));
            fs.appendFileSync(
                'audit.log',
                `${new Date().toISOString()} | LEVEL_4_THREAT_PUBLISHED | Hash: ${validatedThreat.hash}\n`,
                { flag: 'a' }
            );
        }

        return true;
    } catch (error) {
        const message = error.message && error.message.startsWith('UNAUTHORIZED_THREAT_PUBLISH')
            ? error.message
            : `CRITICAL_SCHEMA_VALIDATION_FAILURE: ${error.message}`;
        failClosedThreatPublish(message);
    }
}

module.exports = {
    failClosedThreatPublish,
    publishThreatFingerprint,
    threatFingerprintSchema,
};
