const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');

// Public Key for RS256 Signature Verification
const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
[INSERT_AUTHORIZED_PUB_KEY]
-----END PUBLIC KEY-----`;

function engageL3Override() {
    const args = process.argv.slice(2);
    const isOverride = args.includes('--admin-override');
    const tokenArg = args.find((arg) => arg.startsWith('--token='));

    if (isOverride) {
        if (!tokenArg) {
            console.error('FATAL: Override requested without token. Exiting.');
            process.exit(1);
        }

        const token = tokenArg.split('=')[1];

        try {
            // Cryptographic Verification
            jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] });

            // Non-PII Token Fingerprinting
            const tokenHash = crypto
                .createHash('sha256')
                .update(token)
                .digest('hex')
                .substring(0, 16);
            const logEntry = `${new Date().toISOString()} | L3_OVERRIDE_ENGAGED | TokenFingerprint: ${tokenHash}\n`;

            // Immutable Audit Logging
            fs.appendFileSync('audit.log', logEntry, { flag: 'a' });

            // Mandatory Observability Banner
            console.log('\n==================================================');
            console.log(' ⚠️  LEVEL 3 MAINTENANCE OVERRIDE ACTIVE');
            console.log(' ⚠️  IMMUTABLE AUDIT LOGGING IS ENABLED');
            console.log('==================================================\n');

            return true;
        } catch (err) {
            console.error('FATAL: L3 Token verification failed.', err.message);
            process.exit(1); // Fail-Closed
        }
    }

    return false;
}

if (require.main === module) {
    engageL3Override();
}

module.exports = {
    engageL3Override,
};
