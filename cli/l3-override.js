const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');

function loadPublicKey() {
    try {
        return fs.readFileSync('public.pem', 'utf8');
    } catch (_error) {
        throw new Error('MISSING_PUBLIC_KEY');
    }
}

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
            const publicKey = loadPublicKey();

            // Cryptographic Verification
            jwt.verify(token, publicKey, { algorithms: ['RS256'] });

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
            if (err.message === 'MISSING_PUBLIC_KEY') {
                console.error('MISSING_PUBLIC_KEY');
                process.exit(1);
            }

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
    loadPublicKey,
};
