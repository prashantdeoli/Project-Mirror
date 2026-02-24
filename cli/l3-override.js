const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

function engageL3Override() {
    const args = process.argv.slice(2);
    const isOverride = args.includes('--admin-override');
    const tokenArg = args.find((arg) => arg && arg.startsWith('--token='));

    if (isOverride) {
        // Strict Check: Agar token argument hi nahi hai, toh turant exit
        if (!tokenArg) {
            console.error('FATAL: Override requested without token. Exiting.');
            process.exit(1);
            return false; // Test safety
        }

        const parts = tokenArg.split('=');
        const token = parts[1];

        if (!token) {
            console.error('FATAL: Empty token provided. Exiting.');
            process.exit(1);
            return false;
        }

        try {
            const publicKeyPath = path.join(__dirname, '../public.pem');
            const PUBLIC_KEY = fs.readFileSync(publicKeyPath, 'utf8');

            jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] });

            const tokenHash = crypto.createHash('sha256').update(token).digest('hex').substring(0, 16);
            fs.appendFileSync('audit.log', `${new Date().toISOString()} | L3_OVERRIDE_ENGAGED | ${tokenHash}\n`);

            console.log('\n==================================================');
            console.log(' ⚠️  LEVEL 3 MAINTENANCE OVERRIDE ACTIVE');
            console.log('==================================================\n');

            return true;
        } catch (err) {
            console.error('FATAL: L3 Token verification failed.', err.message);
            process.exit(1);
            return false;
        }
    }
    return false;
}

if (require.main === module) { engageL3Override(); }
module.exports = { engageL3Override };
