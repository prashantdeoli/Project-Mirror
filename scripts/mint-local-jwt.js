const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

try {
    // Look for private.pem in the root folder (one level up from scripts/)
    const privateKeyPath = path.join(__dirname, '../private.pem');
    const privateKey = fs.readFileSync(privateKeyPath, 'utf8');

    const token = jwt.sign(
        { role: 'L3_ADMIN', user: 'local-dev' }, 
        privateKey, 
        { algorithm: 'RS256', expiresIn: '1h' }
    );

    console.log('\n==================================================');
    console.log(' ✅ NEW RSA-SIGNED TOKEN GENERATED');
    console.log('==================================================');
    console.log(token);
    console.log('==================================================\n');
} catch (err) {
    console.error('❌ Error generating token:', err.message);
}
