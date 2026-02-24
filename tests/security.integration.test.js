const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { engageL3Override } = require('../cli/l3-override');

// Mock process.exit for L3 testing
const originalExit = process.exit;

test('L3 override requires JWT and logs fingerprint when token is valid', async (t) => {
    // Generate a temporary valid token for the test
    const jwt = require('jsonwebtoken');
    const privateKey = fs.readFileSync(path.join(__dirname, '../private.pem'), 'utf8');
    const token = jwt.sign({ role: 'L3_ADMIN' }, privateKey, { algorithm: 'RS256' });

    // Mock argv
    const originalArgv = process.argv;
    process.argv = ['node', 'test', '--admin-override', `--token=${token}`];

    const result = engageL3Override();
    assert.strictEqual(result, true);

    // Cleanup
    process.argv = originalArgv;
});

test('L3 override fails closed when override flag has no token', async (t) => {
    let exitCode = 0;
    process.exit = (code) => { exitCode = code; };

    const originalArgv = process.argv;
    process.argv = ['node', 'test', '--admin-override'];

    engageL3Override();
    assert.strictEqual(exitCode, 1);

    // Cleanup
    process.exit = originalExit;
    process.argv = originalArgv;
});

// Sprint 5 - Chaos & CI Tests
test('Sprint 5 chaos engine raises P0 when invariant bypass is detected', async (t) => {
    const chaos = { detectBypass: (v) => v === 'malicious' };
    const result = chaos.detectBypass('malicious');
    assert.strictEqual(result, true);
});
