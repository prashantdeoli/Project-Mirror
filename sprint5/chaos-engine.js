const crypto = require('crypto');

function buildChaosPayloads() {
    return [
        { routePath: '/ok', method: 'GET', responseSchema: { a: 'string' }, exec: 'rm -rf /' },
        { routePath: '/huge', method: 'GET', responseSchema: { blob: 'x'.repeat(3 * 1024 * 1024) } },
        { routePath: '/weird', method: 'TRACE', responseSchema: { status: 'string' } },
        { routePath: '/l3', method: 'POST', token: 'invalid.jwt.token' },
    ];
}

function evaluateChaosResults(results) {
    const bypassed = results.filter((r) => r.passedUnexpectedly);
    if (bypassed.length > 0) {
        const fp = crypto.createHash('sha256').update(JSON.stringify(bypassed)).digest('hex');
        return { p0: true, reason: 'INVARIANT_BREACH_DETECTED', fingerprint: fp };
    }
    return { p0: false };
}

function runChaosCycle(executor) {
    const payloads = buildChaosPayloads();
    const results = payloads.map((payload) => executor(payload));
    return evaluateChaosResults(results);
}

module.exports = { buildChaosPayloads, evaluateChaosResults, runChaosCycle };
