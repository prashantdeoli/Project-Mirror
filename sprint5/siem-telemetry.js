const fs = require('fs');
const https = require('https');

function queueTelemetryLocally(event, queuePath = 'telemetry-queue.enc') {
    const existing = fs.existsSync(queuePath) ? JSON.parse(fs.readFileSync(queuePath, 'utf8')) : [];
    existing.push(event);
    fs.writeFileSync(queuePath, JSON.stringify(existing));
}

function sendTelemetryOverMtls({ endpoint, event, tlsOptions, queuePath = 'telemetry-queue.enc' }) {
    return new Promise((resolve) => {
        const req = https.request(endpoint, {
            method: 'POST',
            cert: tlsOptions.cert,
            key: tlsOptions.key,
            ca: tlsOptions.ca,
            rejectUnauthorized: true,
            headers: { 'content-type': 'application/json' },
        }, (res) => {
            if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
                resolve({ delivered: true });
            } else {
                queueTelemetryLocally(event, queuePath);
                resolve({ delivered: false, queued: true });
            }
        });

        req.on('error', () => {
            queueTelemetryLocally(event, queuePath);
            resolve({ delivered: false, queued: true });
        });

        req.write(JSON.stringify(event));
        req.end();
    });
}

module.exports = { queueTelemetryLocally, sendTelemetryOverMtls };
