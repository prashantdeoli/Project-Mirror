const { chromium } = require('playwright');

// Recursive Schema Redaction (Strips all PII/Values)
function redactJsonSchema(obj) {
    if (obj === null) return 'null';
    if (Array.isArray(obj)) return obj.map(redactJsonSchema);
    if (typeof obj === 'object') {
        const redacted = {};
        for (const key in obj) {
            redacted[key] = redactJsonSchema(obj[key]);
        }
        return redacted;
    }
    return typeof obj; // Returns primitive type strings
}

async function startSecureCrawler(url) {
    const browser = await chromium.launch();
    // Ephemeral Context & Service Worker Suppression
    const context = await browser.newContext({ serviceWorkers: 'block' });
    const page = await context.newPage();

    let totalDataCaptured = 0;
    const DATA_CAP = 100 * 1024 * 1024; // 100MB Total Budget

    // Strict Mutating-Method Routing
    await context.route('**/*', async (route) => {
        const method = route.request().method();
        if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method.toUpperCase())) {
            console.warn(`[Policy] Blocked mutating request: ${method} ${route.request().url()}`);
            return route.abort();
        }
        return route.continue();
    });

    // In-Memory Interception & Guardrails
    page.on('response', async (response) => {
        if (
            response.request().method() === 'GET' &&
            response.headers()['content-type']?.includes('application/json')
        ) {
            try {
                const bodyText = await response.text();

                if (bodyText.length > 2 * 1024 * 1024) {
                    console.warn('[Guardrail] Response exceeded 2MB. Skipped.');
                    return;
                }

                totalDataCaptured += bodyText.length;
                if (totalDataCaptured > DATA_CAP) throw new Error('100MB Session Cap Exceeded');

                const safeSchema = redactJsonSchema(JSON.parse(bodyText));
                console.log('[Redacted Schema Captured]', safeSchema);
            } catch (err) {
                console.error(`[Guardrail] Response processing failed: ${err.message}`);
                throw err;
            }
        }
    });

    await page.goto(url);
}

module.exports = {
    redactJsonSchema,
    startSecureCrawler,
};
