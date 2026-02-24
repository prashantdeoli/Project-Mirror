const { chromium } = require('playwright');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const { URL } = require('url');
const { buildSecureSandbox } = require('../ai/build-secure-sandbox');

const MAX_JSON_BYTES = 2 * 1024 * 1024;

function loadPublicKey() {
    try {
        return fs.readFileSync('public.pem', 'utf8');
    } catch (_error) {
        throw new Error('MISSING_PUBLIC_KEY');
    }
}

function verifyBridgeAccessOrExit(l3Token) {
    if (!l3Token) {
        console.error('UNAUTHORIZED_AI_BRIDGE: Missing L3 Token');
        process.exit(1);
    }

    try {
        const publicKey = loadPublicKey();
        jwt.verify(l3Token, publicKey, { algorithms: ['RS256'] });
    } catch (error) {
        if (error.message === 'MISSING_PUBLIC_KEY') {
            console.error('MISSING_PUBLIC_KEY');
            process.exit(1);
        }

        console.error(`UNAUTHORIZED_AI_BRIDGE: ${error.message}`);
        process.exit(1);
    }
}

function inferSchema(value) {
    if (value === null) return 'null';
    if (Array.isArray(value)) return 'array';
    return typeof value;
}

function extractBlueprintFromJson(responseUrl, method, parsedJson) {
    const routePath = new URL(responseUrl).pathname || '/';
    const responseSchema = {};

    if (parsedJson && typeof parsedJson === 'object' && !Array.isArray(parsedJson)) {
        for (const [key, value] of Object.entries(parsedJson)) {
            responseSchema[key] = inferSchema(value);
        }
    }

    return {
        routePath,
        method,
        responseSchema,
    };
}

async function startAiBridge({ targetUrl, l3Token }) {
    verifyBridgeAccessOrExit(l3Token);

    const browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({ serviceWorkers: 'block' });
    const page = await context.newPage();

    let generated = false;

    page.on('response', async (response) => {
        if (generated) return;

        const method = response.request().method().toUpperCase();
        if (method !== 'GET') return;

        const contentType = response.headers()['content-type'] || '';
        if (!contentType.includes('application/json')) return;

        try {
            const bodyText = await response.text();
            if (Buffer.byteLength(bodyText, 'utf8') > MAX_JSON_BYTES) {
                return;
            }

            const parsed = JSON.parse(bodyText);
            const blueprint = extractBlueprintFromJson(response.url(), method, parsed);
            buildSecureSandbox(JSON.stringify(blueprint));
            generated = true;
        } catch (_error) {
            process.exit(1);
        }
    });

    await page.goto(targetUrl);
    await browser.close();
}

module.exports = {
    extractBlueprintFromJson,
    startAiBridge,
    verifyBridgeAccessOrExit,
};
