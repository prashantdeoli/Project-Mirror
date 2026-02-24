const { z } = require('zod');

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
    return typeof obj;
}

function createGhostMockRouter({ isAdminOverride = false } = {}) {
    return async function ghostRouteHandler(route, mockRegistry) {
        const requestUrl = route.request().url();
        const mock = mockRegistry[requestUrl];
        if (!mock) return route.continue();

        const payload = mock.allowSensitive && !isAdminOverride ? redactJsonSchema(mock.json) : mock.json;
        return route.fulfill({
            status: mock.status || 200,
            contentType: 'application/json',
            json: payload,
        });
    };
}

function introspectSchemaView(jsonPayload, { isAdminOverride = false } = {}) {
    return isAdminOverride ? jsonPayload : redactJsonSchema(jsonPayload);
}

function getIntrospectionBannerState({ isAdminOverride = false } = {}) {
    if (isAdminOverride) {
        return {
            level: 'danger',
            message: 'RAW VALUES VISIBLE - L3 OVERRIDE ACTIVE',
        };
    }

    return {
        level: 'safe',
        message: 'REDACTED VIEW ACTIVE',
    };
}

const endpointSchema = z
    .object({
        path: z.string().startsWith('/'),
        method: z.enum(['GET', 'POST', 'PUT', 'DELETE']),
        responseSchema: z.record(z.string()),
    })
    .strict();

const apiSchema = z
    .object({
        endpoints: z.array(endpointSchema).min(1),
    })
    .strict();

function generateFailClosedMirrorServer(untrustedJsonString) {
    try {
        const parsed = JSON.parse(untrustedJsonString);
        const validated = apiSchema.parse(parsed);

        const routeLines = validated.endpoints
            .map(
                (ep) => `app.${ep.method.toLowerCase()}('${ep.path}', (req, res) => {\n` +
                    `    res.json(${JSON.stringify(ep.responseSchema)});\n` +
                    `});`
            )
            .join('\n\n');

        return `
const express = require('express');
const helmet = require('helmet');

const app = express();
app.use(helmet());
app.use(express.json());

${routeLines}

const PORT = 3000;
app.listen(PORT, '127.0.0.1', () => {
    console.log('Secure Mirror sandbox running strictly on http://127.0.0.1:' + PORT);
});
`.trim();
    } catch (err) {
        throw new Error(`CRITICAL_SCHEMA_VALIDATION_FAILURE: ${err.message}`);
    }
}

module.exports = {
    createGhostMockRouter,
    getIntrospectionBannerState,
    introspectSchemaView,
    generateFailClosedMirrorServer,
    redactJsonSchema,
};
