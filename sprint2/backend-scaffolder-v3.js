const { z } = require('zod');
const fs = require('fs');

const endpointSchema = z
    .object({
        path: z.string().startsWith('/'),
        method: z.enum(['GET', 'POST', 'PUT', 'DELETE']),
        responseSchema: z.record(z.string()),
    })
    .strict();

const scaffolderInputSchema = z
    .object({
        endpoints: z.array(endpointSchema).min(1),
    })
    .strict();

function buildServerTemplate(validatedInput) {
    const routes = validatedInput.endpoints
        .map(
            (endpoint) => `app.${endpoint.method.toLowerCase()}('${endpoint.path}', (req, res) => {\n` +
                `    res.json(${JSON.stringify(endpoint.responseSchema)});\n` +
                `});`
        )
        .join('\n\n');

    return `
const express = require('express');
const helmet = require('helmet');
const { z } = require('zod');

const app = express();
app.use(helmet());
app.use(express.json());

${routes}

const PORT = 3000;
app.listen(PORT, '127.0.0.1', () => {
    console.log('Secure Mirror sandbox running strictly on http://127.0.0.1:' + PORT);
});
`.trim();
}

function generateBackendScaffold(untrustedJsonString, outputPath = 'generated-mirror-server.js') {
    try {
        const parsed = JSON.parse(untrustedJsonString);
        const validated = scaffolderInputSchema.parse(parsed);
        const serverCode = buildServerTemplate(validated);
        fs.writeFileSync(outputPath, serverCode);
        return serverCode;
    } catch (error) {
        console.error('CRITICAL_SCHEMA_VALIDATION_FAILURE');
        console.error(error.errors || error.message);
        process.exit(1);
    }
}

if (require.main === module) {
    const input = process.argv.slice(2).join(' ').trim();
    generateBackendScaffold(input);
}

module.exports = {
    buildServerTemplate,
    generateBackendScaffold,
    scaffolderInputSchema,
};
