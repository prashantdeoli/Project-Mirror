const { z } = require('zod');
const fs = require('fs');

// Strict Validation Schema for Untrusted AI Output
const aiBlueprintSchema = z
    .object({
        routePath: z.string().startsWith('/'),
        method: z.enum(['GET', 'POST', 'PUT', 'DELETE']),
        responseSchema: z.record(z.string()),
    })
    .strict(); // Disallows hallucinated or malicious extra fields

function buildSecureSandbox(untrustedAiJsonString) {
    try {
        const parsedJson = JSON.parse(untrustedAiJsonString);

        // Fail-Closed Zod Parsing
        const validatedData = aiBlueprintSchema.parse(parsedJson);

        // Secure Express Scaffold Generation
        const expressCodeTemplate = `
const express = require('express');
const helmet = require('helmet'); // Mandatory Security Headers

const app = express();
app.use(helmet());
app.use(express.json());

app.${validatedData.method.toLowerCase()}('${validatedData.routePath}', (req, res) => {
    res.json(${JSON.stringify(validatedData.responseSchema)});
});

// Strict Localhost Binding Invariant
const PORT = 3000;
app.listen(PORT, '127.0.0.1', () => {
    console.log('Secure Mirror sandbox running strictly on http://127.0.0.1:' + PORT);
});
`;

        fs.writeFileSync('generated-mirror-server.js', expressCodeTemplate.trim());
        console.log('SUCCESS: Secure backend generated and validated.');
    } catch (error) {
        console.error('🚨 CRITICAL: AI Output Schema Validation Failed.');
        console.error(error.errors || error.message);
        process.exit(1); // Prevent execution of unsafe logic
    }
}

if (require.main === module) {
    const input = process.argv.slice(2).join(' ').trim();
    buildSecureSandbox(input);
}

module.exports = {
    aiBlueprintSchema,
    buildSecureSandbox,
};
