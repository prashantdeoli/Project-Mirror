const fs = require('fs');
const path = require('path');
const { z } = require('zod');

// 1. Strict Security Schema for AI Output
const aiOutputSchema = z.object({
    code: z.string().includes('helmet').includes('127.0.0.1'),
    routePath: z.string(),
    method: z.string()
});

function generateSecureSandbox(inputJson) {
    try {
        const input = JSON.parse(inputJson);
        
        // 2. Simulated AI Generation (Hardened Express Server)
        const mockAiResponse = {
            code: `
const express = require('express');
const helmet = require('helmet');
const app = express();

// Security Middleware
app.use(helmet());
app.use(express.json());

// Generated Route
app.${input.method.toLowerCase()}('${input.routePath}', (req, res) => {
    res.json({ 
        message: "Project Mirror v5.0 - Secure Payload Received", 
        integrity: true 
    });
});

// Fail-Closed Localhost Binding
const PORT = 3000;
app.listen(PORT, '127.0.0.1', () => {
    console.log(\`✅ Secure Mirror sandbox running strictly on http://127.0.0.1:\${PORT}\`);
});
`,
            routePath: input.routePath,
            method: input.method
        };

        // 3. Schema Validation (The Guardrail)
        const validatedOutput = aiOutputSchema.parse(mockAiResponse);

        // 4. File Generation
        fs.writeFileSync('generated-mirror-server.js', validatedOutput.code.trim());
        console.log('SUCCESS: Secure backend generated and validated.');
        
    } catch (error) {
        console.error('🚨 CRITICAL: AI Output Schema Validation Failed.');
        console.error(error.message || error);
        process.exit(1);
    }
}

const inputArgs = process.argv.slice(2)[0];
if (inputArgs) {
    generateSecureSandbox(inputArgs);
} else {
    console.error('FATAL: No input JSON provided.');
    process.exit(1);
}
