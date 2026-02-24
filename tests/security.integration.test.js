const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const Module = require('node:module');

function loadWithMocks(relativePath, mocks) {
    const targetPath = path.resolve(__dirname, '..', relativePath);
    delete require.cache[targetPath];

    const originalRequire = Module.prototype.require;
    Module.prototype.require = function patchedRequire(request) {
        if (Object.prototype.hasOwnProperty.call(mocks, request)) {
            return mocks[request];
        }
        return originalRequire.apply(this, arguments);
    };

    try {
        return require(targetPath);
    } finally {
        Module.prototype.require = originalRequire;
    }
}

test('Electron fortress shell enforces deny-by-default boundaries', async () => {
    const state = {
        quitCalled: false,
        permissionHandler: null,
        willDownloadHandler: null,
        windowOpenHandler: null,
        options: null,
    };

    const app = {
        whenReady() {
            return {
                then: (fn) => {
                    fn();
                },
            };
        },
        quit() {
            state.quitCalled = true;
        },
    };

    function BrowserWindow(options) {
        state.options = options;
        return {
            webContents: {
                setWindowOpenHandler(handler) {
                    state.windowOpenHandler = handler;
                },
            },
            loadURL() {},
        };
    }

    const session = {
        defaultSession: {
            setPermissionRequestHandler(handler) {
                state.permissionHandler = handler;
            },
            on(eventName, handler) {
                if (eventName === 'will-download') state.willDownloadHandler = handler;
            },
        },
    };

    loadWithMocks('electron/main.js', {
        electron: { app, BrowserWindow, session },
    });

    assert.equal(state.options.webPreferences.nodeIntegration, false);
    assert.equal(state.options.webPreferences.contextIsolation, true);
    assert.equal(state.options.webPreferences.sandbox, true);
    assert.equal(state.quitCalled, false);

    let permissionDenied;
    state.permissionHandler({}, 'camera', (allowed) => {
        permissionDenied = allowed;
    });
    assert.equal(permissionDenied, false);

    let prevented = false;
    let cancelled = false;
    state.willDownloadHandler(
        {
            preventDefault() {
                prevented = true;
            },
        },
        {
            cancel() {
                cancelled = true;
            },
            getURL: () => 'https://evil.local/malware.exe',
        }
    );
    assert.equal(prevented, true);
    assert.equal(cancelled, true);

    const windowResult = state.windowOpenHandler({ url: 'https://evil.local' });
    assert.deepEqual(windowResult, { action: 'deny' });
});

test('Playwright interception engine blocks mutating requests and redacts GET JSON', async () => {
    const state = {
        routeHandler: null,
        responseHandler: null,
        gotoUrl: null,
        logs: [],
        warns: [],
    };

    const page = {
        on(eventName, handler) {
            if (eventName === 'response') state.responseHandler = handler;
        },
        async goto(url) {
            state.gotoUrl = url;
        },
    };

    const context = {
        async newPage() {
            return page;
        },
        async route(_pattern, handler) {
            state.routeHandler = handler;
        },
    };

    const browser = {
        async newContext(options) {
            assert.equal(options.serviceWorkers, 'block');
            return context;
        },
    };

    const chromium = {
        async launch() {
            return browser;
        },
    };

    const originalWarn = console.warn;
    const originalLog = console.log;
    console.warn = (...args) => state.warns.push(args.join(' '));
    console.log = (...args) => state.logs.push(args);

    try {
        const { startSecureCrawler } = loadWithMocks('crawler/secure-crawler.js', {
            playwright: { chromium },
        });

        await startSecureCrawler('https://safe.local');

        let aborted = false;
        await state.routeHandler({
            request: () => ({ method: () => 'POST', url: () => 'https://safe.local/api' }),
            abort: async () => {
                aborted = true;
            },
            continue: async () => {
                throw new Error('continue should not be called for POST');
            },
        });
        assert.equal(aborted, true);

        let continued = false;
        await state.routeHandler({
            request: () => ({ method: () => 'GET', url: () => 'https://safe.local/readonly' }),
            abort: async () => {
                throw new Error('abort should not be called for GET');
            },
            continue: async () => {
                continued = true;
            },
        });
        assert.equal(continued, true);

        await state.responseHandler({
            request: () => ({ method: () => 'GET' }),
            headers: () => ({ 'content-type': 'application/json; charset=utf-8' }),
            text: async () => JSON.stringify({ user: 'Alice', age: 30, nested: { active: true } }),
        });

        assert.equal(state.logs.some((entry) => String(entry[0]).includes('[Redacted Schema Captured]')), true);
        const redactedPayload = state.logs.find((entry) => String(entry[0]).includes('[Redacted Schema Captured]'))[1];
        assert.equal(redactedPayload.user, 'string');
        assert.equal(redactedPayload.age, 'number');
        assert.equal(redactedPayload.nested.active, 'boolean');
        assert.equal(state.logs.some((entry) => String(entry).includes('Alice')), false);

        await state.responseHandler({
            request: () => ({ method: () => 'GET' }),
            headers: () => ({ 'content-type': 'application/json' }),
            text: async () => 'x'.repeat(2 * 1024 * 1024 + 1),
        });

        assert.equal(state.warns.some((line) => line.includes('Response exceeded 2MB. Skipped.')), true);
        assert.equal(state.gotoUrl, 'https://safe.local');
    } finally {
        console.warn = originalWarn;
        console.log = originalLog;
    }
});

test('L3 override requires JWT and logs fingerprint when token is valid', () => {
    const writes = [];
    const exits = [];

    const mockFs = {
        appendFileSync(filePath, content, options) {
            writes.push({ filePath, content, options });
        },
    };

    const mockJwt = {
        verify(token, publicKey, opts) {
            assert.equal(token, 'valid.jwt.token');
            assert.match(publicKey, /BEGIN PUBLIC KEY/);
            assert.deepEqual(opts, { algorithms: ['RS256'] });
            return { sub: 'admin' };
        },
    };

    const originalArgv = process.argv;
    const originalExit = process.exit;
    const originalLog = console.log;

    const banners = [];
    process.argv = ['node', 'cli/l3-override.js', '--admin-override', '--token=valid.jwt.token'];
    process.exit = (code) => {
        exits.push(code);
        throw new Error(`exit:${code}`);
    };
    console.log = (...args) => banners.push(args.join(' '));

    try {
        const { engageL3Override } = loadWithMocks('cli/l3-override.js', {
            jsonwebtoken: mockJwt,
            fs: mockFs,
        });

        const result = engageL3Override();
        assert.equal(result, true);
        assert.equal(exits.length, 0);
        assert.equal(writes.length, 1);
        assert.equal(writes[0].filePath, 'audit.log');
        assert.equal(writes[0].options.flag, 'a');
        assert.match(writes[0].content, /L3_OVERRIDE_ENGAGED/);
        assert.match(writes[0].content, /TokenFingerprint: [a-f0-9]{16}/);
        assert.equal(banners.some((line) => line.includes('LEVEL 3 MAINTENANCE OVERRIDE ACTIVE')), true);
    } finally {
        process.argv = originalArgv;
        process.exit = originalExit;
        console.log = originalLog;
    }
});

test('L3 override fails closed when override flag has no token', () => {
    const mockJwt = { verify: () => ({}) };

    const originalArgv = process.argv;
    const originalExit = process.exit;
    process.argv = ['node', 'cli/l3-override.js', '--admin-override'];

    let exitCode;
    process.exit = (code) => {
        exitCode = code;
        throw new Error(`exit:${code}`);
    };

    try {
        const { engageL3Override } = loadWithMocks('cli/l3-override.js', {
            jsonwebtoken: mockJwt,
            fs: { appendFileSync() {} },
        });

        assert.throws(() => engageL3Override(), /exit:1/);
        assert.equal(exitCode, 1);
    } finally {
        process.argv = originalArgv;
        process.exit = originalExit;
    }
});

test('AI validator rejects untrusted extras and enforces secure server template invariants', () => {
    const writes = [];
    const mockFs = {
        writeFileSync(filePath, content) {
            writes.push({ filePath, content });
        },
    };

    const { buildSecureSandbox } = loadWithMocks('ai/build-secure-sandbox.js', {
        zod: {
            z: {
                object(shape) {
                    return {
                        strict() {
                            return {
                                parse(data) {
                                    const allowed = ['routePath', 'method', 'responseSchema'];
                                    for (const key of Object.keys(data)) {
                                        if (!allowed.includes(key)) {
                                            const err = new Error('extra keys');
                                            err.errors = [{ message: 'Unrecognized key' }];
                                            throw err;
                                        }
                                    }
                                    if (typeof data.routePath !== 'string' || !data.routePath.startsWith('/')) {
                                        throw new Error('Invalid routePath');
                                    }
                                    if (!['GET', 'POST', 'PUT', 'DELETE'].includes(data.method)) {
                                        throw new Error('Invalid method');
                                    }
                                    if (typeof data.responseSchema !== 'object' || data.responseSchema === null) {
                                        throw new Error('Invalid responseSchema');
                                    }
                                    for (const value of Object.values(data.responseSchema)) {
                                        if (typeof value !== 'string') {
                                            throw new Error('Invalid responseSchema value');
                                        }
                                    }
                                    return data;
                                },
                            };
                        },
                    };
                },
                string() {
                    return {
                        startsWith() {
                            return {};
                        },
                    };
                },
                enum() {
                    return {};
                },
                record() {
                    return {};
                },
            },
        },
        fs: mockFs,
    });

    buildSecureSandbox(
        JSON.stringify({
            routePath: '/health',
            method: 'GET',
            responseSchema: { status: 'string' },
        })
    );

    assert.equal(writes.length, 1);
    assert.equal(writes[0].filePath, 'generated-mirror-server.js');
    assert.match(writes[0].content, /app\.use\(helmet\(\)\);/);
    assert.match(writes[0].content, /app\.get\('\/health'/);
    assert.match(writes[0].content, /app\.listen\(PORT, '127\.0\.0\.1'/);

    const originalExit = process.exit;
    let exitCode;
    process.exit = (code) => {
        exitCode = code;
        throw new Error(`exit:${code}`);
    };

    try {
        assert.throws(
            () =>
                buildSecureSandbox(
                    JSON.stringify({
                        routePath: '/bad',
                        method: 'GET',
                        responseSchema: { ok: 'string' },
                        exec: 'rm -rf /',
                    })
                ),
            /exit:1/
        );
        assert.equal(exitCode, 1);
    } finally {
        process.exit = originalExit;
    }
});

test('Sprint 2 ghost mocking engine redacts sensitive values unless admin override is active', async () => {
    const calls = [];
    const route = {
        request: () => ({ url: () => 'https://api.local/users' }),
        fulfill: async (payload) => calls.push({ type: 'fulfill', payload }),
        continue: async () => calls.push({ type: 'continue' }),
    };

    const mockRegistry = {
        'https://api.local/users': {
            allowSensitive: true,
            json: { name: 'Alice', age: 30, nested: { active: true } },
        },
    };

    const { createGhostMockRouter } = loadWithMocks('sprint2/secure-mock-schema-tooling.js', {
        zod: {
            z: {
                object() {
                    return {
                        strict() {
                            return {
                                parse(v) {
                                    return v;
                                },
                            };
                        },
                    };
                },
                string() {
                    return { startsWith() { return {}; } };
                },
                enum() {
                    return {};
                },
                record() {
                    return {};
                },
                array() {
                    return { min() { return {}; } };
                },
            },
        },
    });

    const handlerNoOverride = createGhostMockRouter({ isAdminOverride: false });
    await handlerNoOverride(route, mockRegistry);

    assert.equal(calls.length, 1);
    assert.equal(calls[0].type, 'fulfill');
    assert.equal(calls[0].payload.json.name, 'string');
    assert.equal(calls[0].payload.json.age, 'number');
    assert.equal(calls[0].payload.json.nested.active, 'boolean');

    const handlerOverride = createGhostMockRouter({ isAdminOverride: true });
    await handlerOverride(route, mockRegistry);
    assert.equal(calls[1].payload.json.name, 'Alice');
});

test('Sprint 2 fail-closed scaffolding keeps helmet and localhost binding invariants', () => {
    const { generateFailClosedMirrorServer } = loadWithMocks('sprint2/secure-mock-schema-tooling.js', {
        zod: {
            z: {
                object() {
                    return {
                        strict() {
                            return {
                                parse(v) {
                                    if (!v || !Array.isArray(v.endpoints) || v.endpoints.length < 1) {
                                        throw new Error('invalid endpoints');
                                    }
                                    return v;
                                },
                            };
                        },
                    };
                },
                string() {
                    return { startsWith() { return {}; } };
                },
                enum() {
                    return {};
                },
                record() {
                    return {};
                },
                array() {
                    return { min() { return {}; } };
                },
            },
        },
    });

    const code = generateFailClosedMirrorServer(
        JSON.stringify({
            endpoints: [
                {
                    path: '/health',
                    method: 'GET',
                    responseSchema: { status: 'string' },
                },
            ],
        })
    );

    assert.match(code, /app\.use\(helmet\(\)\);/);
    assert.match(code, /app\.listen\(PORT, '127\.0\.0\.1'/);
    assert.match(code, /app\.get\('\/health'/);

    assert.throws(() => generateFailClosedMirrorServer(JSON.stringify({ endpoints: [] })), /CRITICAL_SCHEMA_VALIDATION_FAILURE/);
});

test('Sprint 2 introspection banner state is safe by default and danger under override', () => {
    const { introspectSchemaView, getIntrospectionBannerState } = loadWithMocks('sprint2/secure-mock-schema-tooling.js', {
        zod: {
            z: {
                object() {
                    return {
                        strict() {
                            return {
                                parse(v) {
                                    return v;
                                },
                            };
                        },
                    };
                },
                string() {
                    return { startsWith() { return {}; } };
                },
                enum() {
                    return {};
                },
                record() {
                    return {};
                },
                array() {
                    return { min() { return {}; } };
                },
            },
        },
    });

    const payload = { profile: { name: 'Alice', age: 30 } };
    const safeView = introspectSchemaView(payload, { isAdminOverride: false });
    const safeBanner = getIntrospectionBannerState({ isAdminOverride: false });
    const dangerBanner = getIntrospectionBannerState({ isAdminOverride: true });

    assert.equal(safeView.profile.name, 'string');
    assert.equal(safeBanner.level, 'safe');
    assert.match(safeBanner.message, /REDACTED VIEW ACTIVE/);
    assert.equal(dangerBanner.level, 'danger');
    assert.match(dangerBanner.message, /L3 OVERRIDE ACTIVE/);
});

test('Sprint 2 preload bridge exposes only whitelisted mirrorAPI subscriptions', () => {
    const exposed = {};
    const channelHandlers = {};

    const { } = loadWithMocks('electron/preload.js', {
        electron: {
            contextBridge: {
                exposeInMainWorld(key, value) {
                    exposed[key] = value;
                },
            },
            ipcRenderer: {
                on(channel, handler) {
                    channelHandlers[channel] = handler;
                },
            },
        },
    });

    assert.equal(Object.prototype.hasOwnProperty.call(exposed, 'mirrorAPI'), true);
    assert.equal(typeof exposed.mirrorAPI.onSchemaIntercepted, 'function');
    assert.equal(typeof exposed.mirrorAPI.onSecurityStateChanged, 'function');
    assert.equal(Object.prototype.hasOwnProperty.call(exposed.mirrorAPI, 'ipcRenderer'), false);

    let schemaSeen;
    exposed.mirrorAPI.onSchemaIntercepted((payload) => {
        schemaSeen = payload;
    });
    channelHandlers['schema-intercepted']({}, { user: 'string' });
    assert.deepEqual(schemaSeen, { user: 'string' });

    let bannerSeen;
    exposed.mirrorAPI.onSecurityStateChanged((payload) => {
        bannerSeen = payload;
    });
    channelHandlers['security-state-changed']({}, { level: 'danger', message: 'RAW VALUES VISIBLE - L3 OVERRIDE ACTIVE' });
    assert.deepEqual(bannerSeen, { level: 'danger', message: 'RAW VALUES VISIBLE - L3 OVERRIDE ACTIVE' });
});

test('Sprint 2 dashboard source contains zero schema payload console logging', () => {
    const fs = require('node:fs');
    const dashboardSource = fs.readFileSync(path.resolve(__dirname, '..', 'ui/IntrospectionDashboard.jsx'), 'utf8');

    assert.equal(dashboardSource.includes('console.log('), false);
    assert.equal(dashboardSource.includes('console.dir('), false);
    assert.equal(dashboardSource.includes('onSchemaIntercepted'), true);
    assert.equal(dashboardSource.includes('onSecurityStateChanged'), true);
    assert.equal(dashboardSource.includes('REDACTED VIEW ACTIVE'), true);
});

test('Sprint 2 backend-scaffolder-v3 writes hardened localhost Express scaffold on valid schema', () => {
    const writes = [];
    const mockFs = {
        writeFileSync(filePath, content) {
            writes.push({ filePath, content });
        },
    };

    const { generateBackendScaffold } = loadWithMocks('sprint2/backend-scaffolder-v3.js', {
        zod: {
            z: {
                object() {
                    return {
                        strict() {
                            return {
                                parse(v) {
                                    if (!v || !Array.isArray(v.endpoints) || v.endpoints.length < 1) {
                                        throw new Error('invalid endpoints');
                                    }
                                    for (const ep of v.endpoints) {
                                        const allowed = ['path', 'method', 'responseSchema'];
                                        for (const key of Object.keys(ep)) {
                                            if (!allowed.includes(key)) {
                                                throw new Error('extra endpoint key');
                                            }
                                        }
                                    }
                                    return v;
                                },
                            };
                        },
                    };
                },
                string() {
                    return { startsWith() { return {}; } };
                },
                enum() {
                    return {};
                },
                record() {
                    return {};
                },
                array() {
                    return { min() { return {}; } };
                },
            },
        },
        fs: mockFs,
    });

    const code = generateBackendScaffold(
        JSON.stringify({
            endpoints: [
                {
                    path: '/status',
                    method: 'GET',
                    responseSchema: { ok: 'string' },
                },
            ],
        })
    );

    assert.equal(writes.length, 1);
    assert.equal(writes[0].filePath, 'generated-mirror-server.js');
    assert.match(code, /^const express = require\('express'\);/);
    assert.match(code, /const helmet = require\('helmet'\);/);
    assert.match(code, /const \{ z \} = require\('zod'\);/);
    assert.match(code, /app\.use\(helmet\(\)\);/);
    assert.match(code, /app\.listen\(PORT, '127\.0\.0\.1'/);
});

test('Sprint 2 backend-scaffolder-v3 fails closed with process.exit(1) on malicious schema keys', () => {
    const originalExit = process.exit;
    let exitCode;
    process.exit = (code) => {
        exitCode = code;
        throw new Error(`exit:${code}`);
    };

    try {
        const { generateBackendScaffold } = loadWithMocks('sprint2/backend-scaffolder-v3.js', {
            zod: {
                z: {
                    object() {
                        return {
                            strict() {
                                return {
                                    parse(v) {
                                        for (const ep of v.endpoints || []) {
                                            if (Object.prototype.hasOwnProperty.call(ep, 'exec')) {
                                                const err = new Error('invalid key');
                                                err.errors = [{ message: 'Unrecognized key exec' }];
                                                throw err;
                                            }
                                        }
                                        return v;
                                    },
                                };
                            },
                        };
                    },
                    string() {
                        return { startsWith() { return {}; } };
                    },
                    enum() {
                        return {};
                    },
                    record() {
                        return {};
                    },
                    array() {
                        return { min() { return {}; } };
                    },
                },
            },
            fs: { writeFileSync() { throw new Error('must not write on invalid schema'); } },
        });

        assert.throws(
            () =>
                generateBackendScaffold(
                    JSON.stringify({
                        endpoints: [
                            {
                                path: '/status',
                                method: 'GET',
                                responseSchema: { ok: 'string' },
                                exec: 'rm -rf /',
                            },
                        ],
                    })
                ),
            /exit:1/
        );
        assert.equal(exitCode, 1);
    } finally {
        process.exit = originalExit;
    }
});

test('Sprint 3 persistence layer encrypts/decrypts using L3-gated AES-256-GCM and audits save/load', () => {
    const writes = [];
    const appends = [];
    const readMap = new Map();

    const mockFs = {
        writeFileSync(filePath, content) {
            writes.push({ filePath, content });
            readMap.set(filePath, content);
        },
        readFileSync(filePath) {
            return readMap.get(filePath);
        },
        appendFileSync(filePath, content, options) {
            appends.push({ filePath, content, options });
        },
    };

    const { saveEncryptedMockConfig, loadEncryptedMockConfig } = loadWithMocks('sprint3/persistence-policy-engine.js', {
        fs: mockFs,
        zod: {
            z: {
                object() {
                    return {
                        strict() {
                            return {
                                parse(v) {
                                    return v;
                                },
                            };
                        },
                    };
                },
                string() {
                    return {};
                },
                enum() {
                    return {};
                },
                array() {
                    return { min() { return {}; } };
                },
            },
        },
        jsonwebtoken: {
            verify(token, publicKey, opts) {
                assert.equal(token, 'valid.jwt.token');
                assert.match(publicKey, /BEGIN PUBLIC KEY/);
                assert.deepEqual(opts, { algorithms: ['RS256'] });
                return { role: 'admin' };
            },
        },
    });

    saveEncryptedMockConfig({
        token: 'valid.jwt.token',
        config: { scenario: 'load-test', retries: 2 },
        storagePath: 'tmp/mock.enc',
    });

    assert.equal(writes.length, 1);
    const encryptedEnvelope = JSON.parse(writes[0].content);
    assert.equal(typeof encryptedEnvelope.iv, 'string');
    assert.equal(typeof encryptedEnvelope.authTag, 'string');
    assert.equal(typeof encryptedEnvelope.ciphertext, 'string');
    assert.equal(encryptedEnvelope.ciphertext.includes('load-test'), false);

    const loaded = loadEncryptedMockConfig({ token: 'valid.jwt.token', storagePath: 'tmp/mock.enc' });
    assert.deepEqual(loaded, { scenario: 'load-test', retries: 2 });

    assert.equal(appends.length, 2);
    assert.match(appends[0].content, /PERSISTENCE_SAVE/);
    assert.match(appends[1].content, /PERSISTENCE_LOAD/);
    assert.match(appends[0].content, /TokenFingerprint: [a-f0-9]{16}/);
});

test('Sprint 3 persistence layer fails closed with STORAGE_ACCESS_DENIED when token is missing', () => {
    const originalExit = process.exit;
    let exitCode;

    process.exit = (code) => {
        exitCode = code;
        throw new Error(`exit:${code}`);
    };

    try {
        const { saveEncryptedMockConfig } = loadWithMocks('sprint3/persistence-policy-engine.js', {
            zod: {
                z: {
                    object() {
                        return {
                            strict() {
                                return {
                                    parse(v) {
                                        return v;
                                    },
                                };
                            },
                        };
                    },
                    string() {
                        return {};
                    },
                    enum() {
                        return {};
                    },
                    array() {
                        return { min() { return {}; } };
                    },
                },
            },
            fs: {
                writeFileSync() {
                    throw new Error('should not write without token');
                },
                appendFileSync() {},
            },
            jsonwebtoken: {
                verify() {
                    return { role: 'admin' };
                },
            },
        });

        assert.throws(
            () => saveEncryptedMockConfig({ token: '', config: { test: true }, storagePath: 'tmp/nope.enc' }),
            /exit:1/
        );
        assert.equal(exitCode, 1);
    } finally {
        process.exit = originalExit;
    }
});

test('Sprint 3 policy sync validates canonical policy strictly and detects drift', () => {
    const fsFixture = {
        'repo/docs/architecture/v3.0-specs/policy-sync.json': JSON.stringify({
            policyVersion: '3.0.0',
            redactionMode: 'type-only',
            blockedMethods: ['POST', 'PUT', 'PATCH', 'DELETE'],
        }),
    };

    const { syncPolicyFromRepo, detectPolicyDrift } = loadWithMocks('sprint3/persistence-policy-engine.js', {
        zod: {
            z: {
                object() {
                    return {
                        strict() {
                            return {
                                parse(v) {
                                    const allowedTop = ['policyVersion', 'redactionMode', 'blockedMethods'];
                                    for (const key of Object.keys(v || {})) {
                                        if (!allowedTop.includes(key)) {
                                            throw new Error('invalid policy key');
                                        }
                                    }
                                    return v;
                                },
                            };
                        },
                    };
                },
                string() {
                    return {};
                },
                enum() {
                    return {};
                },
                array() {
                    return { min() { return {}; } };
                },
            },
        },
        fs: {
            readFileSync(filePath) {
                const normalized = String(filePath).replace(/\\/g, '/');
                if (fsFixture[normalized]) return fsFixture[normalized];
                if (normalized.endsWith('/docs/architecture/v3.0-specs/policy-sync.json')) {
                    return fsFixture['repo/docs/architecture/v3.0-specs/policy-sync.json'];
                }
                return undefined;
            },
            appendFileSync() {},
            writeFileSync() {},
        },
        jsonwebtoken: {
            verify() {
                return { role: 'admin' };
            },
        },
    });

    const canonical = syncPolicyFromRepo({
        repoRoot: 'repo',
        relativePolicyPath: 'docs/architecture/v3.0-specs/policy-sync.json',
    });

    assert.equal(canonical.policyVersion, '3.0.0');
    assert.equal(detectPolicyDrift(canonical, canonical), false);

    const localPolicy = {
        ...canonical,
        blockedMethods: ['POST', 'PUT'],
    };
    assert.equal(detectPolicyDrift(localPolicy, canonical), true);
});

test('Sprint 4 heuristic masker returns semantic safe token when confidence >= 95%', () => {
    const { heuristicMaskField } = loadWithMocks('sprint4/autonomous-security-engine.js', {
        zod: {
            z: {
                object() {
                    return { strict() { return { parse(v) { return v; } }; } };
                },
                string() { return {}; },
                unknown() { return {}; },
                enum() { return {}; },
                array() { return { min() { return {}; }, optional() { return {}; } }; },
            },
        },
    });

    const out = heuristicMaskField({ key: 'authToken', value: 'aaa.bbb.ccc' });
    assert.equal(out.failClosedFallback, false);
    assert.equal(out.classification, 'jwt');
    assert.equal(out.redacted, '[SAFE_JWT_TOKEN]');
});

test('Sprint 4 heuristic masker fails closed below threshold', () => {
    const { heuristicMaskField } = loadWithMocks('sprint4/autonomous-security-engine.js', {
        zod: {
            z: {
                object() {
                    return { strict() { return { parse(v) { return v; } }; } };
                },
                string() { return {}; },
                unknown() { return {}; },
                enum() { return {}; },
                array() { return { min() { return {}; }, optional() { return {}; } }; },
            },
        },
    });

    const out = heuristicMaskField({ key: 'nickname', value: 'Alice' });
    assert.equal(out.failClosedFallback, true);
    assert.match(out.redacted, /\[CONFIDENTIAL_STRING\]/);
});

test('Sprint 4 self-heal restores canonical policy and threat sync appends fingerprint', () => {
    const appends = [];
    let policyWritten;

    const fsMock = {
        appendFileSync(_path, content) {
            appends.push(content);
        },
        readFileSync() {
            return JSON.stringify({
                policyVersion: '4.0.0',
                redactionMode: 'type-only',
                blockedMethods: ['POST', 'PUT', 'PATCH', 'DELETE'],
                knownBadFingerprints: [],
            });
        },
        writeFileSync(_path, content) {
            policyWritten = content;
        },
    };

    const { selfHealPolicy, appendKnownBadFingerprint } = loadWithMocks('sprint4/autonomous-security-engine.js', {
        fs: fsMock,
        zod: {
            z: {
                object() {
                    return { strict() { return { parse(v) { return v; } }; } };
                },
                string() { return {}; },
                unknown() { return {}; },
                enum() { return {}; },
                array() { return { min() { return {}; }, optional() { return {}; } }; },
            },
        },
    });

    const local = { policyVersion: '4.0.0', redactionMode: 'full-mask', blockedMethods: ['POST'], knownBadFingerprints: [] };
    const canonical = { policyVersion: '4.0.0', redactionMode: 'type-only', blockedMethods: ['POST', 'PUT', 'PATCH', 'DELETE'], knownBadFingerprints: [] };

    const healed = selfHealPolicy({ localPolicy: local, canonicalPolicy: canonical, l3Authorized: false });
    assert.equal(healed.healed, true);
    assert.equal(healed.policy.redactionMode, 'type-only');
    assert.equal(appends.some((line) => line.includes('LEVEL_4_CRITICAL_AUTO_FIX')), true);

    const fp = appendKnownBadFingerprint({ payload: { blocked: 'schema' }, policyPath: 'docs/architecture/v3.0-specs/policy-sync.json' });
    assert.equal(typeof fp, 'string');
    assert.equal(fp.length, 64);
    assert.equal(typeof policyWritten, 'string');
    assert.equal(policyWritten.includes(fp), true);
});
