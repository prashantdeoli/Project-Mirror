import React, { useEffect, useState } from 'react';

export default function IntrospectionDashboard() {
    const [schemas, setSchemas] = useState([]);
    const [bannerState, setBannerState] = useState({
        level: 'safe',
        message: 'REDACTED VIEW ACTIVE',
    });

    useEffect(() => {
        if (window.mirrorAPI) {
            window.mirrorAPI.onSecurityStateChanged((newState) => {
                setBannerState(newState);
            });

            window.mirrorAPI.onSchemaIntercepted((newSchema) => {
                // Zero-Leakage invariant: do not log intercepted schema payloads.
                setSchemas((previous) => [newSchema, ...previous]);
            });
        }
    }, []);

    return (
        <div className="flex flex-col h-screen bg-gray-900 text-white">
            <div
                className={`w-full p-3 text-center font-bold tracking-widest ${
                    bannerState.level === 'danger' ? 'bg-red-600 text-white' : 'bg-green-600 text-white'
                }`}
            >
                {bannerState.message}
            </div>

            <div className="flex-1 p-6 overflow-y-auto">
                <h2 className="text-xl font-semibold mb-4">Intercepted Payloads</h2>
                {schemas.length === 0 ? (
                    <p className="text-gray-500">Waiting for Playwright interception...</p>
                ) : (
                    schemas.map((schema, idx) => (
                        <div key={idx} className="bg-gray-800 p-4 mb-4 rounded-lg border border-gray-700">
                            <pre className="text-sm text-green-400">{JSON.stringify(schema, null, 2)}</pre>
                        </div>
                    ))
                )}
            </div>
        </div>
    );
}
