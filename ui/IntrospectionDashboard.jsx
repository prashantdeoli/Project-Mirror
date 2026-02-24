import React, { useEffect, useState } from 'react';

function renderHeuristicValue(value) {
    if (typeof value === 'string' && value.startsWith('[CONFIDENTIAL_')) {
        return <span className="text-orange-400 font-bold">{value}</span>;
    }

    if (typeof value === 'string') {
        return <span className="text-cyan-400">{value}</span>;
    }

    return <span className="text-green-400">{JSON.stringify(value)}</span>;
}

function renderSchemaNode(node) {
    if (Array.isArray(node)) {
        return (
            <div className="pl-4 border-l border-gray-700">
                {node.map((item, idx) => (
                    <div key={idx}>{renderSchemaNode(item)}</div>
                ))}
            </div>
        );
    }

    if (node && typeof node === 'object') {
        return (
            <div className="pl-4 border-l border-gray-700 space-y-1">
                {Object.entries(node).map(([key, value]) => (
                    <div key={key}>
                        <span className="text-gray-300 mr-2">{key}:</span>
                        {renderSchemaNode(value)}
                    </div>
                ))}
            </div>
        );
    }

    return renderHeuristicValue(node);
}

export default function IntrospectionDashboard() {
    const [schemas, setSchemas] = useState([]);
    const [bannerState, setBannerState] = useState({
        level: 'safe',
        message: 'REDACTED VIEW ACTIVE',
    });
    const [autoFixAlert, setAutoFixAlert] = useState(null);

    useEffect(() => {
        if (window.mirrorAPI) {
            window.mirrorAPI.onSecurityStateChanged((newState) => {
                setBannerState(newState);
            });

            window.mirrorAPI.onSchemaIntercepted((newSchema) => {
                // Zero-Leakage invariant: do not log intercepted schema payloads.
                setSchemas((previous) => [newSchema, ...previous]);
            });

            window.mirrorAPI.onCriticalAutoFix((auditData) => {
                setAutoFixAlert(auditData);
            });
        }
    }, []);

    return (
        <div className="flex flex-col h-screen bg-gray-900 text-white">
            {autoFixAlert && (
                <div className="w-full p-4 bg-red-800 text-white font-black border-b-4 border-black">
                    ⚠️ LEVEL 4 AUTO-REMEDIATION EXECUTED: {autoFixAlert.reason || 'Canonical policy restored'}
                </div>
            )}

            <div
                className={`w-full p-3 text-center font-bold tracking-widest ${
                    bannerState.level === 'danger' ? 'bg-red-600 text-white' : 'bg-green-600 text-white'
                }`}
            >
                {bannerState.message}
            </div>

            <div className="flex-1 p-6 overflow-y-auto">
                <h2 className="text-xl font-semibold mb-4">Heuristic Payload Intelligence</h2>
                {schemas.length === 0 ? (
                    <p className="text-gray-500">Waiting for Playwright interception...</p>
                ) : (
                    schemas.map((schema, idx) => (
                        <div key={idx} className="bg-gray-800 p-4 mb-4 rounded-lg border border-gray-700">
                            {renderSchemaNode(schema)}
                        </div>
                    ))
                )}
            </div>
        </div>
    );
}
