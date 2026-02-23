const { contextBridge, ipcRenderer } = require('electron');

// Securely expose whitelisted channels only
contextBridge.exposeInMainWorld('mirrorAPI', {
    // Listen for new redacted schemas from the Playwright engine
    onSchemaIntercepted: (callback) => {
        ipcRenderer.on('schema-intercepted', (_event, data) => callback(data));
    },
    // Listen for L3 Override state changes to update the banner
    onSecurityStateChanged: (callback) => {
        ipcRenderer.on('security-state-changed', (_event, bannerState) => callback(bannerState));
    },
});
