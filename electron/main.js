const { app, BrowserWindow, session } = require('electron');

function createMainWindow() {
    const options = {
        webPreferences: {
            nodeIntegration: false, // MUST BE FALSE
            contextIsolation: true, // MUST BE TRUE
            sandbox: true, // MUST BE TRUE
            webSecurity: true,
        },
    };

    // Runtime Self-Test (Fail-Closed)
    if (
        options.webPreferences.nodeIntegration === true ||
        !options.webPreferences.contextIsolation ||
        !options.webPreferences.sandbox
    ) {
        console.error('FATAL SECURITY VIOLATION: Isolation flags compromised. Aborting launch.');
        app.quit();
        return;
    }

    const mainWindow = new BrowserWindow(options);

    // Default-Deny Hardware Permissions
    session.defaultSession.setPermissionRequestHandler((webContents, permission, callback) => {
        console.warn(`[Security] Blocked unauthorized permission request: ${permission}`);
        callback(false);
    });

    // Block Arbitrary File Downloads
    session.defaultSession.on('will-download', (event, item) => {
        event.preventDefault();
        console.warn(`[Security] Blocked download attempt: ${item.getURL()}`);
    });

    // Block Unauthorized Popups/Windows
    mainWindow.webContents.setWindowOpenHandler(({ url }) => {
        console.warn(`[Security] Blocked new window attempt to: ${url}`);
        return { action: 'deny' };
    });

    mainWindow.loadURL('https://your-safe-local-ui.com');
}

app.whenReady().then(createMainWindow);
