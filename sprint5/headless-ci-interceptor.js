const { chromium } = require('playwright');

function isExternalHttp(url) {
    return /^https?:\/\//i.test(url);
}

async function runHeadlessCiInterceptor({ url, mockRegistry = {} }) {
    const browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({ serviceWorkers: 'block' });
    const page = await context.newPage();

    await context.route('**/*', async (route) => {
        const requestUrl = route.request().url();
        const method = route.request().method().toUpperCase();

        if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
            return route.abort();
        }

        if (mockRegistry[requestUrl]) {
            return route.fulfill({ status: 200, contentType: 'application/json', json: mockRegistry[requestUrl] });
        }

        if (isExternalHttp(requestUrl)) {
            throw new Error(`CI_NETWORK_ESCAPE_BLOCKED: ${method} ${requestUrl}`);
        }

        return route.abort();
    });

    try {
        await page.goto(url);
    } catch (error) {
        await browser.close();
        console.error(error.message);
        process.exit(1);
    }

    await browser.close();
}

module.exports = { runHeadlessCiInterceptor, isExternalHttp };
