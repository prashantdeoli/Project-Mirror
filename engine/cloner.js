const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

async function cloneWebsite(urlToClone) {
    try {
        const urlObj = new URL(urlToClone);
        const domain = urlObj.hostname;
        const cloneDir = path.join(__dirname, '..', 'cloned-sites', domain);

        // Create folder for the website
        if (!fs.existsSync(cloneDir)) {
            fs.mkdirSync(cloneDir, { recursive: true });
        }

        console.log(`\n🚀 PROJECT MIRROR ENGINE STARTED`);
        console.log(`🎯 Target: ${urlToClone}`);
        console.log(`📂 Saving to: ${cloneDir}\n`);

        // Launch visible browser so you can see the magic
        const browser = await chromium.launch({ headless: false }); 
        const page = await browser.newPage();

        // Intercept all network responses (CSS, JS, Images, etc.)
        page.on('response', async (response) => {
            const url = response.url();
            if (!url.startsWith('http')) return; // Ignore data URIs

            try {
                const buffer = await response.body();
                let fileName = path.basename(new URL(url).pathname);
                if (!fileName) fileName = 'index.html';
                
                // Sanitize file name
                const safeFileName = fileName.replace(/[^a-zA-Z0-9.\-]/g, '_');
                const savePath = path.join(cloneDir, safeFileName);
                
                fs.writeFileSync(savePath, buffer);
                console.log(`✅ Downloaded: ${safeFileName}`);
            } catch (err) {
                // Ignore failed assets (like blocked trackers)
            }
        });

        // Navigate to the website
        await page.goto(urlToClone, { waitUntil: 'networkidle' });

        // Save the final rendered HTML
        const html = await page.content();
        fs.writeFileSync(path.join(cloneDir, 'mirror-index.html'), html);

        console.log(`\n🎉 MIRROR COMPLETE!`);
        console.log(`Toh bhai, website clone ho gayi hai. Check folder: cloned-sites/${domain}`);
        
        await browser.close();
    } catch (error) {
        console.error("❌ Error:", error.message);
    }
}

const targetUrl = process.argv[2];
if (targetUrl) {
    cloneWebsite(targetUrl);
} else {
    console.log("⚠️ Please provide a URL! Example: node engine/cloner.js https://example.com");
}
