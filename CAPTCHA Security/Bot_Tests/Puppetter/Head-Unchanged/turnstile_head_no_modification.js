const puppeteer = require('puppeteer');

(async () => {
    const browser = await puppeteer.launch({
        headless: false,
        args: ['--start-maximized'],
    });
    const page = await browser.newPage();
    const { width, height } = await page.evaluate(() => {
        return {
            width: screen.width,
            height: screen.height
        };
    });

    await page.setViewport({ width, height });
    await page.goto('https://captchatest.online/turnstile', { waitUntil: 'networkidle0' });
    await page.type('xpath=//*[@id="username"]', 'John');
    await page.type('xpath=//*[@id="password"]', 'Doe');

    // Click on the checkbox
    await new Promise(resolve => setTimeout(resolve, 3000));
    await page.click('xpath=/html/body/div[1]/main/form/button');
})();


