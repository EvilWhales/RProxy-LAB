const puppeteer = require('puppeteer-extra');

const StealthPlugin = require('puppeteer-extra-plugin-stealth')
puppeteer.use(StealthPlugin())

puppeteer.launch({ headless: true }).then(async browser => {
    const page = await browser.newPage();

    await page.goto('https://captchatest.online/recaptcha_v2');
    await page.type('xpath=//*[@id="username"]', 'John');
    await page.type('xpath=//*[@id="password"]', 'Doe');

    // Click on the checkbox
    await new Promise(resolve => setTimeout(resolve, 3000));

    await page.waitForSelector('iframe[title="reCAPTCHA"]');
    const iframeElement = await page.$('iframe[title="reCAPTCHA"]');
    const frame = await iframeElement.contentFrame();
    const checkboxSelector = '#recaptcha-anchor';
    await frame.click(checkboxSelector);

    await new Promise(resolve => setTimeout(resolve, 1000));

    // Listen for all responses after the click
    page.on('response', async (response) => {
        const request = response.request();
        if (request.method() === 'POST') {
            console.log(`Received response for ${request.url()}`);
            if (response.status() === 200) {
                console.log('Success: POST request was successful');
            } else if (response.status() >= 400) {
                console.log(`Error: POST request failed with status ${response.status()}`);
            }
        }
    });

    await page.click('xpath=/html/body/div[1]/main/form/button');
})