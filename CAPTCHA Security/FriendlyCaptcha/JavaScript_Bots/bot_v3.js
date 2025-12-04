const puppeteer = require('puppeteer');

(async () => {
    // Create browser and page
    const browser = await puppeteer.launch({
        headless: false,
    });

    const page = await browser.newPage();

    // Bypass webdriver condition
    await page.evaluateOnNewDocument(() => {
        Object.defineProperty(navigator, 'webdriver', {
            get: () => undefined
        });
    });

    // NEW
    while (true) {
        // Text if challenge has been solved
        const SolvedIndicator = "I am human";
        await page.goto('https://captchatest.online/friendly_captcha');

        // Write name
        await page.type('html body div.content-container main form div.form-field input#username', 'John Doe');

        // Wait for finish
        await page.waitForFunction((xpath, desiredContent) => {
            const element = document.evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
            return element && element.textContent.trim() === desiredContent;
        }, {}, '/html/body/div/main/form/div[3]/div/div/div/span', SolvedIndicator);

        // Press button
        await page.click('xpath=/html/body/div/main/form/button');
    }
})();


