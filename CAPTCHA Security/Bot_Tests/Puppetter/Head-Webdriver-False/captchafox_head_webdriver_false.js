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

    await page.evaluateOnNewDocument(() => {
        Object.defineProperty(navigator, 'webdriver', {
            get: () => undefined
        });
    });

    await page.setViewport({ width, height });
    await page.goto('https://portal.captchafox.com/register', { waitUntil: 'networkidle0' });

    await page.type('xpath=/html/body/div/div[1]/div/div[2]/div[2]/form/div[2]/div/input', 'John@john.de');
    await page.type('xpath=/html/body/div/div[1]/div/div[2]/div[2]/form/div[3]/div/input', 'Doe');

    // Click on the checkbox
    await new Promise(resolve => setTimeout(resolve, 1000));

    // Listen for all responses after the click
    page.on('response', async (response) => {
        const request = response.request();
        if (request.method() === 'POST') {
            console.log(`Received response for ${request.url()}`);
            if (response.status() === 200) {
                console.log('Success: POST request was successful');
                const responseText = await response.text(); // Fetch the response text
                console.log(`Response text: ${responseText}`); // Log the response text
            } else if (response.status() >= 400) {
                console.log(`Error: POST request failed with status ${response.status()}`);
                const responseText = await response.text(); // Fetch the response text even in case of errors
                console.log(`Error response text: ${responseText}`); // Log the error response text
            }
        }
    });

    await page.click('xpath=/html/body/div/div[1]/div/div[2]/div[2]/form/div[4]/div/div/div[1]/div[1]');
})();


