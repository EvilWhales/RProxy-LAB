const puppeteer = require('puppeteer-extra');

const StealthPlugin = require('puppeteer-extra-plugin-stealth')
puppeteer.use(StealthPlugin())

puppeteer.launch({ headless: false }).then(async browser => {
    
    const sites = {
        captchatest: {
            url: 'https://captchatest.online/recaptcha_enterprise',
            actions: async (page) => {
                await page.goto(sites.captchatest.url, { waitUntil: 'networkidle0' });
                await page.type('xpath=//*[@id="username"]', 'John');
                await page.type('xpath=//*[@id="password"]', 'Doe');

                page.on('response', async (response) => {
                    const request = response.request();
                    const url = new URL(request.url());
                    const targetDomain = 'captchatest.online';

                    if (url.hostname.includes(targetDomain) && request.method() === 'POST') {
                        console.log(`Received response for ${request.url()}`);
                        if (response.status() === 200) {
                            console.log('Success: POST request was successful');
                            let text = await response.text();
                            console.log(text);
                        } else if (response.status() >= 400) {
                            console.log(`Error: POST request failed with status ${response.status()}`);
                        }
                    }
                });
                await page.click('xpath=/html/body/div[1]/main/form/button');
                await new Promise(resolve => setTimeout(resolve, 1000));
            }
        },
        captcha2: {
            url: 'https://2captcha.com/de/demo/recaptcha-v3-enterprise',
            actions: async (page) => {
                await page.goto(sites.captcha2.url);
                await new Promise(resolve => setTimeout(resolve, 3000)); // Simulate delay for page scripts
                await page.click('xpath=/html/body/div[1]/div/main/div/div/div[2]/section/div/form/div[2]/button[1]');
                await new Promise(resolve => setTimeout(resolve, 2000));
                // Extract text content using XPath for 2captcha
                const text = await page.evaluate((xpath) => {
                    const element = document.evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
                    return element ? element.textContent : null;
                }, "/html/body/div[1]/div/main/div/div/div[2]/section/div/form/div[1]/pre/code");

                if (text) {
                    console.log(`Text content of the element: ${text}`);
                } else {
                    console.log('No element found with the given XPath.');
                }
            }
        }
    };

    const selectedSite = sites.captchatest; // Toggle this to switch sites

    const page = await browser.newPage();

    // Execute the actions for the selected site
    await selectedSite.actions(page);

    // Close the browser
    await browser.close();
})
