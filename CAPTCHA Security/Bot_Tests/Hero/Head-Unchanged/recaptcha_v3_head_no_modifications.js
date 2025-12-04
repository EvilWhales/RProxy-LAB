const Hero = require('@ulixee/hero-playground');

(async () => {

    const sites = {
        captchatest: {
            url: 'https://captchatest.online/recaptcha_v3',
            actions: async (activeTab) => {
                await activeTab.goto(sites.captchatest.url);
                await activeTab.xpathSelector('/html/body/div/main/form/div[1]/input').$type('John');
                await activeTab.xpathSelector('/html/body/div/main/form/div[2]/input').$type('Doe');
                await activeTab.waitForMillis(500);
                await activeTab.xpathSelector('/html/body/div[1]/main/form/button').$click();
                activeTab.on('resource', async (resource) => {
                    if (resource.request.method == 'POST' && resource.url.includes('captchatest.online')) {
                        console.log(`Response code: ${resource.response.statusCode}`);
                        let text = await resource.buffer.then(x => x?.toString());
                        console.log(`${text}`);
                    }
                });
                await activeTab.waitForMillis(500);
            }
        },
        captcha2: {
            url: 'https://2captcha.com/de/demo/recaptcha-v3',
            actions: async (activeTab) => {
                await activeTab.goto(sites.captcha2.url);
                await activeTab.waitForMillis(1500);
                await activeTab.xpathSelector('/html/body/div[1]/div/main/div/div/div[2]/section/div/form/div[2]/button[1]').$click();
                await activeTab.waitForMillis(2000);
                const text = await activeTab.xpathSelector("/html/body/div[1]/div/main/div/div/div[2]/section/div/form/div[1]/pre/code").textContent;
            
                if (text) {
                    console.log(`Text content of the element: ${text}`);
                } else {
                    console.log('No element found with the given XPath.');
                }
            }
        }
    };

    const selectedSite = sites.captcha2; // Toggle this to switch sites

    const hero = new Hero({ showChromeInteractions: true, showChrome: true });
    const { activeTab } = hero;

    await selectedSite.actions(activeTab);

    await activeTab.close();
})();