const Hero = require('@ulixee/hero-playground');

(async () => {
    const hero = new Hero({ showChromeInteractions: true, showChrome: true });

    const { activeTab } = hero;

    await activeTab.goto('https://captchatest.online/turnstile');

    await activeTab.xpathSelector('/html/body/div/main/form/div[1]/input').$type('John');
    await activeTab.xpathSelector('/html/body/div/main/form/div[2]/input').$type('Doe');

    await activeTab.waitForMillis(1500);

    await activeTab.xpathSelector('/html/body/div[1]/main/form/button').$click();

    activeTab.on('resource', async (resource) => {
        if (resource.request.method == 'POST' && resource.url.includes('captchatest.online')) {
            console.log(`Response code: ${resource.response.statusCode}`);
            let text = await resource.buffer.then(x => x?.toString());
            console.log(`${text}`);
        }
    });

    await activeTab.waitForMillis(50000);

    await activeTab.close();
})();