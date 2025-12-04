const Hero = require('@ulixee/hero-playground');

(async () => {
    const hero = new Hero({ showChromeInteractions: true, showChrome: false });

    const { activeTab } = hero;

    await activeTab.goto('https://captchatest.online/recaptcha_v2');

    await activeTab.xpathSelector('/html/body/div/main/form/div[1]/input').$type('John');
    await activeTab.xpathSelector('/html/body/div/main/form/div[2]/input').$type('Doe');

    const iframe = await activeTab.getFrameEnvironment(activeTab.querySelector('iframe[title="reCAPTCHA"]'));
    await iframe.document.querySelector('#recaptcha-anchor').$click();

    await activeTab.waitForMillis(500);

    activeTab.on('resource', async (resource) => {
        if (resource.request.method == 'POST' && resource.url.includes('captchatest.online')) {
            console.log(`Response code: ${resource.response.statusCode}`);
            let text = await resource.buffer.then(x => x?.toString());
            console.log(`${text}`);
        }
    });

    await activeTab.xpathSelector('/html/body/div[1]/main/form/button').$click();

    await activeTab.waitForMillis(500);

    await activeTab.close();
})();