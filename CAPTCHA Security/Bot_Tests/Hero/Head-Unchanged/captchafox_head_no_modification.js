const Hero = require('@ulixee/hero-playground');

(async () => {
    const hero = new Hero({ showChromeInteractions: true, showChrome: true });

    const { activeTab } = hero;

    await activeTab.goto('https://portal.captchafox.com/register');

    await activeTab.waitForMillis(500);

    await activeTab.xpathSelector('/html/body/div/div[1]/div/div[2]/div[2]/form/div[2]/div/input').$type('John@john.de');
    await activeTab.xpathSelector('/html/body/div/div[1]/div/div[2]/div[2]/form/div[3]/div/input').$type('Doe');

    await activeTab.waitForMillis(1000);

    activeTab.on('resource', async (resource) => {
        if (resource.request.method == 'POST' && resource.url.includes('captchafox')) {
            console.log(`Response code: ${resource.response.statusCode}`);
            let text = await resource.buffer.then(x => x?.toString());
            console.log(`${text}`);
        }
    });

    await activeTab.xpathSelector('/html/body/div/div[1]/div/div[2]/div[2]/form/div[4]/div/div/div[1]/div[1]').$click();

    await activeTab.waitForMillis(2000);

    await activeTab.close();
})();