const puppeteer = require('puppeteer');
const EventEmitter = require('events');
const os = require('os');
const { exec } = require('child_process');


class FriendlyCaptchaBot {
    constructor() {
        this.event_bus = new EventEmitter();
        this.event_bus.on('SwitchTorNode', this.switchTorNode.bind(this));
        this.switchingIp = false;
        this.puzzle_solved = 0;
        this.puzzle_string = null;
    }

    async launch() {
        this.browser = await puppeteer.launch({
            headless: false,
            args: [
                '--proxy-server=socks5://127.0.0.1:9050',
            ]
        });

        this.page = await this.browser.newPage();

        await this.page.evaluateOnNewDocument(() => {
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined
            });
        });

        await this.page.setRequestInterception(true);

        this.page.on('request', async (interceptedRequest) => {
            if (interceptedRequest.url() === 'https://cdn.jsdelivr.net/npm/friendly-challenge@0.9.10/widget.module.min.js') {
                try {
                    const response = await fetch(interceptedRequest.url());
                    if (!response.ok) {
                        console.error("Failed to fetch the original script, status:", response.status);
                        interceptedRequest.continue();
                        return;
                    }

                    let originalScript = await response.text();
                    const originalHeaders = response.headers;

                    const responseHeaders = {};
                    originalHeaders.forEach((value, key) => {
                        responseHeaders[key] = value;
                    });

                    // Prevent client site solving
                    const numCores = os.cpus().length;
                    const modifiedScript = originalScript.replace('this.workers=new Array(4)', `this.workers=new Array(${numCores})`);
                    console.log(`Replaced: this.workers=new Array(${numCores})`);

                    // Update Content-Length if needed
                    responseHeaders['Content-Length'] = String(Buffer.byteLength(modifiedScript));

                    interceptedRequest.respond({
                        status: 200,
                        headers: responseHeaders,
                        body: modifiedScript
                    });

                } catch (error) {
                    console.error("Error in script interception:", error);
                    interceptedRequest.continue();
                }
            }
            else {
                interceptedRequest.continue();
            }
        });

        this.page.on('response', this.handleResponse.bind(this));
    }

    async handleResponse(response) {
        try {
            if (response.status() === 200 && response.url() === 'https://api.friendlycaptcha.com/api/v1/puzzle?sitekey=FCMGEMUD2KTDSQ5H') {
                const contentType = response.headers()['content-type'];
                if (contentType && contentType.includes('application/json')) {
                    const responseBody = await response.json();
                    if (responseBody.success && responseBody.data && responseBody.data.puzzle) {
                        this.puzzle_string = responseBody.data.puzzle;
                        const [, encodedData] = responseBody.data.puzzle.split('.');
                        const decodedData = Buffer.from(encodedData, 'base64');
                        const threshold_value = decodedData[15];
                        const puzzles_to_solve = decodedData[14];
                        console.log(`[${new Date().toISOString()}] Threshold value: ${threshold_value} -- Puzzles to solve ${puzzles_to_solve}`);
                        if (threshold_value > 153) {
                            this.event_bus.emit('SwitchTorNode');
                        }
                    }
                }
            }
        } catch (err) {
            console.error("Error in response handler:", err);
        }
    }

    async switchTorNode() {
        this.switchingIp = true;
        const psCommand = "wsl bash -c 'sudo /usr/sbin/service tor restart; while ! curl --silent --proxy socks5://127.0.0.1:9050 https://api.ipify.org; do sleep 0.5; done'";

        return new Promise((resolve, reject) => {
            exec(`powershell "${psCommand}"`, (error, stdout, stderr) => {
                this.switchingIp = false;
                if (error) {
                    console.error(`exec error: ${error}`);
                    reject(error);
                    return;
                }
                console.log(`Switched ip address to: ${stdout}`);
                resolve(stdout);
            });
        });
    }

    async Scrape() {

        try {
            const SolvedIndicator = "I am human";
            await this.page.goto('https://captchatest.online/friendly_captcha');

            await this.page.type('html body div.content-container main form div.form-field input#username', 'John Doe');

            await this.page.waitForFunction((xpath, desiredContent) => {
                const element = document.evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
                return element && element.textContent.trim() === desiredContent;
            }, {}, '/html/body/div/main/form/div[3]/div/div/div/span', SolvedIndicator);

            await this.page.click('xpath=/html/body/div/main/form/button');

            this.puzzle_solved++;
            console.log(`[${new Date().toISOString()}] Solved puzzle -- Total solved ${this.puzzle_solved}`);
        } catch (err) {
            console.error("Error in loop:", err);
            return false;
        }

        return true;
    }

    async MainLoop() {

        while (true) {
            // Only run Scrape if not switching IP
            if (!this.switchingIp) {
                if (await this.Scrape() === false) {
                    break;
                }
            } else {
                // If IP is being switched, pause for a while before checking again
                await new Promise(resolve => setTimeout(resolve, 100));
            }

        }
        await this.browser.close();
    }
}

(async () => {
    let t_browser = new FriendlyCaptchaBot();

    await t_browser.launch();

    await t_browser.MainLoop();
})();
