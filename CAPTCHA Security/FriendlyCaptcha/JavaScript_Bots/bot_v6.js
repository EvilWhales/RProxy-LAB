const puppeteer = require('puppeteer');
const EventEmitter = require('events');
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
                // '--proxy-server=http://127.0.0.1:8080',
                // '--ignore-certificate-errors'
            ]
        });

        this.page = await this.browser.newPage();

        await this.page.evaluateOnNewDocument(() => {
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined
            });
        });

        this.page.on('response', this.handleResponse.bind(this));

        // One time intercept for changing JavaScript file
        // this.workers=new Array(4) --> this.workers=new Array(100)
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
                    const modifiedScript = originalScript.replace('this.workers=new Array(4)', `this.workers=new Array(0)`);

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
            else if (interceptedRequest.method() === 'POST' && interceptedRequest.url().includes('friendlycaptcha.com/demo')) {
                // Modify the request
                const postData = this.parseFormUrlEncoded(interceptedRequest.postData());

                while (this.puzzle_string === null) {
                    await new Promise(resolve => setTimeout(resolve, 10)); // Wait for 100ms before checking again
                }

                // Get new solution from local executable | By this time we can assume that this.puzzle_string is set
                const newSolution = await this.getNewCaptchaSolution(this.puzzle_string);

                // Replace the captcha solution in the POST data
                postData['frc-captcha-solution'] = newSolution;

                // Convert object back to URL-encoded string
                const modifiedPostData = this.formUrlEncode(postData);

                // Continue the request with modified POST data
                interceptedRequest.continue({
                    method: 'POST',
                    postData: modifiedPostData,
                    headers: interceptedRequest.headers()
                });

                // Reset this.puzzle_string for the next cycle
                this.puzzle_string = null;
            }
            else {
                interceptedRequest.continue();
            }
        });
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
                        if (threshold_value > 170) {
                            this.event_bus.emit('SwitchTorNode');
                        }
                    }
                }
            }
            else if (response.url() === 'https://captchatest.online/friendly_captcha') {

                const responseBody = await response.text();

                if (response.status() === 200 && responseBody.includes("FriendlyCaptcha verification success")) {
                    this.puzzle_solved++;
                    console.log(`[${new Date().toISOString()}] Solved puzzle -- Total solved ${this.puzzle_solved}`);
                }
            }
        } catch (err) {
            // console.error("Error in response handler:", err);
        }
    }

    // Parse URL-encoded data into an object
    parseFormUrlEncoded(data) {
        return data.split('&').reduce((acc, current) => {
            const [key, value] = current.split('=');
            acc[decodeURIComponent(key)] = decodeURIComponent(value);
            return acc;
        }, {});
    }

    // Convert an object to URL-encoded data
    formUrlEncode(data) {
        return Object.keys(data).map(key =>
            `${encodeURIComponent(key)}=${encodeURIComponent(data[key])}`
        ).join('&');
    }

    // Function to execute local script and return output
    getNewCaptchaSolution(puzzle) {
        return new Promise((resolve, reject) => {
            exec(`solver.exe ${puzzle}`, (error, stdout, stderr) => {
                if (error) {
                    console.error('Error executing local script:', error);
                    reject(error);
                    return;
                }
                resolve(stdout.trim());
            });
        });
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
            await this.page.goto('https://captchatest.online/friendly_captcha');

            await this.page.type('html body div.content-container main form div.form-field input#username', 'John Doe');

            while (this.puzzle_string === null) {
                await new Promise(resolve => setTimeout(resolve, 5)); // Wait for 100ms before checking again
            }

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
