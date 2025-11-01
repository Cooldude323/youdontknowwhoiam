const express = require('express');
const path = require('path');
const fs = require('fs');
const app = express();
const PORT = process.env.PORT || 3000;

// Serve all static files in 'public'
app.use(express.static(path.join(__dirname, 'public')));

// Visitor logging middleware
const logFile = path.join(__dirname, 'visitors.log');
if (!fs.existsSync(logFile)) fs.writeFileSync(logFile, '', 'utf8');

app.use((req, res, next) => {
  const ipHeader = req.headers['x-forwarded-for'] || '';
  const ip = ipHeader.split(',')[0].trim() || req.socket.remoteAddress;
  console.log('Detected IP:', ip);
  fs.appendFileSync(logFile, ip + '\n');
  next();
});

// Serve main index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Admin logs page
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'password';

app.get('/logs', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) {
    res.setHeader('WWW-Authenticate', 'Basic realm="IP Logs"');
    return res.status(401).send('Authentication required.');
  }
  const [user, pass] = Buffer.from(auth.split(' ')[1], 'base64').toString().split(':');
  if (user === ADMIN_USER && pass === ADMIN_PASS) {
    const logs = fs.readFileSync(logFile, 'utf8');
    res.send(`<pre>${logs || 'No logs yet'}</pre>`);
  } else {
    res.setHeader('WWW-Authenticate', 'Basic realm="IP Logs"');
    return res.status(401).send('Authentication required.');
  }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
