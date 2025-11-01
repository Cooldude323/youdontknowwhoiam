// server.cjs
const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

// ------------------- CONFIG -------------------
const logFile = path.join(__dirname, 'visitors.log');
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'password';
// ---------------------------------------------

// Create log file if it doesn't exist
if (!fs.existsSync(logFile)) {
  fs.writeFileSync(logFile, '', 'utf8');
}

// Middleware to log every request
app.use((req, res, next) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  console.log('Detected IP:', ip);             // logs to terminal
  fs.appendFileSync(logFile, ip + '\n');      // append to file
  next();
});

// Serve index.html at root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Simple login page to view logs
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

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running at http://0.0.0.0:${PORT}`);
});

