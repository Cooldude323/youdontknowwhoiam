// server.js
import express from "express";
import fs from "fs";
import path from "path";
import basicAuth from "basic-auth";
import helmet from "helmet";

const __dirname = process.cwd();
const app = express();
app.use(helmet());
app.use(express.json());

// Admin credentials (change for production)
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "CHANGEME";

// Log files
const RAW_LOG = path.join(__dirname, "visitors.log");
const HTML_LOG = path.join(__dirname, "visitors.html");

// Serve main index.html
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Helper: normalize IPv4 & IPv6
function normalizeIp(ip) {
  if (!ip) return "";
  if (ip.startsWith("::ffff:")) return ip.slice(7);
  return ip;
}
function getClientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (xff && typeof xff === "string" && xff.length > 0) {
    return normalizeIp(xff.split(",")[0].trim());
  }
  return normalizeIp(req.socket.remoteAddress || "");
}

function escapeHtml(s) {
  return String(s || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Append to both visitors.log (JSON) and visitors.html (table)
function appendVisitorLog(entry) {
  const line = JSON.stringify(entry) + "\n";
  fs.appendFile(RAW_LOG, line, (err) => {
    if (err) console.error("Error writing RAW_LOG:", err);
  });

  if (!fs.existsSync(HTML_LOG)) {
    const header = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Visitor Logs</title>
<style>
body{font-family:Arial,Helvetica,sans-serif;background:#f5f5f5;color:#111;padding:20px}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ddd;padding:8px;text-align:left}
th{background:#222;color:#fff;position:sticky;top:0}
tr:nth-child(even){background:#fff}
.meta{font-size:0.9em;color:#666}
</style>
</head>
<body>
<h1>Visitor Logs</h1>
<table>
<thead><tr><th>Timestamp (UTC)</th><th>IP</th><th>Page</th><th>User-Agent</th></tr></thead>
<tbody>
<!-- LOG_ROWS -->
</tbody>
</table>
</body>
</html>`;
    fs.writeFileSync(HTML_LOG, header, "utf8");
  }

  const row = `<tr><td>${escapeHtml(entry.ts)}</td><td>${escapeHtml(entry.ip)}</td><td>${escapeHtml(entry.page)}</td><td><div class="meta">${escapeHtml(entry.ua)}</div></td></tr>\n`;
  fs.readFile(HTML_LOG, "utf8", (err, data) => {
    if (err) return;
    const updated = data.replace("<tbody>\n<!-- LOG_ROWS -->", `<tbody>\n${row}<!-- LOG_ROWS -->`);
    fs.writeFile(HTML_LOG, updated, "utf8", () => {});
  });
}

// Endpoint for the client logging request
app.post("/log", (req, res) => {
  const ip = getClientIp(req);
  const ua = req.get("User-Agent") || "";
  const page = req.body.page || "index.html";
  const ts = new Date().toISOString();
  appendVisitorLog({ ts, ip, page, ua });
  res.status(204).end();
});

// Basic-auth middleware for /logs
function requireAdmin(req, res, next) {
  const credentials = basicAuth(req);
  if (!credentials || credentials.name !== ADMIN_USER || credentials.pass !== ADMIN_PASS) {
    res.set("WWW-Authenticate", 'Basic realm="admin"');
    return res.status(401).send("Authentication required");
  }
  next();
}

// Secure logs page
app.get("/logs", requireAdmin, (req, res) => {
  if (!fs.existsSync(HTML_LOG)) return res.send("<p>No logs yet.</p>");
  res.sendFile(HTML_LOG);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
  console.log(`🔐 Logs at http://localhost:${PORT}/logs`);
});
