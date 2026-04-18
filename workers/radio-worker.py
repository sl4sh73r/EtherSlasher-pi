#!/usr/bin/env python3
"""EtherSlasher Radio Worker — airodump-ng → SQLite, runs 24/7"""
import csv, io, logging, os, re, signal, sqlite3, subprocess, sys, time

DB_PATH    = '/opt/etherslasher/db/etherslasher.db'
MON_IFACE  = 'wlan1'
CSV_PREFIX = '/tmp/etherslasher-worker'
CYCLE_SECS = 30
STALE_SECS = 300   # 5 min

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    stream=sys.stdout,
)
log = logging.getLogger('radio-worker')

_proc = None


def _cleanup(sig, _frame):
    global _proc
    if _proc:
        try: _proc.kill()
        except: pass
    log.info('Shutting down (signal %d)', sig)
    sys.exit(0)


signal.signal(signal.SIGTERM, _cleanup)
signal.signal(signal.SIGINT,  _cleanup)


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=15, check_same_thread=False)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')
    conn.execute('PRAGMA cache_size=5000')
    conn.execute('PRAGMA temp_store=MEMORY')
    return conn


def init_db(conn):
    conn.executescript('''
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
        CREATE INDEX IF NOT EXISTS idx_ap_lastseen ON access_points(last_seen);
        CREATE INDEX IF NOT EXISTS idx_ap_frames   ON access_points(data_frames DESC);
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
        CREATE INDEX IF NOT EXISTS idx_ap_activity_bssid_ts ON ap_activity(bssid, ts);
        CREATE INDEX IF NOT EXISTS idx_events_ts   ON events(ts);
        CREATE INDEX IF NOT EXISTS idx_creds_ts    ON captured_creds(ts);
    ''')
    conn.commit()


def is_monitor():
    try:
        out = subprocess.check_output(
            ['iw', 'dev', MON_IFACE, 'info'], stderr=subprocess.DEVNULL
        ).decode()
        return 'type monitor' in out
    except:
        return False


BSSID_RE = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')


def parse_csv(path):
    aps = []
    try:
        with open(path, 'r', errors='replace') as f:
            content = f.read()
        ap_section = content.split('Station MAC')[0]
        for row in csv.reader(io.StringIO(ap_section)):
            if len(row) < 14:
                continue
            bssid = row[0].strip()
            if not bssid or bssid == 'BSSID' or not BSSID_RE.match(bssid):
                continue
            try:
                aps.append({
                    'bssid':       bssid,
                    'ssid':        row[13].strip(),
                    'channel':     int(row[3].strip() or 0),
                    'signal':      int(row[8].strip() or 0),
                    'enc':         row[5].strip() or 'OPN',
                    'data_frames': int(row[10].strip() or 0),
                })
            except (ValueError, IndexError):
                continue
    except Exception as e:
        log.warning('CSV parse error: %s', e)
    return aps


def write_aps(conn, aps):
    now = int(time.time())
    ts  = time.strftime('%Y-%m-%dT%H:%M:%S')
    for ap in aps:
        conn.execute(
            '''INSERT INTO access_points
               (bssid, ssid, channel, signal, enc, data_frames, last_seen, first_seen)
               VALUES (?,?,?,?,?,?,?,?)
               ON CONFLICT(bssid) DO UPDATE SET
                   ssid=excluded.ssid, channel=excluded.channel,
                   signal=excluded.signal, enc=excluded.enc,
                   data_frames=excluded.data_frames, last_seen=excluded.last_seen''',
            (ap['bssid'], ap['ssid'], ap['channel'], ap['signal'],
             ap['enc'], ap['data_frames'], now, now),
        )
        conn.execute(
            'INSERT INTO ap_activity (ts,bssid,ssid,channel,power,data_frames,clients_count)'
            ' VALUES (?,?,?,?,?,?,0)',
            (ts, ap['bssid'], ap['ssid'], ap['channel'], ap['signal'], ap['data_frames']),
        )
    conn.execute('DELETE FROM access_points WHERE last_seen < ?', (now - STALE_SECS,))
    conn.commit()


def run_cycle(conn):
    global _proc
    csv_path = f'{CSV_PREFIX}-01.csv'
    for f in (csv_path, f'{CSV_PREFIX}-01.cap'):
        try: os.remove(f)
        except: pass

    log.info('Cycle start (%ds)', CYCLE_SECS)
    _proc = subprocess.Popen(
        ['airodump-ng', '--write', CSV_PREFIX,
         '--output-format', 'csv', '--write-interval', '3', MON_IFACE],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    deadline = time.time() + CYCLE_SECS
    while time.time() < deadline:
        time.sleep(3)
        if not is_monitor():
            log.info('Monitor mode gone — stopping cycle')
            break
        if os.path.exists(csv_path):
            aps = parse_csv(csv_path)
            if aps:
                write_aps(conn, aps)
                log.debug('Wrote %d APs', len(aps))

    try: _proc.kill(); _proc.wait()
    except: pass
    _proc = None


def cleanup_db(conn):
    try:
        conn.execute("DELETE FROM ap_activity WHERE ts < datetime('now', '-1 hour')")
        conn.execute("DELETE FROM events WHERE ts < datetime('now', '-24 hours')")
        conn.commit()
        log.info('Hourly DB cleanup done')
    except Exception as e:
        log.warning('Cleanup error: %s', e)


def main():
    log.info('EtherSlasher radio-worker starting (pid=%d)', os.getpid())
    conn = get_db()
    init_db(conn)
    last_clean = 0

    while True:
        if time.time() - last_clean > 3600:
            cleanup_db(conn)
            last_clean = time.time()

        if is_monitor():
            try:
                run_cycle(conn)
            except Exception as e:
                log.error('Cycle error: %s', e)
                time.sleep(5)
        else:
            time.sleep(5)


if __name__ == '__main__':
    main()
