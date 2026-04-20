#!/usr/bin/env python3
"""EtherSlasher Radio Worker — airodump-ng → SQLite, runs 24/7"""
import csv, io, logging, os, re, signal, sqlite3, subprocess, sys, time

DB_PATH    = '/opt/etherslasher/db/etherslasher.db'
MON_IFACE  = 'wlan1'
CSV_PREFIX = '/tmp/etherslasher-worker'
CYCLE_SECS = 30
STALE_SECS = 300   # 5 min — APs not seen beyond this are removed
STATION_STALE_SECS = 180  # 3 min — stations

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

        CREATE TABLE IF NOT EXISTS stations (
            mac         TEXT PRIMARY KEY,
            bssid       TEXT,
            signal      INTEGER,
            frames      INTEGER DEFAULT 0,
            probes      TEXT    DEFAULT '',
            last_seen   INTEGER,
            first_seen  INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_stations_bssid    ON stations(bssid);
        CREATE INDEX IF NOT EXISTS idx_stations_lastseen ON stations(last_seen);

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
    ''')
    # Safe-create indexes on tables owned by app.js (may or may not exist yet)
    for ddl in [
        "CREATE INDEX IF NOT EXISTS idx_events_ts  ON events(ts)",
        "CREATE INDEX IF NOT EXISTS idx_creds_ts   ON captured_creds(ts)",
    ]:
        try:
            conn.execute(ddl)
        except Exception:
            pass
    conn.commit()


def is_monitor():
    try:
        out = subprocess.check_output(
            ['iw', 'dev', MON_IFACE, 'info'], stderr=subprocess.DEVNULL
        ).decode()
        return 'type monitor' in out
    except Exception:
        pass
    # Fallback for RTL8812AU — iw returns -ENOBUFS in monitor mode
    try:
        out = subprocess.check_output(
            ['ip', 'link', 'show', MON_IFACE], stderr=subprocess.DEVNULL
        ).decode()
        return 'ieee802.11/radiotap' in out or 'PROMISC' in out
    except Exception:
        return False


BSSID_RE  = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
NOT_ASSOC = re.compile(r'not.associated', re.I)


def parse_csv(path):
    """Return (aps, stations) parsed from an airodump-ng CSV file."""
    aps      = []
    stations = []
    try:
        with open(path, 'r', errors='replace') as f:
            content = f.read()

        parts      = content.split('Station MAC')
        ap_section = parts[0]
        st_section = parts[1] if len(parts) > 1 else ''

        # ── Access Points ────────────────────────────────────────────────
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

        # ── Stations (client devices) ────────────────────────────────────
        # CSV columns after the "Station MAC" header line:
        # Station MAC | First time | Last time | Power | # packets | BSSID | Probed ESSIDs
        if st_section:
            lines = st_section.strip().split('\n')
            for row in csv.reader(io.StringIO('\n'.join(lines[1:]))):
                if len(row) < 6:
                    continue
                mac = row[0].strip()
                if not mac or not BSSID_RE.match(mac):
                    continue
                ap_bssid = row[5].strip()
                if NOT_ASSOC.search(ap_bssid) or ap_bssid in ('', 'FF:FF:FF:FF:FF:FF'):
                    ap_bssid = None
                elif not BSSID_RE.match(ap_bssid):
                    ap_bssid = None
                probes_raw = row[6].strip() if len(row) > 6 else ''
                probes = ','.join(p.strip() for p in probes_raw.split(',') if p.strip())
                try:
                    stations.append({
                        'mac':    mac,
                        'bssid':  ap_bssid,
                        'signal': int(row[3].strip() or 0),
                        'frames': int(row[4].strip() or 0),
                        'probes': probes,
                    })
                except (ValueError, IndexError):
                    continue

    except Exception as e:
        log.warning('CSV parse error: %s', e)
    return aps, stations


def write_data(conn, aps, stations):
    now = int(time.time())
    ts  = time.strftime('%Y-%m-%dT%H:%M:%S')

    # ── Access Points ────────────────────────────────────────────────────
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

    # ── Stations ─────────────────────────────────────────────────────────
    for st in stations:
        conn.execute(
            '''INSERT INTO stations (mac, bssid, signal, frames, probes, last_seen, first_seen)
               VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(mac) DO UPDATE SET
                   bssid=COALESCE(excluded.bssid, bssid),
                   signal=excluded.signal,
                   frames=MAX(excluded.frames, frames),
                   probes=CASE WHEN excluded.probes != '' THEN excluded.probes ELSE probes END,
                   last_seen=excluded.last_seen''',
            (st['mac'], st['bssid'], st['signal'], st['frames'],
             st['probes'], now, now),
        )

    # ── Stale cleanup ─────────────────────────────────────────────────────
    conn.execute('DELETE FROM access_points WHERE last_seen < ?', (now - STALE_SECS,))
    conn.execute('DELETE FROM stations       WHERE last_seen < ?', (now - STATION_STALE_SECS,))
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
            aps, stations = parse_csv(csv_path)
            if aps or stations:
                write_data(conn, aps, stations)
                log.debug('Wrote %d APs, %d stations', len(aps), len(stations))

    try: _proc.kill(); _proc.wait()
    except: pass
    _proc = None


def cleanup_db(conn):
    try:
        conn.execute("DELETE FROM ap_activity WHERE ts < datetime('now', '-1 hour')")
        try:
            conn.execute("DELETE FROM events WHERE ts < datetime('now', '-24 hours')")
        except Exception:
            pass
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
