#!/usr/bin/env python3
"""PineapplePI Recon Engine - nmap + MAC vendor + OS fingerprint + SQLite"""
import sqlite3, subprocess, json, re, time, logging, socket
import urllib.request, urllib.error, urllib.parse
from datetime import datetime
from pathlib import Path

DB_PATH = '/opt/pineapple/db/pineapple.db'
LOG_PATH = '/var/log/pineapple/recon.log'

logging.basicConfig(
    filename=LOG_PATH, level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s'
)
log = logging.getLogger('recon')

def init_db():
    con = sqlite3.connect(DB_PATH)
    con.executescript("""
    CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY,
        ip TEXT UNIQUE,
        mac TEXT,
        hostname TEXT,
        vendor TEXT,
        os_guess TEXT,
        open_ports TEXT,
        cves TEXT,
        first_seen TEXT,
        last_seen TEXT,
        raw_nmap TEXT
    );
    CREATE TABLE IF NOT EXISTS traffic_log (
        id INTEGER PRIMARY KEY,
        ts TEXT,
        src_ip TEXT,
        dst_ip TEXT,
        proto TEXT,
        data TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_clients_ip ON clients(ip);
    CREATE INDEX IF NOT EXISTS idx_traffic_ts ON traffic_log(ts);
    """)
    con.commit()
    return con

def get_mac_vendor(mac):
    """Lookup MAC vendor via macvendors API"""
    if not mac or mac == 'Unknown':
        return 'Unknown'
    try:
        url = f'https://api.macvendors.com/{urllib.parse.quote(mac)}'
        req = urllib.request.Request(url, headers={'User-Agent': 'PineapplePI/1.0'})
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.read().decode().strip()
    except Exception:
        return 'Unknown'

def get_leases():
    """Читаем DHCP leases из dnsmasq"""
    leases = {}
    lease_file = '/var/lib/misc/dnsmasq.leases'
    try:
        with open(lease_file) as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 4:
                    ip, mac = parts[2], parts[1]
                    hostname = parts[3] if parts[3] != '*' else 'unknown'
                    leases[ip] = {'mac': mac, 'hostname': hostname}
    except FileNotFoundError:
        pass
    return leases

def run_nmap(ip):
    """nmap сканирование с OS fingerprint"""
    try:
        result = subprocess.run(
            ['nmap', '-O', '--osscan-guess', '-sV', '-T4', '-F',
             '--open', ip, '-oX', '-'],
            capture_output=True, text=True, timeout=60
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        log.warning(f'nmap timeout для {ip}')
        return ''
    except Exception as e:
        log.error(f'nmap error {ip}: {e}')
        return ''

def parse_nmap_xml(xml_data):
    """Парсим nmap XML вывод"""
    import xml.etree.ElementTree as ET
    ports = []
    os_guess = 'Unknown'
    try:
        root = ET.fromstring(xml_data)
        for host in root.findall('host'):
            for port in host.findall('.//port'):
                state = port.find('state')
                if state is not None and state.get('state') == 'open':
                    portid = port.get('portid')
                    svc = port.find('service')
                    svc_name = svc.get('name', '') if svc is not None else ''
                    svc_ver = svc.get('version', '') if svc is not None else ''
                    ports.append(f'{portid}/{svc_name}/{svc_ver}')
            for osmatch in host.findall('.//osmatch'):
                os_guess = osmatch.get('name', 'Unknown')
                break
    except Exception as e:
        log.debug(f'XML parse error: {e}')
    return ports, os_guess

def check_nvd_cves(service_name, version):
    """CVE lookup через NIST NVD API"""
    if not service_name or service_name in ('Unknown', ''):
        return []
    try:
        query = urllib.parse.quote(f'{service_name} {version}')
        url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}&resultsPerPage=5'
        req = urllib.request.Request(url, headers={'User-Agent': 'PineapplePI/1.0'})
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read().decode())
            cves = []
            for item in data.get('vulnerabilities', []):
                cve_id = item.get('cve', {}).get('id', '')
                descs = item.get('cve', {}).get('descriptions', [])
                desc = descs[0].get('value', '')[:100] if descs else ''
                metrics = item.get('cve', {}).get('metrics', {})
                score = ''
                if 'cvssMetricV31' in metrics:
                    score = str(metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseScore', ''))
                elif 'cvssMetricV2' in metrics:
                    score = str(metrics['cvssMetricV2'][0].get('cvssData', {}).get('baseScore', ''))
                cves.append({'id': cve_id, 'score': score, 'desc': desc})
            return cves
    except Exception:
        return []

def scan_client(ip, lease_info):
    """Полное сканирование клиента"""
    log.info(f'Сканирование клиента: {ip}')
    mac = lease_info.get('mac', 'Unknown')
    hostname = lease_info.get('hostname', 'unknown')

    vendor = get_mac_vendor(mac)
    nmap_xml = run_nmap(ip)
    ports, os_guess = parse_nmap_xml(nmap_xml)

    cve_results = []
    for p in ports[:3]:
        parts = p.split('/')
        if len(parts) >= 2:
            svc = parts[1]
            ver = parts[2] if len(parts) > 2 else ''
            cves = check_nvd_cves(svc, ver)
            cve_results.extend(cves)

    return {
        'ip': ip,
        'mac': mac,
        'hostname': hostname,
        'vendor': vendor,
        'os_guess': os_guess,
        'open_ports': json.dumps(ports),
        'cves': json.dumps(cve_results[:10]),
        'raw_nmap': nmap_xml[:2000]
    }

def save_client(con, data):
    now = datetime.now().isoformat()
    con.execute("""
        INSERT INTO clients (ip, mac, hostname, vendor, os_guess, open_ports, cves, first_seen, last_seen, raw_nmap)
        VALUES (:ip, :mac, :hostname, :vendor, :os_guess, :open_ports, :cves, :first_seen, :last_seen, :raw_nmap)
        ON CONFLICT(ip) DO UPDATE SET
            mac=excluded.mac, hostname=excluded.hostname, vendor=excluded.vendor,
            os_guess=excluded.os_guess, open_ports=excluded.open_ports, cves=excluded.cves,
            last_seen=excluded.last_seen, raw_nmap=excluded.raw_nmap
    """, {**data, 'first_seen': now, 'last_seen': now})
    con.commit()

def main():
    log.info('PineapplePI Recon Engine запущен')
    Path('/opt/pineapple/db').mkdir(parents=True, exist_ok=True)
    con = init_db()
    known_clients = set()

    while True:
        try:
            leases = get_leases()
            for ip, info in leases.items():
                if ip not in known_clients:
                    log.info(f'Новый клиент: {ip} ({info})')
                    data = scan_client(ip, info)
                    save_client(con, data)
                    known_clients.add(ip)
                else:
                    con.execute("UPDATE clients SET last_seen=? WHERE ip=?",
                                (datetime.now().isoformat(), ip))
                    con.commit()
            time.sleep(30)
        except KeyboardInterrupt:
            break
        except Exception as e:
            log.error(f'Ошибка main loop: {e}')
            time.sleep(10)

if __name__ == '__main__':
    main()
