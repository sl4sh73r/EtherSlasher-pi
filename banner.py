#!/usr/bin/env python3
import time, subprocess, os, sys
from blessed import Terminal

t = Terminal()

def get_stats():
    def cmd(c):
        try: return subprocess.check_output(c, shell=True, stderr=subprocess.DEVNULL).decode().strip()
        except: return "N/A"
    cpu = cmd("top -bn1 | grep 'Cpu' | awk '{print $2}' | cut -d'%' -f1 | cut -d'.' -f1") or "0"
    ram_pct = cmd("free | awk 'NR==2{printf \"%.0f\", $3/$2*100}'") or "0"
    ram_used = cmd("free -m | awk 'NR==2{printf \"%s/%s\", $3,$2}'") or "0/0"
    temp = cmd("cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null | awk '{printf \"%.0f\", $1/1000}'") or "0"
    ip = cmd("ip addr show end1 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1") or "192.168.2.37"
    uptime = cmd("uptime -p | sed 's/up //'") or "N/A"
    kernel = cmd("uname -r") or "N/A"
    hostname = cmd("hostname") or "etherslasher"
    wlan = cmd("iw dev wlan1 info 2>/dev/null | grep type | awk '{print $2}'").upper() or "IDLE"
    ap = "ACTIVE" if cmd("pgrep -x airbase-ng") else "OFF"
    web = cmd("systemctl is-active etherslasher-web 2>/dev/null").upper() or "DEAD"
    clients = cmd("cat /var/lib/misc/dnsmasq.leases 2>/dev/null | wc -l") or "0"
    creds = cmd("sqlite3 /opt/etherslasher/db/etherslasher.db 'SELECT COUNT(*) FROM captured_creds;' 2>/dev/null") or "0"
    date = cmd("date '+%Y-%m-%d %H:%M:%S UTC'")
    return dict(cpu=int(cpu or 0), ram=int(ram_pct or 0), ram_used=ram_used,
                temp=int(temp or 0), ip=ip, uptime=uptime, kernel=kernel,
                hostname=hostname, wlan=wlan, ap=ap, web=web,
                clients=clients, creds=creds, date=date)

def bar(val, max_val=100, width=20, filled='█', empty='░'):
    n = min(int(val / max_val * width), width)
    return filled * n + empty * (width - n)

def temp_color(t, temp):
    if temp > 75: return t.red
    if temp > 60: return t.color(214)
    return t.color(208)

def print_banner(s):
    O = t.color(208)      # orange
    D = t.color(130)      # dark orange
    W = t.white           # white
    R = t.red
    G = t.color(40)       # green
    N = t.normal
    TC = temp_color(t, s['temp'])

    LOGO = [
        "  ███████╗████████╗██╗  ██╗███████╗██████╗  ",
        "  ██╔════╝╚══██╔══╝██║  ██║██╔════╝██╔══██╗ ",
        "  █████╗     ██║   ███████║█████╗  ██████╔╝ ",
        "  ██╔══╝     ██║   ██╔══██║██╔══╝  ██╔══██╗ ",
        "  ███████╗   ██║   ██║  ██║███████╗██║  ██║ ",
        "  ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ",
        "                                             ",
        "  ███████╗██╗      █████╗ ███████╗██╗  ██╗███████╗██████╗ ",
        "  ██╔════╝██║     ██╔══██╗██╔════╝██║  ██║██╔════╝██╔══██╗",
        "  ███████╗██║     ███████║███████╗███████║█████╗  ██████╔╝",
        "  ╚════██║██║     ██╔══██║╚════██║██╔══██║██╔══╝  ██╔══██╗",
        "  ███████║███████╗██║  ██║███████║██║  ██║███████╗██║  ██║",
        "  ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝",
    ]

    print(t.clear)

    # TOP BORDER
    print(O + "  ╔══════════════════════════════════════════════════════════════════╗" + N)

    # LOGO with typewriter animation
    for i, line in enumerate(LOGO):
        print(O + "  ║  " + line + N)
        time.sleep(0.03)

    print(O + "  ║" + N)
    print(O + "  ║  " + D + "W I F I   A U D I T   P L A T F O R M" + N)
    print(O + "  ║  " + D + "RECON  •  EXPLOIT  •  ANALYZE  •  SECURE" + N)
    print(O + "  ║" + N)
    print(O + "  ╠══════════════════════════════════════════════════════════════════╣" + N)
    print(O + "  ║" + N)
    print(O + "  ║  " + D + "HOST   " + O + f"{s['hostname']:<22}" + D + "DATE   " + O + s['date'] + N)
    print(O + "  ║  " + D + "KERNEL " + O + f"{s['kernel']:<22}" + D + "IP     " + O + s['ip'] + N)
    print(O + "  ║  " + D + "UPTIME " + O + s['uptime'] + N)
    print(O + "  ║" + N)
    print(O + "  ╠═══════════════════════════╦══════════════════════════════════════╣" + N)
    print(O + "  ║  " + W + "SYSTEM" + O + "                   ║  " + W + "SERVICES" + O + "                              ║" + N)
    print(O + "  ╠═══════════════════════════╬══════════════════════════════════════╣" + N)

    # CPU
    cpu_bar = bar(s['cpu'])
    web_col = G if s['web'] == 'ACTIVE' else R
    print(O + "  ║  " + D + "CPU  " + O + f"[{cpu_bar}] {s['cpu']:3d}%" +
          O + "  ║  " + D + "WEB    " + web_col + f"{s['web']:<8}" + O + "                      ║" + N)

    # RAM
    ram_bar = bar(s['ram'])
    wlan_col = G if s['wlan'] in ('MONITOR', 'AP') else O
    print(O + "  ║  " + D + "RAM  " + O + f"[{ram_bar}] {s['ram']:3d}%" +
          O + "  ║  " + D + "RADIO  " + wlan_col + f"{s['wlan']:<8}" + O + "                      ║" + N)

    # TEMP
    temp_bar = bar(s['temp'], max_val=100)
    ap_col = G if s['ap'] == 'ACTIVE' else D
    print(O + "  ║  " + TC + f"TEMP [{temp_bar}] {s['temp']:3d}°C" +
          O + "  ║  " + D + "AP     " + ap_col + f"{s['ap']:<8}" + O + "                      ║" + N)

    print(O + "  ║                           ║                                      ║" + N)

    cl_col = G if int(s['clients'] or 0) > 0 else D
    cr_col = G if int(s['creds'] if s['creds'].isdigit() else 0) > 0 else D
    print(O + "  ║                           ║  " + D + "CLIENTS  " + cl_col + f"{s['clients']:<6}" + O + "                      ║" + N)
    print(O + "  ║                           ║  " + D + "CREDS    " + cr_col + f"{s['creds']:<6}" + O + "                      ║" + N)
    print(O + "  ║                           ║                                      ║" + N)
    print(O + "  ╠═══════════════════════════╩══════════════════════════════════════╣" + N)
    print(O + "  ║  " + D + "DASHBOARD  →  " + O + f"http://{s['ip']}:8080" + O + "                          ║" + N)
    print(O + "  ╠══════════════════════════════════════════════════════════════════╣" + N)

    last = f"  [etherslasher@{s['hostname']}]$ ready to slash."
    sys.stdout.write(O + "  ║")
    for ch in last:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(0.04)
    print(O + "_" + N)
    print(O + "  ╚══════════════════════════════════════════════════════════════════╝" + N)
    print(N)

if __name__ == '__main__':
    try:
        stats = get_stats()
        print_banner(stats)
    except KeyboardInterrupt:
        print(Terminal().normal)
