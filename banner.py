#!/usr/bin/env python3
"""EtherSlasher banner entrypoint."""

from __future__ import annotations

from pathlib import Path
import sys


BOOTSTRAP_FILES = {
    "__init__.py": '''"""EtherSlasher ANSI TUI package."""\n''',
    "renderer.py": r'''from __future__ import annotations

import os
import shutil
import sys

CSI = "\x1b["
RESET = f"{CSI}0m"


def sgr(*codes: int | str) -> str:
    return f"{CSI}{';'.join(str(code) for code in codes)}m"


class TerminalRenderer:
    def __init__(self, stream=None) -> None:
        self.stream = stream or sys.stdout
        self.is_tty = bool(getattr(self.stream, "isatty", lambda: False)())
        self.colors = self.is_tty and os.environ.get("TERM", "dumb") != "dumb"
        self.width, self.height = self.size()

    def size(self) -> tuple[int, int]:
        size = shutil.get_terminal_size((100, 30))
        return max(80, size.columns), max(24, size.lines)

    def draw_text(self, lines: list[str]) -> None:
        payload = "\n".join(lines)
        if self.colors:
            payload = f"{sgr('38', '5', '208')}{payload}{RESET}"
        if payload and not payload.endswith("\n"):
            payload += "\n"
        self.stream.write(payload)
        self.stream.flush()
''',
    "data.py": r'''from __future__ import annotations

import shlex
import shutil
import socket
import subprocess
import time


def run(command: str, timeout: float = 1.0) -> str:
    try:
        result = subprocess.run(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout,
        )
    except Exception:
        return ""
    return result.stdout.strip()


def read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            return handle.read().strip()
    except OSError:
        return ""


class StatsProvider:
    def __init__(self) -> None:
        self.last_total = 0
        self.last_idle = 0
        self.last_cpu = 0

    def _cpu_percent(self) -> int:
        line = read_text("/proc/stat").splitlines()
        if not line:
            return self.last_cpu
        parts = line[0].split()
        if len(parts) < 5:
            return self.last_cpu
        values = [int(value) for value in parts[1:8]]
        idle = values[3] + values[4]
        total = sum(values)
        if self.last_total:
            delta_total = max(1, total - self.last_total)
            delta_idle = max(0, idle - self.last_idle)
            usage = int((1.0 - (delta_idle / delta_total)) * 100)
            self.last_cpu = max(0, min(100, usage))
        self.last_total = total
        self.last_idle = idle
        return self.last_cpu

    def _mem_percent(self) -> int:
        fields = {}
        for line in read_text("/proc/meminfo").splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            fields[key] = int(value.strip().split()[0])
        total = fields.get("MemTotal", 1)
        available = fields.get("MemAvailable", fields.get("MemFree", 0))
        return max(0, min(100, int(((total - available) / total) * 100)))

    def _temp_c(self) -> int:
        for path in (
            "/sys/class/thermal/thermal_zone0/temp",
            "/sys/class/hwmon/hwmon0/temp1_input",
        ):
            value = read_text(path)
            if value.isdigit():
                raw = int(value)
                return raw // 1000 if raw > 1000 else raw
        return 0

    def _ip_address(self) -> str:
        output = run("ip -4 route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i==\"src\") print $(i+1)}'", timeout=0.8)
        return output or "127.0.0.1"

    def _wifi_mode(self) -> str:
        output = run("iw dev 2>/dev/null | awk '/type/ {print toupper($2); exit}'", timeout=0.8)
        return output or "IDLE"

    def _service_status(self, name: str) -> str:
        if shutil.which("systemctl"):
            status = run(f"systemctl is-active {shlex.quote(name)}", timeout=0.8).upper()
            if status:
                return status
        return "UNKNOWN"

    def snapshot(self) -> dict[str, object]:
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        uptime_raw = read_text("/proc/uptime").split()
        uptime_seconds = int(float(uptime_raw[0])) if uptime_raw else 0
        hours, remainder = divmod(uptime_seconds, 3600)
        minutes = remainder // 60
        loadavg = read_text("/proc/loadavg").split()[:3]
        return {
            "hostname": socket.gethostname(),
            "time": now,
            "cpu": self._cpu_percent(),
            "ram": self._mem_percent(),
            "temp": self._temp_c(),
            "ip": self._ip_address(),
            "uptime": f"{hours}h {minutes}m",
            "load": " ".join(loadavg) if loadavg else "0.00 0.00 0.00",
            "web": self._service_status("etherslasher-web"),
            "radio": self._wifi_mode(),
            "ap": "ACTIVE" if run("pgrep -x hostapd || pgrep -x airbase-ng", timeout=0.6) else "OFF",
            "iface": run("iw dev 2>/dev/null | awk '/Interface/ {print $2; exit}'", timeout=0.8) or "wlan0",
        }


''',
    "ui.py": r'''from __future__ import annotations

LOGO = [
    "    ▄██▄            ██",
    "  ▄█▀▀▀██▄       ▄█▀/",
    " ██▄    ▀██▄   ▄██ / ",
    "  ▀██▄    ▀█████▀ /  ",
    "    ▀████▄██▀▀  /    ",
    "        ▀██▀         ",
]


def fit(text: str, width: int) -> str:
    width = max(0, width)
    if len(text) <= width:
        return text
    if width <= 1:
        return text[:width]
    return text[: width - 1] + "…"


def rule(width: int = 100) -> str:
    return "─" * max(1, width)


def bar(label: str, value: int, width: int = 22) -> str:
    value = max(0, min(100, value))
    filled = round((value / 100) * width)
    meter = ("█" * filled) + ("░" * (width - filled))
    return f"{label:<4}[{meter}] {value:>3}%"


def snapshot_lines(stats: dict[str, object]) -> list[str]:
    hostname = str(stats.get("hostname", "etherslasher"))
    ip = str(stats.get("ip", "127.0.0.1"))
    uptime = str(stats.get("uptime", "0h 0m"))
    load = str(stats.get("load", "0.00 0.00 0.00"))
    web = str(stats.get("web", "UNKNOWN"))
    radio = str(stats.get("radio", "IDLE"))
    ap = str(stats.get("ap", "OFF"))
    iface = str(stats.get("iface", "wlan0"))
    temp = int(stats.get("temp", 0))
    cpu = int(stats.get("cpu", 0))
    ram = int(stats.get("ram", 0))

    left = [
        bar("CPU", cpu),
        bar("RAM", ram),
        f"TEMP {temp:>3}C",
        f"UP   {uptime}",
        f"IP   {ip}",
    ]
    right = [
        f"WEB    {web}",
        f"RADIO  {radio}",
        f"AP     {ap}",
        f"IFACE  {iface}",
        f"LOAD   {load}",
    ]

    lines: list[str] = []
    lines.extend(LOGO)
    lines.append("")
    lines.append(f"TEMP: {temp}C | CPU: {cpu}%")
    lines.append(f"host: {hostname}")
    lines.append(rule())
    lines.append("SYSTEM".ljust(50) + "SERVICES")
    for left_line, right_line in zip(left, right):
        lines.append(f"{fit(left_line, 48).ljust(50)}{fit(right_line, 48)}")
    lines.append(rule())
    return lines
''',
    "app.py": r'''from __future__ import annotations

from tui.data import StatsProvider
from tui.renderer import TerminalRenderer
from tui.ui import snapshot_lines


def main() -> int:
    renderer = TerminalRenderer()
    stats = StatsProvider().snapshot()
    renderer.draw_text(snapshot_lines(stats))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
''',
}


def ensure_tui() -> None:
    root = Path(__file__).resolve().parent
    target = root / "tui"
    target.mkdir(parents=True, exist_ok=True)
    for name, content in BOOTSTRAP_FILES.items():
        path = target / name
        if not path.exists():
            path.write_text(content, encoding="utf-8")


def main() -> int:
    ensure_tui()
    root = Path(__file__).resolve().parent
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from tui.app import main as tui_main

    return tui_main()


if __name__ == "__main__":
    raise SystemExit(main())
