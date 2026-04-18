#!/bin/bash
LOG_DIR=/var/log/pineapple
find "$LOG_DIR" -name '*.log' -mtime +1 -exec truncate -s 0 {} \;
find "$LOG_DIR" -name '*.pcap' -mtime +1 -delete
journalctl --vacuum-time=1h 2>/dev/null || true
echo "[$(date)] Логи очищены" >> /var/log/pineapple/cleanup.log
