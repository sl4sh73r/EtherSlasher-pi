#!/bin/bash
# EtherSlasher health monitor — runs every 5 min via cron
PID=$(pgrep -f "node.*app.js" | head -1)
[ -z "$PID" ] && exit 0

MEM=$(awk '/VmRSS/{print $2}' /proc/$PID/status 2>/dev/null)
[ -z "$MEM" ] && exit 0

# Restart if Node.js RSS > 300 MB
if [ "$MEM" -gt 307200 ]; then
    logger "EtherSlasher: OOM restart triggered (RSS=${MEM}kB)"
    systemctl restart etherslasher-web
fi
