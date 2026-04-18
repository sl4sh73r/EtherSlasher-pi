#!/bin/bash

export TERM=${TERM:-xterm-256color}
# Цвета
O='\033[38;5;208m'   # оранжевый
o='\033[38;5;166m'   # тёмный оранжевый
D='\033[38;5;130m'   # dimmed оранжевый
N='\033[0m'          # reset
B='\033[1m'          # bold

# Реальные данные
HOSTNAME=$(hostname)
KERNEL=$(uname -r)
UPTIME=$(uptime -p 2>/dev/null | sed 's/up //' || uptime | sed 's/.*up //' | cut -d',' -f1)
CPU=$(top -bn1 2>/dev/null | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1 | cut -d'.' -f1)
[ -z "$CPU" ] && CPU=$(grep -oP '\d+\.\d+ us' /proc/stat 2>/dev/null | head -1 | grep -oP '\d+' | head -1)
[ -z "$CPU" ] && CPU="0"
RAM_USED=$(free -m 2>/dev/null | awk 'NR==2{printf "%s/%sMB", $3,$2}')
RAM_PCT=$(free 2>/dev/null | awk 'NR==2{printf "%.0f", $3/$2*100}')
[ -z "$RAM_PCT" ] && RAM_PCT="0"
TEMP=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null | awk '{printf "%.0f", $1/1000}')
[ -z "$TEMP" ] && TEMP=$(cat /sys/class/thermal/thermal_zone*/temp 2>/dev/null | head -1 | awk '{printf "%.0f", $1/1000}')
[ -z "$TEMP" ] && TEMP="0"
IP=$(ip addr show end1 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
[ -z "$IP" ] && IP=$(ip addr show eth0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
[ -z "$IP" ] && IP=$(hostname -I 2>/dev/null | awk '{print $1}')
WLAN_MODE=$(iw dev wlan1 info 2>/dev/null | grep type | awk '{print $2}' | tr '[:lower:]' '[:upper:]')
[ -z "$WLAN_MODE" ] && WLAN_MODE="IDLE"
AP_STATUS=$(pgrep -x airbase-ng > /dev/null 2>&1 && echo "ACTIVE" || echo "OFF")
WEB_STATUS=$(systemctl is-active etherslasher-web 2>/dev/null | tr '[:lower:]' '[:upper:]')
[ -z "$WEB_STATUS" ] && WEB_STATUS="UNKNOWN"
CLIENTS=$(cat /var/lib/misc/dnsmasq.leases 2>/dev/null | wc -l)
CREDS=$(sqlite3 /opt/etherslasher/db/etherslasher.db "SELECT COUNT(*) FROM captured_creds;" 2>/dev/null || echo "0")
DATE=$(date '+%Y-%m-%d %H:%M:%S UTC')

# Температура — цвет
if [ "$TEMP" -gt 75 ] 2>/dev/null; then TCOL='\033[38;5;196m'
elif [ "$TEMP" -gt 60 ] 2>/dev/null; then TCOL='\033[38;5;214m'
else TCOL="$O"; fi

clear

echo -e "${O}"
echo -e "  ┌──────────────────────────────────────────────────────────────────┐"
echo -e "  │                                                                  │"
echo -e "  │   ███████╗████████╗██╗  ██╗███████╗██████╗                      │"
echo -e "  │   ██╔════╝╚══██╔══╝██║  ██║██╔════╝██╔══██╗                     │"
echo -e "  │   █████╗     ██║   ███████║█████╗  ██████╔╝                     │"
echo -e "  │   ██╔══╝     ██║   ██╔══██║██╔══╝  ██╔══██╗                     │"
echo -e "  │   ███████╗   ██║   ██║  ██║███████╗██║  ██║                     │"
echo -e "  │   ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝                    │"
echo -e "  │                                                                  │"
echo -e "  │   ███████╗██╗      █████╗ ███████╗██╗  ██╗███████╗██████╗       │"
echo -e "  │   ██╔════╝██║     ██╔══██╗██╔════╝██║  ██║██╔════╝██╔══██╗      │"
echo -e "  │   ███████╗██║     ███████║███████╗███████║█████╗  ██████╔╝      │"
echo -e "  │   ╚════██║██║     ██╔══██║╚════██║██╔══██║██╔══╝  ██╔══██╗      │"
echo -e "  │   ███████║███████╗██║  ██║███████║██║  ██║███████╗██║  ██║      │"
echo -e "  │   ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝     │"
echo -e "  │                                                                  │"
echo -e "  │   ${D}W I F I   A U D I T   P L A T F O R M${O}                         │"
echo -e "  │   ${D}RECON  •  EXPLOIT  •  ANALYZE  •  SECURE${O}                      │"
echo -e "  │                                                                  │"
echo -e "  ├──────────────────────────────────────────────────────────────────┤"
echo -e "  │                                                                  │"
printf  "  │  ${D}HOST${O}     %-20s  ${D}DATE${O}  %s\n" "$HOSTNAME" "$DATE"
printf  "  │  ${D}KERNEL${O}   %-20s  ${D}IP${O}    %s\n" "$KERNEL" "${IP:-N/A}"
printf  "  │  ${D}UPTIME${O}   %-20s\n" "$UPTIME"
echo -e "  │                                                                  │"
echo -e "  ├─────────────────────────┬────────────────────────────────────────┤"
echo -e "  │  SYSTEM                 │  SERVICES                              │"
echo -e "  ├─────────────────────────┼────────────────────────────────────────┤"

# CPU bar (20 блоков = 100%)
CPU_INT=${CPU:-0}
CPU_FILL=$(( CPU_INT / 5 ))
[ "$CPU_FILL" -gt 20 ] && CPU_FILL=20
CPU_EMPTY=$(( 20 - CPU_FILL ))
CPU_BAR=$(printf '█%.0s' $(seq 1 $CPU_FILL 2>/dev/null))$(printf '░%.0s' $(seq 1 $CPU_EMPTY 2>/dev/null))
printf "  │  ${D}CPU${O}  [${O}%-20s${O}] %3s%%  │  ${D}WEB${O}      %-6s                  │\n" \
    "$CPU_BAR" "$CPU_INT" "$WEB_STATUS"

# RAM bar
RAM_INT=${RAM_PCT:-0}
RAM_FILL=$(( RAM_INT / 5 ))
[ "$RAM_FILL" -gt 20 ] && RAM_FILL=20
RAM_EMPTY=$(( 20 - RAM_FILL ))
RAM_BAR=$(printf '█%.0s' $(seq 1 $RAM_FILL 2>/dev/null))$(printf '░%.0s' $(seq 1 $RAM_EMPTY 2>/dev/null))
printf "  │  ${D}RAM${O}  [${O}%-20s${O}] %3s%%  │  ${D}RADIO${O}    %-6s                  │\n" \
    "$RAM_BAR" "$RAM_INT" "$WLAN_MODE"

# TEMP bar
TEMP_INT=${TEMP:-0}
TEMP_FILL=$(( TEMP_INT / 5 ))
[ "$TEMP_FILL" -gt 20 ] && TEMP_FILL=20
TEMP_EMPTY=$(( 20 - TEMP_FILL ))
TEMP_BAR=$(printf '█%.0s' $(seq 1 $TEMP_FILL 2>/dev/null))$(printf '░%.0s' $(seq 1 $TEMP_EMPTY 2>/dev/null))
printf "  │  ${TCOL}TEMP${O} [${TCOL}%-20s${O}] %3s°C  │  ${D}AP${O}       %-6s                  │\n" \
    "$TEMP_BAR" "$TEMP_INT" "$AP_STATUS"

echo -e "  │                         │                                        │"
printf  "  │                         │  ${D}CLIENTS${O}  %-6s                  │\n" "$CLIENTS"
printf  "  │                         │  ${D}CREDS${O}    %-6s                  │\n" "$CREDS"
echo -e "  │                         │                                        │"
echo -e "  ├─────────────────────────┴────────────────────────────────────────┤"
echo -e "  │  DASHBOARD  →  http://${IP:-192.168.2.37}:8080                        │"
echo -e "  ├──────────────────────────────────────────────────────────────────┤"
printf  "  │  [${D}etherslasher${O}@${D}%s${O}]\$ ready to slash._                       │\n" "$HOSTNAME"
echo -e "  └──────────────────────────────────────────────────────────────────┘"
echo -e "${N}"
