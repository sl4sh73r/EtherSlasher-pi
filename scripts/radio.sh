#!/bin/bash
# PineapplePI Radio Stack Manager v2
# wlan0 = BCM (phy1) — admin AP (10.42.0.1)
# wlan1 = RTL8812AU (phy0) — attack interface
set -e

ATTACK_IFACE="wlan1"
AP_IP="10.0.0.1"
LOG_TAG="[$(date '+%H:%M:%S')] RADIO"
log() { echo "$LOG_TAG: $1"; }

cmd="${1:-status}"

detect_uplink() {
    for IFACE in end1 end0 eth1 eth0; do
        if ip route | grep -q "default.*$IFACE"; then echo "$IFACE"; return; fi
    done
    echo "end1"
}

iface_down_clean() {
    # Bring interface down cleanly before mode switch (required for 88XXau driver)
    ip link set "$ATTACK_IFACE" down 2>/dev/null || true
    sleep 0.3
}

start_monitor() {
    log "Monitor mode на $ATTACK_IFACE..."
    nmcli dev set "$ATTACK_IFACE" managed no 2>/dev/null || true
    pkill -f "wpa_supplicant.*$ATTACK_IFACE" 2>/dev/null || true
    iface_down_clean
    iw dev "$ATTACK_IFACE" set type monitor
    ip link set "$ATTACK_IFACE" up
    if iw dev "$ATTACK_IFACE" info 2>/dev/null | grep -q "type monitor"; then
        log "Monitor mode OK на $ATTACK_IFACE"
    else
        log "WARN: monitor mode не подтверждён"
    fi
}

stop_monitor() {
    log "Выключаю monitor mode..."
    pkill -f "airodump-ng" 2>/dev/null || true
    pkill -f "aireplay-ng" 2>/dev/null || true
    pkill -f "aireplay_ng" 2>/dev/null || true
    sleep 0.3
    iface_down_clean
    iw dev "$ATTACK_IFACE" set type managed 2>/dev/null || true
    ip link set "$ATTACK_IFACE" up 2>/dev/null || true
    nmcli dev set "$ATTACK_IFACE" managed yes 2>/dev/null || true
    log "Monitor mode выключен"
}

start_ap() {
    local SSID="${2:-FreeWiFi}"
    local CHANNEL="${3:-6}"
    log "Evil Twin: SSID=$SSID CH=$CHANNEL"

    # Kill all attack processes
    pkill -f "airodump-ng" 2>/dev/null || true
    pkill -f "aireplay-ng" 2>/dev/null || true
    pkill -f "hostapd" 2>/dev/null || true
    pkill -f "dnsmasq.*at0\|dnsmasq.*wlan1" 2>/dev/null || true
    sleep 0.5

    # CRITICAL: interface must be DOWN before mode switch (88XXau driver requirement)
    nmcli dev set "$ATTACK_IFACE" managed no 2>/dev/null || true
    iface_down_clean
    iw dev "$ATTACK_IFACE" set type managed 2>/dev/null || true
    # Leave interface DOWN — hostapd will bring it up in AP mode
    log "Интерфейс $ATTACK_IFACE переведён в managed (down), hostapd запустит его"

    # Write hostapd config
    cat > /opt/pineapple/config/hostapd.conf << EOF
interface=$ATTACK_IFACE
driver=nl80211
ssid=$SSID
hw_mode=g
channel=$CHANNEL
ieee80211n=1
wmm_enabled=1
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
EOF

    # NAT setup (can be done before interface comes up)
    echo 1 > /proc/sys/net/ipv4/ip_forward
    UPLINK=$(detect_uplink)
    iptables -t nat -D POSTROUTING -o "$UPLINK" -j MASQUERADE 2>/dev/null || true
    iptables -t nat -A POSTROUTING -o "$UPLINK" -j MASQUERADE
    iptables -A FORWARD -i "$ATTACK_IFACE" -o "$UPLINK" -j ACCEPT 2>/dev/null || true
    iptables -A FORWARD -i "$UPLINK" -o "$ATTACK_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    log "NAT через $UPLINK готов"
}

stop_ap() {
    log "Останавливаю AP..."
    pkill -f "hostapd" 2>/dev/null || true
    pkill -f "dnsmasq.*wlan1\|dnsmasq.*at0" 2>/dev/null || true
    sleep 0.3
    iptables -t nat -F PREROUTING 2>/dev/null || true
    # Don't flush all POSTROUTING — just remove our rule
    iptables -t nat -D POSTROUTING -j MASQUERADE 2>/dev/null || true
    iptables -F FORWARD 2>/dev/null || true
    iface_down_clean
    iw dev "$ATTACK_IFACE" set type managed 2>/dev/null || true
    ip link set "$ATTACK_IFACE" up 2>/dev/null || true
    nmcli dev set "$ATTACK_IFACE" managed yes 2>/dev/null || true
    log "AP остановлен"
}

show_status() {
    echo "ATTACK_IFACE=$ATTACK_IFACE"
    iw dev "$ATTACK_IFACE" info 2>/dev/null || echo "$ATTACK_IFACE not found"
    if iw dev "$ATTACK_IFACE" info 2>/dev/null | grep -q "type monitor"; then
        echo "MONITOR=active"
    elif iw dev "$ATTACK_IFACE" info 2>/dev/null | grep -q "type AP"; then
        echo "AP=active"
    else
        echo "MODE=managed"
    fi
}

case "$cmd" in
    monitor-start) start_monitor ;;
    monitor-stop)  stop_monitor ;;
    ap-start)      start_ap "$@" ;;
    ap-stop)       stop_ap ;;
    status)        show_status ;;
    *) echo "Usage: $0 {monitor-start|monitor-stop|ap-start [ssid] [ch]|ap-stop|status}"; exit 1 ;;
esac
