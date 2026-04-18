#!/bin/bash
# PineapplePI OPSEC - MAC randomization + hostname rotation
LOG=/var/log/pineapple/opsec.log
log() { echo "[$(date +%T)] OPSEC: $*" | tee -a "$LOG"; }

ADJECTIVES=(shadow dark silent ghost rogue phantom stealth cyber zero)
NOUNS=(node probe beacon unit link pulse wave core)
ADJ=${ADJECTIVES[$RANDOM % ${#ADJECTIVES[@]}]}
NOUN=${NOUNS[$RANDOM % ${#NOUNS[@]}]}
NUM=$((RANDOM % 999))
NEW_HOST="${ADJ}-${NOUN}-${NUM}"
hostnamectl set-hostname "$NEW_HOST" 2>/dev/null || true
log "Hostname: $NEW_HOST"

for IFACE in wlan0 wlan1; do
    if ip link show "$IFACE" &>/dev/null; then
        ip link set "$IFACE" down 2>/dev/null || true
        NEW_MAC=$(printf "02:%02x:%02x:%02x:%02x:%02x" $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))
        ip link set "$IFACE" address "$NEW_MAC" 2>/dev/null || true
        ip link set "$IFACE" up 2>/dev/null || true
        log "$IFACE MAC: $NEW_MAC"
    fi
done
log "OPSEC startup завершён"
