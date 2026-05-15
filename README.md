# EtherSlasher

Open-source educational WiFi security audit platform 
running on Orange Pi RV2 (RISC-V).

## Purpose

EtherSlasher is built as an educational tool for:
- University coursework and thesis research at MIREA — Russian Technological University
- CTF training and security-awareness demonstrations
- Hands-on learning of 802.11 protocols, common attack vectors, 
  and corresponding defenses

## Architecture

- **Dashboard** — Node.js / Express / Socket.io, EVA-inspired UI, 
  live Chart.js telemetry from passive AP scanning
- **Radio worker** — Python wrapper around airodump-ng with SQLite 
  persistence
- **Captive portal** — router-branded templates (MGTS, MTS, Keenetic, 
  TP-Link, Huawei, Xiaomi, Beeline) for phishing-awareness demos
- **Adapter detection** — udev rules + systemd service for universal 
  USB WiFi adapter handling (tested on Alfa AWUS036ACH, TP-Link T2U Nano)

## ⚠️ Authorized Use Only

This tool is intended **exclusively** for:
- Networks you own
- Networks you have explicit written authorization to test  
- Isolated lab environments built for education and research

Running EtherSlasher against networks without authorization is illegal 
in virtually every jurisdiction and violates this project's license. 
The author assumes no liability for misuse.

## License

MIT (see LICENSE)

## Academic context

Developed as part of coursework / thesis research at 
**MIREA — Russian Technological University**.
