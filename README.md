# WIFI-FLOOD

> A high-performance Python tool for generating massive amounts of fake Wi-Fi beacon frames — designed for wireless penetration testing, network security assessments, and 802.11 protocol auditing.

<p align="center">
  <img src="https://img.shields.io/badge/python-3.6%2B-blue?style=for-the-badge&logo=python">
  <img src="https://img.shields.io/badge/scapy-2.5%2B-green?style=for-the-badge">
  <img src="https://img.shields.io/badge/license-MIT-yellow?style=for-the-badge">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20Kali%20Linux-red?style=for-the-badge&logo=linux">
</p>

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [How It Works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Guide](#usage-guide)
- [Output & Statistics](#output--statistics)
- [Technical Details](#technical-details)
- [Ethical & Legal](#ethical--legal)
- [Troubleshooting](#troubleshooting)
- [Cleanup](#cleanup)
- [FAQ](#faq)
- [License](#license)

---

## Overview

**FakeAP Beacon Flood Generator** crafts raw 802.11 management beacon frames at Layer 2 and broadcasts them into the air, flooding nearby Wi-Fi scanners with hundreds (or thousands) of fake access points. Each frame contains a randomized SSID, BSSID (MAC), advertised channel, supported rates, and optional WPA2/RSN information elements — making each fake AP appear legitimate to any scanning device.

### Why Beacon Flooding?

| Use Case | Description |
|----------|-------------|
| **Client behavior analysis** | Observe how Wi-Fi clients scan, rank, and select APs when exposed to hundreds of networks |
| **Stress testing** | Evaluate wireless controllers, AP management software, or client scanning algorithms under load |
| **Signal obfuscation** | Conceal legitimate APs within a dense artificial noise floor during red team operations |
| **Education & research** | Demonstrate 802.11 frame structure, beacon intervals, and wireless protocol fundamentals |
| **Vulnerability probing** | Test for buffer overflows, memory leaks, or parsing bugs in wireless drivers and firmware |

---

## Features

- **Massive scale** — generate 500+ unique fake access points simultaneously
- **Multi-threaded architecture** — concurrent sending threads for maximum frame throughput
- **Fast burst mode** — optional single-threaded tight-loop mode for maximum frame rate
- **Realistic frame generation** — randomized SSIDs, BSSIDs, channels, and WPA2 capabilities
- **Custom SSID pool** — load your own SSID list from a text file
- **Channel control** — restrict to specific channels or use full 2.4/5 GHz spectrum
- **Interval tuning** — microsecond-level control over frame spacing
- **WPA2 toggle** — enable or disable RSN information elements
- **Real-time statistics** — live FPS counter, total frame count, and elapsed time display
- **JSON export** — save the generated AP database to a file for analysis or replay
- **Graceful shutdown** — Ctrl+C stops cleanly with a final summary

---

## How It Works

Wireless access points advertise their presence by periodically broadcasting **beacon frames** — special 802.11 management frames (subtype 8) that contain the AP's MAC address (BSSID), network name (SSID), supported data rates, channel information, and security capabilities.

This tool builds beacon frames from scratch using Scapy and transmits them directly at Layer 2, bypassing the IP stack entirely. Every Wi-Fi scanner in range sees hundreds of access points that don't actually exist.

### Frame Structure

```
RadioTap()
└── Dot11(type=0, subtype=8)
    ├── addr1 = ff:ff:ff:ff:ff:ff (Broadcast)
    ├── addr2 = <random BSSID>
    └── addr3 = <random BSSID>
└── Dot11Beacon(cap="ESS+privacy")
    ├── Dot11Elt(ID="SSID", info="<random name>")
    ├── Dot11Elt(ID="Rates", info=...)
    ├── Dot11Elt(ID="DSset", info=<channel>)
    └── Dot11Elt(ID="RSNinfo", info=...) (WPA2)
```

---

## Requirements

### Hardware

| Component | Requirement |
|-----------|-------------|
| Wireless adapter | **Must support monitor mode and packet injection** |
| Chipset (recommended) | Atheros AR9271, RTL8812AU, RTL8187L |
| Host system | Linux (Kali Linux recommended) |

> ⚠️ Most built-in laptop Wi-Fi cards do NOT support packet injection. An external USB adapter is almost always required.

### Software

| Package | Minimum Version | Command |
|---------|----------------|---------|
| Python | 3.6+ | `sudo apt install python3` |
| Scapy | 2.5+ | `sudo pip3 install scapy` |
| aircrack-ng | Any | `sudo apt install aircrack-ng` |
| wireless-tools | Any | `sudo apt install wireless-tools` |

---

## Installation

```bash
# 1. Install system dependencies
sudo apt update
sudo apt install python3 python3-pip wireless-tools aircrack-ng -y

# 2. Install Scapy
sudo pip3 install scapy

# 3. Download the script
# Save wififlood.py from the source

# 4. Make it executable
chmod +x wififlood.py
```

---

## Quick Start

```bash
# 1. Kill interfering processes
sudo airmon-ng check kill

# 2. Put adapter in monitor mode
sudo airmon-ng start wlan0

# 3. Run beacon flood
sudo python3 wififlood.py -i wlan0mon -n 500

# 4. Press Ctrl+C to stop

# 5. Clean up
sudo airmon-ng stop wlan0mon
sudo systemctl restart NetworkManager
```

---

## Usage Guide

### Command-Line Arguments

```
usage: wififlood.py [-h] [-i INTERFACE] [-n NUM_APS] [--interval INTERVAL]
                       [--threads THREADS] [--fast] [--no-wpa2] [--5ghz]
                       [--channels CHANNELS [CHANNELS ...]] [--ssids SSIDS]
                       [--list-ifaces] [--output OUTPUT]

options:
  -h, --help            Show help message and exit
  -i, --interface       Wireless interface in monitor mode (default: wlan0mon)
  -n, --num-aps         Number of unique fake APs to generate (default: 500)
  --interval            Seconds between frame transmissions (default: 0.001)
  --threads             Number of concurrent sending threads (default: 4)
  --fast                Enable fast single-threaded burst mode
  --no-wpa2             Remove WPA2 RSN information elements (open network)
  --5ghz                Include 5 GHz channels in the channel pool
  --channels, -c        Specify exact channels (e.g., -c 1 6 11)
  --ssids               Path to text file with custom SSIDs (one per line)
  --list-ifaces         List all available network interfaces and exit
  --output, -o          Save generated AP database to JSON file and exit
```

### Examples

**Basic beacon flood:**
```bash
sudo python3 wififlood.py -i wlan0mon -n 500
```

**Maximum throughput:**
```bash
sudo python3 wififlood.py -i wlan0mon -n 1000 --fast --interval 0.0001
```

**Custom SSID list:**
```bash
# Create SSID file
cat > my_ssids.txt << 'EOF'
Free_Public_WiFi
Hotel_Guest_Network
Airport_Free_WiFi
Cafe_Wireless
Office_5G
EOF

# Run with custom SSIDs
sudo python3 wififlood.py -i wlan0mon -n 200 --ssids my_ssids.txt
```

**Specific channels:**
```bash
sudo python3 wififlood.py -i wlan0mon -n 300 -c 1 6 11
```

**Include 5 GHz:**
```bash
sudo python3 wififlood.py -i wlan0mon -n 500 --5ghz
```

**Export AP database only:**
```bash
sudo python3 wififlood.py -i wlan0mon -n 1000 --output my_aps.json
```

**List available interfaces:**
```bash
sudo python3 wififlood.py --list-ifaces
```

---

## Output & Statistics

### Live Display

```
[>] Frames sent: 12,847  Rate: 6,423 fps  Elapsed: 2.0s
[>] Frames sent: 25,891  Rate: 6,472 fps  Elapsed: 4.0s
[>] Frames sent: 37,678  Rate: 6,279 fps  Elapsed: 6.0s
```

### Final Summary

```
[+] Beacon flood stopped
[+] Total frames sent: 43,209
[+] Duration: 6.8s
[+] Average rate: 6,354 frames/second
```

### Performance Reference

| FPS Range | Assessment |
|-----------|------------|
| < 1,000 | Low — check adapter, driver, or interval setting |
| 1,000 - 5,000 | Good — standard USB adapter performance |
| 5,000 - 15,000 | Excellent — high-performance adapter |
| 15,000+ | Maximum — top-tier adapter, fast mode, optimal driver |

---

## Technical Details

### Recommended Adapters

| Model | Chipset | Bands | Injection Quality | Price Range |
|-------|---------|:-----:|:-----------------:|:-----------:|
| Alfa AWUS036ACH | RTL8812AU | 2.4/5 GHz | Excellent | $$$ |
| Alfa AWUS036NHA | AR9271 | 2.4 GHz | Excellent | $$ |
| TP-Link TL-WN722N v1 | AR9271 | 2.4 GHz | Excellent | $ |
| Panda PAU09 | RTL8812AU | 2.4/5 GHz | Excellent | $$$ |
| Alfa AWUS036ACM | MT7612U | 2.4/5 GHz | Good | $$$ |
| Panda PAU05 | AR9271 | 2.4 GHz | Good | $$ |

### Tuning for Maximum Performance

```bash
# Increase kernel write buffer
sudo sysctl -w net.core.wmem_default=1048576
sudo sysctl -w net.core.wmem_max=1048576

# Set CPU governor to performance
sudo cpupower frequency-set -g performance
```

---

## Ethical & Legal

**This tool is for AUTHORIZED SECURITY TESTING ONLY.**

- You must own the wireless network being tested **OR** have explicit written permission from the owner
- Unauthorized beacon flooding may violate local laws (CFAA, EU Cybercrime Directive, etc.)
- Always test in isolated/lab environments before any real-world assessment
- The user assumes all responsibility for compliance with applicable laws

---

## Troubleshooting

### "No module named scapy"
```bash
sudo pip3 install scapy
```

### "Operation not permitted"
```bash
sudo python3 fakeap_flood.py -i wlan0mon -n 500
```

### Interface not found
```bash
sudo python3 fakeap_flood.py --list-ifaces
ip link show
iw dev
```

### Monitor mode not working
```bash
sudo airmon-ng check kill
sudo airmon-ng start wlan0
# Or manually:
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
```

### Low frame rate
```bash
# Try fast mode
sudo python3 fakeap_flood.py -i wlan0mon -n 500 --fast --interval 0.0001

# Check driver
lsmod | grep -E "ath|rtl|mt76"
```

### Adapter keeps disconnecting
```bash
# Disable USB power saving
echo 'on' | sudo tee /sys/bus/usb/devices/*/power/control

# Reconnect adapter and try again
```

---

## Cleanup

```bash
# Stop monitor mode
sudo airmon-ng stop wlan0mon

# Restart network services
sudo systemctl restart NetworkManager

# Reset kernel parameters if modified
sudo sysctl -w net.core.wmem_default=212992
sudo sysctl -w net.core.wmem_max=212992
```

---

## FAQ

**Q: Do I need an external adapter?**  
A: For almost all laptops, yes. Built-in adapters almost never support packet injection.

**Q: Can clients connect to these fake APs?**  
A: No. This tool only sends beacon frames. It does not handle probe responses, authentication, or association.

**Q: Will this damage my adapter?**  
A: No. Beacon flooding sends standard 802.11 frames at normal transmission power.

**Q: Can I use this in a VM?**  
A: Yes, but you must pass through the USB adapter via USB passthrough.

**Q: What's the max number of APs I can generate?**  
A: No hard limit. 10,000 APs uses ~10 MB of RAM. Practical limit depends on your system.

---

## License

**MIT License**

Copyright (c) 2024-2026 SAKSHAM GUPTA

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---
# STAY ETHICAL, STAY HAPPY !
---
<p align="center">
  <sub>Built for the cybersecurity community. Use responsibly.</sub>
  <br>
  <sub>SAKSHAM GUPTA — Intelligent Penetration Tester</sub>
</p>
