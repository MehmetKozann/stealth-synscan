# synscan

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OS Support](https://img.shields.io/badge/OS-Linux%20%7C%20macOS-brightgreen.svg)](https://www.apple.com/macos/)
[![Category](https://img.shields.io/badge/Category-Cybersecurity%20%2F%20Network-red.svg)](#)
[![Build Status](https://github.com/MehmetKozann/stealth-synscan/actions/workflows/ci.yml/badge.svg)](https://github.com/MehmetKozann/stealth-synscan/actions)

> High-Performance, Modular TCP SYN (Half-Open) Port Scanner in Python

`synscan` is a lightweight, stealthy raw-socket port scanner designed for security engineers and penetration testers. It uses half-open SYN scanning, source IP spoofing (decoys), OS fingerprint evasion via dynamic TCP stack parameters, and state checkpointing to enable resumable scans.

---

## Quick Terminal Demo

```text
  ______   _____   __  ___  _____  ______  ___   _ 
 / __ \ \ / / \ \ / / / __|/  ___|/ _____// _ \ | |
 \__ \ \ V /   \ V /  \__ \\ \___ | /    / /_\ \| |
|___/   |_|     |_|   |___/\____/|/     /_/   \_\_|  v1.0
          Stealth TCP SYN (Half-Open) Port Scanner

$ sudo python3 synscan.py 192.168.1.1 -p 22,80,443 --confirm --banner

[*] Local IP: 192.168.1.105 | Decoys: 0
[*] Target: 192.168.1.1 | 3 ports | ~5 pps | decoys: 0 | confirm: on | banner: on
  [+] 192.168.1.1     22    open
  [+] 192.168.1.1     80    open
  [+] 192.168.1.1     443   open
[*] 192.168.1.1: verifying 3 open ports...
      -> 192.168.1.1     22    banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
      -> 192.168.1.1     80    banner: HTTP/1.1 200 OK (Server: nginx/1.18.0)
[+] 192.168.1.1 scan finished in 4s (3/3 open): [22, 80, 443]
[+] Scan complete. Found 3 open ports in total.
```

---

## Features

- **Stealth SYN (Half-Open) Scanning:** Leaves connections in a half-open state without completing 3-way handshakes.
- **Decoy IP Spoofing:** Mixes real source IP with decoy addresses (`--decoy RND:4` or custom IP list) to confuse intrusion detection systems.
- **OS Fingerprint Evasion:** Randomizes TCP options (MSS, Window Scale, SACK permitted) and initial TTL across requests to blend into normal network traffic.
- **Batch Processing & Adaptive Pacing:** Nmap-style bulk SYN transmission with dynamic delay adjustment based on network response rates.
- **Confirmation Pass:** Optional secondary validation pass (`--confirm`) to eliminate false positives.
- **Banner Grabbing:** Automatic service banner fetching (`--banner`) on discovered open ports.
- **State Persistence & Resume:** Save scan state (`--state`) and seamlessly resume interrupted scans (`--resume`).

---

## How It Works (Step-by-Step Architecture)

```text
  [ Target Specification ] ──> [ Target Expansion & DNS Resolve ]
                                             │
                                             ▼
  [ Output JSON / State ] <── [ Asynchronous Socket Listener ] 
                                             ▲
                                             │ (TCP SYN-ACK / RST / ICMP)
                                 [ Raw Packet Generator ] 
                                             │ (Decoy Bursts)
                                             ▼
                                     [ Target Network ]
```

### 1. Target & Port Resolution
The scanner expands target specifications (single IPs, CIDR blocks like `192.168.1.0/24`, or target text files) and resolves domain names using the system resolver. Port ranges (e.g., `1-1024`) are parsed and deduplicated.

### 2. Raw Socket Initialization
Opening raw sockets requires `root` privileges:
- `IPPROTO_RAW`: For injecting raw IPv4 packets with custom headers.
- `IPPROTO_TCP`: For capturing incoming TCP responses (SYN-ACK / RST).
- `IPPROTO_ICMP`: For detecting ICMP Type 3 (Destination Unreachable) error responses.

### 3. Custom SYN Packet Construction & Decoy Shuffling
For each target port, `PacketBuilder` crafts raw IP and TCP packet headers:
- **Dynamic TCP Stack Parameters:** Randomizes Window Size, MSS, Window Scale, and SACK-permitted options to defeat passive OS fingerprinting.
- **Per-Source IP-ID Tracking:** Maintains realistic, incrementing IP-ID sequences per source IP.
- **Decoy Spoofing:** When `--decoy` is enabled, real and decoy packets are shuffled randomly per burst to obfuscate the origin IP.

### 4. Asynchronous Response Processing
The scanner listens concurrently on TCP and ICMP raw sockets using non-blocking `select.select()` multiplexing:
- **SYN-ACK (`0x12`):** Port is recorded as **`OPEN`**.
- **RST (`0x04`):** Port is recorded as **`CLOSED`**.
- **ICMP Type 3 (Unreachable):** Analyzes original TCP header payload inside the ICMP error packet to map source/destination ports, marking port as **`CLOSED`** or **`FILTERED`**.
- **Timeout:** Unanswered probes are marked as **`FILTERED`**.

### 5. Adaptive Rate Pacing
Monitors recent response patterns in real time. If packet loss or filtering rises (suggesting rate-limiting or IDS intervention), the scanner dynamically scales down transmit speed.

### 6. Verification & Banner Grabbing
- **Confirmation Pass (`--confirm`):** Re-tests discovered open ports with a second SYN pass to eliminate false positives.
- **Banner Grabbing (`--banner`):** Establishes a standard full TCP connection (`socket.create_connection`) to retrieve application service banners.

### 7. State Checkpointing & Export
Scan progress is serialized incrementally (`.synscan_state.json`). Interruptions (`Ctrl+C`) gracefully retain state so scanning can resume later via `--resume`. Final results are exported to structured JSON via `--out`.

---

## Requirements

- **Operating System:** Linux / macOS
- **Python Version:** Python 3.8+
- **Privileges:** `root` (sudo) required for raw socket operations (`SOCK_RAW`).

---

## Installation

Clone the repository and install locally:

```bash
git clone https://github.com/MehmetKozann/stealth-synscan.git
cd stealth-synscan
sudo python3 synscan.py --help
```

Or install via `setup.py`:

```bash
sudo python3 setup.py install
```

---

## Quick Usage Examples

### 1. Basic SYN Scan
Scan common ports on a single target:
```bash
sudo python3 synscan.py 192.168.1.1 -p 22,80,443 --rate 5
```

### 2. Full Port Range with Decoys
Scan ports 1-1024 using 4 randomized decoy source IPs:
```bash
sudo python3 synscan.py 10.0.0.5 -p 1-1024 --rate 8 --decoy RND:4
```

### 3. Service Verification & Banner Grabbing
Scan, verify open ports with a second pass, grab banners, and export to JSON:
```bash
sudo python3 synscan.py 10.0.0.5 -p 21,22,80,443 --confirm --banner --out results.json
```

### 4. CIDR Range or File Input
Scan targets listed in a text file or CIDR block:
```bash
sudo python3 synscan.py targets.txt -p 80,443 --rate 3
sudo python3 synscan.py 192.168.1.0/24 -p 80,443
```

### 5. Resuming an Interrupted Scan
If a scan is stopped (e.g. `Ctrl+C`), resume progress from the checkpoint file:
```bash
sudo python3 synscan.py 192.168.1.1 --resume .synscan_state.json
```

---

## Command Line Flags

| Option | Description | Default |
|---|---|---|
| `target` | Target IP, CIDR subnet, comma-separated list, or text file | *Required* |
| `-p, --ports` | Target port specification (e.g. `80,443` or `1-1024`) | *Top 27 ports* |
| `--rate` | Target packet sending rate (packets per second) | `5.0` |
| `--decoy` | Decoy IP list (`IP,IP...` or `RND:N`) | `""` |
| `--retries` | Number of retries for unconfirmed ports | `1` |
| `--timeout` | Response timeout in seconds | `2.0` |
| `--sport` | Fixed source port (`0` for dynamic random port) | `0` |
| `--confirm` | Verify open ports with a secondary pass | `False` |
| `--banner` | Grab service banners from open ports | `False` |
| `--out` | Export scan results to JSON file | `""` |
| `--resume` | Resume scan state from file | `""` |
| `--batch` | Number of SYN packets sent per batch round | `256` |
| `-v, --verbose` | Enable debug logging output | `False` |

---

## Legal & Security Disclaimer

This tool is created strictly for educational purposes, authorized security auditing, and defensive penetration testing. Unauthorized scanning of networks without prior written permission is illegal. The author assumes no liability for misuse or damage caused by this software.

---

## License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for details.
