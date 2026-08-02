# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-08-02

### Added
- **Stealth TCP SYN Scanning:** Half-open port scanning using Python raw sockets (`SOCK_RAW`).
- **Decoy IP Spoofing:** Support for custom decoy IP lists and randomized decoy generation (`--decoy RND:N`).
- **OS Fingerprint Evasion:** Dynamic TCP header stack profiles (MSS, Window Scale, SACK permitted, TTL).
- **Asynchronous Response Handling:** Concurrent TCP SYN-ACK, RST, and ICMP Type 3 error parsing.
- **Adaptive Rate Pacing:** Automatic delay adjustment based on target responsiveness.
- **Verification Pass & Banner Grabbing:** Secondary validation pass (`--confirm`) and service banner extraction (`--banner`).
- **State Checkpointing & Resume:** Auto-save scan state (`.synscan_state.json`) and resume interrupted scans (`--resume`).
- **CLI & Packaging:** Colored terminal interface, ASCII banner, JSON output export (`--out`), and `setup.py` installer.
