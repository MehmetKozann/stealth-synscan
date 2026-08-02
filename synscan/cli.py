import argparse
import logging
import os
import random
import signal
import sys

from .banner import BannerGrabber
from .packet import PacketBuilder
from .report import StateManager, Target
from .scanner import (
    Scanner,
    expand_targets,
    my_ip,
    parse_decoys,
    parse_ports,
    resolve,
)

log = logging.getLogger("synscan")

BANNER = r"""
  ______   _____   __  ___  _____  ______  ___   _ 
 / __ \ \ / / \ \ / / / __|/  ___|/ _____// _ \ | |
 \__ \ \ V /   \ V /  \__ \\ \___ | /    / /_\ \| |
|___/   |_|     |_|   |___/\____/|/     /_/   \_\_|  v1.0
          Stealth TCP SYN (Half-Open) Port Scanner
"""


def main():
    print("\033[96m" + BANNER + "\033[0m")
    ap = argparse.ArgumentParser(description="Stealth TCP SYN (half-open) port scanner without proxies.")
    ap.add_argument("target", help="IP | CIDR | IP,IP,... | file path")
    ap.add_argument(
        "-p",
        "--ports",
        default="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,27017",
        help="Target ports (e.g. 80,443 or 1-1024)",
    )
    ap.add_argument("--rate", type=float, default=5.0, help="Send rate (packets/sec)")
    ap.add_argument("--decoy", default="", help="Decoy IP list (IP,IP,... or RND:N)")
    ap.add_argument("--retries", type=int, default=1, help="Retry attempts for unconfirmed ports")
    ap.add_argument("--timeout", type=float, default=2.0, help="Response timeout in seconds")
    ap.add_argument("--sport", type=int, default=0, help="Fixed source port (0=random)")
    ap.add_argument("--confirm", action="store_true", help="Verify open ports with a second pass")
    ap.add_argument("--banner", action="store_true", help="Grab service banners from open ports")
    ap.add_argument("--out", default="", help="Write scan results to JSON file")
    ap.add_argument("--resume", default="", help="Resume scan progress from state file")
    ap.add_argument("--state", default=".synscan_state.json", help="Path for state checkpoint file")
    ap.add_argument(
        "--batch",
        type=int,
        default=256,
        help="SYN packets sent per batch round",
    )
    ap.add_argument("-v", "--verbose", action="store_true", help="Enable debug log level")
    a = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if a.verbose else logging.INFO,
        stream=sys.stdout,
        format="%(message)s",
    )

    if os.geteuid() != 0:
        log.error("\033[91m[!]\033[0m Root privileges required for raw sockets.")
        sys.exit(1)
    try:
        ports = parse_ports(a.ports)
    except ValueError as e:
        log.error("\033[91m[!]\033[0m Invalid port list: %s (%s)", a.ports, e)
        sys.exit(1)
    if not ports:
        log.error("\033[91m[!]\033[0m No target ports specified.")
        sys.exit(1)
    try:
        decoys = parse_decoys(a.decoy)
    except ValueError as e:
        log.error("\033[91m[!]\033[0m Invalid decoy list: %s", e)
        sys.exit(1)
    if a.rate > 50:
        log.warning("\033[93m[!]\033[0m Rate > 50 pps is high risk and visible to IDS.")
    real = my_ip()
    if not real:
        log.error("\033[91m[!]\033[0m Source IP address could not be resolved.")
        sys.exit(1)
    log.info("\033[94m[*]\033[0m Local IP: %s | Decoys: %d", real, len(decoys))

    state_path = a.state
    resume = StateManager.load(a.resume) if a.resume else None
    if resume:
        ips = list(resume.get("targets", []))
        if not ips:
            log.error("\033[91m[!]\033[0m No remaining targets in state file.")
            sys.exit(1)
        ports_left = list(resume.get("ports", []))
        found_saved = list(resume.get("found", []))
        log.info(
            "\033[94m[*]\033[0m Resuming: %d targets left, current: %s (%d ports left)",
            len(ips),
            ips[0],
            len(ports_left),
        )
    else:
        hosts = expand_targets(a.target)
        if not hosts:
            log.error("\033[91m[!]\033[0m No valid targets resolved.")
            sys.exit(1)
        ips = resolve(hosts)
        random.shuffle(ips)
        if not ips:
            sys.exit(1)
        ports_left, found_saved = [], []

    opts = {
        "real": real,
        "decoys": decoys,
        "rate": a.rate,
        "confirm": a.confirm,
        "banner": a.banner,
        "timeout": a.timeout,
        "retries": a.retries,
        "sport": a.sport,
        "out": a.out,
        "banner_timeout": 4,
        "batch": a.batch,
    }
    scanner = Scanner(opts)
    signal.signal(signal.SIGINT, scanner.request_stop)

    try:
        snd, tcp_sock, icmp_sock = Scanner.open_sockets()
    except OSError as e:
        log.error("\033[91m[!]\033[0m Could not open raw socket: %s", e)
        sys.exit(1)

    total_open = 0
    try:
        for t_idx, target_ip in enumerate(ips):
            if scanner.interrupted:
                break
            if t_idx == 0 and resume:
                tgt = Target(
                    ip=target_ip, ports=list(ports_left), found=list(found_saved)
                )
            else:
                tgt = Target(ip=target_ip, ports=list(ports))
            if not tgt.ports:
                log.info("\033[94m[*]\033[0m %s scan completed, skipping.", target_ip)
                continue

            def state_cb(pl, fd, idx=t_idx):
                StateManager(state_path).save(ips[idx:], pl, fd)

            scanner.scan_target(snd, tcp_sock, icmp_sock, tgt, state_cb)
            if not scanner.interrupted:
                StateManager(state_path).save(ips[t_idx + 1:], [], [])
            total_open += len(tgt.found)
    finally:
        snd.close()
        tcp_sock.close()
        icmp_sock.close()

    if scanner.interrupted:
        log.info("\n\033[93m[!]\033[0m Interrupted. Resume scan command:")
        log.info("    sudo python3 synscan.py %s --resume %s", a.target, state_path)
    else:
        log.info("\033[92m[+]\033[0m Scan complete. Found %d open ports in total.", total_open)
