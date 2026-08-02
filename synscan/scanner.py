import ipaddress
import json
import logging
import os
import random
import select
import socket
import struct
import time
from collections import deque

from .banner import BannerGrabber
from .packet import PacketBuilder
from .report import Target

log = logging.getLogger("synscan")


class Scanner:
    def __init__(self, opts):
        self.real = opts["real"]
        self.decoys = opts["decoys"]
        self.rate = opts["rate"]
        self.batch_size = opts["batch"]
        self.retries = opts["retries"]
        self.timeout = opts["timeout"]
        self.sport_fixed = opts["sport"]
        self.confirm = opts["confirm"]
        self.banner = opts["banner"]
        self.out = opts["out"]
        self.banner_timeout = opts["banner_timeout"]

        self.interrupted = False
        self.builder = PacketBuilder()
        self.grabber = BannerGrabber(self.banner_timeout)
        self.pace_mult = 1.0
        self.recent = deque(maxlen=50)

    def request_stop(self, signum=None, frame=None):
        self.interrupted = True

    @staticmethod
    def open_sockets():
        snd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        return snd, tcp_sock, icmp_sock

    def _sleeper(self, total):
        while total > 0 and not self.interrupted:
            chunk = min(total, 0.5)
            time.sleep(chunk)
            total -= chunk

    @property
    def pkt_delay(self):
        if self.rate < 30:
            return (1.0 / self.rate) * self.pace_mult
        return 0.0

    def burst(self, snd, dst, dport, sport):
        order = [self.real] + self.decoys
        random.shuffle(order)
        delay = self.pkt_delay
        for src in order:
            if self.interrupted:
                return
            self.builder.send(snd, src, dst, sport, dport)
            if delay:
                self._sleeper(delay * random.uniform(0.5, 1.5))

    def new_sport(self):
        return self.sport_fixed or random.randint(1024, 65535)

    def collect_replies(self, outstanding, tcp_sock, icmp_sock, dst, deadline):
        results = {}
        while outstanding:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            rl, _, _ = select.select([tcp_sock, icmp_sock], [], [], min(left, 0.5))
            for s in rl:
                try:
                    data, addr = s.recvfrom(65535)
                except OSError as e:
                    log.warning("recvfrom error: %s", e)
                    continue
                if s is icmp_sock:
                    if len(data) < 36 or data[0] != 3:
                        continue
                    es = (data[28] << 8) | data[29]
                    ed = (data[30] << 8) | data[31]
                    if es not in outstanding or ed != outstanding[es]:
                        continue
                    results[ed] = "closed" if data[1] == 3 else "filtered"
                    del outstanding[es]
                    continue
                if addr[0] != dst or len(data) < 40:
                    continue
                ihl = (data[0] & 0x0F) * 4
                if ihl < 20 or len(data) < ihl + 20:
                    continue
                tcp = data[ihl:]
                sp, dp = struct.unpack("!HH", tcp[:4])
                if dp not in outstanding or sp != outstanding[dp]:
                    continue
                fl = tcp[13]
                if fl & 0x12 == 0x12:
                    results[sp] = "open"
                elif fl & 0x04:
                    results[sp] = "closed"
                else:
                    continue
                del outstanding[dp]
        for sport in list(outstanding):
            results[outstanding[sport]] = "filtered"
        return results

    def scan_pass(self, snd, tcp_sock, icmp_sock, tgt, ports):
        results = {}
        batch = 1 if self.sport_fixed else self.batch_size
        for start in range(0, len(ports), batch):
            if self.interrupted:
                break
            chunk = ports[start:start + batch]
            outstanding = {}
            for port in chunk:
                sport = self.new_sport()
                self.burst(snd, tgt.ip, port, sport)
                outstanding[sport] = port
            if not outstanding:
                continue
            got = {}
            if not self.interrupted:
                got = self.collect_replies(outstanding, tcp_sock, icmp_sock,
                                           tgt.ip, time.monotonic() + self.timeout)
            results.update({str(p): st for p, st in got.items()})
            self.recent.extend(1 if st == "filtered" else 0 for st in got.values())
            if len(self.recent) == self.recent.maxlen:
                silence = sum(self.recent) / float(len(self.recent))
                if silence > 0.6:
                    self.pace_mult = min(self.pace_mult * 1.3, 4.0)
                elif silence < 0.2:
                    self.pace_mult = max(self.pace_mult * 0.85, 0.5)
            if not self.pkt_delay:
                self._sleeper(random.uniform(0.2, 0.8))
        return results

    def scan_target(self, snd, tcp_sock, icmp_sock, tgt, state_cb):
        t0 = time.monotonic()
        ports_left = list(tgt.ports)
        total = len(tgt.ports)
        log.info("\033[94m[*]\033[0m Target: %s | %d ports | ~%g pps | decoys: %d | confirm: %s | banner: %s",
                 tgt.ip, total, self.rate, len(self.decoys),
                 "on" if self.confirm else "off",
                 "on" if self.banner else "off")

        milestone = 200
        for attempt in range(self.retries + 1):
            if self.interrupted or not ports_left:
                break
            if attempt:
                log.info("\033[93m[*]\033[0m %s: retry %d (%d ports remaining)",
                         tgt.ip, attempt, len(ports_left))
            got = self.scan_pass(snd, tcp_sock, icmp_sock, tgt, ports_left)
            tgt.results.update(got)
            fresh = [p for p, st in got.items()
                     if st == "open" and int(p) not in tgt.found]
            for p in fresh:
                log.info("  \033[92m[+]\033[0m %-15s %-5d open", tgt.ip, int(p))
            tgt.found.extend(int(p) for p in fresh)
            ports_left = [p for p in ports_left
                          if got.get(str(p)) == "filtered" or str(p) not in got]
            scanned = total - len(ports_left)
            while milestone <= scanned:
                log.info("\033[94m[*]\033[0m %s: %d/%d scanned (%d open)",
                         tgt.ip, milestone, total, len(tgt.found))
                milestone += 200
            state_cb(ports_left, list(tgt.found))

        if not self.interrupted and self.confirm and tgt.found:
            log.info("\033[93m[*]\033[0m %s: verifying %d open ports...", tgt.ip, len(tgt.found))
            kept = []
            for port in tgt.found:
                if self.interrupted:
                    break
                sport = self.new_sport()
                self.burst(snd, tgt.ip, port, sport)
                got = self.collect_replies({sport: port}, tcp_sock, icmp_sock,
                                           tgt.ip, time.monotonic() + self.timeout)
                if got.get(port) == "open":
                    kept.append(port)
                else:
                    log.info("  \033[91m[-]\033[0m %-15s %-5d unconfirmed (%s)",
                             tgt.ip, port, got.get(port, "filtered"))
                self._sleeper(random.uniform(0.3, 1.0))
            tgt.found = kept

        if not self.interrupted and self.banner and tgt.found:
            for port in tgt.found:
                if self.interrupted:
                    break
                b = self.grabber.grab(tgt.ip, port)
                if b:
                    tgt.banners[str(port)] = b
                    log.info("      \033[96m->\033[0m %-15s %-5d banner: %s", tgt.ip, port, b)
                self._sleeper(random.uniform(0.5, 1.5))

        tgt.duration = int(time.monotonic() - t0)
        log.info("\033[92m[+]\033[0m %s scan finished in %ds (%d/%d open): %s",
                 tgt.ip, tgt.duration, len(tgt.found), total, tgt.found)
        if self.out:
            try:
                with open(self.out, "w") as f:
                    json.dump(tgt.to_dict(), f, indent=2)
            except OSError as e:
                log.warning("\033[91m[!]\033[0m failed to write output %s: %s", self.out, e)


def parse_ports(spec):
    out = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            a_i, b_i = int(a), int(b)
            if not (0 <= a_i <= 65535 and 0 <= b_i <= 65535 and a_i <= b_i):
                raise ValueError("invalid port range: %s" % part)
            out.update(range(a_i, b_i + 1))
        else:
            p = int(part)
            if not 0 <= p <= 65535:
                raise ValueError("port out of range: %s" % part)
            out.add(p)
    return sorted(out)


def parse_decoys(s):
    if not s:
        return []
    if s.lower().startswith("rnd:"):
        try:
            n = int(s.split(":", 1)[1])
        except ValueError:
            raise ValueError("RND:N must specify an integer")
        if not 0 <= n <= 64:
            raise ValueError("decoy count must be 0-64")
        return ["%d.%d.%d.%d" % (random.randint(1, 223),
                                 random.randint(0, 255),
                                 random.randint(0, 255),
                                 random.randint(1, 254))
                for _ in range(n)]
    ips = []
    for x in s.split(","):
        x = x.strip()
        if not x:
            continue
        try:
            ipaddress.IPv4Address(x)
        except ipaddress.AddressValueError:
            raise ValueError("invalid decoy IP: %s" % x)
        ips.append(x)
    return ips


def expand_targets(spec):
    hosts = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if os.path.isfile(part):
            try:
                with open(part) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            hosts.append(line)
            except OSError as e:
                log.warning("\033[91m[!]\033[0m failed to read file %s: %s", part, e)
        elif "/" in part:
            try:
                net = ipaddress.ip_network(part, strict=False)
            except ValueError:
                hosts.append(part)
                continue
            if net.version != 4:
                log.warning("\033[91m[!]\033[0m IPv6 unsupported: %s", part)
                continue
            hosts.extend(str(h) for h in net.hosts())
        else:
            hosts.append(part)
    return hosts


def resolve(hosts):
    ips, seen = [], set()
    for h in hosts:
        try:
            ip = socket.gethostbyname(h)
        except socket.gaierror:
            log.warning("\033[91m[!]\033[0m could not resolve: %s", h)
            continue
        if ":" in ip:
            log.warning("\033[91m[!]\033[0m IPv6 unsupported: %s", h)
            continue
        if ip != h:
            log.info("\033[94m[*]\033[0m DNS: %s -> %s", h, ip)
        if ip not in seen:
            seen.add(ip)
            ips.append(ip)
    return ips


def my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for dst in ("8.8.8.8", "1.1.1.1", "9.9.9.9"):
            try:
                s.connect((dst, 53))
                return s.getsockname()[0]
            except OSError:
                continue
    finally:
        s.close()
    return None
