import random
import socket
import struct


def csum(data):
    # RFC 1071 checksum
    if len(data) & 1:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
        s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


class PacketBuilder:
    _STACKS = [
        (64, 64240, 1460, 7, 1),   # modern linux
        (64, 5840, 1460, 2, 1),    # legacy linux
        (64, 16384, 1460, 7, 1),
        (128, 65535, 1460, 7, 1),  # windows
        (128, 8192, 1400, 2, 1),   # windows vpn
        (255, 65535, 1380, 2, 1),
        (64, 29200, 1460, 7, 1),
        (128, 64240, 1460, 7, 1),
    ]

    def __init__(self):
        self._ipids = {}

    def next_ipid(self, src):
        last = self._ipids.get(src, random.randint(1, 65535))
        ipid = (last + random.randint(1, 3)) & 0xFFFF
        self._ipids[src] = ipid
        return ipid

    def build_syn(self, src, dst, sport, dport, seq, ipid):
        ttl, win, mss, ws, sack = random.choice(self._STACKS)
        opts = bytearray()
        if sack:
            opts += b"\x04\x02"
        opts += struct.pack("!BBH", 2, 4, mss)
        opts += b"\x01"
        if ws:
            opts += struct.pack("!BBB", 3, 3, ws)
        while len(opts) % 4:
            opts += b"\x01"
        tcp_len = 20 + len(opts)
        doff = tcp_len >> 2
        tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 0,
                          doff << 4, 0x02, win, 0, 0) + bytes(opts)
        ph = socket.inet_aton(src) + socket.inet_aton(dst) + \
             struct.pack("!BBH", 0, 6, tcp_len)
        tcp = tcp[:16] + struct.pack("!H", csum(ph + tcp)) + tcp[18:]
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + tcp_len, ipid,
                         0x4000, ttl, 6, 0, socket.inet_aton(src),
                         socket.inet_aton(dst))
        ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
        return ip + tcp

    def send(self, snd, src, dst, sport, dport):
        pkt = self.build_syn(src, dst, sport, dport,
                             random.getrandbits(32), self.next_ipid(src))
        snd.sendto(pkt, (dst, 0))
