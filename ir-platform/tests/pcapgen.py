"""테스트용 합성 패킷 생성기 (Ethernet/IPv4/TCP·UDP)."""

import ipaddress
import struct


def ipv4(src, dst, proto, payload):
    total = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, proto, 0,
                      ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    return hdr + payload


def eth(ip_packet):
    return b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00" + ip_packet


def tcp(src, dst, sport, dport, flags=0x18, payload=b""):
    seg = struct.pack(">HHIIBBHHH", sport, dport, 1, 0, 5 << 4, flags, 65535, 0, 0) + payload
    return eth(ipv4(src, dst, 6, seg))


def udp(src, dst, sport, dport, payload):
    seg = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    return eth(ipv4(src, dst, 17, seg))


def dns_name(name):
    return b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"


def dns_query(name, qid=1):
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack(">HH", 1, 1)


def dns_response(name, ip, qid=1):
    q = dns_name(name) + struct.pack(">HH", 1, 1)
    a = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + ipaddress.IPv4Address(ip).packed
    return struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0) + q + a


def client_hello(sni):
    name = sni.encode()
    sni_ext = struct.pack(">HBH", len(name) + 3, 0, len(name)) + name
    exts = (struct.pack(">HH", 0, len(sni_ext)) + sni_ext
            + struct.pack(">HHH", 10, 6, 4) + struct.pack(">HH", 0x001D, 0x0017)
            + struct.pack(">HHBB", 11, 2, 1, 0))
    body = (struct.pack(">H", 0x0303) + b"\x00" * 32 + b"\x00"
            + struct.pack(">HHH", 4, 0x0A0A, 0x1301) + b"\x01\x00"
            + struct.pack(">H", len(exts)) + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def write_pcap(path, frames):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ts, frame in frames:
        out += struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(frame), len(frame)) + frame
    path.write_bytes(out)


def write_pcapng(path, frames):
    def block(btype, body):
        body += b"\x00" * (-len(body) % 4)
        n = len(body) + 12
        return struct.pack("<II", btype, n) + body + struct.pack("<I", n)
    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack("<HHI", 1, 0, 65535))
    for ts, frame in frames:
        t = int(ts * 1e6)
        out += block(6, struct.pack("<IIIII", 0, t >> 32, t & 0xFFFFFFFF, len(frame), len(frame)) + frame)
    path.write_bytes(out)


def scenario():
    """비컨(10회, 60초 간격), DNS 터널링, TLS SNI, 비표준 포트 HTTP를 포함한 시나리오."""
    t0 = 1_791_000_000.0
    frames = []
    victim, c2, dns = "10.0.0.15", "203.0.113.50", "10.0.0.1"
    frames.append((t0, udp(victim, dns, 50000, 53, dns_query("update.c2-relay.example"))))
    frames.append((t0 + 0.01, udp(dns, victim, 53, 50000, dns_response("update.c2-relay.example", c2))))
    for i in range(10):
        ts = t0 + 1 + i * 60 + (0.5 if i % 2 else 0)
        frames.append((ts, tcp(victim, c2, 40000 + i, 443, flags=0x02)))
        frames.append((ts + 0.1, tcp(victim, c2, 40000 + i, 443, payload=client_hello("update.c2-relay.example"))))
    for i in range(5):
        label = ("a" * 10 + f"{i:02d}" + "q7w8e9r0t1y2u3i4o5p6a7s8d9f0g1h2j3k4l5z6x7c8")
        frames.append((t0 + 700 + i, udp(victim, dns, 51000 + i, 53, dns_query(f"{label}.tunnel.example"))))
    req = b"GET /gate.php?id=15 HTTP/1.1\r\nHost: 198.51.100.9:8888\r\nUser-Agent: Mozilla/4.0\r\n\r\n"
    frames.append((t0 + 800, tcp(victim, "198.51.100.9", 41000, 8888, payload=req)))
    return frames
