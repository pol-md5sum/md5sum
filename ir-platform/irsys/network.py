"""M10 네트워크 분석: PCAP/PCAPNG를 표준 라이브러리로 파싱한다.

추출: 통신 흐름, DNS 질의·응답, HTTP 요청(Host·URI·User-Agent), TLS ClientHello(SNI·JA3).
탐지: 주기적 통신(비컨), DNS 터널링 징후, 외부 대량 전송, 비표준 포트 HTTP.
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import statistics
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import ioc

# 등록 도메인 판단용 2단계 공용 접미사(일부)
SECOND_LEVEL = {"co.kr", "or.kr", "go.kr", "ac.kr", "re.kr", "ne.kr", "pe.kr", "mil.kr", "co.jp", "ne.jp",
                "or.jp", "co.uk", "org.uk", "ac.uk", "com.cn", "net.cn", "org.cn", "com.au", "com.br", "com.tw",
                "com.hk", "com.sg", "co.in"}
GREASE = {0x0A0A + 0x1010 * i for i in range(16)}
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ")
STANDARD_HTTP_PORTS = {80, 8080, 8000, 3128}

BEACON_MIN_EVENTS = 6
BEACON_MAX_CV = 0.2          # 간격의 변동계수(표준편차/평균)
EXFIL_BYTES = 10 * 1024 * 1024
DNS_LONG_LABEL = 40
DNS_MANY_SUBDOMAINS = 50


@dataclass
class Packet:
    ts: float
    src: str
    dst: str
    proto: str               # tcp | udp | other
    sport: int = 0
    dport: int = 0
    length: int = 0
    flags: int = 0
    payload: bytes = b""


@dataclass
class Flow:
    src: str
    dst: str
    sport: int
    dport: int
    proto: str
    packets: int = 0
    bytes: int = 0
    first: float = 0.0
    last: float = 0.0
    starts: list[float] = field(default_factory=list)


# ------------------------------------------------------------------ 파일 형식
def read_packets(path: Path) -> list[Packet]:
    data = Path(path).read_bytes()
    if len(data) < 24:
        raise ValueError("PCAP 파일이 너무 짧습니다.")
    magic = data[:4]
    if magic == b"\x0a\x0d\x0d\x0a":
        frames = _pcapng_frames(data)
    elif magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        frames = _pcap_frames(data)
    else:
        raise ValueError("PCAP/PCAPNG 형식이 아닙니다.")
    out = []
    for ts, linktype, frame in frames:
        p = _decode(ts, linktype, frame)
        if p:
            out.append(p)
    return out


def _pcap_frames(data: bytes):
    le = data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
    nano = data[:4] in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    e = "<" if le else ">"
    linktype = struct.unpack_from(e + "I", data, 20)[0]
    off = 24
    while off + 16 <= len(data):
        sec, frac, incl, _ = struct.unpack_from(e + "IIII", data, off)
        off += 16
        yield sec + frac / (1e9 if nano else 1e6), linktype, data[off:off + incl]
        off += incl


def _pcapng_frames(data: bytes):
    off, e = 0, "<"
    interfaces: list[tuple[int, float]] = []
    while off + 12 <= len(data):
        btype = struct.unpack_from(e + "I", data, off)[0]
        if btype == 0x0A0D0D0A:
            e = "<" if data[off + 8:off + 12] == b"\x4d\x3c\x2b\x1a" else ">"
            interfaces = []
        blen = struct.unpack_from(e + "I", data, off + 4)[0]
        if blen < 12 or off + blen > len(data):
            break
        body = data[off + 8:off + blen - 4]
        if btype == 1:  # Interface Description
            linktype = struct.unpack_from(e + "H", body, 0)[0]
            resol = 1e-6
            opt = 8
            while opt + 4 <= len(body):
                code, olen = struct.unpack_from(e + "HH", body, opt)
                if code == 0:
                    break
                if code == 9 and olen >= 1:
                    v = body[opt + 4]
                    resol = 2 ** -(v & 0x7F) if v & 0x80 else 10 ** -v
                opt += 4 + olen + (-olen % 4)
            interfaces.append((linktype, resol))
        elif btype == 6 and interfaces:  # Enhanced Packet
            iface, hi, lo, cap, _ = struct.unpack_from(e + "IIIII", body, 0)
            linktype, resol = interfaces[iface] if iface < len(interfaces) else interfaces[0]
            yield ((hi << 32) | lo) * resol, linktype, body[20:20 + cap]
        elif btype == 3 and interfaces:  # Simple Packet
            linktype, _ = interfaces[0]
            yield 0.0, linktype, body[4:]
        off += blen


def _decode(ts: float, linktype: int, frame: bytes) -> Packet | None:
    try:
        if linktype == 1:  # Ethernet
            etype, off = struct.unpack_from(">H", frame, 12)[0], 14
            while etype in (0x8100, 0x88A8):
                etype, off = struct.unpack_from(">H", frame, off + 2)[0], off + 4
        elif linktype == 113:  # Linux cooked
            etype, off = struct.unpack_from(">H", frame, 14)[0], 16
        elif linktype == 276:  # Linux cooked v2
            etype, off = struct.unpack_from(">H", frame, 0)[0], 20
        elif linktype in (101, 228, 229, 12):  # Raw IP
            off = 0
            etype = 0x0800 if frame[0] >> 4 == 4 else 0x86DD
        elif linktype == 0:  # BSD loopback
            off = 4
            etype = 0x0800 if frame[off] >> 4 == 4 else 0x86DD
        else:
            return None
        if etype == 0x0800:
            ihl = (frame[off] & 0x0F) * 4
            total = struct.unpack_from(">H", frame, off + 2)[0]
            proto = frame[off + 9]
            src = str(ipaddress.IPv4Address(frame[off + 12:off + 16]))
            dst = str(ipaddress.IPv4Address(frame[off + 16:off + 20]))
            l4, end = off + ihl, off + total
        elif etype == 0x86DD:
            plen = struct.unpack_from(">H", frame, off + 4)[0]
            proto = frame[off + 6]
            src = str(ipaddress.IPv6Address(frame[off + 8:off + 24]))
            dst = str(ipaddress.IPv6Address(frame[off + 24:off + 40]))
            l4, end = off + 40, off + 40 + plen
        else:
            return None
        seg = frame[l4:end]
        if proto == 6 and len(seg) >= 20:
            sport, dport = struct.unpack_from(">HH", seg, 0)
            doff = (seg[12] >> 4) * 4
            return Packet(ts, src, dst, "tcp", sport, dport, end - off, seg[13], seg[doff:])
        if proto == 17 and len(seg) >= 8:
            sport, dport = struct.unpack_from(">HH", seg, 0)
            return Packet(ts, src, dst, "udp", sport, dport, end - off, 0, seg[8:])
        return Packet(ts, src, dst, "other", length=end - off)
    except (struct.error, IndexError, ValueError):
        return None


# ------------------------------------------------------------------ 프로토콜
def _dns_name(msg: bytes, off: int, depth: int = 0) -> tuple[str, int]:
    labels, jumped, end = [], False, off
    while off < len(msg) and depth < 20:
        n = msg[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            ptr = struct.unpack_from(">H", msg, off)[0] & 0x3FFF
            if not jumped:
                end = off + 2
            jumped, off, depth = True, ptr, depth + 1
            continue
        labels.append(msg[off + 1:off + 1 + n].decode("latin-1"))
        off += 1 + n
    return ".".join(labels).lower(), (end if jumped else off)


def parse_dns(payload: bytes) -> dict | None:
    if len(payload) < 12:
        return None
    _, flags, qd, an = struct.unpack_from(">HHHH", payload, 0)
    off = 12
    questions, answers = [], []
    try:
        for _ in range(qd):
            name, off = _dns_name(payload, off)
            qtype = struct.unpack_from(">H", payload, off)[0]
            off += 4
            questions.append({"name": name, "type": qtype})
        for _ in range(an):
            name, off = _dns_name(payload, off)
            atype, _, _, rdlen = struct.unpack_from(">HHIH", payload, off)
            off += 10
            rdata = payload[off:off + rdlen]
            if atype == 1 and rdlen == 4:
                answers.append({"name": name, "type": "A", "data": str(ipaddress.IPv4Address(rdata))})
            elif atype == 28 and rdlen == 16:
                answers.append({"name": name, "type": "AAAA", "data": str(ipaddress.IPv6Address(rdata))})
            elif atype == 5:
                answers.append({"name": name, "type": "CNAME", "data": _dns_name(payload, off)[0]})
            off += rdlen
    except (struct.error, IndexError):
        pass
    if not questions:
        return None
    return {"response": bool(flags & 0x8000), "questions": questions, "answers": answers}


def parse_http(payload: bytes) -> dict | None:
    if not payload.startswith(HTTP_METHODS):
        return None
    head = payload.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace").split("\r\n")
    parts = head[0].split(" ")
    if len(parts) < 2:
        return None
    headers = {}
    for line in head[1:]:
        k, _, v = line.partition(":")
        headers[k.strip().lower()] = v.strip()
    return {"method": parts[0], "uri": parts[1], "host": headers.get("host", ""),
            "user_agent": headers.get("user-agent", "")}


def parse_client_hello(payload: bytes) -> dict | None:
    """TLS ClientHello에서 SNI와 JA3 지문을 계산한다."""
    if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
        return None
    try:
        off = 9
        version = struct.unpack_from(">H", payload, off)[0]
        off += 2 + 32
        off += 1 + payload[off]                                     # session id
        clen = struct.unpack_from(">H", payload, off)[0]
        ciphers = [c for c in struct.unpack_from(f">{clen // 2}H", payload, off + 2) if c not in GREASE]
        off += 2 + clen
        off += 1 + payload[off]                                     # compression
        ext_end = off + 2 + struct.unpack_from(">H", payload, off)[0]
        off += 2
        exts, curves, points, sni = [], [], [], None
        while off + 4 <= min(ext_end, len(payload)):
            etype, elen = struct.unpack_from(">HH", payload, off)
            body = payload[off + 4:off + 4 + elen]
            if etype not in GREASE:
                exts.append(etype)
            if etype == 0 and len(body) >= 5:
                nlen = struct.unpack_from(">H", body, 3)[0]
                sni = body[5:5 + nlen].decode("latin-1").lower()
            elif etype == 10 and len(body) >= 2:
                n = struct.unpack_from(">H", body, 0)[0] // 2
                curves = [c for c in struct.unpack_from(f">{n}H", body, 2) if c not in GREASE]
            elif etype == 11 and body:
                points = list(body[1:1 + body[0]])
            off += 4 + elen
    except (struct.error, IndexError):
        return None
    ja3 = ",".join([str(version), "-".join(map(str, ciphers)), "-".join(map(str, exts)),
                    "-".join(map(str, curves)), "-".join(map(str, points))])
    return {"sni": sni, "ja3": ja3, "ja3_md5": hashlib.md5(ja3.encode()).hexdigest()}


# ------------------------------------------------------------------ 분석
def registered_domain(name: str) -> str:
    labels = name.lower().strip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in (s.count(ch) for ch in set(s)))


def _ts(v: float) -> str:
    return datetime.fromtimestamp(v, timezone.utc).isoformat()


def analyze(path: Path) -> dict:
    packets = read_packets(path)
    flows: dict[tuple, Flow] = {}
    dns_queries: dict[str, dict] = {}
    http, tls = [], []
    resolved: dict[str, set[str]] = defaultdict(set)

    for p in packets:
        key = (p.src, p.sport, p.dst, p.dport, p.proto)
        f = flows.get(key)
        if f is None:
            f = flows[key] = Flow(p.src, p.dst, p.sport, p.dport, p.proto, first=p.ts)
        f.packets += 1
        f.bytes += p.length
        f.last = p.ts
        if p.proto == "tcp" and p.flags & 0x02 and not p.flags & 0x10:      # SYN
            f.starts.append(p.ts)
        if p.proto == "udp" and 53 in (p.sport, p.dport) and p.payload:
            d = parse_dns(p.payload)
            if d:
                for q in d["questions"]:
                    entry = dns_queries.setdefault(q["name"], {"name": q["name"], "count": 0, "first": _ts(p.ts),
                                                               "clients": set()})
                    if not d["response"]:
                        entry["count"] += 1
                        entry["clients"].add(p.src)
                for a in d["answers"]:
                    if a["type"] in ("A", "AAAA"):
                        resolved[a["name"]].add(a["data"])
        if p.proto == "tcp" and p.payload:
            h = parse_http(p.payload)
            if h:
                http.append({**h, "ts": _ts(p.ts), "src": p.src, "dst": p.dst, "dport": p.dport})
            t = parse_client_hello(p.payload)
            if t:
                tls.append({**t, "ts": _ts(p.ts), "src": p.src, "dst": p.dst, "dport": p.dport})

    # UDP는 연결 개념이 없으므로 내부→외부 패킷 시각 자체를 접속 시도로 본다.
    udp_times: dict[tuple, list[float]] = defaultdict(list)
    for p in packets:
        if p.proto == "udp" and p.dport != 53 and ioc.is_public_ip(p.dst) and not ioc.is_public_ip(p.src):
            udp_times[(p.src, p.dst, p.dport, "udp")].append(p.ts)

    findings: list[dict] = []
    techniques: set[str] = set()

    # 비컨: 같은 (내부, 외부, 포트)로 일정 간격 반복 접속
    starts: dict[tuple, list[float]] = defaultdict(list)
    for f in flows.values():
        if f.proto == "tcp" and f.starts and ioc.is_public_ip(f.dst):
            starts[(f.src, f.dst, f.dport, "tcp")] += f.starts
    starts.update(udp_times)
    for (src, dst, dport, proto), times in starts.items():
        times = sorted(times)
        if len(times) < BEACON_MIN_EVENTS:
            continue
        gaps = [b - a for a, b in zip(times, times[1:]) if b > a]
        if len(gaps) < BEACON_MIN_EVENTS - 1:
            continue
        mean = statistics.mean(gaps)
        cv = statistics.pstdev(gaps) / mean if mean else 1
        if cv <= BEACON_MAX_CV and mean >= 1:
            findings.append({"type": "beacon", "severity": "high", "src": src, "dst": dst, "dport": dport,
                             "proto": proto, "events": len(times), "interval_sec": round(mean, 1),
                             "jitter": round(cv, 3), "technique": "T1071",
                             "description": f"{src} → {dst}:{dport} 약 {round(mean)}초 간격 {len(times)}회 반복 접속"})
            techniques.add("T1071.001" if dport in (80, 443, 8080, 8443) else "T1071")

    # DNS 터널링
    by_base: dict[str, set[str]] = defaultdict(set)
    for name in dns_queries:
        by_base[registered_domain(name)].add(name)
    for base, names in by_base.items():
        long_names = [n for n in names if any(len(l) >= DNS_LONG_LABEL for l in n.split("."))
                      or (len(n) > 60 and _entropy(n.replace(".", "")) > 3.8)]
        if long_names or len(names) >= DNS_MANY_SUBDOMAINS:
            findings.append({"type": "dns_tunnel", "severity": "high", "domain": base,
                             "unique_names": len(names), "long_names": len(long_names), "technique": "T1071.004",
                             "description": f"{base} 하위 도메인 {len(names)}개, 비정상적으로 긴 질의 {len(long_names)}건"})
            techniques.add("T1071.004")

    # 외부 대량 전송
    out_bytes: dict[tuple, int] = defaultdict(int)
    for f in flows.values():
        if not ioc.is_public_ip(f.src) and ioc.is_public_ip(f.dst):
            out_bytes[(f.src, f.dst)] += f.bytes
    for (src, dst), n in out_bytes.items():
        if n >= EXFIL_BYTES:
            findings.append({"type": "large_upload", "severity": "medium", "src": src, "dst": dst, "bytes": n,
                             "technique": "T1048",
                             "description": f"{src} → {dst} 외부 전송 {n / 1048576:.1f}MB"})
            techniques.add("T1048")

    # 비표준 포트 HTTP
    for h in http:
        if h["dport"] not in STANDARD_HTTP_PORTS and ioc.is_public_ip(h["dst"]):
            findings.append({"type": "http_nonstandard_port", "severity": "medium", "dst": h["dst"],
                             "dport": h["dport"], "technique": "T1571",
                             "description": f"비표준 포트 {h['dport']}로 HTTP 요청 ({h['host']}{h['uri'][:60]})"})
            techniques.add("T1571")

    external = sorted({f.dst for f in flows.values() if ioc.is_public_ip(f.dst)}
                      | {f.src for f in flows.values() if ioc.is_public_ip(f.src)})
    domains = sorted({n for n in dns_queries} | {t["sni"] for t in tls if t["sni"]}
                     | {h["host"].split(":")[0].lower() for h in http if h["host"]})
    urls = sorted({f"http://{h['host']}{h['uri']}" for h in http if h["host"]})
    iocs = ioc.extract("\n".join(external + domains + urls))

    top = sorted(flows.values(), key=lambda f: f.bytes, reverse=True)[:30]
    return {
        "file": Path(path).name,
        "packets": len(packets),
        "start": _ts(min(p.ts for p in packets)) if packets else None,
        "end": _ts(max(p.ts for p in packets)) if packets else None,
        "flows": len(flows),
        "top_flows": [{"src": f.src, "sport": f.sport, "dst": f.dst, "dport": f.dport, "proto": f.proto,
                       "packets": f.packets, "bytes": f.bytes, "first": _ts(f.first), "last": _ts(f.last)}
                      for f in top],
        "dns": sorted(({**v, "clients": sorted(v["clients"]), "resolved": sorted(resolved.get(k, []))}
                       for k, v in dns_queries.items()), key=lambda d: -d["count"])[:200],
        "http": http[:200],
        "tls": tls[:200],
        "ja3": sorted({t["ja3_md5"] for t in tls}),
        "external_ips": external,
        "findings": findings,
        "iocs": iocs,
        "attack_techniques": sorted(techniques),
    }
