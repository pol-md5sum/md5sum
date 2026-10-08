"""M7 이메일 위협 분석 (.eml).

추출 항목: 제목, 수발신 일시(UTC·KST), 수발신 계정, Received 경유지와 최초 발신 IP,
SPF·DKIM·DMARC 결과, 사칭 징후, 첨부파일(해시·위험 확장자), 본문 링크(표시 문구와 실제 주소 불일치).
.msg/.pst/.ost는 libpff 등 별도 파서가 필요하므로 현재 범위에서 제외한다.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timedelta, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

from . import ioc

KST = timezone(timedelta(hours=9), "KST")

RISKY_EXTS = {
    "exe": "실행파일", "scr": "실행파일", "com": "실행파일", "pif": "실행파일", "msi": "설치파일",
    "dll": "라이브러리", "cpl": "제어판 항목", "bat": "배치 스크립트", "cmd": "배치 스크립트",
    "ps1": "PowerShell", "vbs": "VBScript", "vbe": "VBScript", "js": "JScript", "jse": "JScript",
    "wsf": "Windows Script", "hta": "HTML 응용프로그램", "lnk": "바로가기(LNK)", "chm": "컴파일된 도움말",
    "iso": "디스크 이미지", "img": "디스크 이미지", "vhd": "디스크 이미지", "docm": "매크로 문서",
    "xlsm": "매크로 문서", "pptm": "매크로 문서", "doc": "구형 Office(매크로 가능)", "xls": "구형 Office(매크로 가능)",
    "hwp": "한글 문서", "hwpx": "한글 문서", "jar": "Java", "zip": "압축", "rar": "압축", "7z": "압축",
    "url": "인터넷 바로가기", "one": "OneNote",
}
EXECUTABLE_GROUP = {"exe", "scr", "com", "pif", "msi", "dll", "cpl", "bat", "cmd", "ps1", "vbs", "vbe", "js",
                    "jse", "wsf", "hta", "lnk", "chm", "jar"}

RECEIVED_IP_RE = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]|\((?:[^()]*?)(\d{1,3}(?:\.\d{1,3}){3})(?:[^()]*?)\)")
RECEIVED_FROM_RE = re.compile(r"^\s*from\s+(\S+)", re.I)
RECEIVED_BY_RE = re.compile(r"\bby\s+(\S+)", re.I)
AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)=(\w+)", re.I)


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[dict] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._href is not None:
            self.links.append({"href": self._href.strip(), "text": "".join(self._text).strip()})
            self._href = None


def _dt(value: str | None) -> dict | None:
    if not value:
        return None
    try:
        dt = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return {"raw": value}
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return {"raw": value, "utc": dt.astimezone(timezone.utc).isoformat(), "kst": dt.astimezone(KST).isoformat()}


def parse_received(headers: list[str]) -> list[dict]:
    """Received 헤더를 발신 측(가장 오래된 것)부터 순서대로 정리한다."""
    hops = []
    for raw in reversed(headers):
        line = " ".join(str(raw).split())
        body, _, date_part = line.rpartition(";")
        if not body:
            body, date_part = line, ""
        ips = []
        for m in RECEIVED_IP_RE.finditer(body.split(" by ")[0] if " by " in body else body):
            ip = m.group(1) or m.group(2)
            if ip and ioc._valid_ipv4(ip) and ip not in ips:
                ips.append(ip)
        from_m, by_m = RECEIVED_FROM_RE.search(body), RECEIVED_BY_RE.search(body)
        hops.append({
            "from": from_m.group(1) if from_m else None,
            "by": by_m.group(1).rstrip(";") if by_m else None,
            "ips": ips,
            "public_ips": [ip for ip in ips if ioc.is_public_ip(ip)],
            "date": _dt(date_part.strip()) if date_part.strip() else None,
        })
    return hops


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


def _ext(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def _attachment_flags(name: str, content_type: str, data: bytes) -> list[str]:
    flags = []
    ext = _ext(name)
    parts = name.lower().split(".")
    if len(parts) >= 3 and parts[-1] in EXECUTABLE_GROUP and len(parts[-2]) <= 5:
        flags.append(f"이중 확장자(.{parts[-2]}.{parts[-1]})")
    if "‮" in name:
        flags.append("RLO 문자로 확장자 위장")
    if ext in RISKY_EXTS:
        flags.append(f"위험 형식: {RISKY_EXTS[ext]}")
    if data[:2] == b"MZ" and ext not in {"exe", "dll", "scr", "com", "cpl", "sys"}:
        flags.append("실행파일(MZ) 내용을 다른 확장자로 위장")
    if data[:4] == b"PK\x03\x04" and b"vbaProject.bin" in data:
        flags.append("VBA 매크로 포함(OOXML)")
    if data[:8] == bytes.fromhex("D0CF11E0A1B11AE1") and (b"VBA" in data or b"_VBA_PROJECT" in data):
        flags.append("VBA 매크로 흔적(OLE)")
    if data[:4] == b"PK\x03\x04" and re.search(rb"\.(lnk|exe|js|vbs|hta|scr|bat|cmd|ps1)", data[:65536], re.I):
        flags.append("압축 내부에 실행형 파일명")
    return flags


def analyze(path: Path) -> dict:
    raw = Path(path).read_bytes()
    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)

    def addrs(name: str) -> list[dict]:
        vals = msg.get_all(name, [])
        return [{"name": n, "address": a.lower()} for n, a in getaddresses([str(v) for v in vals]) if a]

    sender = addrs("From")
    return_path = parseaddr(str(msg.get("Return-Path", "")))[1].lower()
    reply_to = addrs("Reply-To")
    hops = parse_received([str(h) for h in msg.get_all("Received", [])])
    origin_ip = next((ip for hop in hops for ip in hop["public_ips"]), None)

    auth: dict[str, str] = {}
    for h in msg.get_all("Authentication-Results", []) + msg.get_all("ARC-Authentication-Results", []):
        for k, v in AUTH_RE.findall(str(h)):
            auth.setdefault(k.lower(), v.lower())
    if "spf" not in auth:
        spf = msg.get("Received-SPF")
        if spf:
            auth["spf"] = str(spf).split()[0].lower()

    # 사칭 징후
    indicators = []
    from_addr = sender[0]["address"] if sender else ""
    from_dom = _domain(from_addr)
    if return_path and _domain(return_path) and _domain(return_path) != from_dom:
        indicators.append(f"From 도메인({from_dom})과 Return-Path 도메인({_domain(return_path)}) 불일치")
    for r in reply_to:
        if r["address"] != from_addr:
            indicators.append(f"Reply-To({r['address']})가 발신 주소와 다름")
    if sender:
        shown = re.findall(r"[\w.+-]+@[\w.-]+", sender[0]["name"] or "")
        if shown and shown[0].lower() != from_addr:
            indicators.append(f"표시 이름에 다른 주소({shown[0]}) 기재")
    for k in ("spf", "dkim", "dmarc"):
        if auth.get(k) in {"fail", "softfail", "permerror", "none"}:
            indicators.append(f"{k.upper()} {auth[k]}")

    # 본문·첨부
    attachments, links, texts = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        if filename or disposition == "attachment":
            data = part.get_payload(decode=True) or b""
            name = filename or "(이름 없음)"
            attachments.append({
                "filename": name,
                "content_type": part.get_content_type(),
                "size": len(data),
                "md5": hashlib.md5(data).hexdigest(),
                "sha256": hashlib.sha256(data).hexdigest(),
                "flags": _attachment_flags(name, part.get_content_type(), data),
            })
            continue
        ctype = part.get_content_type()
        if ctype in {"text/plain", "text/html"}:
            try:
                content = part.get_content()
            except (LookupError, UnicodeDecodeError):
                content = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
            texts.append(content)
            if ctype == "text/html":
                lp = _LinkParser()
                lp.feed(content)
                for link in lp.links:
                    href = link["href"]
                    if not href.lower().startswith(("http://", "https://")):
                        continue
                    host = (urlsplit(href).hostname or "").lower()
                    shown_host = ""
                    shown = ioc.URL_RE.search(link["text"]) or ioc.DOMAIN_RE.search(link["text"])
                    if shown:
                        shown_host = (urlsplit(shown.group(0)).hostname or shown.group(0)).lower()
                    mismatch = bool(shown_host) and not (host == shown_host or host.endswith("." + shown_host))
                    links.append({"url": href, "text": link["text"][:200], "host": host,
                                  "text_mismatch": mismatch})

    body_text = "\n".join(texts)
    seen = {l["url"] for l in links}
    for u in ioc.extract(body_text).get("url", []):
        if u not in seen:
            links.append({"url": u, "text": "", "host": (urlsplit(u).hostname or "").lower(),
                          "text_mismatch": False})
            seen.add(u)
    for l in links:
        if l["text_mismatch"]:
            indicators.append(f"링크 표시 문구와 실제 주소 불일치: {l['text'][:60]} → {l['host']}")
    for a in attachments:
        for f in a["flags"]:
            indicators.append(f"첨부 {a['filename']}: {f}")

    # 수신 측(피해자) 주소·도메인과 메시지 식별자는 IOC에서 뺀다.
    recipients = addrs("To") + addrs("Cc") + addrs("Bcc") + addrs("Delivered-To")
    victim_addrs = {r["address"] for r in recipients}
    victim_domains = {_domain(a) for a in victim_addrs if _domain(a)}
    skip_headers = {"to", "cc", "bcc", "delivered-to", "message-id", "in-reply-to", "references"}
    header_text = "\n".join(f"{k}: {v}" for k, v in msg.items() if k.lower() not in skip_headers)
    iocs = ioc.extract(header_text + "\n" + body_text)
    if "email" in iocs:
        iocs["email"] = [e for e in iocs["email"] if e not in victim_addrs]
    if "domain" in iocs:
        iocs["domain"] = [d for d in iocs["domain"]
                          if not any(d == v or d.endswith("." + v) for v in victim_domains)]
    iocs = {k: v for k, v in iocs.items() if v}
    for a in attachments:
        iocs.setdefault("sha256", [])
        if a["sha256"] not in iocs["sha256"]:
            iocs["sha256"].append(a["sha256"])
    if origin_ip:
        iocs.setdefault("ipv4", [])
        if origin_ip not in iocs["ipv4"]:
            iocs["ipv4"].append(origin_ip)

    return {
        "file": Path(path).name,
        "subject": str(msg.get("Subject", "")),
        "date": _dt(msg.get("Date")),
        "from": sender,
        "to": addrs("To"),
        "cc": addrs("Cc"),
        "reply_to": reply_to,
        "return_path": return_path,
        "message_id": str(msg.get("Message-ID", "")),
        "x_mailer": str(msg.get("X-Mailer", "") or msg.get("User-Agent", "")),
        "received_hops": hops,
        "origin_ip": origin_ip,
        "relay_ips": sorted({ip for hop in hops for ip in hop["public_ips"]}),
        "auth": auth,
        "attachments": attachments,
        "links": links,
        "indicators": indicators,
        "iocs": iocs,
        "attack_techniques": _techniques(attachments, links),
    }


def _techniques(attachments: list[dict], links: list[dict]) -> list[str]:
    t = []
    if attachments:
        t.append("T1566.001")  # Spearphishing Attachment
    if links:
        t.append("T1566.002")  # Spearphishing Link
    if any(a["flags"] for a in attachments):
        t.append("T1204.002")  # User Execution: Malicious File
    if any(l["text_mismatch"] for l in links):
        t.append("T1204.001")  # User Execution: Malicious Link
    return t
