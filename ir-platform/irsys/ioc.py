"""M8 IOC 추출·정규화·무력화(defang)."""

from __future__ import annotations

import ipaddress
import re
import sqlite3
from urllib.parse import urlsplit

from .db import utcnow

# 도메인으로 오인되기 쉬운 파일 확장자
FILE_EXTS = {
    "exe", "dll", "sys", "scr", "bat", "cmd", "ps1", "vbs", "js", "jse", "hta", "lnk", "zip", "rar", "7z",
    "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pdf", "hwp", "hwpx", "txt", "log",
    "png", "jpg", "jpeg", "gif", "ico", "htm", "html", "php", "jsp", "asp", "aspx", "py", "json", "xml",
    "ini", "dat", "tmp", "bin", "iso", "img", "msi", "jar", "chm", "pdb", "evidence", "eml", "csv",
}

REFANG = [
    (re.compile(r"hxxp(s?)://", re.I), r"http\1://"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]", re.I), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[@\]|\[at\]", re.I), "@"),
]

URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`{}|\\^\[\]]+", re.I)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}\b")
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b")
HASH_RES = {
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
}
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)

# 분석에 의미 없는 흔한 도메인 (필요 시 확장)
BENIGN_DOMAINS = {"schemas.microsoft.com", "www.w3.org", "w3.org", "schemas.openxmlformats.org",
                  "ns.adobe.com", "purl.org"}


def refang(text: str) -> str:
    for pattern, repl in REFANG:
        text = pattern.sub(repl, text)
    return text


def defang(value: str) -> str:
    """보고서에 넣을 때 클릭·자동 링크가 되지 않도록 무력화한다."""
    if "://" in value:
        scheme, rest = value.split("://", 1)
        scheme = re.sub(r"^http", "hxxp", scheme, flags=re.I)
        host, slash, path = rest.partition("/")
        return f"{scheme}[://]{host.replace('.', '[.]')}{slash}{path}"
    if "@" in value:
        local, _, dom = value.partition("@")
        return f"{local}[@]{dom.replace('.', '[.]')}"
    return value.replace(".", "[.]")


NON_ROUTABLE_V4 = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
)]


def is_public_ip(value: str) -> bool:
    """사설·루프백·링크로컬·CGNAT·멀티캐스트가 아니면 외부 IP로 본다.

    문서용 대역(192.0.2.0/24 등)은 실제 트래픽에 나오지 않으므로 별도로 제외하지 않는다.
    """
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if ip.version == 4:
        return not any(ip in n for n in NON_ROUTABLE_V4)
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified)


def _valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def extract(text: str, include_private: bool = False) -> dict[str, list[str]]:
    """텍스트에서 IOC를 유형별로 추출한다. 결과는 정렬·중복 제거된 목록이다."""
    text = refang(text)
    found: dict[str, set[str]] = {k: set() for k in
                                  ("url", "domain", "ipv4", "email", "md5", "sha1", "sha256", "cve")}

    for m in URL_RE.finditer(text):
        url = m.group(0).rstrip(".,;:)'\"")
        found["url"].add(url)
        host = (urlsplit(url).hostname or "").lower()
        if host:
            (found["ipv4"] if _valid_ipv4(host) else found["domain"]).add(host)

    for m in EMAIL_RE.finditer(text):
        found["email"].add(m.group(0).lower())

    for m in IPV4_RE.finditer(text):
        if _valid_ipv4(m.group(0)):
            found["ipv4"].add(m.group(0))

    # 해시: 긴 것부터 찾고, 그 부분 문자열은 짧은 해시로 다시 잡지 않는다.
    consumed: list[tuple[int, int]] = []
    for kind in ("sha256", "sha1", "md5"):
        for m in HASH_RES[kind].finditer(text):
            if any(s <= m.start() < e for s, e in consumed):
                continue
            consumed.append(m.span())
            found[kind].add(m.group(0).lower())

    email_domains = {e.split("@", 1)[1] for e in found["email"]}
    for m in DOMAIN_RE.finditer(text):
        d = m.group(0).lower().rstrip(".")
        tld = d.rsplit(".", 1)[-1]
        nxt = text[m.end():m.end() + 1]
        # 이메일 로컬 부분(hong.gildong@)과 키=값 표기(header.from=)는 도메인이 아니다.
        if nxt in {"@", "="} or tld in FILE_EXTS or d in BENIGN_DOMAINS or _valid_ipv4(d):
            continue
        found["domain"].add(d)
    found["domain"] |= email_domains - BENIGN_DOMAINS

    for m in CVE_RE.finditer(text):
        found["cve"].add(m.group(0).upper())

    if not include_private:
        found["ipv4"] = {ip for ip in found["ipv4"] if is_public_ip(ip)}
    return {k: sorted(v) for k, v in found.items() if v}


def store(conn: sqlite3.Connection, case_id: str, iocs: dict[str, list[str]], source: str) -> int:
    """추출한 IOC를 사건에 저장한다. 이미 있는 값은 건너뛴다. 새로 저장한 건수를 돌려준다."""
    added = 0
    for kind, values in iocs.items():
        for v in values:
            cur = conn.execute(
                "INSERT OR IGNORE INTO iocs (case_id, type, value, source, first_seen) VALUES (?, ?, ?, ?, ?)",
                (case_id, kind, v, source, utcnow()),
            )
            added += cur.rowcount
    conn.commit()
    return added


def list_for_case(conn: sqlite3.Connection, case_id: str) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM iocs WHERE case_id = ? ORDER BY type, value", (case_id,)).fetchall()
