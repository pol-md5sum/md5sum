"""M11 대응 자동화: 차단 조치 계획 → 승인(요청자와 다른 사람) → 산출물 생성.

이 모듈은 어떤 시스템에도 직접 적용하지 않는다. 승인된 조치만 방화벽·IDS·DNS·EDR용
검토 산출물과 원복 스크립트로 내보내며, 실제 적용은 운영 담당자가 변경 관리 절차에 따라 한다.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import sqlite3
from importlib import resources
from pathlib import Path

from . import cases, ioc
from .db import utcnow

SCHEMA = """
CREATE TABLE IF NOT EXISTS response_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL REFERENCES cases(id),
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    reason TEXT,
    status TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    decided_by TEXT,
    decided_at TEXT,
    decision_note TEXT,
    exported_at TEXT,
    UNIQUE(case_id, kind, target)
);
"""

KINDS = {"block_ip": "IP 차단", "block_domain": "도메인 차단", "block_url": "URL 차단", "block_hash": "파일 해시 차단"}
IOC_TO_KIND = {"ipv4": "block_ip", "domain": "block_domain", "url": "block_url",
               "sha256": "block_hash", "sha1": "block_hash", "md5": "block_hash"}
VERDICT_RANK = {"malicious": 2, "suspicious": 1}
DOMAIN_OK = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")
HASH_OK = re.compile(r"^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$")
URL_OK = re.compile(r"^https?://[^\s\"'`<>\\]+$", re.I)
SID_BASE = 9_100_000


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)


def load_allowlist() -> dict:
    custom = os.environ.get("IRSYS_ALLOWLIST")
    text = Path(custom).read_text(encoding="utf-8") if custom else \
        resources.files("irsys.data").joinpath("allowlist.json").read_text(encoding="utf-8")
    data = json.loads(text)
    return {"domains": [d.lower() for d in data.get("domains", [])],
            "networks": [ipaddress.ip_network(n) for n in data.get("networks", [])]}


def validate(kind: str, target: str, allow: dict) -> str | None:
    """차단해도 되는 값인지 검사한다. 문제가 있으면 사유를, 없으면 None을 돌려준다."""
    if kind == "block_ip":
        try:
            ip = ipaddress.ip_address(target)
        except ValueError:
            return "IP 형식 오류"
        if not ioc.is_public_ip(target):
            return "내부·예약 IP는 차단하지 않음"
        if any(ip in n for n in allow["networks"]):
            return "차단 예외 네트워크"
        return None
    if kind == "block_domain":
        if not DOMAIN_OK.match(target):
            return "도메인 형식 오류"
        if any(target == d or target.endswith("." + d) for d in allow["domains"]):
            return "차단 예외 도메인"
        return None
    if kind == "block_url":
        if not URL_OK.match(target):
            return "URL 형식 오류"
        host = (re.match(r"^https?://([^/:?#]+)", target, re.I).group(1) or "").lower()
        if any(host == d or host.endswith("." + d) for d in allow["domains"]):
            return "차단 예외 도메인의 URL(URL 단위 차단은 프록시에서 수동 검토)"
        return None
    if kind == "block_hash":
        return None if HASH_OK.match(target) else "해시 형식 오류"
    return "알 수 없는 조치 유형"


def add(conn: sqlite3.Connection, case_id: str, kind: str, target: str, actor: str, reason: str) -> dict:
    ensure_schema(conn)
    cases.get(conn, case_id)
    target = target.strip().lower() if kind != "block_url" else target.strip()
    problem = validate(kind, target, load_allowlist())
    if problem:
        return {"kind": kind, "target": target, "skipped": problem}
    cur = conn.execute(
        "INSERT OR IGNORE INTO response_actions (case_id, kind, target, reason, status, requested_by, requested_at)"
        " VALUES (?, ?, ?, ?, 'pending', ?, ?)", (case_id, kind, target, reason, actor, utcnow()))
    conn.commit()
    if not cur.rowcount:
        return {"kind": kind, "target": target, "skipped": "이미 등록됨"}
    cases.log(conn, case_id, actor, "response-request", f"#{cur.lastrowid} {KINDS[kind]} {target}")
    return {"id": cur.lastrowid, "kind": kind, "target": target, "status": "pending"}


def plan(conn: sqlite3.Connection, case_id: str, actor: str, min_verdict: str = "malicious") -> list[dict]:
    """OSINT 판정이 기준 이상인 IOC로 차단 조치를 요청(대기 상태)한다."""
    need = VERDICT_RANK[min_verdict]
    out = []
    for r in ioc.list_for_case(conn, case_id):
        if VERDICT_RANK.get(r["verdict"] or "", 0) < need or r["type"] not in IOC_TO_KIND:
            continue
        out.append(add(conn, case_id, IOC_TO_KIND[r["type"]], r["value"], actor,
                       f"OSINT 판정 {r['verdict']} (점수 {r['score']})"))
    return out


def list_actions(conn: sqlite3.Connection, case_id: str) -> list[sqlite3.Row]:
    ensure_schema(conn)
    return conn.execute("SELECT * FROM response_actions WHERE case_id = ? ORDER BY id", (case_id,)).fetchall()


def decide(conn: sqlite3.Connection, action_id: int, actor: str, approve: bool, note: str = "") -> None:
    ensure_schema(conn)
    row = conn.execute("SELECT * FROM response_actions WHERE id = ?", (action_id,)).fetchone()
    if row is None:
        raise KeyError(f"조치 #{action_id}을(를) 찾을 수 없습니다.")
    if row["status"] != "pending":
        raise ValueError(f"조치 #{action_id}은(는) 이미 {row['status']} 상태입니다.")
    if approve and row["requested_by"] == actor:
        raise ValueError("요청자 본인은 승인할 수 없습니다(승인 분리 원칙).")
    status = "approved" if approve else "rejected"
    conn.execute("UPDATE response_actions SET status = ?, decided_by = ?, decided_at = ?, decision_note = ? WHERE id = ?",
                 (status, actor, utcnow(), note, action_id))
    conn.commit()
    cases.log(conn, row["case_id"], actor, f"response-{status}", f"#{action_id} {KINDS[row['kind']]} {row['target']} {note}".strip())


def _hash_alg(h: str) -> str:
    return {32: "md5", 40: "sha1", 64: "sha256"}[len(h)]


def _sid(action_id: int, n: int) -> int:
    return SID_BASE + action_id * 10 + n


def export(conn: sqlite3.Connection, case_id: str, outdir: Path, actor: str) -> dict:
    """승인된 조치만 산출물로 내보낸다. 내보내기 직전에 예외 목록으로 다시 검증한다."""
    ensure_schema(conn)
    allow = load_allowlist()
    rows = [r for r in list_actions(conn, case_id) if r["status"] in ("approved", "exported")]
    rows = [r for r in rows if validate(r["kind"], r["target"], allow) is None]
    if not rows:
        raise ValueError("내보낼 승인된 조치가 없습니다.")
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    by = {k: [r for r in rows if r["kind"] == k] for k in KINDS}
    tag = f"irsys-{case_id}"
    files: dict[str, str] = {}

    def write(name: str, lines: list[str]) -> None:
        text = "\n".join(lines) + "\n"
        (outdir / name).write_text(text, encoding="utf-8")
        files[name] = hashlib.sha256(text.encode("utf-8")).hexdigest()

    header = [f"# {tag} 대응 산출물 — 생성 {utcnow()} · 생성자 {actor}",
              "# 자동 적용되지 않습니다. 변경 관리 절차에 따라 검토 후 적용하십시오."]
    ips = [r["target"] for r in by["block_ip"]]
    domains = [r["target"] for r in by["block_domain"]]
    urls = [r["target"] for r in by["block_url"]]
    hashes = [r["target"] for r in by["block_hash"]]

    if ips:
        write("blocklist_ips.txt", ips)
        write("firewall_windows.ps1", header + ["#Requires -RunAsAdministrator"] + [
            line for r in by["block_ip"] for line in (
                f'New-NetFirewallRule -DisplayName "{tag}-{r["id"]}-out" -Direction Outbound -RemoteAddress {r["target"]} -Action Block',
                f'New-NetFirewallRule -DisplayName "{tag}-{r["id"]}-in" -Direction Inbound -RemoteAddress {r["target"]} -Action Block')])
        write("rollback_windows.ps1", header + ["#Requires -RunAsAdministrator",
                                                f'Get-NetFirewallRule -DisplayName "{tag}-*" | Remove-NetFirewallRule'])
        write("firewall_iptables.sh", ["#!/bin/sh", *header, "set -e"] + [
            line for ip in ips for line in (
                f'iptables -I OUTPUT -d {ip} -j DROP -m comment --comment "{tag}"',
                f'iptables -I INPUT -s {ip} -j DROP -m comment --comment "{tag}"')])
        write("rollback_iptables.sh", ["#!/bin/sh", *header] + [
            line for ip in ips for line in (
                f'iptables -D OUTPUT -d {ip} -j DROP -m comment --comment "{tag}" || true',
                f'iptables -D INPUT -s {ip} -j DROP -m comment --comment "{tag}" || true')])
    if domains:
        write("blocklist_domains.txt", domains)
        write("dns_rpz.zone", [f"; {h[2:]}" for h in header] + [
            line for d in domains for line in (f"{d} CNAME .", f"*.{d} CNAME .")])
    if urls:
        write("blocklist_urls.txt", urls)
    if hashes:
        write("blocklist_hashes.txt", hashes)
        conds = [f'hash.{_hash_alg(h)}(0, filesize) == "{h}"' for h in hashes]
        write("yara_hashes.yar", [f"// {h[2:]}" for h in header] + [
            'import "hash"', "", f"rule {tag.replace('-', '_')}_hashes", "{",
            "    meta:", f'        case = "{case_id}"', "    condition:",
            "        " + "\n        or ".join(conds), "}"])
        write("edr_hashes.csv", ["type,value,description"] + [
            f"{_hash_alg(h)},{h},{tag}" for h in hashes])

    rules = []
    for r in by["block_ip"]:
        rules.append(f'alert ip $HOME_NET any -> {r["target"]} any (msg:"{tag} blocked IP outbound"; '
                     f'classtype:trojan-activity; sid:{_sid(r["id"], 0)}; rev:1;)')
        rules.append(f'alert ip {r["target"]} any -> $HOME_NET any (msg:"{tag} blocked IP inbound"; '
                     f'classtype:trojan-activity; sid:{_sid(r["id"], 1)}; rev:1;)')
    for r in by["block_domain"]:
        rules.append(f'alert dns $HOME_NET any -> any any (msg:"{tag} blocked domain DNS {r["target"]}"; '
                     f'dns.query; dotprefix; content:".{r["target"]}"; nocase; endswith; sid:{_sid(r["id"], 0)}; rev:1;)')
        rules.append(f'alert tls $HOME_NET any -> any any (msg:"{tag} blocked domain TLS {r["target"]}"; '
                     f'tls.sni; dotprefix; content:".{r["target"]}"; nocase; endswith; sid:{_sid(r["id"], 1)}; rev:1;)')
    if rules:
        write("suricata.rules", [f"# {h[2:]}" for h in header] + rules)

    manifest = {"case_id": case_id, "generated_at": utcnow(), "generated_by": actor,
                "actions": [{"id": r["id"], "kind": r["kind"], "target": r["target"], "reason": r["reason"],
                             "requested_by": r["requested_by"], "approved_by": r["decided_by"],
                             "approved_at": r["decided_at"]} for r in rows],
                "files": files}
    (outdir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    now = utcnow()
    conn.executemany("UPDATE response_actions SET status = 'exported', exported_at = ? WHERE id = ?",
                     [(now, r["id"]) for r in rows])
    conn.commit()
    cases.log(conn, case_id, actor, "response-export", f"{len(rows)}건 → {outdir}")
    return manifest
