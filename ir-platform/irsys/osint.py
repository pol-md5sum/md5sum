"""M8 OSINT 다중 조회: VirusTotal, Criminal IP, Shodan.

원칙
- API 키는 환경 변수에서만 읽는다(IRSYS_VT_KEY, IRSYS_CRIMINALIP_KEY, IRSYS_SHODAN_KEY).
- 파일은 업로드하지 않는다. 해시·IP·도메인·URL 조회만 한다.
- 같은 값은 캐시(기본 24시간)를 쓰고, 서비스별 최소 호출 간격을 지킨다.
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Callable

from .db import utcnow

Fetch = Callable[[str, dict], tuple[int, dict]]

USER_AGENT = "irsys/0.1 (incident-response)"
CACHE_TTL = timedelta(hours=24)
CRIMINALIP_LEVELS = {"critical": 90, "dangerous": 75, "moderate": 50, "low": 20, "safe": 0}


def _ssl_context() -> ssl.SSLContext:
    cafile = os.environ.get("IRSYS_CA_BUNDLE") or os.environ.get("SSL_CERT_FILE")
    return ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()


def http_fetch(url: str, headers: dict) -> tuple[int, dict]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **headers})
    try:
        with urllib.request.urlopen(req, timeout=30, context=_ssl_context()) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read() or b"{}")
        except ValueError:
            body = {}
        return e.code, body


class RateLimiter:
    def __init__(self, interval: float):
        self.interval = interval
        self.last = 0.0

    def wait(self) -> None:
        delay = self.last + self.interval - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        self.last = time.monotonic()


class Service:
    name = ""
    key_env = ""
    types: set[str] = set()
    default_interval = 1.0

    def __init__(self, key: str | None = None, fetch: Fetch = http_fetch, interval: float | None = None):
        self.key = key if key is not None else os.environ.get(self.key_env, "")
        self.fetch = fetch
        env_interval = os.environ.get(f"IRSYS_{self.name.upper()}_INTERVAL")
        self.limiter = RateLimiter(interval if interval is not None else
                                   float(env_interval) if env_interval else self.default_interval)

    @property
    def enabled(self) -> bool:
        return bool(self.key)

    def supports(self, ioc_type: str) -> bool:
        return ioc_type in self.types

    def query(self, ioc_type: str, value: str) -> dict:
        raise NotImplementedError

    def _get(self, url: str, headers: dict) -> tuple[int, dict]:
        self.limiter.wait()
        return self.fetch(url, headers)


class VirusTotal(Service):
    name = "vt"
    key_env = "IRSYS_VT_KEY"
    types = {"md5", "sha1", "sha256", "ipv4", "domain", "url"}
    default_interval = 15.0  # 무료 API: 분당 4회

    def query(self, ioc_type: str, value: str) -> dict:
        if ioc_type in {"md5", "sha1", "sha256"}:
            path = f"files/{value}"
        elif ioc_type == "ipv4":
            path = f"ip_addresses/{value}"
        elif ioc_type == "domain":
            path = f"domains/{value}"
        else:
            path = "urls/" + base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        status, body = self._get(f"https://www.virustotal.com/api/v3/{path}", {"x-apikey": self.key})
        if status == 404:
            return {"found": False, "score": None}
        if status != 200:
            return {"error": f"HTTP {status}", "detail": body.get("error", {})}
        attr = body.get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
        score = 90 if mal >= 5 else 70 if mal >= 2 else 50 if mal == 1 else 30 if sus else 0
        out = {
            "found": True,
            "score": score,
            "malicious": mal,
            "suspicious": sus,
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attr.get("reputation"),
            "tags": attr.get("tags", [])[:10],
            "link": f"https://www.virustotal.com/gui/search/{urllib.parse.quote(value, safe='')}",
        }
        label = attr.get("popular_threat_classification", {}).get("suggested_threat_label")
        if label:
            out["threat_label"] = label
        for k in ("meaningful_name", "type_description", "as_owner", "country", "registrar"):
            if attr.get(k):
                out[k] = attr[k]
        return out


class CriminalIP(Service):
    name = "criminalip"
    key_env = "IRSYS_CRIMINALIP_KEY"
    types = {"ipv4"}
    default_interval = 1.0

    def query(self, ioc_type: str, value: str) -> dict:
        url = "https://api.criminalip.io/v1/asset/ip/report?" + urllib.parse.urlencode({"ip": value})
        status, body = self._get(url, {"x-api-key": self.key})
        if status != 200:
            return {"error": f"HTTP {status}", "detail": body.get("message", "")}
        score = body.get("score", {}) or {}
        inbound = str(score.get("inbound", "")).lower()
        outbound = str(score.get("outbound", "")).lower()
        issues = body.get("issues", {}) or {}
        flagged = sorted(k for k, v in issues.items() if v is True)
        return {
            "found": True,
            "score": max(CRIMINALIP_LEVELS.get(inbound, 0), CRIMINALIP_LEVELS.get(outbound, 0)),
            "inbound": score.get("inbound"),
            "outbound": score.get("outbound"),
            "issues": flagged,
            "link": f"https://www.criminalip.io/asset/report/{value}",
        }


class Shodan(Service):
    name = "shodan"
    key_env = "IRSYS_SHODAN_KEY"
    types = {"ipv4"}
    default_interval = 1.0

    def query(self, ioc_type: str, value: str) -> dict:
        url = f"https://api.shodan.io/shodan/host/{value}?" + urllib.parse.urlencode({"key": self.key})
        status, body = self._get(url, {})
        if status == 404:
            return {"found": False, "score": None}
        if status != 200:
            return {"error": f"HTTP {status}", "detail": body.get("error", "")}
        tags = body.get("tags", []) or []
        vulns = body.get("vulns", []) or []
        if isinstance(vulns, dict):
            vulns = list(vulns)
        return {
            "found": True,
            # Shodan은 평판 서비스가 아니므로 명시적 태그가 있을 때만 점수를 준다.
            "score": 70 if {"malware", "c2", "compromised"} & set(tags) else 0,
            "ports": sorted(body.get("ports", []))[:30],
            "org": body.get("org"),
            "isp": body.get("isp"),
            "asn": body.get("asn"),
            "country": body.get("country_name"),
            "hostnames": body.get("hostnames", [])[:10],
            "tags": tags,
            "vulns": sorted(vulns)[:20],
            "last_update": body.get("last_update"),
            "link": f"https://www.shodan.io/host/{value}",
        }


SERVICES = {"vt": VirusTotal, "criminalip": CriminalIP, "shodan": Shodan}


def _cache_get(conn: sqlite3.Connection, key: str) -> dict | None:
    row = conn.execute("SELECT response, fetched_at FROM osint_cache WHERE key = ?", (key,)).fetchone()
    if row and datetime.now(timezone.utc) - datetime.fromisoformat(row["fetched_at"]) < CACHE_TTL:
        return json.loads(row["response"])
    return None


def _cache_put(conn: sqlite3.Connection, key: str, result: dict) -> None:
    conn.execute("INSERT OR REPLACE INTO osint_cache (key, response, fetched_at) VALUES (?, ?, ?)",
                 (key, json.dumps(result, ensure_ascii=False), utcnow()))
    conn.commit()


def verdict(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= 70:
        return "malicious"
    if score >= 40:
        return "suspicious"
    return "no-detection"


def lookup(conn: sqlite3.Connection, services: list[Service], ioc_type: str, value: str,
           use_cache: bool = True) -> dict:
    results: dict[str, dict] = {}
    for svc in services:
        if not svc.enabled or not svc.supports(ioc_type):
            continue
        key = f"{svc.name}:{ioc_type}:{value}"
        cached = _cache_get(conn, key) if use_cache else None
        if cached is not None:
            results[svc.name] = {**cached, "cached": True}
            continue
        try:
            res = svc.query(ioc_type, value)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            res = {"error": type(e).__name__, "detail": str(e)}
        if "error" not in res:
            _cache_put(conn, key, res)
        results[svc.name] = res
    scores = [r["score"] for r in results.values() if r.get("score") is not None]
    score = max(scores) if scores else None
    return {"score": score, "verdict": verdict(score), "services": results}


def enrich_case(conn: sqlite3.Connection, case_id: str, services: list[Service],
                types: set[str] | None = None, use_cache: bool = True) -> list[dict]:
    """사건의 IOC를 조회해 점수·판정을 저장한다. 사설 IP 등은 ioc.extract 단계에서 이미 걸러진다."""
    rows = conn.execute("SELECT * FROM iocs WHERE case_id = ? ORDER BY type, value", (case_id,)).fetchall()
    out = []
    for r in rows:
        if types and r["type"] not in types:
            continue
        if not any(s.enabled and s.supports(r["type"]) for s in services):
            continue
        res = lookup(conn, services, r["type"], r["value"], use_cache=use_cache)
        conn.execute(
            "UPDATE iocs SET verdict = ?, score = ?, enrichment = ?, last_checked = ? WHERE id = ?",
            (res["verdict"], res["score"], json.dumps(res["services"], ensure_ascii=False), utcnow(), r["id"]),
        )
        conn.commit()
        out.append({"type": r["type"], "value": r["value"], **res})
    return out


def build_services(names: list[str], fetch: Fetch = http_fetch) -> list[Service]:
    unknown = set(names) - set(SERVICES)
    if unknown:
        raise ValueError(f"알 수 없는 서비스: {', '.join(sorted(unknown))}")
    return [SERVICES[n](fetch=fetch) for n in names]
