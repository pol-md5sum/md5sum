"""SQLite 저장소. 사건·증거·이력·IOC·분석 결과를 한 파일에 보관한다."""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    asset_criticality INTEGER NOT NULL,
    threat_level INTEGER NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    owner TEXT,
    summary TEXT,
    created_at TEXT NOT NULL,
    aware_at TEXT NOT NULL,
    closed_at TEXT
);
CREATE TABLE IF NOT EXISTS case_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL REFERENCES cases(id),
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id),
    original_name TEXT NOT NULL,
    original_path TEXT,
    stored_path TEXT NOT NULL,
    size INTEGER NOT NULL,
    md5 TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    acquired_at TEXT NOT NULL,
    acquired_by TEXT NOT NULL,
    source TEXT,
    notes TEXT
);
CREATE TABLE IF NOT EXISTS custody (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT NOT NULL REFERENCES evidence(id),
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL REFERENCES cases(id),
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT,
    first_seen TEXT NOT NULL,
    verdict TEXT,
    score REAL,
    enrichment TEXT,
    last_checked TEXT,
    UNIQUE(case_id, type, value)
);
CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL REFERENCES cases(id),
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    result TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL REFERENCES cases(id),
    ts TEXT NOT NULL,
    source TEXT NOT NULL,
    host TEXT,
    event TEXT NOT NULL,
    ref TEXT
);
CREATE TABLE IF NOT EXISTS osint_cache (
    key TEXT PRIMARY KEY,
    response TEXT NOT NULL,
    fetched_at TEXT NOT NULL
);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def home() -> Path:
    """데이터 디렉터리. IRSYS_HOME 환경 변수로 바꿀 수 있다."""
    return Path(os.environ.get("IRSYS_HOME", "./irsys-data")).resolve()


def connect(path: Path | None = None) -> sqlite3.Connection:
    base = home()
    base.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path or base / "irsys.db")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    return conn


def save_analysis(conn: sqlite3.Connection, case_id: str, kind: str, target: str, result: dict) -> int:
    cur = conn.execute(
        "INSERT INTO analyses (case_id, kind, target, result, created_at) VALUES (?, ?, ?, ?, ?)",
        (case_id, kind, target, json.dumps(result, ensure_ascii=False, default=str), utcnow()),
    )
    conn.commit()
    return cur.lastrowid


def load_analyses(conn: sqlite3.Connection, case_id: str, kind: str | None = None) -> list[dict]:
    sql = "SELECT * FROM analyses WHERE case_id = ?"
    args: list = [case_id]
    if kind:
        sql += " AND kind = ?"
        args.append(kind)
    rows = conn.execute(sql + " ORDER BY id", args).fetchall()
    return [{**dict(r), "result": json.loads(r["result"])} for r in rows]
