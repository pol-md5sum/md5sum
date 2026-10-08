"""M3 통합 타임라인: 외부 도구 결과(CSV·JSONL)와 시스템 내부 기록을 하나의 시간축으로 합친다.

CSV는 timestamp, source, host, event 열을 기대한다(Hayabusa·Plaso CSV는 열 이름을 매핑해 가져온다).
"""

from __future__ import annotations

import csv
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from . import evidence
from .db import load_analyses

COLUMN_ALIASES = {
    "timestamp": ["timestamp", "Timestamp", "datetime", "date_time", "time", "TimeCreated"],
    "source": ["source", "Channel", "source_long", "parser", "Provider"],
    "host": ["host", "Computer", "hostname", "computer_name"],
    "event": ["event", "message", "Details", "RuleTitle", "desc", "Message"],
}


def normalize_ts(value: str) -> str:
    v = value.strip().replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d %H:%M:%S.%f %z", "%Y-%m-%d %H:%M:%S %z", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.fromisoformat(v) if fmt is None else datetime.strptime(v, fmt)
            break
        except ValueError:
            continue
    else:
        raise ValueError(f"시각 형식을 해석할 수 없습니다: {value}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _pick(row: dict, field: str) -> str:
    for k in COLUMN_ALIASES[field]:
        if row.get(k):
            return str(row[k])
    return ""


def add(conn: sqlite3.Connection, case_id: str, ts: str, source: str, event: str,
        host: str = "", ref: str = "") -> None:
    conn.execute("INSERT INTO timeline (case_id, ts, source, host, event, ref) VALUES (?, ?, ?, ?, ?, ?)",
                 (case_id, normalize_ts(ts), source, host, event, ref))


def import_file(conn: sqlite3.Connection, case_id: str, path: Path, source_label: str = "") -> int:
    path = Path(path)
    n = 0
    if path.suffix.lower() in {".jsonl", ".json"}:
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    else:
        with open(path, newline="", encoding="utf-8-sig") as f:
            rows = list(csv.DictReader(f))
    for row in rows:
        ts = _pick(row, "timestamp")
        event = _pick(row, "event")
        if not ts or not event:
            continue
        add(conn, case_id, ts, source_label or _pick(row, "source") or path.name, event,
            _pick(row, "host"), ref=path.name)
        n += 1
    conn.commit()
    return n


def build_internal(conn: sqlite3.Connection, case_id: str) -> int:
    """증거 수집·이메일 수신·PE 컴파일 시각 등 시스템이 아는 시각을 타임라인에 넣는다."""
    conn.execute("DELETE FROM timeline WHERE case_id = ? AND ref LIKE 'irsys:%'", (case_id,))
    n = 0
    for ev in evidence.list_for_case(conn, case_id):
        add(conn, case_id, ev["acquired_at"], "증거 수집", f"{ev['id']} {ev['original_name']} 수집",
            ref=f"irsys:{ev['id']}")
        n += 1
    for a in load_analyses(conn, case_id, "email"):
        r = a["result"]
        for hop in r.get("received_hops", []):
            if hop.get("date", {}) and hop["date"].get("utc"):
                add(conn, case_id, hop["date"]["utc"], "메일 경유", f"{hop.get('from')} → {hop.get('by')} "
                    f"({', '.join(hop.get('ips', []))})", ref=f"irsys:{a['target']}")
                n += 1
        if r.get("date") and r["date"].get("utc"):
            add(conn, case_id, r["date"]["utc"], "메일 발송", f"제목: {r.get('subject', '')}",
                ref=f"irsys:{a['target']}")
            n += 1
    for a in load_analyses(conn, case_id, "static"):
        pe = a["result"].get("pe") or {}
        if pe.get("compile_time_utc"):
            add(conn, case_id, pe["compile_time_utc"], "PE 컴파일", f"{a['result']['file']} 컴파일 시각(위조 가능)",
                ref=f"irsys:{a['target']}")
            n += 1
    conn.commit()
    return n


def get(conn: sqlite3.Connection, case_id: str) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM timeline WHERE case_id = ? ORDER BY ts, id", (case_id,)).fetchall()
