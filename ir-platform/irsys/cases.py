"""M1 사건 관리: 사건 번호 발급, 심각도 산정, 단계 전환, 활동 기록."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from .db import utcnow

CATEGORIES = {
    "intrusion": "침해사고",
    "pii_leak": "개인정보 유출",
    "malware": "악성코드 감염",
    "phishing": "피싱·이메일 위협",
    "other": "기타",
}

STATUSES = ["new", "analysis", "containment", "recovery", "closed"]
STATUS_KO = {"new": "접수", "analysis": "분석", "containment": "봉쇄", "recovery": "복구", "closed": "종결"}

# 앞 단계로만 진행하되, 재분석이 필요하면 분석 단계로 되돌릴 수 있다.
TRANSITIONS = {
    "new": {"analysis", "closed"},
    "analysis": {"containment", "closed"},
    "containment": {"recovery", "analysis"},
    "recovery": {"closed", "analysis"},
    "closed": {"analysis"},
}


def severity(asset_criticality: int, threat_level: int) -> str:
    """자산 중요도(1~5) × 위협도(1~5)로 심각도를 산정한다."""
    for v in (asset_criticality, threat_level):
        if not 1 <= v <= 5:
            raise ValueError("자산 중요도와 위협도는 1~5 범위여야 합니다.")
    score = asset_criticality * threat_level
    if score >= 20:
        return "critical"
    if score >= 12:
        return "high"
    if score >= 6:
        return "medium"
    return "low"


def _next_id(conn: sqlite3.Connection) -> str:
    year = datetime.now(timezone.utc).year
    prefix = f"IR-{year}-"
    row = conn.execute(
        "SELECT id FROM cases WHERE id LIKE ? ORDER BY id DESC LIMIT 1", (prefix + "%",)
    ).fetchone()
    n = int(row["id"].rsplit("-", 1)[1]) + 1 if row else 1
    return f"{prefix}{n:04d}"


def log(conn: sqlite3.Connection, case_id: str, actor: str, action: str, detail: str = "") -> None:
    conn.execute(
        "INSERT INTO case_events (case_id, ts, actor, action, detail) VALUES (?, ?, ?, ?, ?)",
        (case_id, utcnow(), actor, action, detail),
    )
    conn.commit()


def create(
    conn: sqlite3.Connection,
    title: str,
    category: str,
    asset_criticality: int,
    threat_level: int,
    actor: str,
    aware_at: str | None = None,
    summary: str = "",
) -> str:
    if category not in CATEGORIES:
        raise ValueError(f"사건 유형은 {', '.join(CATEGORIES)} 중 하나여야 합니다.")
    aware = aware_at or utcnow()
    datetime.fromisoformat(aware)  # 형식 검증
    case_id = _next_id(conn)
    conn.execute(
        "INSERT INTO cases (id, title, category, asset_criticality, threat_level, severity, status,"
        " owner, summary, created_at, aware_at) VALUES (?, ?, ?, ?, ?, ?, 'new', ?, ?, ?, ?)",
        (case_id, title, category, asset_criticality, threat_level,
         severity(asset_criticality, threat_level), actor, summary, utcnow(), aware),
    )
    conn.commit()
    log(conn, case_id, actor, "create", f"{CATEGORIES[category]} 사건 접수")
    return case_id


def get(conn: sqlite3.Connection, case_id: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    if row is None:
        raise KeyError(f"사건 {case_id}을(를) 찾을 수 없습니다.")
    return row


def list_all(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM cases ORDER BY created_at DESC").fetchall()


def set_status(conn: sqlite3.Connection, case_id: str, status: str, actor: str, note: str = "") -> None:
    current = get(conn, case_id)["status"]
    if status not in TRANSITIONS[current]:
        allowed = ", ".join(sorted(TRANSITIONS[current]))
        raise ValueError(f"{current} → {status} 전환은 허용되지 않습니다. 가능: {allowed}")
    closed_at = utcnow() if status == "closed" else None
    conn.execute("UPDATE cases SET status = ?, closed_at = ? WHERE id = ?", (status, closed_at, case_id))
    conn.commit()
    log(conn, case_id, actor, "status", f"{STATUS_KO[current]} → {STATUS_KO[status]} {note}".strip())


def recategorize(conn: sqlite3.Connection, case_id: str, category: str, actor: str) -> None:
    if category not in CATEGORIES:
        raise ValueError(f"사건 유형은 {', '.join(CATEGORIES)} 중 하나여야 합니다.")
    conn.execute("UPDATE cases SET category = ? WHERE id = ?", (category, case_id))
    conn.commit()
    log(conn, case_id, actor, "recategorize", CATEGORIES[category])


def events(conn: sqlite3.Connection, case_id: str) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM case_events WHERE case_id = ? ORDER BY id", (case_id,)).fetchall()
