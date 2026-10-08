"""M2 증거 수집·보존.

- 수집 즉시 MD5·SHA-256 이중 해시를 고정한다.
- 원본은 증거 저장소에 읽기 전용으로 보관하고, 분석은 이 사본을 읽기만 한다.
- 증거 취급 이력(Chain of Custody)은 앞 항목의 해시를 포함하는 해시 체인으로
  기록하므로, DB에서 이력을 고치거나 지우면 verify_chain()이 탐지한다.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import stat
from pathlib import Path

from . import cases
from .db import home, utcnow

GENESIS = "0" * 64
CHUNK = 1024 * 1024


def file_hashes(path: Path) -> dict[str, str | int]:
    md5, sha256, size = hashlib.md5(), hashlib.sha256(), 0
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK):
            md5.update(chunk)
            sha256.update(chunk)
            size += len(chunk)
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest(), "size": size}


def _entry_hash(prev_hash: str, evidence_id: str, ts: str, actor: str, action: str, detail: str) -> str:
    payload = json.dumps([prev_hash, evidence_id, ts, actor, action, detail], ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def custody_log(conn: sqlite3.Connection, evidence_id: str, actor: str, action: str, detail: str = "") -> str:
    row = conn.execute(
        "SELECT entry_hash FROM custody WHERE evidence_id = ? ORDER BY id DESC LIMIT 1", (evidence_id,)
    ).fetchone()
    prev = row["entry_hash"] if row else GENESIS
    ts = utcnow()
    h = _entry_hash(prev, evidence_id, ts, actor, action, detail)
    conn.execute(
        "INSERT INTO custody (evidence_id, ts, actor, action, detail, prev_hash, entry_hash)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (evidence_id, ts, actor, action, detail, prev, h),
    )
    conn.commit()
    return h


def _next_id(conn: sqlite3.Connection, case_id: str) -> str:
    n = conn.execute("SELECT COUNT(*) FROM evidence WHERE case_id = ?", (case_id,)).fetchone()[0] + 1
    return f"{case_id}-EV{n:03d}"


def acquire(
    conn: sqlite3.Connection,
    case_id: str,
    src: Path,
    actor: str,
    source: str = "",
    notes: str = "",
) -> dict:
    """파일을 증거로 등록한다. 원본 해시와 사본 해시가 다르면 등록을 중단한다."""
    cases.get(conn, case_id)
    src = Path(src)
    if not src.is_file():
        raise FileNotFoundError(src)
    before = file_hashes(src)
    ev_id = _next_id(conn, case_id)
    dest_dir = home() / "evidence" / case_id / ev_id
    dest_dir.mkdir(parents=True, exist_ok=False)
    # 악성 파일이 실수로 실행되지 않도록 확장자에 .evidence를 붙여 보관한다.
    dest = dest_dir / (src.name + ".evidence")
    shutil.copyfile(src, dest)
    os.chmod(dest, stat.S_IRUSR | stat.S_IRGRP)
    after = file_hashes(dest)
    if before != after:
        os.chmod(dest, stat.S_IWUSR | stat.S_IRUSR)
        dest.unlink()
        raise RuntimeError("복사 전후 해시가 달라 증거 등록을 중단했습니다.")
    conn.execute(
        "INSERT INTO evidence (id, case_id, original_name, original_path, stored_path, size, md5, sha256,"
        " acquired_at, acquired_by, source, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (ev_id, case_id, src.name, str(src.resolve()), str(dest), after["size"], after["md5"],
         after["sha256"], utcnow(), actor, source, notes),
    )
    conn.commit()
    custody_log(conn, ev_id, actor, "acquire",
                f"원본 {src.resolve()} · MD5 {after['md5']} · SHA-256 {after['sha256']}")
    cases.log(conn, case_id, actor, "evidence", f"{ev_id} {src.name} 등록")
    return {"id": ev_id, **after, "stored_path": str(dest)}


def get(conn: sqlite3.Connection, evidence_id: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
    if row is None:
        raise KeyError(f"증거 {evidence_id}을(를) 찾을 수 없습니다.")
    return row


def list_for_case(conn: sqlite3.Connection, case_id: str) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM evidence WHERE case_id = ? ORDER BY id", (case_id,)).fetchall()


def open_for_analysis(conn: sqlite3.Connection, evidence_id: str, actor: str, purpose: str) -> Path:
    """분석 전에 해시를 재검증하고 열람 이력을 남긴 뒤 보관 경로를 돌려준다."""
    result = verify(conn, evidence_id, actor, log_entry=False)
    if not result["ok"]:
        custody_log(conn, evidence_id, actor, "access-denied", f"해시 불일치로 열람 차단 ({purpose})")
        raise RuntimeError(f"{evidence_id} 해시 불일치: 분석을 중단합니다.")
    custody_log(conn, evidence_id, actor, "access", purpose)
    return Path(get(conn, evidence_id)["stored_path"])


def verify(conn: sqlite3.Connection, evidence_id: str, actor: str, log_entry: bool = True) -> dict:
    ev = get(conn, evidence_id)
    path = Path(ev["stored_path"])
    if not path.exists():
        result = {"ok": False, "reason": "보관 파일 없음"}
    else:
        now = file_hashes(path)
        ok = now["md5"] == ev["md5"] and now["sha256"] == ev["sha256"]
        result = {"ok": ok, "md5": now["md5"], "sha256": now["sha256"],
                  "reason": "" if ok else "해시 불일치"}
    if log_entry:
        custody_log(conn, evidence_id, actor, "verify", "일치" if result["ok"] else result["reason"])
    return result


def verify_chain(conn: sqlite3.Connection, evidence_id: str) -> dict:
    """증거 취급 이력의 해시 체인을 처음부터 다시 계산해 위변조를 확인한다."""
    rows = conn.execute("SELECT * FROM custody WHERE evidence_id = ? ORDER BY id", (evidence_id,)).fetchall()
    prev = GENESIS
    for r in rows:
        expected = _entry_hash(prev, evidence_id, r["ts"], r["actor"], r["action"], r["detail"])
        if r["prev_hash"] != prev or r["entry_hash"] != expected:
            return {"ok": False, "entries": len(rows), "broken_at": r["id"]}
        prev = r["entry_hash"]
    return {"ok": bool(rows), "entries": len(rows), "broken_at": None}


def history(conn: sqlite3.Connection, evidence_id: str) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM custody WHERE evidence_id = ? ORDER BY id", (evidence_id,)).fetchall()


def export(conn: sqlite3.Connection, evidence_id: str, dest: Path, actor: str, reason: str) -> Path:
    """증거 사본을 반출한다. 반출 전후 해시를 검증하고 사유를 기록한다."""
    src = open_for_analysis(conn, evidence_id, actor, f"반출 준비: {reason}")
    ev = get(conn, evidence_id)
    dest = Path(dest)
    target = dest / ev["original_name"] if dest.is_dir() else dest
    shutil.copyfile(src, target)
    copied = file_hashes(target)
    if copied["sha256"] != ev["sha256"]:
        target.unlink()
        raise RuntimeError("반출 사본 해시 불일치")
    custody_log(conn, evidence_id, actor, "export", f"{target} · 사유: {reason}")
    return target
