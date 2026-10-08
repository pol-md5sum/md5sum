import hashlib
import os
import stat

import pytest

from irsys import cases, evidence


def test_acquire_verify_and_chain(conn, tmp_path):
    cid = cases.create(conn, "t", "malware", 3, 3, "a")
    src = tmp_path / "sample.bin"
    src.write_bytes(b"evidence-bytes")
    ev = evidence.acquire(conn, cid, src, "kim")
    assert ev["sha256"] == hashlib.sha256(b"evidence-bytes").hexdigest()
    assert ev["stored_path"].endswith(".evidence")
    assert not os.stat(ev["stored_path"]).st_mode & stat.S_IWUSR  # 읽기 전용

    assert evidence.verify(conn, ev["id"], "kim")["ok"]
    path = evidence.open_for_analysis(conn, ev["id"], "lee", "정적 분석")
    assert path.read_bytes() == b"evidence-bytes"
    chain = evidence.verify_chain(conn, ev["id"])
    assert chain == {"ok": True, "entries": 3, "broken_at": None}
    assert [r["action"] for r in evidence.history(conn, ev["id"])] == ["acquire", "verify", "access"]


def test_tampered_custody_is_detected(conn, tmp_path):
    cid = cases.create(conn, "t", "malware", 3, 3, "a")
    src = tmp_path / "s.bin"
    src.write_bytes(b"x")
    ev = evidence.acquire(conn, cid, src, "kim")
    evidence.verify(conn, ev["id"], "kim")
    conn.execute("UPDATE custody SET actor = 'mallory' WHERE action = 'acquire'")
    conn.commit()
    res = evidence.verify_chain(conn, ev["id"])
    assert not res["ok"] and res["broken_at"] is not None


def test_modified_evidence_blocks_analysis(conn, tmp_path):
    cid = cases.create(conn, "t", "malware", 3, 3, "a")
    src = tmp_path / "s.bin"
    src.write_bytes(b"original")
    ev = evidence.acquire(conn, cid, src, "kim")
    os.chmod(ev["stored_path"], stat.S_IRUSR | stat.S_IWUSR)
    with open(ev["stored_path"], "ab") as f:
        f.write(b"!")
    with pytest.raises(RuntimeError):
        evidence.open_for_analysis(conn, ev["id"], "lee", "분석")
    assert evidence.history(conn, ev["id"])[-1]["action"] == "access-denied"


def test_export_logs_reason(conn, tmp_path):
    cid = cases.create(conn, "t", "malware", 3, 3, "a")
    src = tmp_path / "s.bin"
    src.write_bytes(b"data")
    ev = evidence.acquire(conn, cid, src, "kim")
    out = tmp_path / "out"
    out.mkdir()
    target = evidence.export(conn, ev["id"], out, "kim", "수사기관 제출")
    assert target.read_bytes() == b"data"
    assert "수사기관 제출" in evidence.history(conn, ev["id"])[-1]["detail"]
