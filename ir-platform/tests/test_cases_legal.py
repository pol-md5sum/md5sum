from datetime import datetime, timezone

import pytest

from irsys import cases, legal


def test_severity_matrix():
    assert cases.severity(5, 5) == "critical"
    assert cases.severity(4, 3) == "high"
    assert cases.severity(2, 3) == "medium"
    assert cases.severity(1, 2) == "low"
    with pytest.raises(ValueError):
        cases.severity(0, 3)


def test_case_ids_and_transitions(conn):
    a = cases.create(conn, "피싱 메일", "phishing", 3, 4, "analyst")
    b = cases.create(conn, "웹쉘", "intrusion", 5, 4, "analyst")
    assert a.endswith("-0001") and b.endswith("-0002")
    cases.set_status(conn, a, "analysis", "analyst")
    with pytest.raises(ValueError):
        cases.set_status(conn, a, "recovery", "analyst")  # 봉쇄를 건너뛸 수 없음
    cases.set_status(conn, a, "containment", "analyst")
    assert cases.get(conn, a)["status"] == "containment"
    assert [e["action"] for e in cases.events(conn, a)] == ["create", "status", "status"]


def test_pii_leak_deadline_72h():
    aware = "2026-10-06T00:00:00+00:00"
    now = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
    [d] = legal.deadlines("pii_leak", aware, now)
    assert d["due_at"] == "2026-10-09T00:00:00+00:00"
    assert d["remaining_hours"] == 36.0
    assert d["alerts_passed"] == [0.25, 0.5]
    assert not d["overdue"]
    assert legal.deadlines("phishing", aware, now) == []


def test_mask_pii_keeps_hashes_and_ioc_emails():
    sha = "0101234567812a" + "0" * 50
    text = (f"주민 900101-1234567, 전화 010-1234-5678, 카드 1234-5678-9012-3456, "
            f"피해자 hong@victim.example, 공격자 admin@evil.example, 해시 {sha}")
    masked, counts = legal.mask_pii(text, keep_emails={"admin@evil.example"})
    assert "900101-1******" in masked
    assert "010-****-5678" in masked
    assert "1234-****-****-3456" in masked
    assert "h***@victim.example" in masked
    assert "admin@evil.example" in masked
    assert sha in masked
    assert counts == {"주민등록번호": 1, "카드번호": 1, "휴대전화": 1, "이메일": 1}
