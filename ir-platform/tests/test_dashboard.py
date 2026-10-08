import json
import re
import shutil
import subprocess
from datetime import datetime, timezone

import pytest
from conftest import FIXTURES

from irsys import cases, dashboard, db, emailx, ioc


def _payload(html: str) -> dict:
    m = re.search(r'<script id="data" type="application/json">(.*?)</script>', html, re.S)
    return json.loads(m.group(1))


def test_dashboard_collects_cases_and_masks(conn):
    now = datetime(2026, 10, 8, tzinfo=timezone.utc)
    a = cases.create(conn, "홍길동 010-1234-5678 제보 </script><script>alert(1)</script>", "pii_leak", 5, 3,
                     "analyst", aware_at="2026-10-04T00:00:00+00:00")
    b = cases.create(conn, "피싱", "phishing", 3, 3, "analyst")
    r = emailx.analyze(FIXTURES / "phish.eml")
    db.save_analysis(conn, b, "email", "EV1", r)
    ioc.store(conn, b, r["iocs"], "email")

    html = dashboard.build(conn, now)
    assert html.count("<script") == 2  # 제목에 넣은 스크립트가 태그로 살아나지 않음
    data = _payload(html)
    by_id = {c["id"]: c for c in data["cases"]}
    assert "010-****-5678" in by_id[a]["title"]
    assert by_id[a]["deadlines"][0]["overdue"]          # 72시간 경과
    assert by_id[b]["detections"] == len(r["indicators"])
    assert {h["technique"] for h in data["technique_hits"]} >= {"T1566.001", "T1566.002"}
    assert data["techniques"]["T1566.001"][1] == "initial-access"


def test_every_used_technique_has_a_tactic():
    attack = dashboard.load_attack()
    tactics = {t for t, _ in attack["tactics"]}
    assert all(v[1] in tactics for v in attack["techniques"].values())
    used = set()
    for path in __import__("pathlib").Path(dashboard.__file__).parent.glob("*.py"):
        used |= set(re.findall(r'"(T1\d{3}(?:\.\d{3})?)"', path.read_text(encoding="utf-8")))
    missing = {t for t in used if t not in attack["techniques"] and t.split(".")[0] not in attack["techniques"]}
    assert not missing


@pytest.mark.skipif(not shutil.which("node"), reason="node 없음")
def test_dashboard_script_parses(conn, tmp_path):
    cases.create(conn, "t", "intrusion", 3, 3, "a")
    html = dashboard.build(conn)
    script = re.findall(r"<script>(.*?)</script>", html, re.S)[-1]
    js = tmp_path / "d.js"
    js.write_text(script, encoding="utf-8")
    res = subprocess.run(["node", "--check", str(js)], capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
