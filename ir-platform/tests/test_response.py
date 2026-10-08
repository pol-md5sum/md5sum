import json

import pytest

from irsys import cases, ioc, response


@pytest.fixture()
def case(conn):
    cid = cases.create(conn, "t", "intrusion", 4, 4, "requester")
    ioc.store(conn, cid, {"ipv4": ["203.0.113.50", "8.8.8.8"], "domain": ["c2-relay.example", "update.microsoft.com"],
                          "sha256": ["a" * 64], "md5": ["b" * 32], "url": ["http://c2-relay.example/gate.php"]}, "t")
    conn.execute("UPDATE iocs SET verdict = 'malicious', score = 90 WHERE case_id = ?", (cid,))
    conn.execute("UPDATE iocs SET verdict = 'suspicious', score = 50 WHERE value = ?", ("b" * 32,))
    conn.commit()
    return cid


def test_plan_skips_allowlisted_and_respects_threshold(conn, case):
    res = response.plan(conn, case, "requester")
    planned = {r["target"] for r in res if "id" in r}
    skipped = {r["target"]: r["skipped"] for r in res if "skipped" in r}
    assert planned == {"203.0.113.50", "c2-relay.example", "a" * 64, "http://c2-relay.example/gate.php"}
    assert skipped == {"8.8.8.8": "차단 예외 네트워크", "update.microsoft.com": "차단 예외 도메인"}
    assert {r["target"] for r in response.plan(conn, case, "requester", "suspicious") if "id" in r} == {"b" * 32}


def test_validation_blocks_injection_and_internal():
    allow = response.load_allowlist()
    assert response.validate("block_ip", "10.0.0.5", allow) == "내부·예약 IP는 차단하지 않음"
    assert response.validate("block_ip", "1.2.3.4; rm -rf /", allow) == "IP 형식 오류"
    assert response.validate("block_domain", 'evil.example"; drop', allow) == "도메인 형식 오류"
    assert response.validate("block_hash", "zz" * 16, allow) == "해시 형식 오류"
    assert response.validate("block_url", "http://x.example/\"a", allow) == "URL 형식 오류"


def test_four_eyes_and_export(conn, case, tmp_path):
    actions = {r["target"]: r["id"] for r in response.plan(conn, case, "requester") if "id" in r}
    with pytest.raises(ValueError):
        response.decide(conn, actions["203.0.113.50"], "requester", True)
    with pytest.raises(ValueError):
        response.export(conn, case, tmp_path / "out", "approver")  # 승인 전에는 내보낼 것 없음
    for target in ("203.0.113.50", "c2-relay.example", "a" * 64):
        response.decide(conn, actions[target], "approver", True, "CAB-1234")
    response.decide(conn, actions["http://c2-relay.example/gate.php"], "approver", False, "도메인 차단으로 충분")
    with pytest.raises(ValueError):
        response.decide(conn, actions["203.0.113.50"], "approver", True)  # 이미 결정됨

    m = response.export(conn, case, tmp_path / "out", "approver")
    out = tmp_path / "out"
    assert {a["target"] for a in m["actions"]} == {"203.0.113.50", "c2-relay.example", "a" * 64}
    assert all(a["approved_by"] == "approver" for a in m["actions"])
    assert not (out / "blocklist_urls.txt").exists()  # 반려된 조치는 제외
    assert "-RemoteAddress 203.0.113.50 -Action Block" in (out / "firewall_windows.ps1").read_text()
    assert "Remove-NetFirewallRule" in (out / "rollback_windows.ps1").read_text()
    assert "iptables -D OUTPUT -d 203.0.113.50" in (out / "rollback_iptables.sh").read_text()
    assert "*.c2-relay.example CNAME ." in (out / "dns_rpz.zone").read_text()
    rules = (out / "suricata.rules").read_text()
    assert 'dns.query; dotprefix; content:".c2-relay.example"; nocase; endswith;' in rules
    assert len({line.split("sid:")[1].split(";")[0] for line in rules.splitlines() if "sid:" in line}) == 4
    yar = (out / "yara_hashes.yar").read_text()
    assert 'import "hash"' in yar and f'hash.sha256(0, filesize) == "{"a" * 64}"' in yar
    saved = json.loads((out / "manifest.json").read_text())
    assert set(saved["files"]) >= {"suricata.rules", "yara_hashes.yar", "dns_rpz.zone", "firewall_iptables.sh"}
    statuses = {r["target"]: r["status"] for r in response.list_actions(conn, case)}
    assert statuses["203.0.113.50"] == "exported"
    assert statuses["http://c2-relay.example/gate.php"] == "rejected"
