import base64

from irsys import cases, ioc, osint


def test_extract_refangs_and_filters():
    text = """
    C2: hxxps://c2-server[.]example/gate.php?id=1 and 198.51.100.23, 10.0.0.5
    drop: payload.exe, report.hwp
    mail: attacker@evil-mail.example
    hash: 44d88612fea8a8f36de82e1278abb02f
    sha256 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
    CVE-2017-11882
    """
    r = ioc.extract(text)
    assert r["url"] == ["https://c2-server.example/gate.php?id=1"]
    assert "c2-server.example" in r["domain"]
    assert "evil-mail.example" in r["domain"]
    assert not {"payload.exe", "report.hwp"} & set(r["domain"])
    assert r["ipv4"] == ["198.51.100.23"]  # 사설 IP 제외
    assert r["md5"] == ["44d88612fea8a8f36de82e1278abb02f"]
    assert r["sha256"] == ["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"]
    assert "md5" not in {k for k, v in ioc.extract("a" * 64).items() if k != "sha256"}
    assert r["cve"] == ["CVE-2017-11882"]


def test_defang():
    assert ioc.defang("https://evil.example/a.b") == "hxxps[://]evil[.]example/a.b"
    assert ioc.defang("1.2.3.4") == "1[.]2[.]3[.]4"
    assert ioc.defang("a@b.example") == "a[@]b[.]example"


def fake_fetch(calls):
    def fetch(url, headers):
        calls.append(url)
        if "virustotal" in url and "/files/" in url:
            return 200, {"data": {"attributes": {
                "last_analysis_stats": {"malicious": 40, "suspicious": 1, "harmless": 0, "undetected": 20},
                "popular_threat_classification": {"suggested_threat_label": "trojan.appleseed/kimsuky"},
                "tags": ["peexe"]}}}
        if "virustotal" in url and "/urls/" in url:
            assert url.rsplit("/", 1)[1] == base64.urlsafe_b64encode(b"http://x.example/").decode().rstrip("=")
            return 404, {}
        if "virustotal" in url:
            return 200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0}}}}
        if "criminalip" in url:
            return 200, {"score": {"inbound": "Dangerous", "outbound": "Safe"},
                         "issues": {"is_vpn": False, "is_scanner": True}}
        if "shodan" in url:
            return 200, {"ports": [443, 22], "org": "Example Hosting", "tags": ["vpn"], "vulns": ["CVE-2023-0001"]}
        raise AssertionError(url)
    return fetch


def test_enrich_case_with_cache(conn):
    cid = cases.create(conn, "t", "malware", 3, 3, "a")
    ioc.store(conn, cid, {"sha256": ["a" * 64], "ipv4": ["198.51.100.23"], "url": ["http://x.example/"]}, "test")
    calls: list[str] = []
    services = [cls(key="k", fetch=fake_fetch(calls), interval=0) for cls in osint.SERVICES.values()]
    res = {r["value"]: r for r in osint.enrich_case(conn, cid, services)}
    assert res["a" * 64]["verdict"] == "malicious"
    assert res["a" * 64]["services"]["vt"]["threat_label"] == "trojan.appleseed/kimsuky"
    ip = res["198.51.100.23"]
    assert ip["score"] == 75 and ip["verdict"] == "malicious"
    assert ip["services"]["criminalip"]["issues"] == ["is_scanner"]
    assert ip["services"]["shodan"]["ports"] == [22, 443]
    assert res["http://x.example/"]["verdict"] == "unknown"
    n = len(calls)
    osint.enrich_case(conn, cid, services)
    assert len(calls) == n  # 모두 캐시 적중(404 결과도 캐시)


def test_services_without_keys_are_skipped(conn, monkeypatch):
    for env in ("IRSYS_VT_KEY", "IRSYS_CRIMINALIP_KEY", "IRSYS_SHODAN_KEY"):
        monkeypatch.delenv(env, raising=False)
    cid = cases.create(conn, "t", "malware", 3, 3, "a")
    ioc.store(conn, cid, {"ipv4": ["198.51.100.23"]}, "test")
    services = osint.build_services(["vt", "shodan"])
    assert osint.enrich_case(conn, cid, services) == []


def test_no_domain_false_positives_from_headers():
    r = ioc.extract("spf=fail smtp.mailfrom=bulk.example; header.from=evil.example; to hong.gildong@victim.example")
    assert "smtp.mailfrom" not in r["domain"]
    assert "header.from" not in r["domain"]
    assert "hong.gildong" not in r["domain"]
    assert {"bulk.example", "evil.example", "victim.example"} <= set(r["domain"])
