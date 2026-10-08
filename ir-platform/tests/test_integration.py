import json

import pcapgen
from test_eventlog import scenario as evtx_scenario
from test_memory import vol_results

from irsys.cli import main


def run(capsys, *argv, actor="analyst"):
    capsys.readouterr()
    assert main(["--actor", actor, *argv]) == 0, argv
    return capsys.readouterr().out


def test_full_incident_flow(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("IRSYS_HOME", str(tmp_path / "home"))
    pcap = tmp_path / "capture.pcap"
    pcapgen.write_pcap(pcap, pcapgen.scenario())
    xml = tmp_path / "security.xml"
    xml.write_text(evtx_scenario(), encoding="utf-8")
    voldir = tmp_path / "vol"
    voldir.mkdir()
    for k, v in vol_results().items():
        (voldir / f"{k}.json").write_text(json.dumps(v))

    cid = run(capsys, "case", "new", "--title", "RDP 침입 후 C2 통신", "--category", "intrusion",
              "--asset", "5", "--threat", "4").split()[0]
    net = json.loads(run(capsys, "network", cid, str(pcap)))
    assert {f["type"] for f in net["findings"]} >= {"beacon", "dns_tunnel"}
    evt = json.loads(run(capsys, "evtlog", cid, str(xml)))
    assert any(f["type"] == "bruteforce_success" for f in evt["findings"])
    mem = json.loads(run(capsys, "memory", cid, "--from-json", str(voldir)))
    assert any(f["type"] == "injected_code" for f in mem["findings"])

    iocs = run(capsys, "ioc", "list", cid)
    assert "203[.]0[.]113[.]50" in iocs and "198[.]51[.]100[.]7" in iocs

    added = json.loads(run(capsys, "response", "add", cid, "block_ip", "203.0.113.50", "--reason", "비컨 C2"))
    run(capsys, "response", "add", cid, "block_domain", "c2-relay.example", "--reason", "C2 도메인")
    assert main(["--actor", "analyst", "response", "approve", str(added["id"])]) == 1  # 본인 승인 불가
    run(capsys, "response", "approve", str(added["id"]), "--note", "CAB-77", actor="lead")
    out = run(capsys, "response", "export", cid, str(tmp_path / "out"), actor="lead")
    assert "1건 내보냄" in out and (tmp_path / "out" / "suricata.rules").exists()

    run(capsys, "timeline", "build", cid)
    tl = run(capsys, "timeline", "show", cid)
    assert "TLS 최초 접속 update.c2-relay.example" in tl
    assert "무차별" in tl or "로그인 실패" in tl

    run(capsys, "apt", cid)
    report = tmp_path / "r.md"
    run(capsys, "report", cid, "--out", str(report))
    text = report.read_text(encoding="utf-8")
    for heading in ("## 6. 네트워크 분석", "## 7. 이벤트 로그 분석", "## 8. 메모리 분석", "## 12. 대응 조치",
                    "## 13. 타임라인(UTC)", "## 14. 보고서용 문장"):
        assert heading in text, heading
    assert "update[.]c2-relay[.]example" in text
    assert "산출물 생성" in text and "승인 대기" in text
    assert "T1110" in text and "T1071.004" in text and "T1055" in text
    assert "정보통신망" in text  # 침해사고 신고 기한
