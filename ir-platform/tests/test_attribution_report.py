import json

from conftest import FIXTURES

from irsys import attribution
from irsys.cli import main


def test_scoring_prefers_matching_group():
    observed = {
        "techniques": ["T1566.001", "T1204.002", "T1059.001", "T1218.005", "T1176"],
        "labels": ["trojan.appleseed/kimsuky"],
        "lure_text": "대북정책 세미나 원고 자문",
        "hangul": 3,
        "compile_times_kst": ["2026-03-03T11:00:00+09:00"],
    }
    res = attribution.score(observed)
    assert res[0]["group"] == "Kimsuky"
    top = res[0]
    assert top["axes"]["code"] == 0.8
    assert top["axes"]["target"] == 1.0
    assert top["axes"]["lang_time"] == 1.0
    assert top["axes"]["ttp"] > res[1]["axes"]["ttp"]
    # 인프라 근거가 없고 점수가 0.75 미만이므로 '높음'이 아님
    assert top["grade"] in {"중간", "낮음"}


def test_false_flag_guard():
    assert attribution.grade(0.8, {"infra": 0, "ttp": 0.3}) == "중간"
    assert attribution.grade(0.8, {"infra": 0.5, "ttp": 0.3}) == "높음"
    assert attribution.grade(0.4, {"infra": 1, "ttp": 1}) == "낮음"


def test_end_to_end_cli(tmp_path, monkeypatch, pe_file, capsys):
    monkeypatch.setenv("IRSYS_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("IRSYS_ACTOR", "tester")
    assert main(["case", "new", "--title", "자문 사칭 피싱", "--category", "phishing",
                 "--asset", "4", "--threat", "4", "--aware-at", "2026-10-06T02:00:00+00:00"]) == 0
    cid = capsys.readouterr().out.split()[0]
    assert main(["email", cid, str(FIXTURES / "phish.eml")]) == 0
    assert main(["static", cid, str(pe_file)]) == 0
    assert main(["case", "category", cid, "pii_leak"]) == 0
    assert main(["timeline", "build", cid]) == 0
    assert main(["apt", cid]) == 0
    capsys.readouterr()
    out = tmp_path / "report.md"
    assert main(["report", cid, "--out", str(out)]) == 0
    text = out.read_text(encoding="utf-8")

    assert "[자문 요청] 대북정책 세미나 원고 검토" in text
    assert "203[.]0[.]113[.]77" in text           # 최초 발신 IP(무력화)
    assert "admin@unikorea-gov.example" in text     # 공격자 주소는 유지
    assert "hong.gildong@victim.example" not in text  # 피해자 주소는 마스킹
    assert "h***@victim.example" in text
    assert "자문요청서.hwp.lnk" in text
    assert "login-verify[.]example" in text
    assert "개인정보 보호법 제34조" in text and "2026-10-09T02:00:00+00:00" in text
    assert "Kimsuky" in text
    assert "## 3줄 요약" in text and "## 14. 보고서용 문장" in text
    assert "T1566.001" in text
    assert "정상" in text  # 증거 취급 이력 체인

    capsys.readouterr()
    assert main(["evidence", "list", cid]) == 0
    ev_ids = [line.split()[0] for line in capsys.readouterr().out.splitlines()]
    assert len(ev_ids) == 2
    assert main(["evidence", "custody", ev_ids[0]]) == 0
    custody = json.loads(capsys.readouterr().out)
    assert custody["chain"]["ok"]
    assert [e["action"] for e in custody["entries"]] == ["acquire", "access"]
