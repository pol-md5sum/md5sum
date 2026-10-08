"""M4 메모리 분석: Volatility 3 결과(JSON 렌더러)를 해석한다.

두 가지 방식으로 입력을 받는다.
1) Volatility 3가 설치되어 있으면 run()으로 직접 실행(vol -r json -f <이미지> <플러그인>).
2) 다른 분석 장비에서 만든 결과 JSON 디렉터리(windows.pslist.json 등)를 load_dir()로 읽는다.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from . import ioc
from .eventlog import OFFICE, SHELLS
from .static import SCRIPT_RULES

PLUGINS = ["windows.pslist", "windows.cmdline", "windows.netscan", "windows.malfind"]

# 정상 부모 프로세스 (SANS "Hunt Evil" 기준 일부)
EXPECTED_PARENT = {
    "services.exe": {"wininit.exe"},
    "lsass.exe": {"wininit.exe"},
    "svchost.exe": {"services.exe", "msmpeng.exe"},
    "lsaiso.exe": {"wininit.exe"},
    "taskhostw.exe": {"svchost.exe"},
    "runtimebroker.exe": {"svchost.exe"},
}
SINGLETONS = {"lsass.exe", "services.exe", "wininit.exe", "lsaiso.exe"}
CRITICAL_NAMES = {"svchost.exe", "lsass.exe", "services.exe", "csrss.exe", "winlogon.exe", "explorer.exe",
                  "smss.exe", "wininit.exe", "spoolsv.exe", "taskhostw.exe", "dllhost.exe", "conhost.exe"}
SUSPICIOUS_PATH = re.compile(r"(?i)\\(temp|appdata\\local\\temp|users\\public|programdata|perflogs)\\|\\\$recycle\.bin\\")


def find_volatility() -> str | None:
    return os.environ.get("IRSYS_VOL") or shutil.which("vol") or shutil.which("vol.py")


def run(image: Path, outdir: Path, plugins: list[str] | None = None, timeout: int = 3600) -> dict[str, list]:
    vol = find_volatility()
    if not vol:
        raise RuntimeError("Volatility 3(vol)를 찾을 수 없습니다. IRSYS_VOL로 경로를 지정하거나 --from-json을 쓰십시오.")
    outdir.mkdir(parents=True, exist_ok=True)
    results = {}
    for plugin in plugins or PLUGINS:
        proc = subprocess.run([vol, "-q", "-r", "json", "-f", str(image), plugin],
                              capture_output=True, text=True, timeout=timeout, check=False)
        if proc.returncode != 0:
            results[plugin] = {"error": proc.stderr.strip()[-500:]}
            continue
        (outdir / f"{plugin}.json").write_text(proc.stdout, encoding="utf-8")
        results[plugin] = json.loads(proc.stdout or "[]")
    return results


def load_dir(path: Path) -> dict[str, list]:
    results = {}
    for p in sorted(Path(path).glob("*.json")):
        results[p.stem] = json.loads(p.read_text(encoding="utf-8"))
    if not results:
        raise ValueError(f"{path}에 Volatility JSON 결과가 없습니다.")
    return results


def _flatten(rows: list) -> list[dict]:
    out = []
    for r in rows if isinstance(rows, list) else []:
        out.append(r)
        out += _flatten(r.get("__children", []))
    return out


def _osa_distance(a: str, b: str) -> int:
    """편집 거리(인접 글자 순서 바꿈을 1로 계산)."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def analyze(results: dict[str, list]) -> dict:
    procs = _flatten(results.get("windows.pslist") or results.get("windows.pstree") or [])
    by_pid = {p.get("PID"): p for p in procs}
    name = lambda p: str(p.get("ImageFileName") or "").lower()  # noqa: E731
    cmdlines = {r.get("PID"): str(r.get("Args") or "") for r in _flatten(results.get("windows.cmdline", []))}
    findings: list[dict] = []

    def add(kind, severity, technique, pid, description):
        findings.append({"type": kind, "severity": severity, "technique": technique, "pid": pid,
                         "description": description})

    counts: dict[str, int] = {}
    for p in procs:
        if p.get("ExitTime") in (None, "", "N/A"):
            counts[name(p)] = counts.get(name(p), 0) + 1
    for n in SINGLETONS:
        if counts.get(n, 0) > 1:
            add("duplicate_singleton", "high", "T1036.005", None, f"{n} 프로세스가 {counts[n]}개 실행 중")

    for p in procs:
        n, pid = name(p), p.get("PID")
        parent = by_pid.get(p.get("PPID"))
        pname = name(parent) if parent else ""
        if n in EXPECTED_PARENT and parent and pname not in EXPECTED_PARENT[n]:
            add("unexpected_parent", "high", "T1036.005", pid, f"{n}(PID {pid})의 부모가 {pname}(PID {p.get('PPID')})")
        if n not in CRITICAL_NAMES:
            for c in CRITICAL_NAMES:
                if _osa_distance(n, c) == 1:
                    add("name_masquerade", "high", "T1036.005", pid, f"{n}(PID {pid})가 정상 프로세스 {c}와 유사한 이름")
                    break
        if pname in OFFICE and n in SHELLS:
            add("office_spawns_shell", "high", "T1204.002", pid, f"{pname}가 {n}(PID {pid}) 실행")
        cmd = cmdlines.get(pid, "")
        if cmd and SUSPICIOUS_PATH.search(cmd):
            add("suspicious_path", "medium", "T1036", pid, f"{n}(PID {pid}) 비정상 경로에서 실행: {cmd[:150]}")
        for _, pat, tech, desc in SCRIPT_RULES:
            if cmd and re.search(pat, cmd):
                add("suspicious_cmdline", "medium", tech, pid, f"{n}(PID {pid}) {desc}: {cmd[:150]}")

    connections = []
    for c in _flatten(results.get("windows.netscan", [])):
        fa = str(c.get("ForeignAddr") or "")
        if ioc.is_public_ip(fa):
            owner = c.get("Owner") or name(by_pid.get(c.get("PID"), {}))
            connections.append({"pid": c.get("PID"), "owner": owner, "proto": c.get("Proto"),
                                "local": f"{c.get('LocalAddr')}:{c.get('LocalPort')}",
                                "remote": f"{fa}:{c.get('ForeignPort')}", "state": c.get("State")})
            if str(owner).lower() in {"rundll32.exe", "regsvr32.exe", "mshta.exe", "powershell.exe", "notepad.exe",
                                      "lsass.exe", "winword.exe", "excel.exe"}:
                add("unusual_network_process", "high", "T1071", c.get("PID"),
                    f"{owner}(PID {c.get('PID')})가 외부 {fa}:{c.get('ForeignPort')}와 통신")

    for m in _flatten(results.get("windows.malfind", [])):
        prot = str(m.get("Protection") or "")
        hexdump = str(m.get("Hexdump") or "").replace("\n", " ").lower()
        is_pe = hexdump.startswith("4d 5a") or "mz" in hexdump[:60]
        if "EXECUTE_READWRITE" in prot:
            add("injected_code", "high" if is_pe else "medium", "T1055", m.get("PID"),
                f"{m.get('Process')}(PID {m.get('PID')}) {prot} 영역 {m.get('Start VPN')}"
                + (" — PE 헤더 포함" if is_pe else ""))

    iocs = ioc.extract("\n".join([c["remote"].rsplit(":", 1)[0] for c in connections] + list(cmdlines.values())))
    return {
        "plugins": sorted(results),
        "errors": {k: v["error"] for k, v in results.items() if isinstance(v, dict) and "error" in v},
        "processes": len(procs),
        "external_connections": connections,
        "findings": findings,
        "iocs": iocs,
        "attack_techniques": sorted({f["technique"] for f in findings}),
    }
