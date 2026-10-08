"""M3 Windows 이벤트 로그 분석 (Security·System·PowerShell·Sysmon).

입력: XML 내보내기(wevtutil qe <채널> /f:xml, Get-WinEvent | ToXml) 또는
python-evtx가 설치된 경우 .evtx 원본.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import ioc
from .static import SCRIPT_RULES

NS = re.compile(r"\{[^}]*\}")
WINDOW = timedelta(minutes=10)
BRUTE_FORCE_MIN = 10
SPRAY_MIN_USERS = 5

OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "hwp.exe", "acrord32.exe", "msaccess.exe",
          "mspub.exe", "onenote.exe"}
SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
          "regsvr32.exe", "certutil.exe", "bitsadmin.exe"}
SUSPICIOUS_SERVICE = re.compile(r"(?i)(powershell|cmd(\.exe)?\s*/c|%comspec%|\\temp\\|\\appdata\\|\\users\\public\\|rundll32|mshta)")
ADMIN_GROUPS = re.compile(r"(?i)(administrators|domain admins|enterprise admins|schema admins|remote desktop users)")
LOG_ON_TYPES = {"2": "대화형", "3": "네트워크", "4": "배치", "5": "서비스", "7": "잠금 해제",
                "8": "네트워크(평문)", "9": "새 자격 증명", "10": "원격 대화형(RDP)", "11": "캐시된 대화형"}


def _local(tag: str) -> str:
    return NS.sub("", tag)


def _parse_event(el: ET.Element) -> dict | None:
    ev: dict = {"data": {}}
    for child in el:
        name = _local(child.tag)
        if name == "System":
            for s in child:
                sn = _local(s.tag)
                if sn == "EventID":
                    ev["event_id"] = int((s.text or "0").strip())
                elif sn == "TimeCreated":
                    ev["ts"] = s.get("SystemTime")
                elif sn == "Channel":
                    ev["channel"] = s.text or ""
                elif sn == "Computer":
                    ev["computer"] = s.text or ""
                elif sn == "Provider":
                    ev["provider"] = s.get("Name", "")
                elif sn == "EventRecordID":
                    ev["record_id"] = s.text
        elif name in ("EventData", "UserData"):
            for i, d in enumerate(child.iter()):
                if d is child:
                    continue
                key = d.get("Name") or _local(d.tag)
                if d.text and d.text.strip():
                    ev["data"][key] = d.text.strip()
    if "event_id" not in ev or not ev.get("ts"):
        return None
    ts = ev["ts"].replace("Z", "+00:00")
    if "." in ts:  # 7자리 소수 초를 6자리로 맞춘다
        head, frac = ts.split(".", 1)
        digits = re.match(r"\d+", frac).group(0)
        ts = f"{head}.{digits[:6]}{frac[len(digits):]}"
    dt = datetime.fromisoformat(ts)
    ev["dt"] = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    ev["ts"] = ev["dt"].isoformat()
    return ev


def read_events(path: Path) -> list[dict]:
    path = Path(path)
    raw = path.read_bytes()
    if raw[:8] == b"ElfFile\x00":
        try:
            from Evtx.Evtx import Evtx  # type: ignore  # python-evtx (선택)
        except ImportError as e:
            raise ValueError("EVTX 원본은 python-evtx가 필요합니다. wevtutil qe <채널> /f:xml 로 내보내 주십시오.") from e
        with Evtx(str(path)) as log:
            xml_text = "<Events>" + "".join(r.xml() for r in log.records()) + "</Events>"
    else:
        xml_text = raw.decode("utf-8-sig", errors="replace")
        if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
            xml_text = raw.decode("utf-16")
    if "<!DOCTYPE" in xml_text or "<!ENTITY" in xml_text:
        raise ValueError("DTD가 포함된 XML은 처리하지 않습니다.")
    xml_text = re.sub(r"<\?xml[^>]*\?>", "", xml_text)
    root = ET.fromstring(f"<Root>{xml_text}</Root>")
    events = [e for e in (_parse_event(el) for el in root.iter() if _local(el.tag) == "Event") if e]
    return sorted(events, key=lambda e: e["dt"])


def _basename(p: str) -> str:
    return re.split(r"[\\/]", p or "")[-1].lower()


def _finding(ev: dict, kind: str, severity: str, technique: str, description: str) -> dict:
    return {"ts": ev["ts"], "computer": ev.get("computer", ""), "event_id": ev["event_id"], "type": kind,
            "severity": severity, "technique": technique, "description": description}


def _command_rules(cmd: str) -> list[tuple[str, str]]:
    return [(t, d) for _, p, t, d in SCRIPT_RULES if re.search(p, cmd)]


def analyze(path: Path) -> dict:
    events = read_events(path)
    findings: list[dict] = []
    failed: dict[str, list[tuple[datetime, str]]] = defaultdict(list)
    logons: Counter = Counter()
    ioc_text: list[str] = []

    for ev in events:
        eid, d, chan = ev["event_id"], ev["data"], ev.get("channel", "").lower()

        if (eid == 1102 and "security" in chan) or (eid == 104 and "system" in chan):
            findings.append(_finding(ev, "log_cleared", "high", "T1070.001",
                                     f"{ev.get('channel')} 로그 삭제 (계정 {d.get('SubjectUserName', '-')})"))

        elif eid == 4625:
            ip = d.get("IpAddress", "-")
            failed[ip].append((ev["dt"], d.get("TargetUserName", "-").lower()))

        elif eid == 4624:
            ip, user, ltype = d.get("IpAddress", "-"), d.get("TargetUserName", "-"), d.get("LogonType", "")
            if user.endswith("$") or ltype == "5":
                continue
            logons[(user, ip, LOG_ON_TYPES.get(ltype, ltype))] += 1
            recent = [t for t, _ in failed.get(ip, []) if ev["dt"] - WINDOW <= t <= ev["dt"]]
            if ip not in ("-", "127.0.0.1", "::1") and len(recent) >= BRUTE_FORCE_MIN:
                findings.append(_finding(ev, "bruteforce_success", "critical", "T1110",
                                         f"{ip}에서 로그인 실패 {len(recent)}회 후 {user} 계정 로그인 성공"))
            if ltype == "10" and ioc.is_public_ip(ip):
                findings.append(_finding(ev, "external_rdp", "high", "T1021.001",
                                         f"외부 IP {ip}에서 {user} 계정 RDP 로그인"))
            if ioc.is_public_ip(ip):
                ioc_text.append(ip)

        elif eid in (4688, 1) and (eid == 4688 or "sysmon" in chan):
            image = d.get("NewProcessName") or d.get("Image", "")
            parent = d.get("ParentProcessName") or d.get("ParentImage", "")
            cmd = d.get("CommandLine", "")
            if _basename(parent) in OFFICE and _basename(image) in SHELLS:
                findings.append(_finding(ev, "office_spawns_shell", "high", "T1204.002",
                                         f"{_basename(parent)}가 {_basename(image)} 실행: {cmd[:150]}"))
            for t, desc in _command_rules(cmd):
                findings.append(_finding(ev, "suspicious_command", "medium", t, f"{desc}: {cmd[:150]}"))
            ioc_text.append(cmd)

        elif eid == 7045:
            img = d.get("ImagePath", "")
            sev = "high" if SUSPICIOUS_SERVICE.search(img) else "medium"
            findings.append(_finding(ev, "service_installed", sev, "T1543.003",
                                     f"서비스 설치 {d.get('ServiceName', '-')}: {img[:150]}"))
            ioc_text.append(img)

        elif eid == 4698:
            findings.append(_finding(ev, "scheduled_task", "medium", "T1053.005",
                                     f"예약 작업 생성 {d.get('TaskName', '-')} (계정 {d.get('SubjectUserName', '-')})"))
            ioc_text.append(d.get("TaskContent", ""))

        elif eid == 4720:
            findings.append(_finding(ev, "account_created", "medium", "T1136.001",
                                     f"계정 생성 {d.get('TargetUserName', '-')} (생성자 {d.get('SubjectUserName', '-')})"))

        elif eid in (4728, 4732, 4756):
            group = d.get("TargetUserName", "")
            sev = "high" if ADMIN_GROUPS.search(group) else "medium"
            findings.append(_finding(ev, "group_member_added", sev, "T1098",
                                     f"{group} 그룹에 {d.get('MemberName') or d.get('MemberSid', '-')} 추가"))

        elif eid == 4104:
            text = d.get("ScriptBlockText", "")
            for t, desc in _command_rules(text):
                findings.append(_finding(ev, "powershell_scriptblock", "medium", t, f"스크립트 블록: {desc}"))
            ioc_text.append(text)

        elif eid == 3 and "sysmon" in chan:
            if ioc.is_public_ip(d.get("DestinationIp", "")):
                ioc_text.append(d["DestinationIp"])
                if d.get("DestinationHostname"):
                    ioc_text.append(d["DestinationHostname"])

        elif eid == 22 and "sysmon" in chan:
            ioc_text.append(d.get("QueryName", ""))

        elif eid == 10 and "sysmon" in chan and _basename(d.get("TargetImage", "")) == "lsass.exe":
            src = _basename(d.get("SourceImage", ""))
            if src not in {"wmiprvse.exe", "svchost.exe", "msmpeng.exe", "lsm.exe", "wininit.exe", "csrss.exe"}:
                findings.append(_finding(ev, "lsass_access", "high", "T1003.001",
                                         f"{src}가 lsass.exe 메모리 접근 (권한 {d.get('GrantedAccess', '-')})"))

    # 무차별 대입·패스워드 스프레이 (10분 창)
    for ip, attempts in failed.items():
        attempts.sort()
        reported_brute = reported_spray = False
        for i, (t, _) in enumerate(attempts):
            window = [a for a in attempts[i:] if a[0] - t <= WINDOW]
            users = {u for _, u in window}
            if not reported_brute and len(window) >= BRUTE_FORCE_MIN:
                findings.append({"ts": t.isoformat(), "computer": "", "event_id": 4625, "type": "bruteforce",
                                 "severity": "high", "technique": "T1110.001",
                                 "description": f"{ip}에서 10분 내 로그인 실패 {len(window)}회 (계정 {len(users)}개)"})
                reported_brute = True
            if not reported_spray and len(users) >= SPRAY_MIN_USERS:
                findings.append({"ts": t.isoformat(), "computer": "", "event_id": 4625, "type": "password_spray",
                                 "severity": "high", "technique": "T1110.003",
                                 "description": f"{ip}에서 10분 내 서로 다른 계정 {len(users)}개 로그인 실패"})
                reported_spray = True
        if ioc.is_public_ip(ip):
            ioc_text.append(ip)

    findings.sort(key=lambda f: f["ts"])
    return {
        "file": Path(path).name,
        "events": len(events),
        "start": events[0]["ts"] if events else None,
        "end": events[-1]["ts"] if events else None,
        "computers": sorted({e.get("computer", "") for e in events if e.get("computer")}),
        "event_counts": dict(Counter(e["event_id"] for e in events).most_common(30)),
        "logons": [{"user": u, "ip": ip, "type": t, "count": n} for (u, ip, t), n in logons.most_common(50)],
        "failed_logons": {ip: len(v) for ip, v in failed.items()},
        "findings": findings,
        "iocs": ioc.extract("\n".join(ioc_text)),
        "attack_techniques": sorted({f["technique"] for f in findings}),
    }
