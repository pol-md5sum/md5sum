"""M5 악성코드 정적 분석.

샘플은 실행하지 않고 바이트만 읽는다. 외부 라이브러리 없이 동작하며,
yara-python이 설치되어 있고 규칙 경로를 주면 YARA 매칭을 추가로 수행한다.
"""

from __future__ import annotations

import base64
import hashlib
import math
import re
import struct
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import ioc

KST = timezone(timedelta(hours=9), "KST")

MAGIC = [
    (b"MZ", "PE(Windows 실행파일)"),
    (b"\x7fELF", "ELF(리눅스 실행파일)"),
    (b"%PDF", "PDF"),
    (bytes.fromhex("D0CF11E0A1B11AE1"), "OLE 복합문서(구형 Office·HWP)"),
    (b"PK\x03\x04", "ZIP 계열(OOXML·JAR·APK 포함)"),
    (bytes.fromhex("4C0000000114020000000000C000000000000046"), "Windows 바로가기(LNK)"),
    (b"Rar!", "RAR"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip"),
    (b"{\\rtf", "RTF"),
    (b"MSCF", "CAB"),
]

SUSPICIOUS_IMPORTS = {
    "VirtualAlloc": "T1055", "VirtualAllocEx": "T1055", "WriteProcessMemory": "T1055",
    "CreateRemoteThread": "T1055", "NtUnmapViewOfSection": "T1055.012", "QueueUserAPC": "T1055.004",
    "SetWindowsHookExA": "T1056.001", "SetWindowsHookExW": "T1056.001", "GetAsyncKeyState": "T1056.001",
    "URLDownloadToFileA": "T1105", "URLDownloadToFileW": "T1105", "InternetOpenUrlA": "T1071.001",
    "InternetOpenUrlW": "T1071.001", "HttpSendRequestA": "T1071.001", "HttpSendRequestW": "T1071.001",
    "WinHttpSendRequest": "T1071.001", "CryptEncrypt": "T1486", "IsDebuggerPresent": "T1622",
    "CheckRemoteDebuggerPresent": "T1622", "RegSetValueExA": "T1112", "RegSetValueExW": "T1112",
    "CreateServiceA": "T1543.003", "CreateServiceW": "T1543.003", "AdjustTokenPrivileges": "T1134",
    "ShellExecuteA": "T1106", "ShellExecuteW": "T1106", "WinExec": "T1106",
}

# (이름, 정규식, ATT&CK, 설명)
SCRIPT_RULES = [
    ("powershell_encoded", r"(?i)powershell[^\n]{0,80}\s-(?:e|en|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", "T1059.001", "PowerShell 인코딩 명령"),
    ("powershell_download", r"(?i)(DownloadString|DownloadFile|Invoke-WebRequest|iwr |Net\.WebClient|Start-BitsTransfer)", "T1105", "원격 파일 다운로드"),
    ("powershell_iex", r"(?i)\b(IEX|Invoke-Expression)\b", "T1059.001", "동적 코드 실행(IEX)"),
    ("base64_decode", r"(?i)(FromBase64String|base64_decode|atob\(|certutil[^\n]{0,40}-decode)", "T1140", "Base64 디코딩"),
    ("wscript_shell", r"(?i)(WScript\.Shell|Shell\.Application|ActiveXObject)", "T1059.005", "Windows 스크립트 호스트 실행"),
    ("mshta", r"(?i)\bmshta(\.exe)?\b", "T1218.005", "mshta 프록시 실행"),
    ("regsvr32", r"(?i)regsvr32[^\n]{0,60}/i:\s*https?://", "T1218.010", "regsvr32 원격 스크립틀릿"),
    ("rundll32", r"(?i)\brundll32(\.exe)?\b", "T1218.011", "rundll32 프록시 실행"),
    ("schtasks", r"(?i)schtasks[^\n]{0,40}/create", "T1053.005", "예약 작업 등록"),
    ("run_key", r"(?i)\\CurrentVersion\\Run(Once)?\b", "T1547.001", "Run 키 지속성"),
    ("hidden_window", r"(?i)(-w(indowstyle)?\s+hidden|-nop\b|-noni\b|bypass)", "T1564.003", "숨김 창·정책 우회"),
    ("amsi_bypass", r"(?i)(amsiInitFailed|AmsiScanBuffer|amsiutils)", "T1562.001", "AMSI 우회 시도"),
    ("char_obfuscation", r"(?i)(chr\(\d+\)\s*[&+]\s*){8,}|(\[char\]\d+\s*\+\s*){8,}", "T1027", "문자 코드 난독화"),
    ("vba_autoexec", r"(?i)\b(AutoOpen|Document_Open|Workbook_Open|Auto_Open)\b", "T1137", "Office 매크로 자동 실행"),
    ("defender_tamper", r"(?i)(Set-MpPreference|Add-MpPreference\s+-ExclusionPath)", "T1562.001", "백신 설정 변조"),
    ("log_clear", r"(?i)(wevtutil[^\n]{0,20}\bcl\b|Clear-EventLog)", "T1070.001", "이벤트 로그 삭제"),
    ("shadow_delete", r"(?i)vssadmin[^\n]{0,20}delete\s+shadows", "T1490", "볼륨 섀도 복사본 삭제"),
]

WEBSHELL_RULES = [
    ("php_eval_input", r"(?i)(eval|assert|system|passthru|shell_exec|exec|popen)\s*\(\s*(base64_decode\s*\()?\s*\$_(POST|GET|REQUEST|COOKIE)", "PHP 요청값 실행"),
    ("php_preg_e", r"(?i)preg_replace\s*\(\s*['\"].*/e['\"]", "PHP preg_replace /e 실행"),
    ("php_obfuscated_eval", r"(?i)eval\s*\(\s*(gzinflate|gzuncompress|str_rot13|base64_decode)\s*\(", "PHP 난독화 eval"),
    ("jsp_runtime_exec", r"Runtime\.getRuntime\(\)\.exec\s*\(\s*request\.getParameter", "JSP 요청값 명령 실행"),
    ("asp_eval_request", r"(?i)(eval|execute)\s*\(?\s*request(\.form|\.querystring)?\s*\(", "ASP 요청값 실행"),
    ("aspx_process_start", r"(?i)Process\.Start\s*\([^)]*Request", "ASPX 요청값 프로세스 실행"),
    ("cmd_param", r"(?i)\$_(POST|GET|REQUEST)\[['\"](cmd|command|exec|c)['\"]\]", "명령 파라미터"),
]


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return round(-sum(c / n * math.log2(c / n) for c in counts.values()), 3)


def file_type(data: bytes, name: str = "") -> str:
    for magic, label in MAGIC:
        if data.startswith(magic):
            if label.startswith("ZIP") and b"word/" in data[:4096]:
                return "OOXML 문서(Word)"
            if label.startswith("ZIP") and b"xl/" in data[:4096]:
                return "OOXML 문서(Excel)"
            if label.startswith("OLE") and b"H\x00w\x00p\x00S\x00u\x00m\x00m\x00a\x00r\x00y" in data:
                return "HWP 문서(OLE)"
            return label
    ext = name.rsplit(".", 1)[-1].lower() if "." in name.replace(".evidence", "") else ""
    head = data[:4096].lower()
    if b"<?php" in head:
        return "PHP 스크립트"
    if b"<%@" in head or b"<%" in head:
        return "서버 스크립트(JSP/ASP)"
    if ext in {"ps1", "vbs", "js", "hta", "bat", "cmd", "py", "sh"}:
        return f"스크립트(.{ext})"
    try:
        data[:4096].decode("utf-8")
        return "텍스트"
    except UnicodeDecodeError:
        return "알 수 없는 바이너리"


def strings(data: bytes, min_len: int = 5, limit: int = 20000) -> list[str]:
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    wide_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
    out = [m.group(0).decode("ascii") for m in ascii_re.finditer(data)]
    out += [m.group(0).decode("utf-16le") for m in wide_re.finditer(data)]
    return out[:limit]


def hangul_strings(data: bytes, limit: int = 50) -> list[str]:
    """UTF-8·UTF-16LE·CP949로 기록된 한글 문자열을 찾는다(작성자 언어 흔적)."""
    found: list[str] = []
    for m in re.finditer(rb"(?:[\xea-\xed][\x80-\xbf]{2}|[\x20-\x7e]){4,}", data):
        s = m.group(0).decode("utf-8", "ignore")
        if re.search("[가-힣]{2,}", s):
            found.append(s.strip())
    for m in re.finditer(rb"(?:[\x00-\xff][\xac-\xd7]|[\x20-\x7e]\x00){4,}", data):
        s = m.group(0).decode("utf-16le", "ignore")
        if re.search("[가-힣]{2,}", s):
            found.append(s.strip())
    return list(dict.fromkeys(found))[:limit]


# ---------------------------------------------------------------- PE
class PEError(ValueError):
    pass


def parse_pe(data: bytes) -> dict:
    if data[:2] != b"MZ" or len(data) < 64:
        raise PEError("MZ 헤더 없음")
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off:pe_off + 4] != b"PE\x00\x00":
        raise PEError("PE 시그니처 없음")
    machine, nsec, timestamp, _, _, opt_size, characteristics = struct.unpack_from("<HHIIIHH", data, pe_off + 4)
    opt = pe_off + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    is64 = magic == 0x20B
    entry = struct.unpack_from("<I", data, opt + 16)[0]
    subsystem = struct.unpack_from("<H", data, opt + 68)[0]
    dd_off = opt + (112 if is64 else 96)
    n_dirs = struct.unpack_from("<I", data, dd_off - 4)[0]
    dirs = [struct.unpack_from("<II", data, dd_off + 8 * i) for i in range(min(n_dirs, 16))]

    sections = []
    sec_off = opt + opt_size
    for i in range(nsec):
        base = sec_off + 40 * i
        if base + 40 > len(data):
            break
        name = data[base:base + 8].rstrip(b"\x00").decode("latin-1")
        vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", data, base + 8)
        chars = struct.unpack_from("<I", data, base + 36)[0]
        raw = data[rptr:rptr + rsize]
        sections.append({
            "name": name, "virtual_address": vaddr, "virtual_size": vsize, "raw_size": rsize,
            "raw_pointer": rptr, "entropy": entropy(raw),
            "executable": bool(chars & 0x20000000), "writable": bool(chars & 0x80000000),
        })

    def rva_to_off(rva: int) -> int | None:
        for s in sections:
            size = max(s["virtual_size"], s["raw_size"])
            if s["virtual_address"] <= rva < s["virtual_address"] + size:
                return rva - s["virtual_address"] + s["raw_pointer"]
        return None

    def cstr(off: int | None, max_len: int = 256) -> str:
        if off is None or off >= len(data):
            return ""
        end = data.find(b"\x00", off, off + max_len)
        return data[off:end if end != -1 else off + max_len].decode("latin-1")

    imports: dict[str, list[str]] = {}
    if len(dirs) > 1 and dirs[1][0]:
        off = rva_to_off(dirs[1][0])
        while off is not None and off + 20 <= len(data) and len(imports) < 512:
            oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", data, off)
            if not (oft or name_rva or ft):
                break
            dll = cstr(rva_to_off(name_rva)).lower()
            funcs = []
            thunk = rva_to_off(oft or ft)
            step, flag = (8, 1 << 63) if is64 else (4, 1 << 31)
            while thunk is not None and thunk + step <= len(data) and len(funcs) < 4096:
                val = struct.unpack_from("<Q" if is64 else "<I", data, thunk)[0]
                if val == 0:
                    break
                if val & flag:
                    funcs.append(f"ord{val & 0xFFFF}")
                else:
                    funcs.append(cstr((rva_to_off(val & 0x7FFFFFFF) or 0) + 2))
                thunk += step
            imports[dll] = funcs
            off += 20

    compile_time = datetime.fromtimestamp(timestamp, timezone.utc) if timestamp else None
    pdb = None
    m = re.search(rb"[A-Za-z]:\\[^\x00\r\n]{3,200}\.pdb", data)
    if m:
        pdb = m.group(0).decode("latin-1")
    return {
        "machine": {0x14C: "x86", 0x8664: "x64", 0xAA64: "ARM64"}.get(machine, hex(machine)),
        "is_dll": bool(characteristics & 0x2000),
        "subsystem": {2: "GUI", 3: "콘솔"}.get(subsystem, str(subsystem)),
        "entry_point": hex(entry),
        "compile_time_utc": compile_time.isoformat() if compile_time else None,
        "compile_time_kst": compile_time.astimezone(KST).isoformat() if compile_time else None,
        "sections": sections,
        "imports": imports,
        "imphash": imphash(imports),
        "pdb_path": pdb,
        "overlay_size": max(0, len(data) - max((s["raw_pointer"] + s["raw_size"] for s in sections), default=0)),
    }


def imphash(imports: dict[str, list[str]]) -> str | None:
    """pefile과 같은 방식(소문자 dll명.함수명, 확장자 제거)으로 임포트 해시를 계산한다."""
    items = []
    for dll, funcs in imports.items():
        base = dll.rsplit(".", 1)[0] if dll.rsplit(".", 1)[-1] in {"dll", "ocx", "sys"} else dll
        items += [f"{base}.{f.lower()}" for f in funcs]
    return hashlib.md5(",".join(items).encode()).hexdigest() if items else None


# ---------------------------------------------------------------- 분석
def _decode_powershell(text: str) -> list[str]:
    out = []
    for m in re.finditer(r"(?i)\s-(?:e|en|enc|encodedcommand)\s+([A-Za-z0-9+/=]{20,})", text):
        try:
            out.append(base64.b64decode(m.group(1)).decode("utf-16le"))
        except (ValueError, UnicodeDecodeError):
            continue
    return out


def _match_rules(text: str) -> tuple[list[dict], list[dict]]:
    script = [{"rule": n, "technique": t, "description": d, "sample": m.group(0)[:120]}
              for n, p, t, d in SCRIPT_RULES if (m := re.search(p, text))]
    web = [{"rule": n, "technique": "T1505.003", "description": d, "sample": m.group(0)[:120]}
           for n, p, d in WEBSHELL_RULES if (m := re.search(p, text))]
    return script, web


def _yara(path: Path, rules_path: str | None) -> list[str] | None:
    if not rules_path:
        return None
    try:
        import yara  # type: ignore
    except ImportError:
        return None
    rules = yara.compile(filepath=rules_path)
    return [m.rule for m in rules.match(str(path))]


def analyze(path: Path, display_name: str | None = None, yara_rules: str | None = None) -> dict:
    data = Path(path).read_bytes()
    name = display_name or Path(path).name
    ftype = file_type(data, name)
    text = "\n".join(strings(data))
    if ftype in {"텍스트", "PHP 스크립트", "서버 스크립트(JSP/ASP)"} or ftype.startswith("스크립트"):
        text = data.decode("utf-8", "replace") + "\n" + text

    decoded = _decode_powershell(text)
    script_hits, web_hits = _match_rules(text + "\n" + "\n".join(decoded))

    result: dict = {
        "file": name,
        "size": len(data),
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "type": ftype,
        "entropy": entropy(data),
        "script_indicators": script_hits,
        "webshell_indicators": web_hits,
        "decoded_powershell": [d[:2000] for d in decoded],
        "hangul_strings": hangul_strings(data),
        "iocs": ioc.extract(text + "\n" + "\n".join(decoded)),
        "findings": [],
    }

    if data[:2] == b"MZ":
        try:
            pe = parse_pe(data)
            result["pe"] = pe
            flat = {f for funcs in pe["imports"].values() for f in funcs}
            result["suspicious_imports"] = {f: SUSPICIOUS_IMPORTS[f] for f in sorted(flat) if f in SUSPICIOUS_IMPORTS}
            for s in pe["sections"]:
                if s["entropy"] >= 7.2:
                    result["findings"].append(f"섹션 {s['name']} 엔트로피 {s['entropy']} (패킹·암호화 의심)")
                if s["executable"] and s["writable"]:
                    result["findings"].append(f"섹션 {s['name']} 쓰기·실행 동시 허용")
                if s["name"].upper().startswith("UPX"):
                    result["findings"].append("UPX 패커 섹션")
            if not pe["imports"]:
                result["findings"].append("임포트 테이블 없음(동적 로딩·패킹 의심)")
            if pe["overlay_size"] > 1024:
                result["findings"].append(f"오버레이 {pe['overlay_size']}바이트")
            if pe["pdb_path"]:
                result["findings"].append(f"PDB 경로: {pe['pdb_path']}")
        except (PEError, struct.error) as e:
            result["findings"].append(f"PE 파싱 실패: {e}")

    if result["hangul_strings"]:
        result["findings"].append(f"한글 문자열 {len(result['hangul_strings'])}건")
    if not data[:2] == b"MZ" and result["entropy"] >= 7.5 and len(data) > 4096:
        result["findings"].append(f"파일 전체 엔트로피 {result['entropy']} (암호화·압축 데이터)")

    yara_hits = _yara(Path(path), yara_rules)
    if yara_hits is not None:
        result["yara"] = yara_hits

    techniques = {h["technique"] for h in script_hits + web_hits}
    techniques |= set(result.get("suspicious_imports", {}).values())
    if any(s["entropy"] >= 7.2 for s in result.get("pe", {}).get("sections", [])):
        techniques.add("T1027.002")  # Software Packing
    if ftype == "Windows 바로가기(LNK)":
        techniques.add("T1204.002")
    result["attack_techniques"] = sorted(techniques)
    result["risk"] = _risk(result)
    return result


def _risk(r: dict) -> str:
    points = 2 * len(r["webshell_indicators"]) + len(r["script_indicators"]) + len(r.get("suspicious_imports", {}))
    points += sum(1 for f in r["findings"] if "엔트로피" in f or "쓰기·실행" in f or "UPX" in f)
    if r["webshell_indicators"] or points >= 6:
        return "높음"
    if points >= 3:
        return "중간"
    return "낮음"
