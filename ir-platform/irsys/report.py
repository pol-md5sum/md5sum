"""M12 보고서 생성: 사건 데이터에서 Markdown 분석 보고서를 만든다.

- 모든 문장은 저장된 분석 결과에서 만들며, 근거가 없는 항목은 "확인되지 않음"으로 쓴다.
- IOC는 무력화(defang) 표기하고, 개인정보는 마스킹한다(공격자 주소 등 IOC 이메일은 유지).
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from . import attribution, cases, evidence, ioc, legal, timeline
from .db import load_analyses

SEV_KO = {"critical": "긴급", "high": "높음", "medium": "중간", "low": "낮음"}
VERDICT_KO = {"malicious": "악성", "suspicious": "의심", "no-detection": "탐지 없음", "unknown": "미확인"}


def _cell(v) -> str:
    return str(v if v not in (None, "") else "-").replace("|", "\\|").replace("\n", " ")


def _table(headers: list[str], rows: list[list]) -> str:
    if not rows:
        return "_해당 없음_\n"
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    out += ["| " + " | ".join(_cell(c) for c in r) + " |" for r in rows]
    return "\n".join(out) + "\n"


def _addr(lst: list[dict]) -> str:
    return ", ".join(f"{a['name']} <{a['address']}>" if a.get("name") else a["address"] for a in lst) or "-"


def build(conn: sqlite3.Connection, case_id: str, now: datetime | None = None) -> str:
    c = cases.get(conn, case_id)
    now = now or datetime.now(timezone.utc)
    evs = evidence.list_for_case(conn, case_id)
    iocs = ioc.list_for_case(conn, case_id)
    emails = load_analyses(conn, case_id, "email")
    statics = load_analyses(conn, case_id, "static")
    attr_runs = load_analyses(conn, case_id, "attribution")
    tl = timeline.get(conn, case_id)
    dls = legal.deadlines(c["category"], c["aware_at"], now)

    L: list[str] = []
    L.append(f"# 침해사고 분석 보고서 — {c['id']}\n")
    L.append(f"작성 시각: {now.replace(microsecond=0).isoformat()} (UTC) · 시스템: irsys\n")

    # 1. 사건 개요
    L.append("## 1. 사건 개요\n")
    L.append(_table(["항목", "내용"], [
        ["사건 번호", c["id"]],
        ["제목", c["title"]],
        ["유형", cases.CATEGORIES[c["category"]]],
        ["심각도", f"{SEV_KO[c['severity']]} (자산 중요도 {c['asset_criticality']} × 위협도 {c['threat_level']})"],
        ["진행 단계", cases.STATUS_KO[c["status"]]],
        ["인지 시각(UTC)", c["aware_at"]],
        ["담당", c["owner"]],
    ]))

    # 2. 법정 신고 기한
    L.append("## 2. 법정 신고 기한\n")
    if dls:
        L.append(_table(["조치", "기한(UTC)", "남은 시간", "근거", "조문 확인"], [
            [d["action"], d["due_at"], "기한 경과" if d["overdue"] else f"{d['remaining_hours']}시간",
             d["basis"], "확인됨" if d["verified"] else "최신 조문 재확인 필요"] for d in dls]))
    else:
        L.append("이 사건 유형에 설정된 법정 신고 기한 규칙이 없습니다.\n")

    # 3. 증거 목록과 무결성
    L.append("## 3. 증거 목록과 무결성\n")
    rows = []
    for e in evs:
        chain = evidence.verify_chain(conn, e["id"])
        rows.append([e["id"], e["original_name"], e["size"], e["md5"], e["sha256"], e["acquired_at"],
                     e["acquired_by"], "정상" if chain["ok"] else f"이상(항목 {chain['broken_at']})"])
    L.append(_table(["증거 번호", "파일명", "크기(B)", "MD5", "SHA-256", "수집 시각(UTC)", "수집자", "취급 이력 체인"], rows))

    # 4. 이메일 분석
    keep_emails: set[str] = set()
    L.append("## 4. 이메일 분석\n")
    if not emails:
        L.append("분석한 이메일이 없습니다.\n")
    else:
        for a in emails:
            r = a["result"]
            keep_emails |= {x["address"] for x in r.get("from", [])}
            keep_emails |= {x["address"] for x in r.get("reply_to", [])}
            if r.get("return_path"):
                keep_emails.add(r["return_path"])
            L.append(f"### {a['target']} — {r.get('file')}\n")
            date = r.get("date") or {}
            L.append(_table(["항목", "내용"], [
                ["메일 제목", r.get("subject")],
                ["발신 일시", f"{date.get('kst', date.get('raw', '-'))} (KST) / {date.get('utc', '-')} (UTC)"],
                ["발신 계정", _addr(r.get("from", []))],
                ["수신 계정", _addr(r.get("to", []))],
                ["참조", _addr(r.get("cc", []))],
                ["회신 주소(Reply-To)", _addr(r.get("reply_to", []))],
                ["Return-Path", r.get("return_path")],
                ["최초 발신 IP", ioc.defang(r["origin_ip"]) if r.get("origin_ip") else "확인되지 않음"],
                ["경유지 공인 IP", ", ".join(ioc.defang(i) for i in r.get("relay_ips", [])) or "-"],
                ["SPF / DKIM / DMARC", " / ".join(r.get("auth", {}).get(k, "-") for k in ("spf", "dkim", "dmarc"))],
                ["메일 클라이언트", r.get("x_mailer")],
                ["첨부파일", f"{len(r.get('attachments', []))}개" if r.get("attachments") else "없음"],
            ]))
            L.append("**경유지(발신 측부터)**\n")
            L.append(_table(["순서", "from", "by", "IP", "시각(UTC)"], [
                [i + 1, h.get("from"), h.get("by"), ", ".join(h.get("ips", [])),
                 (h.get("date") or {}).get("utc")] for i, h in enumerate(r.get("received_hops", []))]))
            if r.get("attachments"):
                L.append("**첨부파일**\n")
                L.append(_table(["파일명", "형식", "크기(B)", "SHA-256", "위험 징후"], [
                    [x["filename"], x["content_type"], x["size"], x["sha256"], "; ".join(x["flags"]) or "-"]
                    for x in r["attachments"]]))
            if r.get("links"):
                L.append("**링크**\n")
                L.append(_table(["URL(무력화)", "표시 문구", "표시·실제 불일치"], [
                    [ioc.defang(l["url"]), l["text"][:60], "예" if l["text_mismatch"] else "아니오"]
                    for l in r["links"]]))
            if r.get("indicators"):
                L.append("**의심 징후**\n")
                L += [f"- {i}" for i in r["indicators"]]
                L.append("")

    # 5. 정적 분석
    L.append("## 5. 악성코드 정적 분석\n")
    if not statics:
        L.append("정적 분석을 수행한 파일이 없습니다.\n")
    else:
        L.append(_table(["대상", "파일", "형식", "SHA-256", "엔트로피", "위험도", "주요 소견"], [
            [a["target"], a["result"]["file"], a["result"]["type"], a["result"]["sha256"], a["result"]["entropy"],
             a["result"]["risk"], "; ".join(
                 [h["description"] for h in a["result"]["script_indicators"] + a["result"]["webshell_indicators"]]
                 + a["result"]["findings"])[:300] or "-"] for a in statics]))
        for a in statics:
            pe = a["result"].get("pe")
            if pe:
                L.append(f"- {a['target']} PE: {pe['machine']}, 컴파일 {pe['compile_time_kst']} (KST, 위조 가능), "
                         f"imphash {pe['imphash'] or '-'}, PDB {pe['pdb_path'] or '-'}")
        L.append("")

    # 6. IOC
    L.append("## 6. 침해지표(IOC)\n")
    L.append(_table(["유형", "값(무력화)", "판정", "점수", "조회 서비스", "출처"], [
        [r["type"], ioc.defang(r["value"]) if r["type"] in {"url", "domain", "ipv4", "email"} else r["value"],
         VERDICT_KO.get(r["verdict"] or "unknown", r["verdict"]), r["score"],
         ", ".join(json.loads(r["enrichment"]).keys()) if r["enrichment"] else "미조회", r["source"]]
        for r in iocs]))

    # 7. ATT&CK
    techniques = sorted({t for a in emails + statics for t in a["result"].get("attack_techniques", [])})
    L.append("## 7. MITRE ATT&CK 매핑\n")
    L.append((", ".join(f"[{t}](https://attack.mitre.org/techniques/{t.replace('.', '/')}/)" for t in techniques)
              or "매핑된 기법 없음") + "\n")

    # 8. APT 연계
    L.append("## 8. APT 연계 평가\n")
    if attr_runs:
        res = attr_runs[-1]["result"]["groups"]
        L.append(_table(["그룹", "점수", "신뢰도", *attribution.AXIS_KO.values()], [
            [f"[{g['group']}]({g['url']})", g["score"], g["grade"], *[g["axes"][k] for k in attribution.AXIS_KO]]
            for g in res]))
        top = res[0]
        for k, label in attribution.AXIS_KO.items():
            if top["evidence"][k]:
                L.append(f"- {top['group']} · {label}: {', '.join(map(str, top['evidence'][k]))[:300]}")
        L.append("\n귀속 점수는 공개 정보 기반 추정치이며 최종 판단은 분석관이 한다.\n")
    else:
        L.append("연계 분석을 실행하지 않았습니다.\n")

    # 9. 타임라인
    L.append("## 9. 타임라인(UTC)\n")
    L.append(_table(["시각", "출처", "호스트", "이벤트"], [[t["ts"], t["source"], t["host"], t["event"]] for t in tl[:200]]))

    # 10. 보고서용 문장, 3줄 요약
    malicious = [r for r in iocs if r["verdict"] == "malicious"]
    sentences = [f"{c['id']} 사건은 {c['aware_at'][:10]}에 인지된 {cases.CATEGORIES[c['category']]} 사건으로, "
                 f"심각도는 {SEV_KO[c['severity']]}으로 산정되었다."]
    if evs:
        broken = [e["id"] for e in evs if not evidence.verify_chain(conn, e["id"])["ok"]]
        sentences.append(f"증거 {len(evs)}건을 수집하여 MD5·SHA-256 해시로 고정하였으며, 증거 취급 이력 검증 결과 "
                         + ("이상이 없었다." if not broken else f"{', '.join(broken)}에서 이상이 확인되었다."))
    for a in emails:
        r = a["result"]
        sentences.append(
            f"메일 「{r.get('subject')}」은 {_addr(r.get('from', []))} 계정에서 "
            f"{(r.get('date') or {}).get('kst', '확인되지 않은 시각')}(KST)에 발송되었고, 최초 발신 IP는 "
            f"{ioc.defang(r['origin_ip']) if r.get('origin_ip') else '확인되지 않았'}"
            f"{'이다' if r.get('origin_ip') else '다'}. 첨부파일 {len(r.get('attachments', []))}개, "
            f"링크 {len(r.get('links', []))}개가 포함되어 있다.")
    if iocs:
        sentences.append(f"추출된 IOC {len(iocs)}건 중 OSINT 조회에서 악성으로 판정된 항목은 {len(malicious)}건이다.")
    if techniques:
        sentences.append(f"확인된 공격 기법은 MITRE ATT&CK 기준 {', '.join(techniques[:8])} 등 {len(techniques)}개이다.")
    if attr_runs:
        top = attr_runs[-1]["result"]["groups"][0]
        sentences.append(f"APT 연계 평가 결과, {top['statement']}(점수 {top['score']})으로 판단된다.")
    L.append("## 10. 보고서용 문장\n")
    L.append("> " + " ".join(sentences) + "\n")

    L.append("## 3줄 요약\n")
    summary = [
        f"{cases.CATEGORIES[c['category']]} 사건, 심각도 {SEV_KO[c['severity']]}, 증거 {len(evs)}건 무결성 고정",
        f"IOC {len(iocs)}건 추출, 악성 판정 {len(malicious)}건, ATT&CK 기법 {len(techniques)}개",
        (f"APT 연계: {attr_runs[-1]['result']['groups'][0]['statement']}" if attr_runs else "APT 연계 분석 미실행")
        + (f" · 신고 기한 {dls[0]['due_at']}" if dls else ""),
    ]
    L += [f"- {s}" for s in summary]
    L.append("\n## 출처\n")
    L.append("- MITRE ATT&CK: https://attack.mitre.org/")
    L.append("- OSINT: VirusTotal, Criminal IP, Shodan (각 IOC의 조회 결과 링크는 시스템 DB에 저장)")
    L.append("- 신고 기한 근거: irsys/data/legal_rules.json에 기재된 조문 (국가법령정보센터 https://www.law.go.kr)")

    text, _ = legal.mask_pii("\n".join(L) + "\n", keep_emails=keep_emails)
    return text
