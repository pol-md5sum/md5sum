"""명령행 인터페이스: python -m irsys <명령> ..."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

from . import attribution, cases, emailx, evidence, ioc, legal, osint, report, static, timeline
from .db import connect, save_analysis


def _actor(args) -> str:
    return args.actor or os.environ.get("IRSYS_ACTOR") or getpass.getuser()


def _print(obj) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2, default=str))


def _row(r) -> dict:
    return dict(r) if r is not None else {}


def _evidence_path(conn, args, purpose: str) -> tuple[Path, str, str]:
    """증거 번호면 해시 재검증 후 보관 사본을, 아니면 증거로 먼저 등록한 뒤 그 사본을 쓴다."""
    target = args.target
    if Path(target).is_file():
        ev = evidence.acquire(conn, args.case, Path(target), _actor(args), source="분석 요청 시 자동 등록")
        target = ev["id"]
    path = evidence.open_for_analysis(conn, target, _actor(args), purpose)
    return path, target, evidence.get(conn, target)["original_name"]


def cmd_case(args, conn) -> None:
    if args.action == "new":
        cid = cases.create(conn, args.title, args.category, args.asset, args.threat, _actor(args),
                           aware_at=args.aware_at, summary=args.summary or "")
        c = cases.get(conn, cid)
        print(f"{cid} 생성 · 심각도 {c['severity']}")
        for d in legal.deadlines(c["category"], c["aware_at"]):
            print(f"  신고 기한 {d['due_at']} ({d['action']}, 남은 {d['remaining_hours']}시간)")
    elif args.action == "list":
        for c in cases.list_all(conn):
            print(f"{c['id']}  [{cases.STATUS_KO[c['status']]}] {c['severity']:8} {c['title']}")
    elif args.action == "show":
        c = cases.get(conn, args.case)
        _print({"case": _row(c), "deadlines": legal.deadlines(c["category"], c["aware_at"]),
                "events": [_row(e) for e in cases.events(conn, args.case)]})
    elif args.action == "status":
        cases.set_status(conn, args.case, args.status, _actor(args), args.note or "")
        print(f"{args.case} → {cases.STATUS_KO[args.status]}")
    elif args.action == "category":
        cases.recategorize(conn, args.case, args.category, _actor(args))
        print(f"{args.case} 유형 변경 → {cases.CATEGORIES[args.category]}")


def cmd_evidence(args, conn) -> None:
    if args.action == "add":
        _print(evidence.acquire(conn, args.case, Path(args.file), _actor(args), args.source or "", args.notes or ""))
    elif args.action == "list":
        for e in evidence.list_for_case(conn, args.case):
            print(f"{e['id']}  {e['sha256']}  {e['original_name']}")
    elif args.action == "verify":
        res = evidence.verify(conn, args.evidence, _actor(args))
        _print({"hash": res, "custody_chain": evidence.verify_chain(conn, args.evidence)})
        if not res["ok"]:
            sys.exit(2)
    elif args.action == "custody":
        _print({"chain": evidence.verify_chain(conn, args.evidence),
                "entries": [_row(r) for r in evidence.history(conn, args.evidence)]})
    elif args.action == "export":
        print(evidence.export(conn, args.evidence, Path(args.dest), _actor(args), args.reason))


def cmd_email(args, conn) -> None:
    path, ev_id, _ = _evidence_path(conn, args, "이메일 분석")
    result = emailx.analyze(path)
    result["file"] = evidence.get(conn, ev_id)["original_name"]
    save_analysis(conn, args.case, "email", ev_id, result)
    added = ioc.store(conn, args.case, result["iocs"], f"email:{ev_id}")
    cases.log(conn, args.case, _actor(args), "analysis", f"이메일 분석 {ev_id} · IOC {added}건 추가")
    _print(result)


def cmd_static(args, conn) -> None:
    path, ev_id, name = _evidence_path(conn, args, "정적 분석")
    result = static.analyze(path, display_name=name, yara_rules=args.yara)
    save_analysis(conn, args.case, "static", ev_id, result)
    iocs = {**result["iocs"]}
    iocs.setdefault("sha256", []).append(result["sha256"])
    added = ioc.store(conn, args.case, iocs, f"static:{ev_id}")
    cases.log(conn, args.case, _actor(args), "analysis", f"정적 분석 {ev_id} · 위험도 {result['risk']} · IOC {added}건 추가")
    _print(result)


def cmd_ioc(args, conn) -> None:
    if args.action == "extract":
        text = Path(args.file).read_text(encoding="utf-8", errors="replace") if args.file else args.text
        found = ioc.extract(text or "", include_private=args.include_private)
        added = ioc.store(conn, args.case, found, args.source or "manual")
        _print({"added": added, "iocs": found})
    elif args.action == "list":
        for r in ioc.list_for_case(conn, args.case):
            print(f"{r['type']:7} {ioc.defang(r['value']):60} {r['verdict'] or '-':13} {r['score'] if r['score'] is not None else '-'}")
    elif args.action == "enrich":
        services = osint.build_services(args.services.split(","))
        disabled = [s.name for s in services if not s.enabled]
        if disabled:
            print(f"API 키가 없어 건너뜀: {', '.join(disabled)} (환경 변수 {', '.join(s.key_env for s in services if not s.enabled)})",
                  file=sys.stderr)
        types = set(args.types.split(",")) if args.types else None
        res = osint.enrich_case(conn, args.case, services, types=types, use_cache=not args.no_cache)
        cases.log(conn, args.case, _actor(args), "osint", f"{len(res)}건 조회")
        _print(res)


def cmd_timeline(args, conn) -> None:
    if args.action == "import":
        print(f"{timeline.import_file(conn, args.case, Path(args.file), args.label or '')}건 가져옴")
    elif args.action == "build":
        print(f"내부 기록 {timeline.build_internal(conn, args.case)}건 반영")
    elif args.action == "show":
        for t in timeline.get(conn, args.case):
            print(f"{t['ts']}  {t['source']:10} {t['host'] or '-':15} {t['event']}")


def cmd_apt(args, conn) -> None:
    observed = attribution.collect_observed(
        conn, args.case,
        extra_techniques=args.technique or [],
        extra_labels=args.label or [],
        extra_text=args.text or "",
    )
    groups = attribution.score(observed)
    save_analysis(conn, args.case, "attribution", "case", {"observed": observed, "groups": groups})
    cases.log(conn, args.case, _actor(args), "attribution", f"최고 {groups[0]['group']} {groups[0]['score']} ({groups[0]['grade']})")
    _print(groups)


def cmd_legal(args, conn) -> None:
    if args.action == "deadlines":
        c = cases.get(conn, args.case)
        _print(legal.deadlines(c["category"], c["aware_at"]))
    elif args.action == "mask":
        text, counts = legal.mask_pii(Path(args.file).read_text(encoding="utf-8", errors="replace"))
        sys.stdout.write(text)
        print(f"\n[마스킹] {counts}", file=sys.stderr)


def cmd_report(args, conn) -> None:
    text = report.build(conn, args.case)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        cases.log(conn, args.case, _actor(args), "report", f"보고서 생성 {args.out}")
        print(args.out)
    else:
        sys.stdout.write(text)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="irsys", description="침해사고 대응·분석 종합시스템")
    p.add_argument("--actor", help="작업자 이름(기본: IRSYS_ACTOR 또는 OS 사용자)")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("case", help="M1 사건 관리").add_subparsers(dest="action", required=True)
    n = c.add_parser("new")
    n.add_argument("--title", required=True)
    n.add_argument("--category", required=True, choices=list(cases.CATEGORIES))
    n.add_argument("--asset", type=int, required=True, help="자산 중요도 1~5")
    n.add_argument("--threat", type=int, required=True, help="위협도 1~5")
    n.add_argument("--aware-at", help="인지 시각 ISO 8601 (기본: 지금)")
    n.add_argument("--summary")
    c.add_parser("list")
    s = c.add_parser("show"); s.add_argument("case")
    s = c.add_parser("status"); s.add_argument("case"); s.add_argument("status", choices=cases.STATUSES); s.add_argument("--note")
    s = c.add_parser("category"); s.add_argument("case"); s.add_argument("category", choices=list(cases.CATEGORIES))

    e = sub.add_parser("evidence", help="M2 증거 수집·보존").add_subparsers(dest="action", required=True)
    a = e.add_parser("add"); a.add_argument("case"); a.add_argument("file"); a.add_argument("--source"); a.add_argument("--notes")
    a = e.add_parser("list"); a.add_argument("case")
    a = e.add_parser("verify"); a.add_argument("evidence")
    a = e.add_parser("custody"); a.add_argument("evidence")
    a = e.add_parser("export"); a.add_argument("evidence"); a.add_argument("dest"); a.add_argument("--reason", required=True)

    m = sub.add_parser("email", help="M7 이메일 분석 (.eml)")
    m.add_argument("case"); m.add_argument("target", help="증거 번호 또는 .eml 파일 경로")

    st = sub.add_parser("static", help="M5 정적 분석")
    st.add_argument("case"); st.add_argument("target", help="증거 번호 또는 파일 경로"); st.add_argument("--yara", help="YARA 규칙 파일")

    i = sub.add_parser("ioc", help="M8 IOC").add_subparsers(dest="action", required=True)
    x = i.add_parser("extract"); x.add_argument("case"); x.add_argument("--file"); x.add_argument("--text")
    x.add_argument("--source"); x.add_argument("--include-private", action="store_true")
    x = i.add_parser("list"); x.add_argument("case")
    x = i.add_parser("enrich"); x.add_argument("case"); x.add_argument("--services", default="vt,criminalip,shodan")
    x.add_argument("--types", help="예: sha256,ipv4"); x.add_argument("--no-cache", action="store_true")

    t = sub.add_parser("timeline", help="M3 타임라인").add_subparsers(dest="action", required=True)
    x = t.add_parser("import"); x.add_argument("case"); x.add_argument("file"); x.add_argument("--label")
    x = t.add_parser("build"); x.add_argument("case")
    x = t.add_parser("show"); x.add_argument("case")

    ap = sub.add_parser("apt", help="M9 APT 연계 분석")
    ap.add_argument("case"); ap.add_argument("--technique", action="append", help="추가 ATT&CK 기법 ID")
    ap.add_argument("--label", action="append", help="추가 악성코드 계열명"); ap.add_argument("--text", help="추가 미끼 문구")

    lg = sub.add_parser("legal", help="법적 요건").add_subparsers(dest="action", required=True)
    x = lg.add_parser("deadlines"); x.add_argument("case")
    x = lg.add_parser("mask"); x.add_argument("file")

    r = sub.add_parser("report", help="M12 보고서")
    r.add_argument("case"); r.add_argument("--out")
    return p


HANDLERS = {"case": cmd_case, "evidence": cmd_evidence, "email": cmd_email, "static": cmd_static, "ioc": cmd_ioc,
            "timeline": cmd_timeline, "apt": cmd_apt, "legal": cmd_legal, "report": cmd_report}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    conn = connect()
    try:
        HANDLERS[args.command](args, conn)
    except (KeyError, ValueError, FileNotFoundError, RuntimeError) as e:
        print(f"오류: {e}", file=sys.stderr)
        return 1
    finally:
        conn.close()
    return 0
