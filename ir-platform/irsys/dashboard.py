"""M12 대시보드: 모든 사건을 한 화면에 모은 단일 HTML 파일을 만든다.

외부 라이브러리·CDN을 쓰지 않으므로 인터넷이 차단된 분석망에서도 열린다.
개인정보는 내장 전에 마스킹하고, IOC는 무력화 표기로만 넣는다.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from importlib import resources

from . import attribution, cases, legal, response
from .db import load_analyses
from .report import FINDING_KO, SEV_KO

EMAIL_SEVERITY = "medium"


def load_attack() -> dict:
    text = resources.files("irsys.data").joinpath("attack_techniques.json").read_text(encoding="utf-8")
    return json.loads(text)


def _detections(case_id: str, analyses: list[dict]) -> list[dict]:
    out = []
    for a in analyses:
        r, kind, when = a["result"], a["kind"], a["created_at"]
        if kind in ("network", "eventlog", "memory"):
            for f in r.get("findings", []):
                out.append({"case": case_id, "source": kind, "ts": f.get("ts") or r.get("start"), "analyzed_at": when,
                            "severity": f.get("severity", "medium"), "type": f["type"],
                            "type_ko": FINDING_KO.get(f["type"], f["type"]), "technique": f.get("technique", ""),
                            "description": f["description"][:240]})
        elif kind == "email":
            date = (r.get("date") or {}).get("utc") or when
            for text in r.get("indicators", []):
                out.append({"case": case_id, "source": kind, "ts": date, "analyzed_at": when, "severity": EMAIL_SEVERITY,
                            "type": "email_indicator", "type_ko": "이메일 의심 징후", "technique": "T1566",
                            "description": f"{r.get('subject', '')[:60]} — {text}"[:240]})
        elif kind == "static":
            sev = {"높음": "high", "중간": "medium"}.get(r.get("risk"), "low")
            for h in r.get("script_indicators", []) + r.get("webshell_indicators", []):
                out.append({"case": case_id, "source": kind, "ts": None, "analyzed_at": when, "severity": sev,
                            "type": "webshell" if h["technique"] == "T1505.003" else "script_indicator",
                            "type_ko": "웹쉘" if h["technique"] == "T1505.003" else "악성 스크립트 징후",
                            "technique": h["technique"], "description": f"{r['file']} — {h['description']}"})
    return out


def collect(conn: sqlite3.Connection, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    attack = load_attack()
    out_cases, detections, technique_hits = [], [], []
    for c in cases.list_all(conn):
        analyses = load_analyses(conn, c["id"])
        dets = _detections(c["id"], analyses)
        detections += dets
        for a in analyses:
            for t in a["result"].get("attack_techniques", []):
                technique_hits.append({"case": c["id"], "technique": t, "source": a["kind"]})
        iocs = conn.execute("SELECT verdict FROM iocs WHERE case_id = ?", (c["id"],)).fetchall()
        attr = [a for a in analyses if a["kind"] == "attribution"]
        top = attr[-1]["result"]["groups"][0] if attr else None
        acts = response.list_actions(conn, c["id"])
        dls = legal.deadlines(c["category"], c["aware_at"], now) if c["status"] != "closed" else []
        out_cases.append({
            "id": c["id"], "title": c["title"], "category": cases.CATEGORIES[c["category"]],
            "severity": c["severity"], "severity_ko": SEV_KO[c["severity"]],
            "status": c["status"], "status_ko": cases.STATUS_KO[c["status"]], "aware_at": c["aware_at"],
            "deadlines": [{"action": d["action"], "due_at": d["due_at"], "remaining_hours": d["remaining_hours"],
                           "overdue": d["overdue"], "verified": d["verified"]} for d in dls],
            "detections": len(dets),
            "high": sum(1 for d in dets if d["severity"] in ("high", "critical")),
            "iocs": len(iocs),
            "malicious": sum(1 for i in iocs if i["verdict"] == "malicious"),
            "apt": {"group": top["group"], "grade": top["grade"], "score": top["score"],
                    "statement": attribution.phrase(top["group"], top["grade"])} if top else None,
            "pending_actions": sum(1 for a in acts if a["status"] == "pending"),
            "actions": len(acts),
        })
    return {
        "generated_at": now.replace(microsecond=0).isoformat(),
        "cases": out_cases,
        "detections": sorted(detections, key=lambda d: d["ts"] or "", reverse=True),
        "technique_hits": technique_hits,
        "tactics": attack["tactics"],
        "techniques": attack["techniques"],
    }


def render(data: dict) -> str:
    payload = json.dumps(data, ensure_ascii=False)
    payload, _ = legal.mask_pii(payload)
    # <script 내부에서 태그로 해석될 수 있는 문자를 모두 이스케이프한다(JSON 의미는 같음).
    payload = payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return TEMPLATE.replace("__DATA__", payload)


def build(conn: sqlite3.Connection, now: datetime | None = None) -> str:
    return render(collect(conn, now))


TEMPLATE = r"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>침해사고 대시보드</title>
<style>
:root {
  color-scheme: light;
  --page: #f9f9f7; --surface: #fcfcfb; --ink: #0b0b0b; --ink-2: #52514e; --muted: #898781;
  --grid: #e1e0d9; --axis: #c3c2b7; --ring: rgba(11,11,11,0.10);
  --series-1: #2a78d6;
  --heat-1: #86b6ef; --heat-2: #5598e7; --heat-3: #256abf; --heat-4: #104281;
  --heat-ink-1: #0b0b0b; --heat-ink-2: #0b0b0b; --heat-ink-3: #ffffff; --heat-ink-4: #ffffff;
  --good: #0ca30c; --warning: #fab219; --serious: #ec835a; --critical: #d03b3b; --good-ink: #006300;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    color-scheme: dark;
    --page: #0d0d0d; --surface: #1a1a19; --ink: #ffffff; --ink-2: #c3c2b7; --muted: #898781;
    --grid: #2c2c2a; --axis: #383835; --ring: rgba(255,255,255,0.10);
    --series-1: #3987e5;
    --heat-1: #184f95; --heat-2: #256abf; --heat-3: #3987e5; --heat-4: #86b6ef;
    --heat-ink-1: #ffffff; --heat-ink-2: #ffffff; --heat-ink-3: #0b0b0b; --heat-ink-4: #0b0b0b;
    --good-ink: #0ca30c;
  }
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --page: #0d0d0d; --surface: #1a1a19; --ink: #ffffff; --ink-2: #c3c2b7; --muted: #898781;
  --grid: #2c2c2a; --axis: #383835; --ring: rgba(255,255,255,0.10);
  --series-1: #3987e5;
  --heat-1: #184f95; --heat-2: #256abf; --heat-3: #3987e5; --heat-4: #86b6ef;
  --heat-ink-1: #ffffff; --heat-ink-2: #ffffff; --heat-ink-3: #0b0b0b; --heat-ink-4: #0b0b0b;
  --good-ink: #0ca30c;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--page); color: var(--ink);
  font: 14px/1.5 system-ui, -apple-system, "Segoe UI", "Apple SD Gothic Neo", "Malgun Gothic", sans-serif; }
header { display: flex; flex-wrap: wrap; align-items: center; gap: 12px; padding: 16px; max-width: 1280px; margin: 0 auto; }
header h1 { font-size: 20px; margin: 0; flex: 1 1 auto; }
header .meta { color: var(--muted); font-size: 12px; }
select, button { font: inherit; color: var(--ink); background: var(--surface); border: 1px solid var(--axis);
  border-radius: 6px; padding: 6px 10px; }
main { max-width: 1280px; margin: 0 auto; padding: 0 16px 32px; display: grid; gap: 16px;
  grid-template-columns: repeat(12, minmax(0, 1fr)); }
.card { background: var(--surface); border-radius: 10px; box-shadow: 0 0 0 1px var(--ring); padding: 16px; min-width: 0; }
.card h2 { font-size: 15px; margin: 0 0 4px; }
.card .sub { color: var(--ink-2); font-size: 12px; margin: 0 0 12px; }
.span-12 { grid-column: span 12; } .span-8 { grid-column: span 8; } .span-6 { grid-column: span 6; }
.span-4 { grid-column: span 4; } .span-3 { grid-column: span 3; }
@media (max-width: 900px) { .span-8, .span-6, .span-4 { grid-column: span 12; } .span-3 { grid-column: span 6; } }
.tile .label { color: var(--ink-2); font-size: 13px; }
.tile .value { font-size: 32px; font-weight: 600; line-height: 1.2; margin-top: 4px; }
.tile .note { color: var(--muted); font-size: 12px; margin-top: 4px; }
.status { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 600; white-space: nowrap; }
.status .dot { width: 10px; height: 10px; border-radius: 50%; flex: none; }
.status.critical .dot { background: var(--critical); } .status.serious .dot { background: var(--serious); }
.status.warning .dot { background: var(--warning); } .status.good .dot { background: var(--good); }
.status.neutral .dot { background: var(--axis); }
.bar-row { display: grid; grid-template-columns: minmax(96px, 200px) 1fr; gap: 8px; align-items: center; min-height: 28px; }
.bar-row .blabel { color: var(--ink-2); font-size: 12px; text-align: right; line-height: 1.3; }
.bar-row .track { display: flex; align-items: center; gap: 6px; min-width: 0; }
.bar-row .bar { height: 14px; background: var(--series-1); border-radius: 0 4px 4px 0; flex: none; }
.bar-row .bval { font-size: 12px; font-variant-numeric: tabular-nums; }
.bar-row:hover .bar, .bar-row:focus .bar { opacity: .85; }
.heat { display: grid; gap: 8px; }
.heat .tactic { display: grid; grid-template-columns: 112px 1fr; gap: 8px; align-items: start; }
.heat .tname { color: var(--ink-2); font-size: 12px; padding-top: 4px; }
.heat .cells { display: flex; flex-wrap: wrap; gap: 4px; }
.heat .cell { border-radius: 4px; padding: 3px 8px; font-size: 12px; font-variant-numeric: tabular-nums; cursor: default; }
.heat .empty { color: var(--muted); font-size: 12px; padding-top: 4px; }
.legend { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; color: var(--ink-2); font-size: 12px; margin-top: 12px; }
.legend .sw { width: 16px; height: 12px; border-radius: 3px; display: inline-block; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 13px; min-width: 560px; }
table.wide { min-width: 900px; }
th { text-align: left; color: var(--ink-2); font-weight: 600; border-bottom: 1px solid var(--axis); padding: 6px 8px; white-space: nowrap; }
td { border-bottom: 1px solid var(--grid); padding: 6px 8px; vertical-align: top; }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
tr.clickable { cursor: pointer; } tr.clickable:hover td { background: var(--page); }
.empty-state { color: var(--muted); padding: 12px 0; }
#tip { position: fixed; pointer-events: none; z-index: 10; background: var(--surface); color: var(--ink);
  box-shadow: 0 0 0 1px var(--ring), 0 4px 16px rgba(0,0,0,.18); border-radius: 8px; padding: 8px 10px;
  font-size: 12px; max-width: 320px; display: none; }
#tip b { display: block; margin-bottom: 2px; }
</style>
</head>
<body>
<header>
  <h1>침해사고 대시보드</h1>
  <label>사건 <select id="filter"><option value="">전체 사건</option></select></label>
  <button id="theme" type="button" aria-label="밝은·어두운 화면 전환">화면 전환</button>
  <div class="meta" id="meta"></div>
</header>
<main>
  <section class="card tile span-3"><div class="label">진행 중 사건</div><div class="value" id="k-open">-</div><div class="note" id="k-open-note"></div></section>
  <section class="card tile span-3"><div class="label">법정 신고 기한</div><div class="value" id="k-deadline">-</div><div class="note" id="k-deadline-note"></div></section>
  <section class="card tile span-3"><div class="label">높음 이상 탐지</div><div class="value" id="k-high">-</div><div class="note" id="k-high-note"></div></section>
  <section class="card tile span-3"><div class="label">승인 대기 차단 조치</div><div class="value" id="k-actions">-</div><div class="note" id="k-actions-note"></div></section>

  <section class="card span-6">
    <h2>탐지 유형별 건수</h2><p class="sub">네트워크·이벤트 로그·메모리·이메일·정적 분석 탐지 합계</p>
    <div class="bars" id="bars"></div>
  </section>
  <section class="card span-6">
    <h2>신고 기한</h2><p class="sub">종결되지 않은 사건의 법정 신고·통지 기한 (UTC)</p>
    <div class="table-wrap" id="deadlines"></div>
  </section>

  <section class="card span-12">
    <h2>MITRE ATT&amp;CK 관측 기법</h2><p class="sub">전술별로 관측된 기법과 관측 횟수(분석 결과 기준)</p>
    <div class="heat" id="heat"></div>
    <div class="legend" id="heat-legend"></div>
  </section>

  <section class="card span-12">
    <h2>사건 목록</h2><p class="sub">행을 누르면 해당 사건만 봅니다</p>
    <div class="table-wrap" id="cases"></div>
  </section>

  <section class="card span-12">
    <h2>높음 이상 탐지</h2><p class="sub">최신순 최대 100건</p>
    <div class="table-wrap" id="detections"></div>
  </section>
</main>
<div id="tip" role="tooltip"></div>
<script id="data" type="application/json">__DATA__</script>
<script>
(function () {
  "use strict";
  var DATA = JSON.parse(document.getElementById("data").textContent);
  var SEV = { critical: ["긴급", "critical"], high: ["높음", "serious"], medium: ["중간", "warning"], low: ["낮음", "good"] };
  var SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
  var SOURCE = { network: "네트워크", eventlog: "이벤트 로그", memory: "메모리", email: "이메일", static: "정적 분석" };
  var filterEl = document.getElementById("filter");
  var tip = document.getElementById("tip");

  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); }
  function el(id) { return document.getElementById(id); }
  function status(kind, label) { return '<span class="status ' + kind + '"><span class="dot" aria-hidden="true"></span>' + esc(label) + "</span>"; }
  function sev(s) { var v = SEV[s] || [s, "neutral"]; return status(v[1], v[0]); }
  function fmt(ts) { return ts ? String(ts).replace("T", " ").slice(0, 16) : "-"; }
  function hours(h) { return Math.abs(h) >= 48 ? Math.round(h / 24) + "일" : Math.round(h) + "시간"; }

  function showTip(evt, html) {
    tip.innerHTML = html; tip.style.display = "block";
    var x = evt.clientX + 14, y = evt.clientY + 14, w = tip.offsetWidth, h = tip.offsetHeight;
    if (x + w > window.innerWidth - 8) x = evt.clientX - w - 14;
    if (y + h > window.innerHeight - 8) y = evt.clientY - h - 14;
    tip.style.left = Math.max(8, x) + "px"; tip.style.top = Math.max(8, y) + "px";
  }
  function hideTip() { tip.style.display = "none"; }
  function bindTips(root) {
    root.querySelectorAll("[data-tip]").forEach(function (n) {
      n.addEventListener("mousemove", function (e) { showTip(e, n.getAttribute("data-tip")); });
      n.addEventListener("mouseleave", hideTip);
      n.addEventListener("focus", function () { var r = n.getBoundingClientRect(); showTip({ clientX: r.right, clientY: r.top }, n.getAttribute("data-tip")); });
      n.addEventListener("blur", hideTip);
    });
  }

  DATA.cases.forEach(function (c) {
    var o = document.createElement("option"); o.value = c.id; o.textContent = c.id + " " + c.title; filterEl.appendChild(o);
  });
  el("meta").textContent = "생성 " + fmt(DATA.generated_at) + " UTC · 사건 " + DATA.cases.length + "건";

  function render() {
    var sel = filterEl.value;
    var cs = DATA.cases.filter(function (c) { return !sel || c.id === sel; });
    var dets = DATA.detections.filter(function (d) { return !sel || d.case === sel; });
    var hits = DATA.technique_hits.filter(function (h) { return !sel || h.case === sel; });

    // KPI
    var open = cs.filter(function (c) { return c.status !== "closed"; });
    el("k-open").textContent = open.length;
    var crit = open.filter(function (c) { return c.severity === "critical"; }).length;
    el("k-open-note").textContent = "긴급 " + crit + "건 · 전체 " + cs.length + "건";
    var dls = [];
    cs.forEach(function (c) { c.deadlines.forEach(function (d) { dls.push(Object.assign({ case: c.id, title: c.title }, d)); }); });
    var overdue = dls.filter(function (d) { return d.overdue; }).length;
    var soon = dls.filter(function (d) { return !d.overdue && d.remaining_hours <= 24; }).length;
    el("k-deadline").textContent = dls.length;
    el("k-deadline-note").innerHTML = overdue ? status("critical", "기한 경과 " + overdue + "건") + " " + (soon ? status("warning", "24시간 이내 " + soon + "건") : "")
      : soon ? status("warning", "24시간 이내 " + soon + "건") : (dls.length ? status("good", "모두 여유 있음") : "해당 사건 없음");
    var high = dets.filter(function (d) { return d.severity === "high" || d.severity === "critical"; });
    el("k-high").textContent = high.length;
    el("k-high-note").textContent = "전체 탐지 " + dets.length + "건";
    var pending = cs.reduce(function (s, c) { return s + c.pending_actions; }, 0);
    var actions = cs.reduce(function (s, c) { return s + c.actions; }, 0);
    el("k-actions").textContent = pending;
    el("k-actions-note").textContent = "요청 " + actions + "건 중";

    // 탐지 유형 막대
    var counts = {};
    dets.forEach(function (d) {
      var k = d.type_ko; counts[k] = counts[k] || { n: 0, high: 0 }; counts[k].n++;
      if (d.severity === "high" || d.severity === "critical") counts[k].high++;
    });
    var rows = Object.keys(counts).map(function (k) { return [k, counts[k]]; }).sort(function (a, b) { return b[1].n - a[1].n; }).slice(0, 12);
    if (!rows.length) { el("bars").innerHTML = '<div class="empty-state">탐지 결과가 없습니다.</div>'; }
    else {
      var max = rows[0][1].n;
      el("bars").innerHTML = rows.map(function (r) {
        var t = "<b>" + esc(r[0]) + "</b>" + r[1].n + "건 (높음 이상 " + r[1].high + "건)";
        return '<div class="bar-row" tabindex="0" data-tip="' + esc(t) + '"><div class="blabel">' + esc(r[0]) + '</div>' +
          '<div class="track"><div class="bar" style="width:calc((100% - 40px) * ' + (r[1].n / max).toFixed(4) + ')"></div>' +
          '<span class="bval">' + r[1].n + "</span></div></div>";
      }).join("");
      bindTips(el("bars"));
    }

    // 신고 기한 표
    dls.sort(function (a, b) { return a.remaining_hours - b.remaining_hours; });
    el("deadlines").innerHTML = dls.length ? "<table><thead><tr><th>사건</th><th>조치</th><th>기한</th><th>상태</th></tr></thead><tbody>" +
      dls.map(function (d) {
        var st = d.overdue ? status("critical", "경과 " + hours(-d.remaining_hours)) : d.remaining_hours <= 24 ? status("warning", hours(d.remaining_hours) + " 남음") : status("good", hours(d.remaining_hours) + " 남음");
        return "<tr><td>" + esc(d.case) + "</td><td>" + esc(d.action) + (d.verified ? "" : ' <span style="color:var(--muted)">(조문 확인 필요)</span>') + "</td><td>" + fmt(d.due_at) + "</td><td>" + st + "</td></tr>";
      }).join("") + "</tbody></table>" : '<div class="empty-state">신고 기한 규칙이 적용되는 진행 중 사건이 없습니다.</div>';

    // ATT&CK 히트맵
    var tcount = {}, tcases = {};
    hits.forEach(function (h) {
      tcount[h.technique] = (tcount[h.technique] || 0) + 1;
      tcases[h.technique] = tcases[h.technique] || {}; tcases[h.technique][h.case] = 1;
    });
    var maxT = Math.max.apply(null, [1].concat(Object.keys(tcount).map(function (k) { return tcount[k]; })));
    var bins = [], prev = 0;
    [1, 2, 3, 4].forEach(function (s) {
      var hi = Math.ceil(s / 4 * maxT);
      if (hi > prev) { bins.push([s, prev + 1, hi]); prev = hi; }
    });
    function step(n) { for (var i = 0; i < bins.length; i++) if (n <= bins[i][2]) return bins[i][0]; return 4; }
    var byTactic = {};
    Object.keys(tcount).forEach(function (t) {
      var info = DATA.techniques[t] || DATA.techniques[t.split(".")[0]] || [t, "unknown"];
      (byTactic[info[1]] = byTactic[info[1]] || []).push([t, info[0], tcount[t]]);
    });
    var tactics = DATA.tactics.concat([["unknown", "미분류"]]);
    var heat = tactics.filter(function (tc) { return byTactic[tc[0]]; }).map(function (tc) {
      var cells = byTactic[tc[0]].sort(function (a, b) { return b[2] - a[2]; }).map(function (x) {
        var s = step(x[2]);
        var t = "<b>" + esc(x[0]) + " " + esc(x[1]) + "</b>" + esc(tc[1]) + " · 관측 " + x[2] + "회 · 사건 " + Object.keys(tcases[x[0]]).length + "건";
        return '<span class="cell" tabindex="0" data-tip="' + esc(t) + '" style="background:var(--heat-' + s + ');color:var(--heat-ink-' + s + ')">' + esc(x[0]) + " · " + x[2] + "</span>";
      }).join("");
      return '<div class="tactic"><div class="tname">' + esc(tc[1]) + '</div><div class="cells">' + cells + "</div></div>";
    }).join("");
    el("heat").innerHTML = heat || '<div class="empty-state">관측된 기법이 없습니다.</div>';
    el("heat-legend").innerHTML = heat ? "관측 횟수 " + bins.map(function (b) {
      return '<span class="sw" style="background:var(--heat-' + b[0] + ')"></span>' + (b[1] === b[2] ? b[1] : b[1] + "–" + b[2]);
    }).join(" ") : "";
    bindTips(el("heat"));

    // 사건 표
    el("cases").innerHTML = cs.length ? "<table class=\"wide\"><thead><tr><th>사건</th><th>제목</th><th>유형</th><th>심각도</th><th>단계</th><th>탐지(높음↑)</th><th>IOC(악성)</th><th>APT 연계</th><th>차단 대기</th></tr></thead><tbody>" +
      cs.map(function (c) {
        var apt = c.apt ? esc(c.apt.group) + " · " + esc(c.apt.grade) + " (" + c.apt.score + ")" : "-";
        return '<tr class="clickable" data-case="' + esc(c.id) + '"><td>' + esc(c.id) + "</td><td>" + esc(c.title) + "</td><td>" + esc(c.category) + "</td><td>" + sev(c.severity) +
          "</td><td>" + esc(c.status_ko) + '</td><td class="num">' + c.detections + " (" + c.high + ')</td><td class="num">' + c.iocs + " (" + c.malicious + ")</td><td>" + apt +
          '</td><td class="num">' + c.pending_actions + "</td></tr>";
      }).join("") + "</tbody></table>" : '<div class="empty-state">사건이 없습니다.</div>';
    el("cases").querySelectorAll("tr.clickable").forEach(function (tr) {
      tr.addEventListener("click", function () { filterEl.value = sel === tr.dataset.case ? "" : tr.dataset.case; render(); });
    });

    // 고위험 탐지 표
    var top = high.slice().sort(function (a, b) { return (SEV_ORDER[a.severity] - SEV_ORDER[b.severity]) || ((a.ts || "") < (b.ts || "") ? 1 : -1); }).slice(0, 100);
    el("detections").innerHTML = top.length ? "<table class=\"wide\"><thead><tr><th>시각(UTC)</th><th>사건</th><th>출처</th><th>위험도</th><th>유형</th><th>ATT&amp;CK</th><th>내용</th></tr></thead><tbody>" +
      top.map(function (d) {
        var when = d.ts ? fmt(d.ts) : '<span style="color:var(--muted)" title="발생 시각 정보 없음">분석 ' + fmt(d.analyzed_at) + "</span>";
        return "<tr><td>" + when + "</td><td>" + esc(d.case) + "</td><td>" + esc(SOURCE[d.source] || d.source) + "</td><td>" + sev(d.severity) + "</td><td>" + esc(d.type_ko) +
          "</td><td>" + esc(d.technique) + "</td><td>" + esc(d.description) + "</td></tr>";
      }).join("") + "</tbody></table>" : '<div class="empty-state">높음 이상 탐지가 없습니다.</div>';
  }

  filterEl.addEventListener("change", render);
  el("theme").addEventListener("click", function () {
    var root = document.documentElement;
    var dark = root.getAttribute("data-theme") ? root.getAttribute("data-theme") === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
    root.setAttribute("data-theme", dark ? "light" : "dark");
  });
  render();
})();
</script>
</body>
</html>
"""
