"""M9 APT 연계 분석 엔진.

6개 증거 축의 가중 점수로 그룹별 연계 가능성을 산정한다.

    S_g = Σ w_i · m_(i,g)   (0 ≤ m ≤ 1, Σ w = 1)

결과는 "확정"이 아니라 신뢰도 등급(높음·중간·낮음)이며, 최종 판단은 분석관이 한다.
위장(false flag)에 대비해 코드·언어 흔적만으로는 "높음"을 주지 않는다.
"""

from __future__ import annotations

import json
import math
import sqlite3
from datetime import datetime
from importlib import resources

from .db import load_analyses

WEIGHTS = {"code": 0.25, "infra": 0.20, "ttp": 0.20, "target": 0.15, "lang_time": 0.10, "external": 0.10}
AXIS_KO = {"code": "코드 유사도", "infra": "인프라 중첩", "ttp": "TTP(ATT&CK)", "target": "표적·미끼",
           "lang_time": "언어·시간대 흔적", "external": "외부 보고 일치"}


def load_profiles() -> list[dict]:
    text = resources.files("irsys.data").joinpath("apt_profiles.json").read_text(encoding="utf-8")
    return json.loads(text)["groups"]


def grade(score: float, axes: dict[str, float]) -> str:
    if score >= 0.75:
        # 인프라 또는 TTP 근거 없이 '높음'을 주지 않는다(위장 대비).
        return "높음" if axes["infra"] > 0 or axes["ttp"] >= 0.5 else "중간"
    if score >= 0.5:
        return "중간"
    return "낮음"


def phrase(group: str, g: str) -> str:
    return {
        "높음": f"{group} 그룹과의 연계 가능성이 높음",
        "중간": f"{group} 그룹의 기존 수법과 유사점이 확인됨",
        "낮음": f"{group} 그룹과의 연계 근거 불충분",
    }[g]


def _technique_idf(profiles: list[dict]) -> dict[str, float]:
    n = len(profiles)
    df: dict[str, int] = {}
    for p in profiles:
        for t in set(p["techniques"]):
            df[t] = df.get(t, 0) + 1
    return {t: math.log((n + 1) / (c + 0.5)) for t, c in df.items()}


def score(observed: dict, profiles: list[dict] | None = None) -> list[dict]:
    """observed 키: techniques, iocs, labels, imphashes, lure_text, hangul, compile_times_kst."""
    profiles = profiles or load_profiles()
    idf = _technique_idf(profiles)
    default_idf = math.log(len(profiles) + 1)
    techniques = set(observed.get("techniques", []))
    iocs = {v.lower() for v in observed.get("iocs", [])}
    labels = " ".join(observed.get("labels", [])).lower()
    imphashes = set(observed.get("imphashes", []))
    lure = observed.get("lure_text", "").lower()

    # 언어·시간대: 한글 흔적, 컴파일 시각이 평일 KST 08~20시인 비율
    times = [datetime.fromisoformat(t) for t in observed.get("compile_times_kst", []) if t]
    work = [t for t in times if t.weekday() < 5 and 8 <= t.hour < 20]
    lang_time = (0.5 if observed.get("hangul") else 0.0) + (0.5 * len(work) / len(times) if times else 0.0)

    results = []
    for p in profiles:
        evidence: dict[str, list[str]] = {}
        axes: dict[str, float] = {}

        hits = imphashes & set(p.get("imphashes", []))
        fam = [s for s in p.get("software", []) if s.lower() in labels]
        axes["code"] = 1.0 if hits else 0.8 if fam else 0.0
        evidence["code"] = [f"imphash {h}" for h in hits] + [f"악성코드 계열 {s}" for s in fam]

        infra = iocs & {v.lower() for v in p.get("known_iocs", [])}
        axes["infra"] = min(1.0, len(infra) / 2)
        evidence["infra"] = sorted(infra)

        prof_t = set(p["techniques"])
        total = sum(idf.get(t, default_idf) for t in techniques)
        matched, partial = [], []
        gain = 0.0
        for t in techniques:
            w = idf.get(t, default_idf)
            if t in prof_t:
                gain += w
                matched.append(t)
            elif t.split(".")[0] in {x.split(".")[0] for x in prof_t}:
                gain += 0.5 * w
                partial.append(t)
        axes["ttp"] = round(gain / total, 3) if total else 0.0
        evidence["ttp"] = sorted(matched) + [f"{t}(상위 기법만 일치)" for t in sorted(partial)]

        kw = [k for k in p.get("lure_keywords", []) if k.lower() in lure]
        axes["target"] = round(min(1.0, len(kw) / 3), 3)
        evidence["target"] = kw

        axes["lang_time"] = round(lang_time, 3)
        evidence["lang_time"] = ([f"한글 문자열 {observed.get('hangul')}건"] if observed.get("hangul") else []) + (
            [f"컴파일 시각 {len(work)}/{len(times)}건이 평일 KST 08~20시"] if times else [])

        ext = iocs & {v.lower() for v in p.get("reported_iocs", [])}
        axes["external"] = 1.0 if ext else 0.0
        evidence["external"] = sorted(ext)

        s = round(sum(WEIGHTS[k] * axes[k] for k in WEIGHTS), 3)
        g = grade(s, axes)
        results.append({"group": p["name"], "id": p["id"], "url": p.get("attack_url"), "score": s,
                        "grade": g, "statement": phrase(p["name"], g), "axes": axes, "evidence": evidence})
    return sorted(results, key=lambda r: r["score"], reverse=True)


def collect_observed(conn: sqlite3.Connection, case_id: str, extra_techniques: list[str] | None = None,
                     extra_labels: list[str] | None = None, extra_text: str = "") -> dict:
    """사건에 저장된 분석 결과에서 연계 분석 입력값을 모은다."""
    techniques = set(extra_techniques or [])
    labels = list(extra_labels or [])
    imphashes, compile_times = [], []
    lure_parts = [extra_text]
    hangul = 0
    for a in load_analyses(conn, case_id):
        r = a["result"]
        techniques |= set(r.get("attack_techniques", []))
        if a["kind"] == "email":
            lure_parts.append(r.get("subject", ""))
            lure_parts += [x["filename"] for x in r.get("attachments", [])]
        if a["kind"] == "static":
            pe = r.get("pe") or {}
            if pe.get("imphash"):
                imphashes.append(pe["imphash"])
            if pe.get("compile_time_kst"):
                compile_times.append(pe["compile_time_kst"])
            if pe.get("pdb_path"):
                labels.append(pe["pdb_path"])
            hangul += len(r.get("hangul_strings", []))
            lure_parts += r.get("hangul_strings", [])
            lure_parts.append(r.get("file", ""))
    iocs = []
    for row in conn.execute("SELECT value, enrichment FROM iocs WHERE case_id = ?", (case_id,)):
        iocs.append(row["value"])
        if row["enrichment"]:
            for svc in json.loads(row["enrichment"]).values():
                if svc.get("threat_label"):
                    labels.append(svc["threat_label"])
                labels += [str(t) for t in svc.get("tags", [])]
    return {"techniques": sorted(techniques), "iocs": iocs, "labels": labels, "imphashes": imphashes,
            "lure_text": "\n".join(lure_parts), "hangul": hangul, "compile_times_kst": compile_times}
