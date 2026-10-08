"""법적 요건 자동화: 신고 기한 계산, 개인정보 마스킹."""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from importlib import resources

ALERT_RATIOS = (0.25, 0.5, 0.75)


def load_rules() -> list[dict]:
    text = resources.files("irsys.data").joinpath("legal_rules.json").read_text(encoding="utf-8")
    return json.loads(text)["rules"]


def _parse(ts: str) -> datetime:
    dt = datetime.fromisoformat(ts)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def deadlines(category: str, aware_at: str, now: datetime | None = None) -> list[dict]:
    """사건 유형과 인지 시각으로 법정 신고 기한과 남은 시간을 계산한다."""
    now = now or datetime.now(timezone.utc)
    aware = _parse(aware_at)
    out = []
    for rule in load_rules():
        if rule["category"] != category:
            continue
        due = aware + timedelta(hours=rule["hours"])
        remaining = due - now
        elapsed_ratio = (now - aware) / timedelta(hours=rule["hours"])
        out.append({
            **rule,
            "aware_at": aware.isoformat(),
            "due_at": due.isoformat(),
            "remaining_hours": round(remaining.total_seconds() / 3600, 1),
            "overdue": remaining.total_seconds() < 0,
            "alerts_passed": [r for r in ALERT_RATIOS if elapsed_ratio >= r],
        })
    return out


# 보고서·외부 조회·AI 입력 전에 적용하는 개인정보 패턴
PII_PATTERNS = [
    ("주민등록번호", re.compile(r"(?<![0-9A-Za-z])(\d{6})-?([1-4])\d{6}(?![0-9A-Za-z])"), lambda m: f"{m.group(1)}-{m.group(2)}******"),
    ("카드번호", re.compile(r"(?<![0-9A-Za-z])(\d{4})-(\d{4})-(\d{4})-(\d{4})(?![0-9A-Za-z])"), lambda m: f"{m.group(1)}-****-****-{m.group(4)}"),
    ("휴대전화", re.compile(r"(?<![0-9A-Za-z.:])(01[016789])-?(\d{3,4})-?(\d{4})(?![0-9A-Za-z])"), lambda m: f"{m.group(1)}-****-{m.group(3)}"),
    ("이메일", re.compile(r"\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"),
     lambda m: f"{m.group(1)}***@{m.group(2)}"),
]


def mask_pii(text: str, keep_emails: set[str] | None = None) -> tuple[str, dict[str, int]]:
    """개인정보를 마스킹하고 유형별 건수를 돌려준다.

    keep_emails: 공격자 주소처럼 IOC로 남겨야 하는 이메일 (소문자).
    """
    keep = {e.lower() for e in (keep_emails or set())}
    counts: dict[str, int] = {}
    for name, pattern, repl in PII_PATTERNS:
        def sub(m: re.Match, name=name, repl=repl) -> str:
            if name == "이메일" and m.group(0).lower() in keep:
                return m.group(0)
            counts[name] = counts.get(name, 0) + 1
            return repl(m)
        text = pattern.sub(sub, text)
    return text, counts
