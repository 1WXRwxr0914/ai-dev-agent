"""用户自定义禁用函数/关键词规则。"""

from __future__ import annotations

import re
from collections.abc import Iterable

from .models import Severity
from .rules import Finding, Rule, RuleContext

CUSTOM_RULE_CODE = "CUSTOM"
CUSTOM_RULE_NAME = "【自定义】违规"
_TERM_SPLIT = re.compile(r"[,，;；\r\n]+")


def parse_custom_terms(raw: str) -> list[str]:
    """解析逗号/分号/换行分隔的自定义项，去重并保持输入顺序。"""
    terms: list[str] = []
    seen: set[str] = set()
    for item in _TERM_SPLIT.split(raw or ""):
        term = item.strip().strip("\"'").strip()
        key = term.casefold()
        if not term or key in seen:
            continue
        seen.add(key)
        terms.append(term)
    return terms


def build_custom_rule(terms: Iterable[str] | str) -> Rule | None:
    """根据用户输入构建自定义规则；没有有效项时返回 None。"""
    if isinstance(terms, str):
        cleaned = parse_custom_terms(terms)
    else:
        cleaned = parse_custom_terms("\n".join(str(item) for item in terms))

    if not cleaned:
        return None

    # 用 ASCII 标识符边界而不是 \w：既能避免 eval 命中 evaluate，
    # 又能让中文关键词在中文注释/字符串中被命中。
    patterns = [
        (
            term,
            re.compile(
                rf"(?<![A-Za-z0-9_]){re.escape(term)}(?![A-Za-z0-9_])",
                re.IGNORECASE,
            ),
        )
        for term in cleaned
    ]

    def check(ctx: RuleContext) -> Iterable[Finding]:
        for number, line in enumerate(ctx.lines, start=1):
            for term, pattern in patterns:
                if pattern.search(line):
                    yield Finding(
                        number,
                        f"命中自定义禁用项「{term}」",
                        "移除或替换该函数/关键词，或联系安全团队确认",
                    )

    return Rule(
        code=CUSTOM_RULE_CODE,
        name=CUSTOM_RULE_NAME,
        severity=Severity.HIGH,
        check=check,
        description="命中用户配置的禁用函数名或关键词",
    )
