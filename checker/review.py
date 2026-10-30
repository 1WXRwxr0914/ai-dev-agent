"""Code Review 指南生成所需的提示词与代码打包。"""

from __future__ import annotations

from collections.abc import Iterable

REVIEW_INSTRUCTION = (
    "你是一个资深架构师。请为这段准备提交的代码生成一份 Reviewer 指南。"
    "包含：1. 核心功能一句话总结；2. 建议的审查顺序（先看哪个函数）；"
    "3. 必须人工仔细核对的 3 个风险点。"
)

REVIEW_SYSTEM_PROMPT = (
    "你是一位资深架构师和代码审查专家。请使用清晰的 Markdown 标题和列表输出，"
    "不要输出与 Reviewer 指南无关的开场白。"
)

REVIEW_MAX_CHARS = 20_000
_TRUNCATED_MARKER = "\n# ... 代码已截断 ...\n"


def build_review_payload(
    sources: dict[str, str],
    ordered_paths: Iterable[str] | None = None,
    max_chars: int = REVIEW_MAX_CHARS,
) -> tuple[str, bool]:
    """把扫描到的源码拼成带文件名的代码块，返回（代码文本, 是否截断）。"""
    order: list[str] = []
    seen: set[str] = set()
    for path in ordered_paths or []:
        if path in sources and path not in seen:
            order.append(path)
            seen.add(path)
    for path in sorted(sources):
        if path not in seen:
            order.append(path)
            seen.add(path)

    blocks: list[str] = []
    used = 0
    truncated = False

    for path in order:
        source = sources.get(path, "")
        header = f"### 文件：{path}\n```python\n"
        footer = "\n```\n"
        overhead = len(header) + len(footer)

        if used + overhead + len(source) <= max_chars:
            blocks.append(header + source + footer)
            used += overhead + len(source)
            continue

        remaining = max_chars - used - overhead
        if remaining > 100:
            blocks.append(
                header + source[:remaining] + _TRUNCATED_MARKER + footer
            )
        truncated = True
        break

    return "\n".join(blocks).strip(), truncated
