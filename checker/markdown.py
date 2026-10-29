"""Markdown 体检报告渲染与写盘。"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .models import FileReport, Issue, ScanReport


def render_file_markdown(
    file_report: FileReport,
    generated_at: datetime | None = None,
) -> str:
    """把单个文件的检查结果渲染为 Markdown 文本。"""
    generated = generated_at or datetime.now()
    counts = file_report.counts
    name = Path(file_report.path).name or file_report.path

    lines = [
        f"# 代码体检报告：{name}",
        "",
        "> 由开发者效率预检 Agent 生成",
        "",
        "| 项目 | 内容 |",
        "| --- | --- |",
        f"| 文件路径 | {_cell(_code_span(file_report.path))} |",
        f"| 综合得分 | **{file_report.score} / 100**（{file_report.rating}） |",
        f"| 代码行数 | {file_report.line_count} |",
        f"| 检查耗时 | {file_report.elapsed:.3f}s |",
        f"| 问题数量 | {len(file_report.issues)} 个"
        f"（严重 {counts['high']} / 警告 {counts['medium']} / 提示 {counts['low']}） |",
        f"| 生成时间 | {generated:%Y-%m-%d %H:%M:%S} |",
        "",
        "## 问题清单",
        "",
    ]

    if not file_report.issues:
        lines.append("未发现问题，代码状态良好。")
    else:
        lines.extend(
            [
                "| # | 级别 | 位置 | 规则 | 检查项 | 说明 |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for index, issue in enumerate(file_report.issues, start=1):
            lines.append(
                f"| {index} | {issue.severity.label} | {_position(issue)} | "
                f"{issue.rule} | {_cell(issue.name)} | {_cell(issue.message)} |"
            )

        lines.extend(["", "## 问题详情", ""])
        for index, issue in enumerate(file_report.issues, start=1):
            lines.append(
                f"### {index}. [{issue.severity.label}] {issue.rule} {issue.name}"
            )
            lines.append("")
            lines.append(f"- **位置**：{_position(issue)}")
            lines.append(f"- **说明**：{issue.message}")
            if issue.evidence:
                lines.append(f"- **代码**：{_code_span(issue.evidence)}")
            if issue.suggestion:
                lines.append(f"- **建议**：{issue.suggestion}")
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def write_file_reports(report: ScanReport, output_dir: str | Path) -> list[Path]:
    """为报告中的每个文件写一份同名 .md，返回生成的文件路径列表。

    同名文件（不同目录下基名相同的 .py）按出现顺序追加 _2、_3 后缀，避免互相覆盖。
    """
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    generated = datetime.now()
    seen: dict[str, int] = {}
    written: list[Path] = []

    for file_report in report.files:
        stem = Path(file_report.path).stem or "report"
        seen[stem] = seen.get(stem, 0) + 1
        suffix = "" if seen[stem] == 1 else f"_{seen[stem]}"
        path = directory / f"{stem}{suffix}.md"
        path.write_text(
            render_file_markdown(file_report, generated_at=generated),
            encoding="utf-8",
            newline="\n",
        )
        written.append(path)

    return written


def _position(issue: Issue) -> str:
    """返回问题定位描述。"""
    return f"第 {issue.line} 行" if issue.line > 0 else "文件级"


def _cell(text: str) -> str:
    """转义表格单元格中的竖线与换行。"""
    return " ".join(text.splitlines()).replace("|", "\\|")


def _code_span(text: str) -> str:
    """用行内代码包裹文本，自动选择不与内容冲突的反引号长度。"""
    value = text.strip()
    if not value:
        return ""
    if "`" not in value:
        return f"`{value}`"
    fence = "``"
    while fence in value:
        fence += "`"
    return f"{fence} {value} {fence}"
