"""Markdown 体检报告渲染与写盘。"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .context_health import ContextHealthReport
from .dependencies import DependencyReport, ImportReference
from .models import (
    FileReport,
    Issue,
    ReviewPriority,
    ScanReport,
    Severity,
)

_SEVERITY_TEXT = {
    Severity.HIGH: "高危",
    Severity.MEDIUM: "中危",
    Severity.LOW: "低危",
}


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


def render_scan_markdown(
    report: ScanReport,
    generated_at: datetime | None = None,
    target: str | None = None,
    dependencies: DependencyReport | None = None,
) -> str:
    """把一次完整的安全扫描渲染为可导出的 Markdown 诊断报告。

    target 用于覆盖报告中的扫描目标名称（上传文件扫描时报告对象里的
    目标通常是临时路径，不适合直接展示给用户）；dependencies 用于把
    依赖真实性校验结果单独列入报告。
    """
    generated = generated_at or datetime.now()
    counts = report.counts
    lines = [
        "# 🛡️ AI 代码安全诊断报告",
        "",
        "> 由开发者效率预检 Agent 生成，仅供人工复核参考。",
        "",
        "| 项目 | 内容 |",
        "| --- | --- |",
        f"| 扫描目标 | {_cell(_code_span(target or report.target))} |",
        f"| 扫描文件数 | {len(report.files)} |",
        f"| 综合得分 | **{report.score} / 100**（{report.rating}） |",
        f"| 问题总数 | {report.total_issues} 个"
        f"（高危 {counts['high']} / 中危 {counts['medium']} / 低危 {counts['low']}） |",
        f"| 检查耗时 | {report.elapsed:.3f}s |",
        f"| 生成时间 | {generated:%Y-%m-%d %H:%M:%S} |",
        "",
        "> 审查优先级：P0=阻断合并，P1=优先审查，P2=常规审查。",
        "",
    ]

    p0_issues = [
        issue
        for file_report in report.files
        for issue in file_report.issues
        if issue.priority is ReviewPriority.P0
    ]
    if p0_issues:
        lines.extend(
            [
                f"> 🚨 **存在阻断合并的风险**：检测到 {len(p0_issues)} 个 "
                "P0 级问题（硬编码密钥），请修复后再合并代码。",
                "",
            ]
        )

    if dependencies is not None:
        lines.extend(_dependency_section(dependencies))

    if not report.files:
        lines.append("未找到可检查的 Python 文件。")

    for file_report in report.files:
        lines.extend(
            [
                f"## 文件：{_code_span(file_report.path)}",
                "",
                f"- **得分**：{file_report.score} / 100（{file_report.rating}）",
                f"- **代码行数**：{file_report.line_count}",
                f"- **问题数量**：{len(file_report.issues)}",
                "",
            ]
        )
        if not file_report.issues:
            lines.extend(["未发现问题，代码状态良好。", ""])
            continue

        lines.extend(
            [
                "### 问题清单",
                "",
                "| # | 级别 | 优先级 | 位置 | 规则 | 检查项 | 说明 |",
                "| --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for index, issue in enumerate(file_report.issues, start=1):
            lines.append(
                f"| {index} | {_SEVERITY_TEXT[issue.severity]} | "
                f"{issue.priority.value} | {_position(issue)} | "
                f"{issue.rule} | {_cell(issue.name)} | {_cell(issue.message)} |"
            )

        lines.extend(["", "### 问题详情", ""])
        for index, issue in enumerate(file_report.issues, start=1):
            lines.extend(
                [
                    f"#### {index}. [{issue.priority.value}]"
                    f"[{_SEVERITY_TEXT[issue.severity]}] "
                    f"{issue.rule} {_cell(issue.name)}",
                    "",
                    f"- **位置**：{_position(issue)}",
                    f"- **说明**：{_cell(issue.message)}",
                ]
            )
            if issue.evidence:
                lines.append(f"- **代码**：{_code_span(issue.evidence)}")
            if issue.suggestion:
                lines.append(f"- **建议**：{_cell(issue.suggestion)}")
            lines.append("")

    lines.extend(
        ["---", "", "> ⚠️ 自动扫描结果仅供参考，请结合人工复核后再合并代码。", ""]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_context_markdown(
    report: ContextHealthReport,
    generated_at: datetime | None = None,
) -> str:
    """把一次上下文健康检查渲染为可导出的 Markdown 诊断报告。"""
    generated = generated_at or datetime.now()
    lines = [
        "# 📊 AI 上下文健康诊断报告",
        "",
        "> 由开发者效率预检 Agent 生成，用于评估代码文件对 AI Token 窗口的占用风险。",
        "",
        "| 项目 | 内容 |",
        "| --- | --- |",
        f"| 扫描目录 | {_cell(_code_span(report.target))} |",
        f"| 扫描文件数 | {len(report.files)} |",
        f"| 代码总行数 | {report.total_lines} |",
        f"| 文件总体积 | {_format_size(report.total_size_bytes)} |",
        f"| 超过 {report.threshold} 行文件 | {len(report.oversized_files)} |",
        f"| TODO / FIXME | {report.todo_count} / {report.fixme_count} |",
        f"| 检查耗时 | {report.elapsed:.3f}s |",
        f"| 生成时间 | {generated:%Y-%m-%d %H:%M:%S} |",
        "",
        "## 上下文污染预警",
        "",
    ]

    if report.oversized_files:
        for item in report.oversized_files:
            lines.append(
                f"- **【上下文污染预警】**{_code_span(item.path)} 超过 "
                f"{report.threshold} 行，会严重挤占 AI 的 Token 窗口，建议拆分！"
            )
    else:
        lines.append(f"全部文件均未超过 {report.threshold} 行，上下文体积健康。")

    lines.extend(
        [
            "",
            "## 文件体积与债务概览",
            "",
            "| 文件 | 总行数 | 文件大小 | TODO | FIXME | 状态 |",
            "| --- | ---: | ---: | ---: | ---: | --- |",
        ]
    )
    for item in report.files:
        status = (
            f"⚠️ 超过 {report.threshold} 行" if item.is_oversized else item.status
        )
        lines.append(
            f"| {_cell(item.path)} | {item.line_count} | "
            f"{_format_size(item.size_bytes)} | {item.todo_count} | "
            f"{item.fixme_count} | {status} |"
        )

    lines.extend(["", "## 代码债务明细", ""])
    if not report.debt_items:
        lines.append("未发现 TODO / FIXME 注释。")
    else:
        lines.extend(
            [
                "| # | 文件 | 行号 | 类型 | 注释内容 |",
                "| --- | --- | ---: | --- | --- |",
            ]
        )
        for index, item in enumerate(report.debt_items, start=1):
            lines.append(
                f"| {index} | {_cell(item.file)} | {item.line} | "
                f"{item.kind} | {_cell(item.text)} |"
            )

    lines.extend(
        ["", "---", "", "> ⚠️ 上下文健康建议仅供参考，请结合项目实际情况决定是否拆分文件。", ""]
    )
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


def _dependency_section(dependencies: DependencyReport) -> list[str]:
    """渲染依赖真实性校验章节。"""
    lines = ["## 依赖真实性校验", ""]
    if not dependencies.references:
        lines.extend(["未发现需要校验的第三方依赖。", ""])
        return lines

    lines.extend(
        [
            "| 导入名 | PyPI 包名 | 状态 | 引用位置 |",
            "| --- | --- | --- | --- |",
        ]
    )
    for status in sorted(
        dependencies.statuses.values(), key=lambda item: item.name.casefold()
    ):
        refs = dependencies.references_for(status.name)
        lines.append(
            f"| {_cell(status.name)} | {_cell(status.distribution)} | "
            f"{status.label} | {_cell(_format_locations(refs))} |"
        )

    missing = dependencies.missing
    if missing:
        lines.extend(["", "### 🚨 幻觉依赖风险", ""])
        for status in sorted(
            missing, key=lambda item: item.name.casefold()
        ):
            refs = dependencies.references_for(status.name)
            lines.append(
                f"- **【幻觉依赖风险】**`{status.name}` 在 PyPI 上不存在"
                f"（查询包名：`{status.distribution}`）；"
                f"引用位置：{_format_locations(refs)}。"
            )

    unknown = dependencies.unknown
    if unknown:
        names = "、".join(
            item.name
            for item in sorted(unknown, key=lambda status: status.name.casefold())
        )
        lines.extend(
            ["", f"> ⚠️ 以下依赖因网络问题未能完成校验：{names}。"]
        )

    lines.append("")
    return lines


def _format_locations(
    references: list[ImportReference], limit: int = 8
) -> str:
    """把引用位置格式化为 Markdown 文本。"""
    locations = [f"`{item.file}:{item.line}`" for item in references]
    if not locations:
        return "—"
    if len(locations) > limit:
        return "、".join(locations[:limit]) + f" 等 {len(locations)} 处"
    return "、".join(locations)


def _format_size(size_bytes: int) -> str:
    """把字节数格式化为易读的体积。"""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes / (1024 * 1024):.2f} MB"


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
