"""终端报告渲染。"""

from __future__ import annotations

from .models import ScanReport, Severity

_LINE = "=" * 64
_THIN = "-" * 64
_RANK = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3}


def render_text(
    report: ScanReport,
    min_severity: Severity = Severity.LOW,
    limit: int | None = None,
) -> str:
    """把扫描报告渲染为终端文本；limit 限制每个文件展示的问题数。"""
    output = [
        _LINE,
        "开发者效率预检 Agent - 检查报告",
        _LINE,
        f"目标路径: {report.target}",
        f"扫描文件: {len(report.files)} 个    耗时: {report.elapsed:.3f}s",
        f"最低显示: {min_severity.label}",
    ]

    if not report.files:
        output.append("")
        output.append("未找到可检查的 Python 文件。")
        output.append(_LINE)
        return "\n".join(output)

    for file_report in report.files:
        visible = [
            issue
            for issue in file_report.issues
            if _RANK[issue.severity] >= _RANK[min_severity]
        ]
        if limit is not None:
            visible = visible[:limit]

        output.append("")
        output.append(_THIN)
        status = "通过" if file_report.passed else f"{len(file_report.issues)} 个问题"
        output.append(
            f"{file_report.path}    得分 {file_report.score}/100 · "
            f"{file_report.rating} · {status}"
        )
        if not visible:
            if file_report.issues:
                output.append("  （问题低于显示级别或已被 limit 截断，未展示）")
            continue

        for issue in visible:
            location = f"第 {issue.line} 行" if issue.line > 0 else "文件级"
            output.append(
                f"  [{issue.severity.label}] {location}  {issue.rule} {issue.name}"
            )
            output.append(f"        {issue.message}")
            if issue.evidence:
                output.append(f"        代码: {issue.evidence}")
            if issue.suggestion:
                output.append(f"        建议: {issue.suggestion}")

    counts = report.counts
    output.append("")
    output.append(_THIN)
    output.append(
        "汇总: {} 个文件, {} 个问题 (严重 {} / 警告 {} / 提示 {})".format(
            len(report.files),
            report.total_issues,
            counts["high"],
            counts["medium"],
            counts["low"],
        )
    )
    output.append(f"综合得分: {report.score}/100    评级: {report.rating}")
    output.append(_LINE)
    return "\n".join(output)
