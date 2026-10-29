"""开发者效率预检 Agent 命令行入口。

用法示例:
    python main.py                          # 检查默认 sample_code 目录
    python main.py path/to/project          # 检查指定目录
    python main.py . --min-severity medium  # 只显示警告及以上
    python main.py sample_code --json       # 输出 JSON 报告
    python main.py sample_code --strict     # 存在严重问题时退出码为 1

每次扫描结束后，会在当前目录的 reports/ 下为每个 .py 文件生成同名 Markdown 报告。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from checker import CheckEngine
from checker.markdown import write_file_reports
from checker.models import ScanReport, Severity
from checker.report import render_text

REPORT_DIR_NAME = "reports"


def build_parser() -> argparse.ArgumentParser:
    """构建并返回命令行参数解析器。"""
    parser = argparse.ArgumentParser(
        prog="dev-efficiency-agent",
        description="开发者效率预检 Agent：在提交前扫描代码异味与高风险写法。",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default="sample_code",
        help="要检查的文件或目录（默认 sample_code）",
    )
    parser.add_argument(
        "--min-severity",
        choices=[item.value for item in Severity],
        default="low",
        help="报告中显示的最低严重级别（默认 low）",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help="排除的目录名、文件名或通配符，可重复指定",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="输出 JSON 格式报告",
    )
    parser.add_argument(
        "--fail-under",
        type=int,
        default=None,
        metavar="SCORE",
        help="综合得分低于该值时返回退出码 1",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="存在严重问题时返回退出码 1",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 1.0.0",
    )
    return parser


def write_markdown_reports(report: ScanReport) -> tuple[Path, list[Path]]:
    """在项目根目录（当前工作目录）的 reports/ 下生成 Markdown 报告。

    写入失败时给出警告但不影响扫描结果，返回值为（报告目录, 已生成文件列表）。
    """
    output_dir = Path.cwd() / REPORT_DIR_NAME
    try:
        written = write_file_reports(report, output_dir)
    except OSError as exc:
        print(f"警告: 无法写入 Markdown 报告: {exc}", file=sys.stderr)
        return output_dir, []
    return output_dir, written


def _display_dir(path: Path) -> str:
    """优先输出相对于当前工作目录的路径，便于阅读。"""
    try:
        return path.resolve().relative_to(Path.cwd()).as_posix()
    except ValueError:
        return path.as_posix()


def main(argv: list[str] | None = None) -> int:
    """执行一次预检并返回进程退出码。"""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)

    engine = CheckEngine(exclude=args.exclude)
    try:
        report = engine.run(args.target)
    except FileNotFoundError as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 2

    output_dir, written = write_markdown_reports(report)
    location = _display_dir(output_dir)

    if args.json:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
        print(f"Markdown 报告目录: {location}", file=sys.stderr)
    else:
        print(render_text(report, min_severity=Severity(args.min_severity)))
        print(f"Markdown 报告: {location}/ （{len(written)} 份）")

    if args.fail_under is not None and report.score < args.fail_under:
        return 1
    has_high = any(
        issue.severity is Severity.HIGH
        for file_report in report.files
        for issue in file_report.issues
    )
    if args.strict and has_high:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
