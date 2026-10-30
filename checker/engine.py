"""扫描调度：发现文件、执行规则并汇总结果。"""

from __future__ import annotations

import ast
import fnmatch
import time
from collections.abc import Iterable
from pathlib import Path

from .custom_rules import build_custom_rule
from .models import FileReport, Issue, ScanReport, Severity
from .rules import RULES, Rule, RuleContext

DEFAULT_EXCLUDED_DIRS = frozenset(
    {
        "__pycache__",
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "build",
        "dist",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
    }
)


class CheckEngine:
    """按规则集扫描 Python 文件并生成报告。"""

    def __init__(
        self,
        rules: list[Rule] | None = None,
        exclude: list[str] | None = None,
        display_root: str | Path | None = None,
        custom_terms: Iterable[str] | str | None = None,
    ):
        """初始化引擎；exclude 支持目录名、文件名或相对路径通配符。

        display_root 用于把扫描结果中的文件路径显示为相对于该目录的形式，
        适合扫描临时解压目录时隐藏服务器上的真实路径。custom_terms 会额外
        注册一条「【自定义】违规」规则。
        """
        self.rules = list(RULES if rules is None else rules)
        self.exclude = list(exclude or [])
        self.display_root = (
            Path(display_root).expanduser().resolve() if display_root is not None else None
        )
        if custom_terms:
            custom_rule = build_custom_rule(custom_terms)
            if custom_rule is not None:
                self.rules.append(custom_rule)

    def run(self, target: str | Path) -> ScanReport:
        """扫描目标文件或目录，返回汇总报告。"""
        started = time.perf_counter()
        root = Path(target).expanduser()
        if not root.exists():
            raise FileNotFoundError(f"目标不存在: {root}")
        files = self.discover(root)
        reports = [self.check_file(path) for path in files]
        reports.sort(key=lambda item: (item.score, item.path))
        return ScanReport(
            target=str(root),
            files=reports,
            elapsed=time.perf_counter() - started,
        )

    def discover(self, target: Path) -> list[Path]:
        """收集需要检查的 .py 文件，自动跳过常见依赖与缓存目录。"""
        if target.is_file():
            return [target]
        found: list[Path] = []
        for path in sorted(target.rglob("*.py")):
            if any(part in DEFAULT_EXCLUDED_DIRS for part in path.parts):
                continue
            relative = path.relative_to(target).as_posix()
            if self._is_excluded(relative, path.name):
                continue
            found.append(path)
        return found

    def _is_excluded(self, relative: str, name: str) -> bool:
        return any(
            fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(name, pattern)
            for pattern in self.exclude
        )

    def check_file(self, path: Path) -> FileReport:
        """检查单个文件，返回该文件的报告。"""
        started = time.perf_counter()
        display = self._display_path(path)
        try:
            source = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            issue = Issue("PE000", "文件读取失败", Severity.HIGH, str(exc), display, 0)
            return FileReport(
                path=display,
                issues=[issue],
                elapsed=time.perf_counter() - started,
            )

        lines = source.splitlines()
        try:
            tree = ast.parse(source, filename=display)
        except SyntaxError as exc:
            evidence = ""
            if exc.lineno and exc.lineno <= len(lines):
                evidence = lines[exc.lineno - 1].strip()[:120]
            issue = Issue(
                "PE000",
                "语法错误",
                Severity.HIGH,
                f"无法解析文件: {exc.msg}",
                display,
                exc.lineno or 0,
                evidence=evidence,
                suggestion="先修复语法错误，再重新运行预检",
            )
            return FileReport(
                path=display,
                issues=[issue],
                line_count=len(lines),
                elapsed=time.perf_counter() - started,
            )

        context = RuleContext(path=display, source=source, tree=tree, lines=lines)
        issues: list[Issue] = []
        for item in self.rules:
            try:
                findings = list(item.check(context))
            except Exception as exc:  # 单条规则失败不应中断整个扫描
                issues.append(
                    Issue(
                        "PE999",
                        "规则执行失败",
                        Severity.HIGH,
                        f"{item.code} {item.name}: {exc}",
                        display,
                        0,
                    )
                )
                continue
            for finding in findings:
                issues.append(
                    Issue(
                        rule=item.code,
                        name=item.name,
                        severity=item.severity,
                        message=finding.message,
                        file=display,
                        line=finding.line,
                        evidence=context.evidence(finding.line),
                        suggestion=finding.suggestion,
                    )
                )
        issues.sort(
            key=lambda issue: (
                issue.priority.rank,
                -issue.severity.weight,
                issue.line,
                issue.rule,
            )
        )
        return FileReport(
            path=display,
            issues=issues,
            line_count=len(lines),
            elapsed=time.perf_counter() - started,
        )

    def _display_path(self, path: Path) -> str:
        """优先输出相对于 display_root 或当前工作目录的路径，便于阅读。"""
        if self.display_root is not None:
            try:
                return path.resolve().relative_to(self.display_root).as_posix()
            except ValueError:
                pass
        try:
            return path.resolve().relative_to(Path.cwd()).as_posix()
        except ValueError:
            return path.as_posix()
