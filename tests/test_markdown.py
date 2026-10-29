"""Markdown 报告的渲染与写盘测试。"""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from checker import (
    CheckEngine,
    render_context_markdown,
    render_file_markdown,
    render_scan_markdown,
    write_file_reports,
)
from checker.context_health import scan_context_health
from checker.dependencies import (
    DependencyReport,
    ImportReference,
    PackageStatus,
)
from checker.models import FileReport, Issue, ScanReport, Severity


class MarkdownReportTestCase(unittest.TestCase):
    """在临时目录中验证生成的文件名与内容。"""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.source_dir = self.root / "src"
        self.source_dir.mkdir()
        self.report_dir = self.root / "reports"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_generates_one_markdown_per_python_file(self) -> None:
        (self.source_dir / "clean.py").write_text(
            '"""干净模块。"""\n\n\ndef add(left, right):\n'
            '    """返回两数之和。"""\n    return left + right\n',
            encoding="utf-8",
        )
        (self.source_dir / "risky.py").write_text(
            '"""风险模块。"""\n\nAPI_TOKEN = "sk-live-abcdef123456"\n',
            encoding="utf-8",
        )

        report = CheckEngine().run(self.source_dir)
        written = write_file_reports(report, self.report_dir)

        self.assertTrue(self.report_dir.is_dir())
        self.assertEqual(
            sorted(path.name for path in written), ["clean.md", "risky.md"]
        )
        self.assertEqual(
            sorted(path.name for path in self.report_dir.iterdir()),
            ["clean.md", "risky.md"],
        )

    def test_markdown_contains_issue_details(self) -> None:
        (self.source_dir / "risky.py").write_text(
            '"""风险模块。"""\n\nAPI_TOKEN = "sk-live-abcdef123456"\n',
            encoding="utf-8",
        )
        report = CheckEngine().run(self.source_dir)
        written = write_file_reports(report, self.report_dir)

        content = written[0].read_text(encoding="utf-8")
        self.assertIn("# 代码体检报告：risky.py", content)
        self.assertIn("PE011", content)
        self.assertIn("严重", content)
        self.assertIn("## 问题清单", content)
        self.assertIn("## 问题详情", content)
        self.assertIn("得分", content)

    def test_clean_file_markdown_has_no_problem_table(self) -> None:
        file_report = FileReport(path="clean.py", line_count=6)
        content = render_file_markdown(
            file_report, generated_at=datetime(2026, 1, 1, 12, 0, 0)
        )

        self.assertIn("100 / 100", content)
        self.assertIn("未发现问题，代码状态良好。", content)
        self.assertNotIn("## 问题详情", content)
        self.assertIn("2026-01-01 12:00:00", content)

    def test_duplicate_basenames_do_not_overwrite(self) -> None:
        report = ScanReport(
            target=str(self.root),
            files=[FileReport(path="a/util.py"), FileReport(path="b/util.py")],
        )
        written = write_file_reports(report, self.report_dir)

        self.assertEqual([path.name for path in written], ["util.md", "util_2.md"])
        self.assertTrue(all(path.exists() for path in written))

    def test_pipe_characters_are_escaped_in_tables(self) -> None:
        issue = Issue(
            rule="PE999",
            name="测试 | 项",
            severity=Severity.HIGH,
            message="说明 | 内容",
            file="x.py",
            line=3,
        )
        file_report = FileReport(path="x.py", issues=[issue])
        content = render_file_markdown(file_report)

        self.assertIn("测试 \\| 项", content)
        self.assertIn("说明 \\| 内容", content)

    def test_scan_export_markdown_contains_score_and_details(self) -> None:
        (self.source_dir / "risky.py").write_text(
            '"""风险模块。"""\n\nAPI_TOKEN = "sk-live-abcdef123456"\n',
            encoding="utf-8",
        )
        report = CheckEngine().run(self.source_dir)

        content = render_scan_markdown(
            report,
            generated_at=datetime(2026, 1, 1, 12, 0, 0),
            target="risky.py",
        )

        self.assertIn("# 🛡️ AI 代码安全诊断报告", content)
        self.assertIn("扫描目标 | `risky.py`", content)
        self.assertIn("综合得分", content)
        self.assertIn(f"{report.score} / 100", content)
        self.assertIn("PE011", content)
        self.assertIn("### 问题清单", content)
        self.assertIn("### 问题详情", content)
        self.assertIn("| 级别 | 优先级 |", content)
        self.assertIn("存在阻断合并的风险", content)
        self.assertIn("[P0][高危] PE011", content)
        self.assertIn("2026-01-01 12:00:00", content)

    def test_scan_export_markdown_aggregates_multiple_files(self) -> None:
        (self.source_dir / "risky.py").write_text(
            '"""风险模块。"""\n\nAPI_TOKEN = "sk-live-abcdef123456"\n',
            encoding="utf-8",
        )
        (self.source_dir / "clean.py").write_text(
            '"""干净模块。"""\n\n\ndef add(left, right):\n'
            '    """返回两数之和。"""\n    return left + right\n',
            encoding="utf-8",
        )
        report = CheckEngine(display_root=self.source_dir).run(self.source_dir)

        content = render_scan_markdown(report, target="project.zip")

        self.assertIn("| 扫描目标 | `project.zip` |", content)
        self.assertIn("| 扫描文件数 | 2 |", content)
        self.assertIn("## 文件：`risky.py`", content)
        self.assertIn("## 文件：`clean.py`", content)
        self.assertIn("未发现问题，代码状态良好。", content)

    def test_scan_export_markdown_lists_hallucinated_dependencies(self) -> None:
        (self.source_dir / "risky.py").write_text(
            "import fake_pkg\n", encoding="utf-8"
        )
        report = CheckEngine(display_root=self.source_dir).run(self.source_dir)
        dependencies = DependencyReport(
            references=[
                ImportReference(
                    name="fake_pkg",
                    candidates=("fake-pkg",),
                    file="risky.py",
                    line=1,
                )
            ],
            statuses={
                "fake_pkg": PackageStatus(
                    name="fake_pkg",
                    distribution="fake-pkg",
                    exists=False,
                    detail="PyPI 返回 404",
                )
            },
        )

        content = render_scan_markdown(report, dependencies=dependencies)

        self.assertIn("## 依赖真实性校验", content)
        self.assertIn("### 🚨 幻觉依赖风险", content)
        self.assertIn("【幻觉依赖风险】", content)
        self.assertIn("fake_pkg", content)
        self.assertIn("`risky.py:1`", content)

    def test_context_export_markdown_contains_metrics_and_debt(self) -> None:
        (self.source_dir / "big.py").write_text(
            "\n".join(["value = 1"] * 305)
            + "\n# TODO: split this file\n# FIXME: fix this later\n",
            encoding="utf-8",
        )
        report = scan_context_health(self.source_dir)

        content = render_context_markdown(
            report, generated_at=datetime(2026, 1, 1, 12, 0, 0)
        )

        self.assertIn("# 📊 AI 上下文健康诊断报告", content)
        self.assertIn("【上下文污染预警】", content)
        self.assertIn("超过 300 行", content)
        self.assertIn(f"| 代码总行数 | {report.total_lines} |", content)
        self.assertIn("## 文件体积与债务概览", content)
        self.assertIn("## 代码债务明细", content)
        self.assertIn("TODO: split this file", content)
        self.assertIn("FIXME: fix this later", content)


if __name__ == "__main__":
    unittest.main()
