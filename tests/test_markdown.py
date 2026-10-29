"""Markdown 报告的渲染与写盘测试。"""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from checker import CheckEngine, render_file_markdown, write_file_reports
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


if __name__ == "__main__":
    unittest.main()
