"""checker 核心规则与引擎的单元测试。"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from checker import (
    CheckEngine,
    ReviewPriority,
    Severity,
    review_priority_for,
)
from checker.models import ScanReport


class CheckerTestCase(unittest.TestCase):
    """为每个测试创建独立临时目录，避免相互污染。"""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def scan_source(self, source: str, name: str = "sample.py") -> ScanReport:
        """写入源码并扫描临时目录。"""
        (self.root / name).write_text(source, encoding="utf-8")
        return CheckEngine().run(self.root)

    @staticmethod
    def rule_codes(report: ScanReport) -> set[str]:
        """收集报告中出现的所有规则编号。"""
        return {
            issue.rule
            for file_report in report.files
            for issue in file_report.issues
        }

    def test_detects_bare_except(self) -> None:
        source = (
            '"""测试模块。"""\n\n\n'
            "def run():\n"
            '    """执行任务。"""\n'
            "    try:\n"
            "        return 1\n"
            "    except:\n"
            "        return 0\n"
        )
        report = self.scan_source(source)
        self.assertIn("PE005", self.rule_codes(report))

    def test_detects_hardcoded_secret(self) -> None:
        source = '"""测试模块。"""\n\nAPI_TOKEN = "sk-live-abcdef123456"\n'
        report = self.scan_source(source)
        self.assertIn("PE011", self.rule_codes(report))
        high = report.counts["high"]
        self.assertGreaterEqual(high, 1)

    def test_detects_mutable_default(self) -> None:
        source = (
            '"""测试模块。"""\n\n\n'
            "def add(item, bucket=[]):\n"
            '    """添加元素。"""\n'
            "    bucket.append(item)\n"
            "    return bucket\n"
        )
        report = self.scan_source(source)
        self.assertIn("PE009", self.rule_codes(report))

    def test_detects_unused_import(self) -> None:
        source = (
            '"""测试模块。"""\n\n'
            "import json\n\n\n"
            "def ping():\n"
            '    """返回常量。"""\n'
            "    return 1\n"
        )
        report = self.scan_source(source)
        self.assertIn("PE012", self.rule_codes(report))

    def test_clean_file_scores_100(self) -> None:
        source = (
            '"""干净模块。"""\n\n\n'
            "def add(left, right):\n"
            '    """返回两数之和。"""\n'
            "    return left + right\n"
        )
        report = self.scan_source(source)
        self.assertEqual(report.total_issues, 0)
        self.assertEqual(report.score, 100)
        self.assertEqual(report.rating, "优秀")

    def test_syntax_error_is_reported(self) -> None:
        report = self.scan_source("def broken(:\n    pass\n")
        self.assertEqual(report.total_issues, 1)
        self.assertEqual(report.files[0].issues[0].rule, "PE000")
        self.assertIs(report.files[0].issues[0].severity, Severity.HIGH)

    def test_json_output_roundtrip(self) -> None:
        source = '"""测试模块。"""\n\nAPI_TOKEN = "sk-live-abcdef123456"\n'
        report = self.scan_source(source)
        payload = json.loads(json.dumps(report.to_dict(), ensure_ascii=False))
        self.assertEqual(payload["file_count"], 1)
        self.assertEqual(payload["files"][0]["issues"][0]["severity"], "high")
        self.assertEqual(payload["files"][0]["issues"][0]["priority"], "P0")

    def test_review_priority_mapping(self) -> None:
        self.assertIs(
            review_priority_for("PE011", Severity.HIGH), ReviewPriority.P0
        )
        self.assertIs(
            review_priority_for("PE017", Severity.MEDIUM), ReviewPriority.P1
        )
        self.assertIs(
            review_priority_for("PE003", Severity.LOW), ReviewPriority.P2
        )
        self.assertIs(
            review_priority_for("PE004", Severity.LOW), ReviewPriority.P2
        )
        self.assertIs(
            review_priority_for("PE013", Severity.HIGH), ReviewPriority.P1
        )
        self.assertIs(
            review_priority_for("PE001", Severity.LOW), ReviewPriority.P2
        )

    def test_detects_uncaught_external_call(self) -> None:
        source = (
            '"""测试模块。"""\n\n'
            "import requests\n\n\n"
            "def fetch():\n"
            '    """拉取数据。"""\n'
            '    return requests.get("https://example.com")\n'
        )
        report = self.scan_source(source)

        self.assertIn("PE017", self.rule_codes(report))
        issue = next(
            issue
            for file_report in report.files
            for issue in file_report.issues
            if issue.rule == "PE017"
        )
        self.assertIs(issue.priority, ReviewPriority.P1)

    def test_caught_external_call_is_not_reported(self) -> None:
        source = (
            '"""测试模块。"""\n\n'
            "import requests\n\n\n"
            "def fetch():\n"
            '    """拉取数据。"""\n'
            "    try:\n"
            '        return requests.get("https://example.com")\n'
            "    except requests.RequestException:\n"
            "        return None\n"
        )
        report = self.scan_source(source)

        self.assertNotIn("PE017", self.rule_codes(report))

    def test_display_root_reports_relative_paths(self) -> None:
        (self.root / "pkg").mkdir()
        (self.root / "pkg" / "mod.py").write_text(
            '"""模块。"""\n\nVALUE = 1\n', encoding="utf-8"
        )

        report = CheckEngine(display_root=self.root).run(self.root)

        self.assertEqual([item.path for item in report.files], ["pkg/mod.py"])

    def test_scan_sample_code_directory(self) -> None:
        sample_dir = Path(__file__).resolve().parents[1] / "sample_code"
        report = CheckEngine().run(sample_dir)
        self.assertEqual(len(report.files), 5)
        self.assertGreater(report.total_issues, 0)
        self.assertLess(report.score, 100)
        codes = self.rule_codes(report)
        for code in ("PE005", "PE010", "PE011", "PE013", "PE015"):
            self.assertIn(code, codes)


if __name__ == "__main__":
    unittest.main()
