"""自定义禁用项规则的单元测试。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from checker import CheckEngine, ReviewPriority, Severity
from checker.custom_rules import (
    CUSTOM_RULE_CODE,
    CUSTOM_RULE_NAME,
    build_custom_rule,
    parse_custom_terms,
)


class CustomRulesTestCase(unittest.TestCase):
    """验证规则解析、匹配和引擎集成。"""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def scan(self, source: str, terms: list[str]):
        """写入源码并带自定义规则扫描。"""
        path = self.root / "sample.py"
        path.write_text(source, encoding="utf-8")
        return CheckEngine(display_root=self.root, custom_terms=terms).run(path)

    @staticmethod
    def custom_issues(report):
        """取出所有自定义规则命中项。"""
        return [
            issue
            for file_report in report.files
            for issue in file_report.issues
            if issue.rule == CUSTOM_RULE_CODE
        ]

    def test_parse_terms_splits_and_deduplicates(self) -> None:
        terms = parse_custom_terms("eval, exec\nEVAL；os.system，'password'")

        self.assertEqual(terms, ["eval", "exec", "os.system", "password"])

    def test_custom_rule_metadata(self) -> None:
        rule = build_custom_rule(["eval"])

        self.assertIsNotNone(rule)
        self.assertEqual(rule.code, CUSTOM_RULE_CODE)
        self.assertEqual(rule.name, CUSTOM_RULE_NAME)
        self.assertIs(rule.severity, Severity.HIGH)

    def test_matches_function_and_keyword(self) -> None:
        source = (
            '"""测试模块。"""\n\n'
            'RESULT = eval("1 + 1")\n'
            "# password rotation required\n"
        )

        report = self.scan(source, ["eval", "password"])
        issues = self.custom_issues(report)

        self.assertEqual(len(issues), 2)
        self.assertEqual({issue.name for issue in issues}, {CUSTOM_RULE_NAME})
        self.assertIn("eval", " ".join(issue.message for issue in issues))
        self.assertIn("password", " ".join(issue.message for issue in issues))
        self.assertEqual({issue.line for issue in issues}, {3, 4})
        self.assertTrue(
            all(issue.priority is ReviewPriority.P1 for issue in issues)
        )

    def test_word_boundary_and_case_insensitive(self) -> None:
        source = (
            '"""测试模块。"""\n\n'
            "evaluate()\n"
            "medieval = 1\n"
            'EVAL("x")\n'
        )

        report = self.scan(source, ["eval"])
        issues = self.custom_issues(report)

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].line, 5)

    def test_dotted_term_is_escaped_and_matched(self) -> None:
        source = (
            '"""测试模块。"""\n\n'
            "import os\n"
            'os.system("dir")\n'
        )

        report = self.scan(source, ["os.system"])
        issues = self.custom_issues(report)

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].line, 4)

    def test_matches_chinese_keyword_in_comment(self) -> None:
        source = '"""测试模块。"""\n\n# 请勿在代码中写入密码明文\n'

        report = self.scan(source, ["密码"])
        issues = self.custom_issues(report)

        self.assertEqual(len(issues), 1)
        self.assertIn("密码", issues[0].message)

    def test_no_terms_does_not_add_custom_rule(self) -> None:
        report = self.scan('"""测试模块。"""\n\nVALUE = 1\n', [])

        self.assertEqual(self.custom_issues(report), [])


if __name__ == "__main__":
    unittest.main()
