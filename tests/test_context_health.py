"""上下文健康检查模块的单元测试。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from checker.context_health import (
    LINE_THRESHOLD,
    find_debt_items,
    resolve_target,
    scan_context_health,
)


class ContextHealthTestCase(unittest.TestCase):
    """每个测试使用独立临时目录。"""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write(self, relative: str, content: str) -> Path:
        """在临时目录中写入文件。"""
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_scan_reports_lines_size_and_debt(self) -> None:
        self.write(
            "small.py",
            "x = 1\n# TODO: rename this\ny = 2  # FIXME: later\n",
        )
        big_source = "\n".join(f"value_{i} = {i}" for i in range(305)) + "\n# TODO: split\n"
        self.write("big.py", big_source)

        report = scan_context_health(self.root)

        self.assertEqual([item.path for item in report.files], ["big.py", "small.py"])
        big = report.files[0]
        self.assertEqual(big.line_count, 306)
        self.assertEqual(big.size_bytes, (self.root / "big.py").stat().st_size)
        self.assertTrue(big.is_oversized)
        self.assertEqual(report.total_lines, 309)
        self.assertEqual(report.todo_count, 2)
        self.assertEqual(report.fixme_count, 1)
        self.assertEqual(report.total_debt, 3)
        self.assertEqual([item.path for item in report.oversized_files], ["big.py"])

    def test_threshold_boundary(self) -> None:
        self.write("exact.py", "\n".join(["x = 1"] * LINE_THRESHOLD) + "\n")
        self.write("over.py", "\n".join(["x = 1"] * (LINE_THRESHOLD + 1)) + "\n")

        report = scan_context_health(self.root)
        by_name = {item.path: item for item in report.files}

        self.assertFalse(by_name["exact.py"].is_oversized)
        self.assertTrue(by_name["over.py"].is_oversized)
        self.assertEqual([item.path for item in report.oversized_files], ["over.py"])

    def test_ignores_todo_inside_string_literal(self) -> None:
        source = 'TEXT = "# TODO: not a comment"\n# FIXME: real debt\n'

        items = find_debt_items(source, "sample.py")

        self.assertEqual([(item.line, item.kind) for item in items], [(2, "FIXME")])
        self.assertEqual(items[0].text, "FIXME: real debt")

    def test_keeps_comments_when_tokenize_fails(self) -> None:
        source = "values = [1, 2\n# TODO: close the list\n"

        items = find_debt_items(source, "broken.py")

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].kind, "TODO")

    def test_skips_excluded_directories(self) -> None:
        self.write("keep.py", "# TODO: keep me\n")
        self.write("__pycache__/skip.py", "# TODO: skip me\n")
        self.write("venv/lib/skip.py", "# FIXME: skip me too\n")

        report = scan_context_health(self.root)

        self.assertEqual([item.path for item in report.files], ["keep.py"])
        self.assertEqual(report.todo_count, 1)
        self.assertEqual(report.fixme_count, 0)

    def test_resolve_target_limits_scan_root(self) -> None:
        self.write("pkg/module.py", "")

        self.assertEqual(resolve_target("pkg", self.root), (self.root / "pkg").resolve())
        with self.assertRaises(ValueError):
            resolve_target("../outside", self.root)
        with self.assertRaises(ValueError):
            resolve_target("missing", self.root)
        with tempfile.TemporaryDirectory() as outside:
            with self.assertRaises(ValueError):
                resolve_target(outside, self.root)


if __name__ == "__main__":
    unittest.main()
