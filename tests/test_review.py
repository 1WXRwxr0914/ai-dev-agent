"""Code Review 指南代码打包的单元测试。"""

from __future__ import annotations

import unittest

from checker.review import REVIEW_INSTRUCTION, build_review_payload


class ReviewPayloadTestCase(unittest.TestCase):
    """验证提示词和代码打包/截断逻辑。"""

    def test_instruction_contains_required_sections(self) -> None:
        self.assertIn("你是一个资深架构师", REVIEW_INSTRUCTION)
        self.assertIn("核心功能一句话总结", REVIEW_INSTRUCTION)
        self.assertIn("建议的审查顺序", REVIEW_INSTRUCTION)
        self.assertIn("必须人工仔细核对的 3 个风险点", REVIEW_INSTRUCTION)

    def test_builds_ordered_file_blocks(self) -> None:
        payload, truncated = build_review_payload(
            {"a.py": "A = 1\n", "b.py": "B = 2\n"},
            ordered_paths=["b.py", "a.py"],
        )

        self.assertFalse(truncated)
        self.assertIn("### 文件：b.py", payload)
        self.assertIn("### 文件：a.py", payload)
        self.assertLess(payload.index("b.py"), payload.index("a.py"))
        self.assertIn("B = 2", payload)

    def test_appends_sources_missing_from_order(self) -> None:
        payload, _ = build_review_payload(
            {"a.py": "A = 1\n", "b.py": "B = 2\n"},
            ordered_paths=["a.py"],
        )

        self.assertIn("### 文件：b.py", payload)

    def test_truncates_long_code(self) -> None:
        payload, truncated = build_review_payload(
            {"big.py": "x = 1\n" * 1000},
            max_chars=1000,
        )

        self.assertTrue(truncated)
        self.assertIn("代码已截断", payload)
        self.assertIn("### 文件：big.py", payload)

    def test_empty_sources_returns_empty_payload(self) -> None:
        payload, truncated = build_review_payload({})

        self.assertEqual(payload, "")
        self.assertFalse(truncated)


if __name__ == "__main__":
    unittest.main()
