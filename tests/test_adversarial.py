"""红蓝对抗提示词与解析工具的单元测试。"""

from __future__ import annotations

import unittest

from checker.adversarial import (
    BLUE_FIX_PROMPT,
    MAX_ROUNDS,
    RED_ATTACK_PROMPT,
    build_blue_prompt,
    build_red_prompt,
    extract_python_code,
    is_defense_success,
)


class AdversarialPromptTestCase(unittest.TestCase):
    """验证提示词内容与模型输出解析。"""

    def test_prompt_constants_match_required_text(self) -> None:
        self.assertIn("你是顶级黑客", RED_ATTACK_PROMPT)
        self.assertIn("崩溃或窃取数据", RED_ATTACK_PROMPT)
        self.assertIn("你是安全专家", BLUE_FIX_PROMPT)
        self.assertIn("防御此攻击", BLUE_FIX_PROMPT)
        self.assertEqual(MAX_ROUNDS, 3)

    def test_red_prompt_includes_code_and_conclusion_marker(self) -> None:
        prompt = build_red_prompt("API_TOKEN = 'x'")

        self.assertIn("你是顶级黑客", prompt)
        self.assertIn("API_TOKEN = 'x'", prompt)
        self.assertIn("【结论】无法攻破", prompt)

    def test_blue_prompt_includes_code_and_attack(self) -> None:
        prompt = build_blue_prompt("print('x')", "攻击者读取了 Token")

        self.assertIn("你是安全专家", prompt)
        self.assertIn("print('x')", prompt)
        self.assertIn("攻击者读取了 Token", prompt)
        self.assertIn("只输出修复后的完整 Python 代码", prompt)

    def test_extract_python_code_prefers_fenced_block(self) -> None:
        response = (
            "修复说明：\n```python\nAPI_TOKEN = 'safe'\n```\n"
            "```python\nprint('other')\n```"
        )

        self.assertEqual(extract_python_code(response), "API_TOKEN = 'safe'")

    def test_extract_python_code_without_fence(self) -> None:
        self.assertEqual(
            extract_python_code("API_TOKEN = 'safe'"),
            "API_TOKEN = 'safe'",
        )

    def test_defense_success_detection(self) -> None:
        self.assertTrue(is_defense_success("经过分析，无法攻破。\n【结论】无法攻破"))
        self.assertTrue(is_defense_success("无法攻破"))
        self.assertFalse(is_defense_success("可以读取 Token\n【结论】攻破成功"))
        self.assertFalse(
            is_defense_success(
                "虽然无法攻破 A 路径，但可以通过 B 路径攻击。\n【结论】攻破成功"
            )
        )


if __name__ == "__main__":
    unittest.main()
