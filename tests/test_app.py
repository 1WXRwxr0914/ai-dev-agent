"""Streamlit 双引擎页面的端到端测试（基于 AppTest，无需启动服务器）。"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[1]
PAGE_SCAN = "🛡️ 安全扫描与修复"
PAGE_CONTEXT = "📊 上下文健康检查"


class AppIntegrationTestCase(unittest.TestCase):
    """登录、双引擎切换和两个页面的扫描结果。"""

    def test_switch_between_engines_and_run_scans(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            scan_root = Path(temp)
            (scan_root / "big.py").write_text(
                "\n".join(["value = 1"] * 305) + "\n# TODO: split this file\n",
                encoding="utf-8",
            )

            with mock.patch.dict(os.environ, {"CONTEXT_SCAN_ROOT": str(scan_root)}):
                at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=30)
                at.run()
                self.assertFalse(at.exception)

                # 登录后出现侧边栏导航，默认停留在安全扫描页。
                at.text_input[0].set_value("admin")
                at.text_input[1].set_value("123456")
                at.form_submit_button[0].click().run()
                self.assertFalse(at.exception)
                self.assertEqual(at.radio[0].options, [PAGE_SCAN, PAGE_CONTEXT])
                self.assertEqual(at.radio[0].value, PAGE_SCAN)

                # 原有安全扫描功能仍然可用。
                content = (ROOT / "sample_code" / "user_service.py").read_bytes()
                at.file_uploader[0].set_value(
                    ("user_service.py", content, "text/x-python")
                ).run()
                self.assertFalse(at.exception)
                self.assertEqual(at.subheader[0].value, "漏洞明细")
                self.assertGreater(len(at.dataframe[0].value), 0)
                self.assertIn("退出登录", [button.label for button in at.button])

                # 切换到上下文健康检查页面。
                at.radio[0].set_value(PAGE_CONTEXT).run()
                self.assertFalse(at.exception)
                self.assertIn(
                    "要扫描的文件夹路径",
                    [widget.label for widget in at.text_input],
                )
                self.assertIn("退出登录", [button.label for button in at.button])

                # 扫描临时目录：大文件应触发红色预警和 TODO 统计。
                at.text_input[0].set_value(".")
                at.form_submit_button[0].click().run()
                self.assertFalse(at.exception)
                self.assertEqual(
                    at.error[0].value,
                    "【上下文污染预警】big.py 超过 300 行，会严重挤占 AI 的 Token 窗口，建议拆分！",
                )
                files = at.dataframe[0].value
                self.assertEqual(files.iloc[0]["文件"], "big.py")
                self.assertEqual(files.iloc[0]["总行数"], 306)
                self.assertEqual(files.iloc[0]["状态"], "⚠️ 超过 300 行")
                debt = at.dataframe[1].value
                self.assertEqual(len(debt), 1)
                self.assertEqual(debt.iloc[0]["类型"], "TODO")

                # 切回安全扫描页，导航仍然正常。
                at.radio[0].set_value(PAGE_SCAN).run()
                self.assertFalse(at.exception)
                self.assertIn(
                    "请上传一个 .py 文件开始扫描。",
                    [info.value for info in at.info],
                )


if __name__ == "__main__":
    unittest.main()
