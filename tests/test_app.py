"""Streamlit 双引擎页面的端到端测试（基于 AppTest，无需启动服务器）。"""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
import zipfile
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
                self.assertEqual(len(at.download_button), 0)

                # 原有安全扫描功能仍然可用。
                content = (ROOT / "sample_code" / "user_service.py").read_bytes()
                at.file_uploader[0].set_value(
                    ("user_service.py", content, "text/x-python")
                ).run()
                self.assertFalse(at.exception)
                self.assertIn("漏洞明细", [item.value for item in at.subheader])
                self.assertGreater(len(at.dataframe[0].value), 0)
                self.assertEqual(
                    set(at.dataframe[0].value["文件"]), {"user_service.py"}
                )
                self.assertIn("审查优先级", at.dataframe[0].value.columns)
                self.assertEqual(at.dataframe[0].value.iloc[0]["审查优先级"], "P0")
                self.assertTrue(
                    any(
                        "存在阻断合并的风险" in item.value
                        for item in at.error
                    )
                )
                self.assertIn("退出登录", [button.label for button in at.button])

                # 安全页应生成高/中/低危占比环形图。
                severity_charts = at.get("vega_lite_chart")
                self.assertEqual(len(severity_charts), 1)
                severity_spec = json.loads(severity_charts[0].proto.spec)
                self.assertEqual(severity_spec["layer"][0]["mark"]["type"], "arc")
                self.assertEqual(severity_spec["layer"][1]["mark"]["type"], "text")
                self.assertEqual(
                    severity_spec["layer"][0]["encoding"]["color"]["scale"]["range"],
                    ["#c62828", "#b26a00", "#2e7d32"],
                )
                self.assertEqual(len(at.download_button), 1)
                self.assertEqual(at.download_button[0].label, "📥 导出诊断报告")

                # 换成无漏洞文件后，饼图应随扫描结果消失。
                clean = (ROOT / "sample_code" / "clean_module.py").read_bytes()
                at.file_uploader[0].set_value(
                    ("clean_module.py", clean, "text/x-python")
                ).run()
                self.assertFalse(at.exception)
                self.assertEqual(len(at.get("vega_lite_chart")), 0)
                self.assertEqual(len(at.error), 0)
                self.assertIn(
                    "未发现漏洞，暂无可展示的级别分布。",
                    [item.value for item in at.info],
                )

                # 切换到上下文健康检查页面。
                at.radio[0].set_value(PAGE_CONTEXT).run()
                self.assertFalse(at.exception)
                self.assertIn(
                    "要扫描的文件夹路径",
                    [widget.label for widget in at.text_input],
                )
                self.assertIn("退出登录", [button.label for button in at.button])
                self.assertEqual(len(at.download_button), 0)

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

                # 上下文页应生成行数柱状图：普通柱蓝色、超限柱红色。
                line_charts = at.get("vega_lite_chart")
                self.assertEqual(len(line_charts), 1)
                line_spec = json.loads(line_charts[0].proto.spec)
                self.assertEqual(line_spec["layer"][0]["mark"]["type"], "bar")
                self.assertEqual(
                    line_spec["layer"][0]["encoding"]["color"]["scale"]["range"],
                    ["#2a78d6", "#c62828"],
                )
                self.assertEqual(line_spec["layer"][1]["mark"]["type"], "rule")
                self.assertEqual(len(at.download_button), 1)
                self.assertEqual(at.download_button[0].label, "📥 导出诊断报告")

                # 切回安全扫描页，导航仍然正常。
                at.radio[0].set_value(PAGE_SCAN).run()
                self.assertFalse(at.exception)
                self.assertIn(
                    "请上传一个 .py 文件或 .zip 压缩包开始扫描。",
                    [info.value for info in at.info],
                )

                # ZIP 压缩包：解压后汇总扫描其中所有 .py 文件。
                buffer = io.BytesIO()
                with zipfile.ZipFile(
                    buffer, "w", zipfile.ZIP_DEFLATED
                ) as archive:
                    archive.writestr(
                        "pkg/user_service.py",
                        (ROOT / "sample_code" / "user_service.py").read_bytes(),
                    )
                    archive.writestr(
                        "pkg/clean_module.py",
                        (ROOT / "sample_code" / "clean_module.py").read_bytes(),
                    )
                    archive.writestr("pkg/readme.txt", "ignored")
                at.file_uploader[0].set_value(
                    ("project.zip", buffer.getvalue(), "application/zip")
                ).run()
                self.assertFalse(at.exception)
                captions = [item.value for item in at.caption]
                self.assertTrue(
                    any(
                        "project.zip" in text and "2 个 .py 文件" in text
                        for text in captions
                    )
                )
                issue_frame = at.dataframe[0].value
                self.assertIn("文件", issue_frame.columns)
                self.assertIn("pkg/user_service.py", set(issue_frame["文件"]))
                self.assertEqual(at.download_button[0].label, "📥 导出诊断报告")

    def test_ai_fix_backup_and_rollback(self) -> None:
        source = (
            '"""演示模块。"""\n\n'
            'API_TOKEN = "sk-live-abcdef123456"\n'
        )

        class FakeResponse:
            status_code = 200
            text = ""

            def json(self):
                return {
                    "choices": [
                        {"message": {"content": 'API_TOKEN = "from-env"'}}
                    ]
                }

        post_called = {"backup_existed": False}

        def fake_post(*args, **kwargs):
            workspace_value = at.session_state.get("fix_workspace_path")
            if workspace_value:
                post_called["backup_existed"] = (
                    Path(workspace_value) / "demo.py.bak"
                ).exists()
            return FakeResponse()

        with mock.patch("requests.post", side_effect=fake_post):
            at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=30)
            at.run()
            at.text_input[0].set_value("admin")
            at.text_input[1].set_value("123456")
            at.form_submit_button[0].click().run()
            at.file_uploader[0].set_value(
                ("demo.py", source.encode("utf-8"), "text/x-python")
            ).run()
            self.assertFalse(at.exception)

            api_input = next(
                widget
                for widget in at.text_input
                if widget.label == "DeepSeek API Key"
            )
            api_input.set_value("test-key").run()

            fix_button = next(
                button for button in at.button if button.label == "🔧 一键 AI 修复"
            )
            fix_button.click().run()
            self.assertFalse(at.exception)
            self.assertTrue(post_called["backup_existed"])

            backups = at.session_state["fix_backups"]
            self.assertIn("demo.py", backups)
            backup_path = Path(backups["demo.py"])
            self.assertTrue(backup_path.name.endswith(".bak"))
            self.assertEqual(backup_path.read_text(encoding="utf-8"), source)

            workspace = Path(at.session_state["fix_workspace_path"])
            current = workspace / "demo.py"
            self.assertEqual(current.read_text(encoding="utf-8"), source)
            self.assertIn(
                "⏪ 回滚到修复前",
                [button.label for button in at.button],
            )

            # 模拟修复过程对工作区文件的修改，验证回滚会恢复备份。
            current.write_text("BROKEN\n", encoding="utf-8")
            rollback = next(
                button
                for button in at.button
                if button.label == "⏪ 回滚到修复前"
            )
            rollback.click().run()

            self.assertFalse(at.exception)
            self.assertEqual(current.read_text(encoding="utf-8"), source)
            self.assertEqual(at.session_state["ai_fix_cache"], {})
            self.assertIn(
                "已回滚，请重新扫描确认",
                [message.value for message in at.success],
            )

            workspace_tmp = at.session_state.get("fix_workspace_tmp")
            if workspace_tmp is not None:
                workspace_tmp.cleanup()

    def test_hallucinated_dependency_is_reported(self) -> None:
        source = (
            '"""演示模块。"""\n\n'
            "import requests\n"
            "import totally_fake_package\n\n\n"
            "def fetch():\n"
            '    """发起请求。"""\n'
            '    return requests.get("https://example.com")\n'
        )

        class FakeResponse:
            def __init__(self, status_code: int):
                self.status_code = status_code

        def fake_get(url: str, **kwargs):
            return FakeResponse(200 if url.endswith("/requests/json") else 404)

        with mock.patch(
            "checker.dependencies.requests.head", side_effect=fake_get
        ):
            at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=30)
            at.run()
            at.text_input[0].set_value("admin")
            at.text_input[1].set_value("123456")
            at.form_submit_button[0].click().run()
            at.file_uploader[0].set_value(
                ("demo.py", source.encode("utf-8"), "text/x-python")
            ).run()

            self.assertFalse(at.exception)
            errors = [item.value for item in at.error]
            self.assertTrue(
                any(
                    "【幻觉依赖风险】" in text
                    and "totally_fake_package" in text
                    for text in errors
                )
            )
            dependency_frame = at.dataframe[1].value
            statuses = dict(
                zip(dependency_frame["依赖"], dependency_frame["状态"])
            )
            self.assertEqual(
                statuses["totally_fake_package"], "❌ 幻觉依赖风险"
            )
            self.assertEqual(statuses["requests"], "✅ 存在")
            self.assertEqual(at.download_button[0].label, "📥 导出诊断报告")


if __name__ == "__main__":
    unittest.main()
