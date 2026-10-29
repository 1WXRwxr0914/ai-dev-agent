"""依赖提取与 PyPI 真实性校验的单元测试。"""

from __future__ import annotations

import unittest

import requests

from checker.dependencies import (
    extract_imports,
    fetch_distribution,
    verify_dependencies,
)


class FakeResponse:
    """模拟 requests.Response 的最小接口。"""

    def __init__(self, status_code: int):
        self.status_code = status_code


def fake_fetcher(mapping: dict[str, int | Exception]):
    """按 PyPI 包名返回状态码，并记录调用次数。"""
    calls: list[str] = []

    def fetch(url: str, headers=None, timeout=None, **kwargs):
        package = url.rsplit("/", 2)[-2]
        calls.append(package)
        result = mapping.get(package, 404)
        if isinstance(result, Exception):
            raise result
        return FakeResponse(result)

    return fetch, calls


class ImportExtractionTestCase(unittest.TestCase):
    """验证 import 提取的过滤规则与包名映射。"""

    def test_filters_stdlib_relative_and_local_imports(self) -> None:
        sources = {
            "pkg/app.py": (
                '"""演示模块。"""\n'
                "import os\n"
                "import requests\n"
                "import pkg\n"
                "from . import helper\n"
                "from flask_sqlalchemy import Model\n"
                "from PIL import Image\n"
            )
        }

        references = extract_imports(sources)
        names = [item.name for item in references]

        self.assertIn("requests", names)
        self.assertIn("flask_sqlalchemy", names)
        self.assertIn("PIL", names)
        self.assertNotIn("os", names)
        self.assertNotIn("pkg", names)
        self.assertNotIn("helper", names)

        pil = next(item for item in references if item.name == "PIL")
        self.assertEqual(pil.candidates[0], "pillow")
        self.assertIn("pil", pil.candidates)
        self.assertEqual(pil.line, 7)

    def test_normalizes_distribution_name(self) -> None:
        references = extract_imports(
            {"app.py": "from flask_sqlalchemy import Model\n"}
        )

        self.assertEqual(references[0].candidates, ("flask-sqlalchemy",))

    def test_skips_file_with_syntax_error(self) -> None:
        references = extract_imports({"broken.py": "def broken(:\n    pass\n"})

        self.assertEqual(references, [])


class PyPIVerificationTestCase(unittest.TestCase):
    """用可注入的 fetcher 验证 404、超时、别名和缓存行为。"""

    def test_404_marks_hallucinated_dependency(self) -> None:
        references = extract_imports(
            {"app.py": "import totally_fake_package\n"}
        )
        fetcher, _ = fake_fetcher({"totally-fake-package": 404})

        result = verify_dependencies(
            references, cache={}, fetcher=fetcher, max_workers=2
        )

        self.assertEqual(len(result.missing), 1)
        status = result.missing[0]
        self.assertEqual(status.name, "totally_fake_package")
        self.assertEqual(status.distribution, "totally-fake-package")
        self.assertIs(status.exists, False)
        self.assertIn("404", status.detail)

    def test_alias_falls_back_to_real_distribution(self) -> None:
        references = extract_imports({"app.py": "from PIL import Image\n"})
        fetcher, _ = fake_fetcher({"pillow": 200, "pil": 404})

        result = verify_dependencies(
            references, cache={}, fetcher=fetcher, max_workers=2
        )

        status = result.statuses["pil"]
        self.assertIs(status.exists, True)
        self.assertEqual(status.distribution, "pillow")
        self.assertEqual(result.missing, [])

    def test_timeout_is_unknown_not_hallucination(self) -> None:
        references = extract_imports({"app.py": "import requests\n"})
        fetcher, _ = fake_fetcher({"requests": requests.Timeout()})

        result = verify_dependencies(
            references, cache={}, fetcher=fetcher, max_workers=2
        )

        status = result.statuses["requests"]
        self.assertIsNone(status.exists)
        self.assertIn("超时", status.detail)
        self.assertEqual(result.missing, [])
        self.assertEqual(len(result.unknown), 1)

    def test_connection_error_does_not_raise(self) -> None:
        references = extract_imports({"app.py": "import requests\n"})
        fetcher, _ = fake_fetcher({"requests": requests.ConnectionError()})

        result = verify_dependencies(
            references, cache={}, fetcher=fetcher, max_workers=2
        )

        self.assertIsNone(result.statuses["requests"].exists)

    def test_cache_avoids_repeated_network_calls(self) -> None:
        references = extract_imports({"app.py": "import requests\n"})
        fetcher, calls = fake_fetcher({"requests": 200})
        cache = {}

        verify_dependencies(references, cache=cache, fetcher=fetcher, max_workers=1)
        verify_dependencies(references, cache=cache, fetcher=fetcher, max_workers=1)

        self.assertEqual(calls, ["requests"])

    def test_fetch_uses_pypi_json_url_and_timeout(self) -> None:
        captured: dict[str, object] = {}

        def fetch(url: str, headers=None, timeout=None, **kwargs):
            captured.update(
                url=url, headers=headers, timeout=timeout, **kwargs
            )
            return FakeResponse(200)

        result = fetch_distribution("requests", timeout=1.25, fetcher=fetch)

        self.assertIs(result.exists, True)
        self.assertEqual(captured["url"], "https://pypi.org/pypi/requests/json")
        self.assertEqual(captured["timeout"], 1.25)
        self.assertIs(captured["allow_redirects"], True)
        self.assertIn("User-Agent", captured["headers"])


if __name__ == "__main__":
    unittest.main()
