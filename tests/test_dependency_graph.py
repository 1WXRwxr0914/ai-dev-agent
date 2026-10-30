"""项目内部依赖图谱的单元测试。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from checker.dependency_graph import (
    build_dependency_figure,
    build_project_dependency_graph,
)

ROOT = Path(__file__).resolve().parents[1]


class DependencyGraphTestCase(unittest.TestCase):
    """在临时目录中验证文件级 import 解析与核心节点。"""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write(self, relative: str, content: str) -> None:
        """写入测试源码。"""
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def test_builds_edges_and_core_nodes(self) -> None:
        self.write("a.py", "import b\n")
        self.write("b.py", "import c\n")
        self.write("c.py", "from b import something\n")
        self.write("d.py", "import os\n")

        data = build_project_dependency_graph(self.root)

        self.assertEqual(
            set(data.edges),
            {("a.py", "b.py"), ("b.py", "c.py"), ("c.py", "b.py")},
        )
        self.assertEqual(data.in_degrees["b.py"], 2)
        self.assertEqual(data.core_nodes, ["b.py"])
        self.assertTrue(data.has_edges)

        figure = build_dependency_figure(data)
        core_traces = [
            trace
            for trace in figure.data
            if trace.name == "核心节点（被引用最多）"
        ]
        self.assertEqual(len(core_traces), 1)
        self.assertEqual(core_traces[0].marker.color, "#c62828")
        self.assertEqual(core_traces[0].marker.size, 58)
        self.assertEqual(len(figure.layout.annotations), 3)

    def test_resolves_relative_package_imports(self) -> None:
        self.write("pkg/__init__.py", '"""包。"""\n')
        self.write("pkg/a.py", "from . import b\n")
        self.write("pkg/b.py", "from .c import helper\n")
        self.write("pkg/c.py", '"""工具模块。"""\n')

        data = build_project_dependency_graph(self.root)

        self.assertIn(("pkg/a.py", "pkg/__init__.py"), set(data.edges))
        self.assertIn(("pkg/a.py", "pkg/b.py"), set(data.edges))
        self.assertIn(("pkg/b.py", "pkg/c.py"), set(data.edges))

    def test_ignores_external_and_self_imports(self) -> None:
        self.write(
            "single.py",
            "import os\nimport requests\nimport single\nfrom external import x\n",
        )

        data = build_project_dependency_graph(self.root)

        self.assertEqual(data.nodes, ["single.py"])
        self.assertEqual(data.edges, [])
        self.assertEqual(data.core_nodes, [])
        self.assertFalse(data.has_edges)

    def test_sample_code_highlights_data_utils(self) -> None:
        data = build_project_dependency_graph(ROOT / "sample_code")

        self.assertEqual(data.core_nodes, ["data_utils.py"])
        self.assertIn(
            ("analytics_service.py", "data_utils.py"), set(data.edges)
        )
        self.assertIn(
            ("reporting_service.py", "data_utils.py"), set(data.edges)
        )


if __name__ == "__main__":
    unittest.main()
