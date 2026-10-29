"""ZIP 安全解压模块的单元测试。"""

from __future__ import annotations

import io
import stat
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest import mock

from checker.archive import ArchiveError, extract_python_files


def make_zip(entries: dict[str, bytes | str]) -> bytes:
    """在内存中生成测试用 ZIP。"""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


class ArchiveTestCase(unittest.TestCase):
    """验证只提取 .py 且拒绝危险压缩包。"""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "extract"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_extracts_only_python_files_and_keeps_tree(self) -> None:
        data = make_zip(
            {
                "pkg/a.py": "x = 1\n",
                "pkg/data.txt": "not python",
                "b.py": "y = 2\n",
            }
        )

        paths = extract_python_files(data, self.root)

        relative = sorted(path.relative_to(self.root).as_posix() for path in paths)
        self.assertEqual(relative, ["b.py", "pkg/a.py"])
        self.assertEqual((self.root / "pkg/a.py").read_text(encoding="utf-8"), "x = 1\n")
        self.assertFalse((self.root / "pkg/data.txt").exists())

    def test_rejects_path_traversal(self) -> None:
        data = make_zip({"../evil.py": "x = 1\n"})

        with self.assertRaisesRegex(ArchiveError, "不安全路径"):
            extract_python_files(data, self.root)

    def test_rejects_absolute_and_drive_paths(self) -> None:
        for name in ("/tmp/evil.py", "C:/evil.py"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ArchiveError, "不安全路径"):
                    extract_python_files(make_zip({name: "x = 1\n"}), self.root)

    def test_rejects_symlink_entries(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            info = zipfile.ZipInfo("link.py")
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, "target.py")

        with self.assertRaisesRegex(ArchiveError, "符号链接"):
            extract_python_files(buffer.getvalue(), self.root)

    def test_rejects_archives_without_python_files(self) -> None:
        with self.assertRaisesRegex(ArchiveError, "没有找到 .py 文件"):
            extract_python_files(make_zip({"readme.txt": "hello"}), self.root)

    def test_rejects_too_many_python_files(self) -> None:
        data = make_zip({"a.py": "x = 1\n", "b.py": "y = 2\n"})

        with mock.patch("checker.archive.MAX_PY_FILES", 1):
            with self.assertRaisesRegex(ArchiveError, "超过 1 个"):
                extract_python_files(data, self.root)

    def test_rejects_oversized_uncompressed_content(self) -> None:
        data = make_zip({"big.py": "x = 1\n" * 100})

        with mock.patch("checker.archive.MAX_UNCOMPRESSED_BYTES", 10):
            with self.assertRaisesRegex(ArchiveError, "超过 10 B|体积异常"):
                extract_python_files(data, self.root)

    def test_rejects_duplicate_entries(self) -> None:
        buffer = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(buffer, "w") as archive:
                archive.writestr("same.py", "x = 1\n")
                archive.writestr("same.py", "y = 2\n")

        with self.assertRaisesRegex(ArchiveError, "重复文件"):
            extract_python_files(buffer.getvalue(), self.root)


if __name__ == "__main__":
    unittest.main()
