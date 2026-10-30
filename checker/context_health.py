"""上下文健康检查：统计 Python 文件体积并扫描 TODO / FIXME 代码债务。

该模块只读取文件内容并做词法分析（tokenize），不会执行被扫描的代码。
"""

from __future__ import annotations

import io
import re
import time
import tokenize
from dataclasses import dataclass, field
from pathlib import Path

from .engine import DEFAULT_EXCLUDED_DIRS

# 单个文件超过该行数时，视为会严重挤占 AI 上下文窗口。
LINE_THRESHOLD = 300

_DEBT_PATTERN = re.compile(r"\b(TODO|FIXME)\b", re.IGNORECASE)


@dataclass(frozen=True)
class DebtItem:
    """一条 TODO / FIXME 注释。"""

    file: str
    line: int
    kind: str
    text: str


@dataclass
class FileHealth:
    """单个文件的体积与代码债务统计。"""

    path: str
    line_count: int
    size_bytes: int
    debt_items: list[DebtItem] = field(default_factory=list)
    read_error: str = ""

    @property
    def todo_count(self) -> int:
        """本文件中的 TODO 数量。"""
        return sum(1 for item in self.debt_items if item.kind == "TODO")

    @property
    def fixme_count(self) -> int:
        """本文件中的 FIXME 数量。"""
        return sum(1 for item in self.debt_items if item.kind == "FIXME")

    @property
    def debt_count(self) -> int:
        """本文件中的 TODO + FIXME 总数。"""
        return len(self.debt_items)

    @property
    def is_oversized(self) -> bool:
        """行数是否超过阈值。"""
        return self.line_count > LINE_THRESHOLD

    @property
    def status(self) -> str:
        """供页面展示的状态文本。"""
        if self.read_error:
            return "读取失败"
        return "超过阈值" if self.is_oversized else "正常"


@dataclass
class ContextHealthReport:
    """一次上下文健康检查的汇总结果。"""

    target: str
    files: list[FileHealth] = field(default_factory=list)
    elapsed: float = 0.0
    threshold: int = LINE_THRESHOLD

    @property
    def total_lines(self) -> int:
        """所有文件的总行数。"""
        return sum(item.line_count for item in self.files)

    @property
    def total_size_bytes(self) -> int:
        """所有文件的总字节数。"""
        return sum(item.size_bytes for item in self.files)

    @property
    def oversized_files(self) -> list[FileHealth]:
        """超过行数阈值的文件。"""
        return [item for item in self.files if item.is_oversized]

    @property
    def debt_items(self) -> list[DebtItem]:
        """全部文件的代码债务明细。"""
        return [debt for item in self.files for debt in item.debt_items]

    @property
    def total_debt(self) -> int:
        """TODO + FIXME 总数。"""
        return len(self.debt_items)

    @property
    def todo_count(self) -> int:
        """所有文件中的 TODO 数量。"""
        return sum(item.todo_count for item in self.files)

    @property
    def fixme_count(self) -> int:
        """所有文件中的 FIXME 数量。"""
        return sum(item.fixme_count for item in self.files)


def resolve_target(raw: str, allowed_root: Path) -> Path:
    """把用户输入解析为扫描目录，并限制在 allowed_root 之内。

    相对路径按 allowed_root 解析；绝对路径或 ../ 越界路径会被拒绝，
    避免公网部署时被用来读取服务器上的其他文件。
    """
    text = (raw or "").strip().strip('"').strip("'")
    if not text:
        raise ValueError("请输入要扫描的文件夹路径。")

    root = Path(allowed_root).expanduser().resolve()
    candidate = Path(text).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve()
    except OSError as exc:
        raise ValueError(f"无法解析路径：{exc}") from exc

    if resolved != root and root not in resolved.parents:
        raise ValueError(f"为保证安全，只能扫描 {root.name}/ 目录内的文件夹。")
    if not resolved.exists():
        raise ValueError(f"文件夹不存在：{text}")
    if not resolved.is_dir():
        raise ValueError(f"不是文件夹：{text}")
    return resolved


def iter_python_files(root: Path) -> list[Path]:
    """递归收集 .py 文件，跳过缓存/依赖目录与符号链接。"""
    found: list[Path] = []
    for path in root.rglob("*.py"):
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if any(part in DEFAULT_EXCLUDED_DIRS for part in relative.parts):
            continue
        if path.is_symlink():
            continue
        found.append(path)
    return sorted(found, key=lambda item: item.relative_to(root).as_posix().lower())


def _read_source(path: Path) -> str:
    """读取源码；遇到非 UTF-8 内容时替换无法解码的字节。"""
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="replace")


def find_debt_items(source: str, filename: str) -> list[DebtItem]:
    """从源码注释中找出 TODO / FIXME。

    优先使用 tokenize，只检查真正的注释 token，避免把字符串中的
    "# TODO" 误判为代码债务；词法分析失败时对注释行做兜底匹配。
    """
    items: list[DebtItem] = []
    seen: set[tuple[int, str, str]] = set()

    def add(line_no: int, comment: str) -> None:
        match = _DEBT_PATTERN.search(comment)
        if match is None:
            return
        text = comment.lstrip("#").strip()
        key = (line_no, match.group(1).upper(), text)
        if key in seen:
            return
        seen.add(key)
        items.append(DebtItem(filename, line_no, match.group(1).upper(), text))

    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type == tokenize.COMMENT:
                add(token.start[0], token.string)
    except (tokenize.TokenError, IndentationError, SyntaxError):
        # 源码可能有语法错误；保留已解析到的注释，并补扫未识别的注释行。
        for line_no, line in enumerate(source.splitlines(), start=1):
            position = line.find("#")
            if position >= 0:
                add(line_no, line[position:])

    return items


def scan_context_health(target: str | Path) -> ContextHealthReport:
    """扫描目录下所有 .py 文件，返回行数、体积和代码债务报告。"""
    started = time.perf_counter()
    root = Path(target).expanduser().resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"目标不是文件夹: {root}")

    try:
        target_display = root.relative_to(Path.cwd()).as_posix()
    except ValueError:
        target_display = root.as_posix()

    files: list[FileHealth] = []
    for path in iter_python_files(root):
        display = path.relative_to(root).as_posix()
        try:
            size_bytes = path.stat().st_size
        except OSError as exc:
            files.append(FileHealth(display, 0, 0, read_error=str(exc)))
            continue
        try:
            source = _read_source(path)
        except OSError as exc:
            files.append(FileHealth(display, 0, size_bytes, read_error=str(exc)))
            continue
        lines = source.splitlines()
        files.append(
            FileHealth(
                path=display,
                line_count=len(lines),
                size_bytes=size_bytes,
                debt_items=find_debt_items(source, display),
            )
        )

    files.sort(key=lambda item: (-item.line_count, item.path))
    return ContextHealthReport(
        target=target_display,
        files=files,
        elapsed=time.perf_counter() - started,
    )
