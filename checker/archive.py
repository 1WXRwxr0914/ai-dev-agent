"""安全解压上传的 ZIP 压缩包，只提取其中的 Python 源文件。

企业场景下不能直接信任用户上传的压缩包，因此这里会：
- 拒绝路径穿越、绝对路径、Windows 盘符和符号链接；
- 限制条目数量、Python 文件数量与解压后总体积，缓解压缩炸弹；
- 只把 .py 文件落到临时目录，不执行任何压缩包内容。
"""

from __future__ import annotations

import io
import re
import stat
import zipfile
from pathlib import Path, PurePosixPath

MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 50 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 5000
MAX_PY_FILES = 1000
_CHUNK_SIZE = 64 * 1024
_DRIVE_PATTERN = re.compile(r"^[A-Za-z]:")


class ArchiveError(ValueError):
    """压缩包无法安全解压时抛出，消息可直接展示给用户。"""


def extract_python_files(data: bytes, destination: str | Path) -> list[Path]:
    """把 ZIP 中的 .py 文件安全解压到 destination，返回解压后的路径列表。"""
    if not data:
        raise ArchiveError("压缩包为空。")
    if len(data) > MAX_ARCHIVE_BYTES:
        raise ArchiveError(
            f"压缩包超过 {_format_size(MAX_ARCHIVE_BYTES)} 上限，请拆分后重试。"
        )

    root = Path(destination).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)

    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ArchiveError("上传的文件不是有效的 ZIP 压缩包。") from exc

    extracted: list[Path] = []
    total_bytes = 0
    seen: set[str] = set()

    with archive:
        infos = archive.infolist()
        if len(infos) > MAX_ARCHIVE_ENTRIES:
            raise ArchiveError(
                f"压缩包条目超过 {MAX_ARCHIVE_ENTRIES} 个，已拒绝处理。"
            )

        for info in infos:
            if info.is_dir():
                continue
            relative = _safe_relative_path(info.filename)
            if not relative.name.lower().endswith(".py"):
                continue
            if info.flag_bits & 0x1:
                raise ArchiveError(f"压缩包条目已加密，无法扫描：{info.filename}")
            if stat.S_ISLNK(info.external_attr >> 16):
                raise ArchiveError(f"压缩包包含符号链接，已拒绝处理：{info.filename}")

            key = relative.as_posix().casefold()
            if key in seen:
                raise ArchiveError(f"压缩包包含重复文件：{info.filename}")
            seen.add(key)

            if len(extracted) >= MAX_PY_FILES:
                raise ArchiveError(
                    f"压缩包内的 .py 文件超过 {MAX_PY_FILES} 个，已拒绝处理。"
                )
            if info.file_size > MAX_UNCOMPRESSED_BYTES - total_bytes:
                raise ArchiveError(
                    f"压缩包解压后的源码超过 {_format_size(MAX_UNCOMPRESSED_BYTES)} 上限。"
                )

            target = (root / Path(*relative.parts)).resolve()
            if target == root or root not in target.parents:
                raise ArchiveError(f"压缩包包含不安全路径：{info.filename}")

            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info, "r") as source, target.open("wb") as output:
                    copied = 0
                    while True:
                        chunk = source.read(_CHUNK_SIZE)
                        if not chunk:
                            break
                        copied += len(chunk)
                        if copied > MAX_UNCOMPRESSED_BYTES - total_bytes:
                            raise ArchiveError(
                                "压缩包解压后的源码体积异常，已停止处理。"
                            )
                        output.write(chunk)
            except (RuntimeError, NotImplementedError, zipfile.BadZipFile) as exc:
                raise ArchiveError(f"无法读取压缩包条目 {info.filename}：{exc}") from exc
            except OSError as exc:
                raise ArchiveError(f"无法解压 {info.filename}：{exc}") from exc

            total_bytes += copied
            extracted.append(target)

    if not extracted:
        raise ArchiveError("压缩包内没有找到 .py 文件。")
    return extracted


def _safe_relative_path(name: str) -> PurePosixPath:
    """校验并返回压缩包条目的相对路径。"""
    normalized = name.replace("\\", "/")
    if (
        not normalized
        or normalized.startswith("/")
        or "\x00" in normalized
        or _DRIVE_PATTERN.match(normalized)
    ):
        raise ArchiveError(f"压缩包包含不安全路径：{name}")
    relative = PurePosixPath(normalized)
    if not relative.parts or ".." in relative.parts:
        raise ArchiveError(f"压缩包包含不安全路径：{name}")
    return relative


def _format_size(size_bytes: int) -> str:
    """把字节数格式化为易读的体积。"""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes / (1024 * 1024):.0f} MB"
