"""第三方依赖真实性校验：提取 import 并查询 PyPI 是否存在对应项目。"""

from __future__ import annotations

import ast
import re
import sys
from collections.abc import Callable, MutableMapping
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import quote

import requests

PYPI_JSON_URL = "https://pypi.org/pypi/{package}/json"
DEFAULT_TIMEOUT = 5.0
DEFAULT_MAX_WORKERS = 8
DEFAULT_MAX_WAIT = 6.0
USER_AGENT = "dev-efficiency-agent/1.0"
_HEADERS = {"User-Agent": USER_AGENT, "Accept": "application/json"}

# 常见「导入名 → PyPI 发行名」不一致的情况，避免把真实依赖误报为幻觉依赖。
IMPORT_ALIASES = {
    "pil": "pillow",
    "cv2": "opencv-python",
    "sklearn": "scikit-learn",
    "skimage": "scikit-image",
    "yaml": "pyyaml",
    "bs4": "beautifulsoup4",
    "dateutil": "python-dateutil",
    "dotenv": "python-dotenv",
    "jwt": "pyjwt",
    "jose": "python-jose",
    "crypto": "pycryptodome",
    "openssl": "pyopenssl",
    "attr": "attrs",
    "pkg_resources": "setuptools",
    "mysqldb": "mysqlclient",
    "serial": "pyserial",
    "usb": "pyusb",
    "zmq": "pyzmq",
    "fitz": "pymupdf",
    "docx": "python-docx",
    "pptx": "python-pptx",
    "magic": "python-magic",
    "multipart": "python-multipart",
    "pylab": "matplotlib",
    "mpl_toolkits": "matplotlib",
    "ruamel": "ruamel.yaml",
    "wx": "wxpython",
    "gi": "pygobject",
    "win32api": "pywin32",
    "win32con": "pywin32",
    "win32com": "pywin32",
    "win32file": "pywin32",
    "win32gui": "pywin32",
    "win32process": "pywin32",
    "win32service": "pywin32",
    "win32serviceutil": "pywin32",
}

_STDLIB = frozenset(getattr(sys, "stdlib_module_names", ())) | frozenset(
    sys.builtin_module_names
)
_SKIP_MODULES = _STDLIB | {"__future__"}
_NORMALIZE_PATTERN = re.compile(r"[-_.]+")


@dataclass(frozen=True)
class ImportReference:
    """源码中的一处第三方导入。"""

    name: str
    candidates: tuple[str, ...]
    file: str
    line: int

    @property
    def distribution(self) -> str:
        """优先展示的 PyPI 包名。"""
        return self.candidates[0] if self.candidates else self.name


@dataclass(frozen=True)
class PackageFetchResult:
    """单个 PyPI 包名查询结果。"""

    exists: bool | None
    detail: str


@dataclass(frozen=True)
class PackageStatus:
    """汇总后的依赖校验状态（按导入名去重）。"""

    name: str
    distribution: str
    exists: bool | None
    detail: str = ""

    @property
    def label(self) -> str:
        """供页面和报告展示的状态文本。"""
        if self.exists is True:
            return "✅ 存在"
        if self.exists is False:
            return "❌ 幻觉依赖风险"
        return "⚠️ 未验证"


@dataclass
class DependencyReport:
    """一次依赖真实性校验的汇总结果。"""

    references: list[ImportReference] = field(default_factory=list)
    statuses: dict[str, PackageStatus] = field(default_factory=dict)

    @property
    def missing(self) -> list[PackageStatus]:
        """PyPI 中确认不存在的依赖（幻觉依赖风险）。"""
        return [item for item in self.statuses.values() if item.exists is False]

    @property
    def unknown(self) -> list[PackageStatus]:
        """因网络问题未能完成校验的依赖。"""
        return [item for item in self.statuses.values() if item.exists is None]

    @property
    def existing(self) -> list[PackageStatus]:
        """确认存在的依赖。"""
        return [item for item in self.statuses.values() if item.exists is True]

    def references_for(self, name: str) -> list[ImportReference]:
        """返回某个导入名的全部引用位置。"""
        key = name.casefold()
        return [item for item in self.references if item.name.casefold() == key]


def extract_imports(
    sources: dict[str, str],
    local_modules: set[str] | None = None,
) -> list[ImportReference]:
    """从源码中提取第三方 import，跳过标准库、相对导入和项目内模块。"""
    local = {name.casefold() for name in (local_modules or set())}
    local |= _discover_local_modules(sources)

    references: list[ImportReference] = []
    seen: set[tuple[str, str, int]] = set()

    for filename, source in sources.items():
        try:
            tree = ast.parse(source, filename=filename)
        except (SyntaxError, ValueError, RecursionError):
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level or not node.module:
                    continue
                names = [node.module.split(".")[0]]
            else:
                continue

            for name in names:
                key = name.casefold()
                if not name or key in _SKIP_MODULES or key in local:
                    continue
                dedupe_key = (key, filename, node.lineno)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                references.append(
                    ImportReference(
                        name=name,
                        candidates=tuple(_distribution_candidates(name)),
                        file=filename,
                        line=node.lineno,
                    )
                )

    references.sort(key=lambda item: (item.file, item.line, item.name.casefold()))
    return references


def fetch_distribution(
    distribution: str,
    timeout: float = DEFAULT_TIMEOUT,
    fetcher: Callable[..., Any] | None = None,
) -> PackageFetchResult:
    """查询一个 PyPI 发行名，网络异常时返回 unknown 而不是抛出异常。"""
    fetch = fetcher or requests.head
    url = PYPI_JSON_URL.format(package=quote(distribution, safe=""))
    try:
        # 只关心状态码：HEAD 请求不会下载部分大包的完整 JSON（例如 Pillow）。
        response = fetch(
            url,
            headers=_HEADERS,
            timeout=timeout,
            allow_redirects=True,
        )
    except requests.Timeout:
        return PackageFetchResult(None, "网络超时")
    except requests.RequestException as exc:
        return PackageFetchResult(None, f"网络错误：{exc.__class__.__name__}")
    except Exception as exc:  # 校验逻辑本身不应影响主扫描流程
        return PackageFetchResult(None, f"校验异常：{exc.__class__.__name__}")

    status = getattr(response, "status_code", None)
    closer = getattr(response, "close", None)
    if callable(closer):
        closer()
    if status == 200:
        return PackageFetchResult(True, "PyPI 上存在该包")
    if status == 404:
        return PackageFetchResult(False, "PyPI 返回 404，不存在该包")
    if status == 429:
        return PackageFetchResult(None, "PyPI 请求频率受限（HTTP 429）")
    return PackageFetchResult(None, f"PyPI 返回 HTTP {status}")


def verify_dependencies(
    references: list[ImportReference],
    cache: MutableMapping[str, PackageFetchResult] | None = None,
    fetcher: Callable[..., Any] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_workers: int = DEFAULT_MAX_WORKERS,
    max_wait: float | None = DEFAULT_MAX_WAIT,
) -> DependencyReport:
    """并发校验依赖；总等待时间有上限，网络问题不会影响主扫描结果。"""
    if not references:
        return DependencyReport(references=[], statuses={})

    candidates: list[str] = []
    seen_candidates: set[str] = set()
    for reference in references:
        for candidate in reference.candidates:
            if candidate and candidate not in seen_candidates:
                seen_candidates.add(candidate)
                candidates.append(candidate)

    results: dict[str, PackageFetchResult] = dict(cache or {})
    pending = [name for name in candidates if name not in results]
    if pending:
        executor = ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(pending))))
        futures = {
            executor.submit(fetch_distribution, name, timeout, fetcher): name
            for name in pending
        }
        done, not_done = wait(futures, timeout=max_wait)

        for future in done:
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception as exc:  # 单个查询失败不影响其他依赖
                results[name] = PackageFetchResult(
                    None, f"校验异常：{exc.__class__.__name__}"
                )
        for future in not_done:
            name = futures[future]
            results[name] = PackageFetchResult(None, "校验超时")
            future.cancel()
        executor.shutdown(wait=False, cancel_futures=True)

    if cache is not None:
        cache.update(results)

    statuses: dict[str, PackageStatus] = {}
    for reference in references:
        key = reference.name.casefold()
        if key in statuses:
            continue
        statuses[key] = _resolve_status(reference, results)
    return DependencyReport(references=references, statuses=statuses)


def _resolve_status(
    reference: ImportReference,
    results: dict[str, PackageFetchResult],
) -> PackageStatus:
    """按候选包名顺序判断依赖是否存在；别名优先，原始导入名兜底。"""
    unknown_detail = ""
    for candidate in reference.candidates:
        result = results.get(candidate)
        if result is None:
            unknown_detail = unknown_detail or "未获得校验结果"
            continue
        if result.exists is True:
            return PackageStatus(
                reference.name, candidate, True, result.detail
            )
        if result.exists is None:
            unknown_detail = unknown_detail or result.detail

    if unknown_detail:
        return PackageStatus(
            reference.name,
            reference.distribution,
            None,
            unknown_detail,
        )
    return PackageStatus(
        reference.name,
        reference.distribution,
        False,
        "PyPI 返回 404，不存在该包",
    )


def _distribution_candidates(name: str) -> list[str]:
    """返回按优先级排列的 PyPI 候选包名。"""
    candidates: list[str] = []
    alias = IMPORT_ALIASES.get(name.casefold())
    for candidate in (alias, _normalize_distribution(name)):
        if candidate and candidate not in candidates:
            candidates.append(candidate)
    return candidates


def _normalize_distribution(name: str) -> str:
    """按 PEP 503 规范化 PyPI 发行名。"""
    return _NORMALIZE_PATTERN.sub("-", name).strip("-").lower()


def _discover_local_modules(sources: dict[str, str]) -> set[str]:
    """从扫描到的源码路径推断项目内顶层模块名。"""
    names: set[str] = set()
    for filename in sources:
        parts = PurePosixPath(filename).parts
        if not parts:
            continue
        first = parts[0]
        if first.endswith(".py"):
            first = first[:-3]
        if first:
            names.add(first.casefold())
        if len(parts) == 1:
            stem = PurePosixPath(filename).stem
            if stem:
                names.add(stem.casefold())
    return names
