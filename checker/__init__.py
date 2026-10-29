"""开发者效率预检 Agent 的核心包。"""

from .engine import CheckEngine
from .markdown import render_file_markdown, write_file_reports
from .models import FileReport, Issue, ScanReport, Severity

__version__ = "1.0.0"

__all__ = [
    "CheckEngine",
    "FileReport",
    "Issue",
    "ScanReport",
    "Severity",
    "render_file_markdown",
    "write_file_reports",
    "__version__",
]
