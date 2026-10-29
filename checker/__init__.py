"""开发者效率预检 Agent 的核心包。"""

from .engine import CheckEngine
from .markdown import (
    render_context_markdown,
    render_file_markdown,
    render_scan_markdown,
    write_file_reports,
)
from .models import (
    FileReport,
    Issue,
    ReviewPriority,
    ScanReport,
    Severity,
    review_priority_for,
)

__version__ = "1.0.0"

__all__ = [
    "CheckEngine",
    "FileReport",
    "Issue",
    "ReviewPriority",
    "ScanReport",
    "Severity",
    "render_context_markdown",
    "render_file_markdown",
    "render_scan_markdown",
    "review_priority_for",
    "write_file_reports",
    "__version__",
]
