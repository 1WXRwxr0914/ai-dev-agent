"""预检结果的数据模型。"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """问题严重级别，权重用于文件评分扣分。"""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def label(self) -> str:
        """返回中文级别名称。"""
        return {"high": "严重", "medium": "警告", "low": "提示"}[self.value]

    @property
    def weight(self) -> int:
        """返回该级别在评分中扣除的分数。"""
        return {"high": 10, "medium": 4, "low": 1}[self.value]

    @classmethod
    def parse(cls, value: str) -> "Severity":
        """把命令行字符串转换为级别枚举。"""
        try:
            return cls(value.lower())
        except ValueError as exc:
            raise ValueError(f"未知的严重级别: {value}") from exc


@dataclass(frozen=True)
class Issue:
    """单条检查结论。"""

    rule: str
    name: str
    severity: Severity
    message: str
    file: str
    line: int
    evidence: str = ""
    suggestion: str = ""

    def to_dict(self) -> dict[str, Any]:
        """转换为可 JSON 序列化的字典。"""
        return {
            "rule": self.rule,
            "name": self.name,
            "severity": self.severity.value,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence,
            "suggestion": self.suggestion,
        }


@dataclass
class FileReport:
    """单个文件的检查结果。"""

    path: str
    issues: list[Issue] = field(default_factory=list)
    line_count: int = 0
    elapsed: float = 0.0

    @property
    def score(self) -> int:
        """100 分减去所有问题扣分，最低 0 分。"""
        deduction = sum(issue.severity.weight for issue in self.issues)
        return max(0, 100 - deduction)

    @property
    def rating(self) -> str:
        """返回文件得分对应的评级。"""
        return rating_for(self.score)

    @property
    def counts(self) -> dict[str, int]:
        """按级别统计问题数量。"""
        return {item.value: self.count(item) for item in Severity}

    @property
    def passed(self) -> bool:
        """没有任何问题时视为通过。"""
        return not self.issues

    def count(self, severity: Severity) -> int:
        """统计指定级别的问题数量。"""
        return sum(1 for issue in self.issues if issue.severity is severity)

    def to_dict(self) -> dict[str, Any]:
        """转换为可 JSON 序列化的字典。"""
        return {
            "path": self.path,
            "score": self.score,
            "rating": self.rating,
            "line_count": self.line_count,
            "elapsed": round(self.elapsed, 4),
            "counts": self.counts,
            "issues": [issue.to_dict() for issue in self.issues],
        }


@dataclass
class ScanReport:
    """一次完整扫描的汇总结果。"""

    target: str
    files: list[FileReport] = field(default_factory=list)
    elapsed: float = 0.0

    @property
    def score(self) -> int:
        """所有文件得分的平均值。"""
        if not self.files:
            return 100
        return round(sum(item.score for item in self.files) / len(self.files))

    @property
    def rating(self) -> str:
        """返回综合得分对应的评级。"""
        return rating_for(self.score)

    @property
    def total_issues(self) -> int:
        """所有文件的问题总数。"""
        return sum(len(item.issues) for item in self.files)

    @property
    def counts(self) -> dict[str, int]:
        """按级别统计全部问题数量。"""
        return {
            severity.value: sum(item.count(severity) for item in self.files)
            for severity in Severity
        }

    def to_dict(self) -> dict[str, Any]:
        """转换为可 JSON 序列化的字典。"""
        return {
            "target": self.target,
            "score": self.score,
            "rating": self.rating,
            "file_count": len(self.files),
            "total_issues": self.total_issues,
            "counts": self.counts,
            "elapsed": round(self.elapsed, 4),
            "files": [item.to_dict() for item in self.files],
        }


def rating_for(score: int) -> str:
    """把 0-100 的分数映射为中文评级。"""
    if score >= 90:
        return "优秀"
    if score >= 75:
        return "良好"
    if score >= 60:
        return "需改进"
    return "风险较高"
