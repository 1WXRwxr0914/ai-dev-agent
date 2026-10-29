"""演示用的干净模块：不应触发任何检查项。"""

from dataclasses import dataclass


PASSING_SCORE = 60


@dataclass
class Grade:
    """一次评分结果。"""

    score: int
    comment: str


def grade_of(score):
    """根据分数返回评级说明。"""
    if score >= 90:
        return "优秀"
    if score >= 75:
        return "良好"
    if score >= PASSING_SCORE:
        return "需改进"
    return "风险较高"


def build_grades(scores):
    """把分数列表转换成独立的评分对象。"""
    return [Grade(score=value, comment=grade_of(value)) for value in scores]
