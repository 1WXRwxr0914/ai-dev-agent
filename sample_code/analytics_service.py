"""演示服务模块：复用 data_utils 的归一化能力。"""

from data_utils import normalize


def normalize_scores(values):
    """把分数归一化到 0-1 区间。"""
    return normalize(values)
