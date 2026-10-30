"""演示服务模块：调用 data_utils 生成统计摘要。"""

import data_utils


def summarize_rows(rows):
    """返回输入数据的统计摘要。"""
    return data_utils.profile(rows)
