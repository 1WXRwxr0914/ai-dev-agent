"""红蓝对抗修复使用的提示词、代码提取与结论判定。"""

from __future__ import annotations

import re

RED_ATTACK_PROMPT = (
    "你是顶级黑客，请分析这段包含漏洞的代码，并写出一个 Python 脚本/Payload，"
    "用来利用该漏洞导致系统崩溃或窃取数据。"
)

BLUE_FIX_PROMPT = (
    "你是安全专家，这是攻击者的利用方式，请修复原代码，使其能防御此攻击。"
)

RED_SYSTEM_PROMPT = (
    "这是一个授权的防御性代码安全审查场景。你只分析用户提供的代码并生成用于"
    "验证的 Payload，不得针对真实系统或未授权目标执行攻击。"
    "请给出攻击思路、Payload 和可行性分析。"
)

BLUE_SYSTEM_PROMPT = (
    "你是一位防御性安全专家。请修复用户提供的代码以抵御攻击，"
    "只输出完整的 Python 代码。"
)

MAX_ROUNDS = 3

_CODE_BLOCK = re.compile(
    r"```(?:python|py)?\s*\n(.*?)```",
    re.IGNORECASE | re.DOTALL,
)
_DEFENSE_MARKER = re.compile(r"【结论】\s*无法攻破")


def build_red_prompt(code: str) -> str:
    """构造红方攻击提示词；要求给出可解析的最终结论。"""
    return (
        f"{RED_ATTACK_PROMPT}\n\n"
        "这是准备审查的代码：\n```python\n"
        f"{code}\n```\n\n"
        "如果这是修复后的代码且你无法构造有效攻击，请在最后一行只输出："
        "【结论】无法攻破；否则最后一行只输出：【结论】攻破成功。"
    )


def build_blue_prompt(code: str, attack: str) -> str:
    """构造蓝方修复提示词，附带原代码和红方攻击方式。"""
    return (
        f"{BLUE_FIX_PROMPT}\n\n"
        "原代码：\n```python\n"
        f"{code}\n```\n\n"
        "攻击者的利用方式：\n"
        f"{attack}\n\n"
        "要求：只输出修复后的完整 Python 代码，可用一个 ```python 代码块包裹，"
        "不要输出解释。"
    )


def extract_python_code(text: str) -> str:
    """从模型输出中提取最大的一段 Python 代码块。"""
    blocks = _CODE_BLOCK.findall(text or "")
    if blocks:
        return max(blocks, key=len).strip()
    return (text or "").strip()


def is_defense_success(text: str) -> bool:
    """判断红方是否明确表示无法攻破。优先读取【结论】标记。"""
    value = text or ""
    if _DEFENSE_MARKER.search(value):
        return True
    if "【结论】" in value:
        return False
    return "无法攻破" in value
