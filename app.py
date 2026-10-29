"""AI 代码安全预检 Agent 的 Streamlit 演示界面。

启动方式:
    streamlit run app.py

上传的 .py 文件会先写入临时目录，再交给 checker.CheckEngine 做静态扫描；
扫描过程只解析 AST，不会执行上传的代码。
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import os
import tempfile
from pathlib import Path

import pandas as pd
import requests
import streamlit as st

from checker import CheckEngine, ScanReport, Severity

APP_TITLE = "AI代码安全预检Agent"
APP_SUBTITLE = "上传 Python 文件，快速发现安全风险与代码异味"

# 演示账号；可通过环境变量覆盖（比赛提交时把账号密码随链接一并提供即可）。
LOGIN_USER = os.getenv("APP_LOGIN_USER", "admin")
LOGIN_PASSWORD = os.getenv("APP_LOGIN_PASSWORD", "123456")

# DeepSeek 使用 OpenAI 兼容接口；可通过环境变量覆盖。
DEEPSEEK_API_URL = os.getenv("DEEPSEEK_API_URL", "https://api.deepseek.com/v1/chat/completions")
DEEPSEEK_MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
DEEPSEEK_TIMEOUT = 90

SYSTEM_PROMPT = (
    "你是一位资深 Python 安全工程师，擅长在不改变业务逻辑的前提下修复安全漏洞。"
    "你只输出可直接替换原位置的代码，不输出任何解释或 Markdown 代码块标记。"
)

# 展示用的级别名称和配色（背景色, 文字色）。
SEVERITY_TEXT = {
    Severity.HIGH: "高危",
    Severity.MEDIUM: "中危",
    Severity.LOW: "低危",
}
SEVERITY_STYLE = {
    "高危": "background-color: #fdecea; color: #c62828; font-weight: 600;",
    "中危": "background-color: #fff4e0; color: #b26a00; font-weight: 600;",
    "低危": "background-color: #e8f5e9; color: #2e7d32; font-weight: 600;",
}
RISK_STYLE = {
    "高危": ("#fdecea", "#c62828"),
    "中危": ("#fff4e0", "#b26a00"),
    "低危": ("#e8f5e9", "#2e7d32"),
    "安全": ("#e8f5e9", "#2e7d32"),
}
_CARD_CSS = (
    "border-radius: 12px; padding: 14px 18px; height: 100%;"
    "border: 1px solid rgba(0, 0, 0, 0.08);"
)


def is_authenticated() -> bool:
    """当前会话是否已通过登录校验。"""
    return bool(st.session_state.get("authenticated", False))


def render_login() -> None:
    """渲染登录页：校验通过前不显示任何扫描功能。"""
    st.markdown(
        f"""
        <div style="text-align: center; padding: 2.4rem 0 0.6rem 0;">
            <h1 style="margin-bottom: 0.3rem;">🛡️ {APP_TITLE}</h1>
            <p style="color: #6b7280; font-size: 1.05rem; margin-top: 0;">请先登录后使用代码预检功能</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    _, form_col, _ = st.columns([1, 1.4, 1])
    with form_col:
        with st.form("login_form", clear_on_submit=False):
            username = st.text_input("账号", placeholder="请输入账号", autocomplete="username")
            password = st.text_input(
                "密码",
                type="password",
                placeholder="请输入密码",
                autocomplete="current-password",
            )
            submitted = st.form_submit_button("登录", type="primary", use_container_width=True)

    if not submitted:
        return

    user_ok = hmac.compare_digest(username.strip(), LOGIN_USER)
    password_ok = hmac.compare_digest(password, LOGIN_PASSWORD)
    if user_ok and password_ok:
        st.session_state["authenticated"] = True
        st.session_state["login_user"] = LOGIN_USER
        st.rerun()
    else:
        st.error("账号或密码错误，请重新输入。")


def scan_uploaded_file(filename: str, content: bytes) -> ScanReport:
    """把上传内容写入临时 .py 文件，调用现有引擎扫描后返回报告。"""
    safe_name = Path(filename).name or "uploaded.py"
    with tempfile.TemporaryDirectory(prefix="precheck_") as tmp_dir:
        path = Path(tmp_dir) / safe_name
        path.write_bytes(content)
        return CheckEngine().run(path)


def risk_level(report: ScanReport) -> str:
    """按最严重的问题级别确定综合风险等级。"""
    counts = report.counts
    if counts["high"]:
        return "高危"
    if counts["medium"]:
        return "中危"
    if counts["low"]:
        return "低危"
    return "安全"


def render_header() -> None:
    """渲染标题与说明。"""
    st.markdown(
        f"""
        <div style="text-align: center; padding: 1.2rem 0 0.4rem 0;">
            <h1 style="margin-bottom: 0.3rem;">🛡️ {APP_TITLE}</h1>
            <p style="color: #6b7280; font-size: 1.05rem; margin-top: 0;">{APP_SUBTITLE}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_stat_card(label: str, value: str, background: str, color: str, note: str = "") -> None:
    """渲染一张彩色统计卡片。"""
    note_html = f'<div style="font-size: 0.8rem; color: #6b7280;">{note}</div>' if note else ""
    st.markdown(
        f"""
        <div style="{_CARD_CSS} background: {background};">
            <div style="font-size: 0.85rem; color: #5f6368;">{label}</div>
            <div style="font-size: 2rem; font-weight: 700; color: {color}; line-height: 1.25;">{value}</div>
            {note_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_summary(report: ScanReport) -> None:
    """展示综合得分、风险等级和问题统计。"""
    level = risk_level(report)
    level_bg, level_fg = RISK_STYLE[level]
    counts = report.counts

    score_col, risk_col, issue_col = st.columns([1, 1, 1.1])
    with score_col:
        render_stat_card("综合得分", f"{report.score} / 100", "#f8fafc", "#1f2937", f"评级：{report.rating}")
    with risk_col:
        render_stat_card("风险等级", level, level_bg, level_fg, "按最严重的问题判定")
    with issue_col:
        note = (
            f'<span style="color:#c62828;">高危 {counts["high"]}</span> · '
            f'<span style="color:#b26a00;">中危 {counts["medium"]}</span> · '
            f'<span style="color:#2e7d32;">低危 {counts["low"]}</span>'
        )
        render_stat_card("问题统计", str(report.total_issues), "#f8fafc", "#1f2937", note)

    st.progress(min(max(report.score, 0), 100) / 100)


def build_issue_table(report: ScanReport) -> pd.DataFrame:
    """把扫描结果转换为表格数据。"""
    rows = [
        {
            "级别": SEVERITY_TEXT[issue.severity],
            "行号": issue.line if issue.line > 0 else "文件级",
            "规则": issue.rule,
            "检查项": issue.name,
            "问题描述": issue.message,
            "代码片段": issue.evidence,
            "修复建议": issue.suggestion,
        }
        for file_report in report.files
        for issue in file_report.issues
    ]
    return pd.DataFrame(rows)


def render_issues(report: ScanReport) -> None:
    """用表格展示漏洞明细；高危标红、低危标绿。"""
    st.subheader("漏洞明细")
    frame = build_issue_table(report)

    if frame.empty:
        st.success("未发现任何问题，代码预检通过 ✅")
        return

    styled = frame.style.map(
        lambda value: SEVERITY_STYLE.get(value, ""),
        subset=["级别"],
    )
    st.dataframe(styled, width="stretch", hide_index=True)
    st.caption(f"共 {len(frame)} 条问题，按严重程度排序。")


def _env_api_key() -> str:
    """优先读取环境变量，其次读取 Streamlit secrets 中的 DeepSeek 密钥。"""
    key = os.getenv("DEEPSEEK_API_KEY", "").strip()
    if key:
        return key
    try:
        return str(st.secrets.get("deepseek_api_key", "")).strip()
    except Exception:  # 未创建 secrets.toml 时 st.secrets 可能抛出异常
        return ""


def render_api_config() -> str:
    """在侧边栏展示 DeepSeek 配置，返回本次使用的 API Key。"""
    env_key = _env_api_key()
    with st.sidebar:
        st.header("⚙️ AI 修复配置")
        typed = st.text_input(
            "DeepSeek API Key",
            type="password",
            placeholder="已从环境变量读取" if env_key else "sk-...",
            help="留空时使用环境变量 DEEPSEEK_API_KEY 或 .streamlit/secrets.toml 中的 deepseek_api_key。",
        )
        model = st.text_input("模型名称", value=DEEPSEEK_MODEL)
        st.caption("接口地址：`DEEPSEEK_API_URL` 环境变量可覆盖。")
        st.session_state["deepseek_model"] = model.strip() or DEEPSEEK_MODEL

        st.divider()
        st.caption(f"当前账号：{st.session_state.get('login_user', '')}")
        if st.button("退出登录", use_container_width=True):
            st.session_state.pop("authenticated", None)
            st.session_state.pop("login_user", None)
            st.rerun()
    return typed.strip() or env_key


def extract_code_snippet(source: str, line: int) -> tuple[int, int, str]:
    """提取问题所在的代码片段，返回（起始行, 结束行, 代码文本）。

    优先取问题所在的函数/类；函数过大或问题属于文件级时，退化为行号附近的窗口。
    """
    lines = source.splitlines()
    total = len(lines)
    if total == 0:
        return 1, 0, ""
    if line <= 0:  # 语法错误、规则失败等文件级问题：给出文件开头部分
        end = min(total, 200)
        return 1, end, "\n".join(lines[:end])

    line = min(max(line, 1), total)
    try:
        tree = ast.parse(source)
    except SyntaxError:
        tree = None

    if tree is not None:
        best: tuple[int, int] | None = None
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                start = node.lineno
                end = getattr(node, "end_lineno", None) or start
                if start <= line <= end and (best is None or end - start < best[1] - best[0]):
                    best = (start, end)
        if best and best[1] - best[0] + 1 <= 80:
            return best[0], best[1], "\n".join(lines[best[0] - 1:best[1]])

    start = max(1, line - 8)
    end = min(total, line + 8)
    return start, end, "\n".join(lines[start - 1:end])


def build_fix_prompt(
    filename: str,
    start: int,
    end: int,
    snippet: str,
    issues: list,
) -> str:
    """构造发送给 DeepSeek 的修复提示词。"""
    problems = "\n".join(
        f"- 第 {issue.line if issue.line > 0 else '文件级'} 行 [{issue.rule} {issue.name}]："
        f"{issue.message}；修复建议：{issue.suggestion or '按安全最佳实践修复'}"
        for issue in issues
    )
    return f"""以下代码摘自 Python 文件 `{filename}` 的第 {start}-{end} 行：

```python
{snippet}
```

需要修复的高危问题：
{problems}

要求：
1. 只修复上述安全问题，保持原有业务逻辑、函数签名、缩进和命名不变；
2. 不引入第三方依赖；
3. 硬编码密钥类问题改为从环境变量读取（如 os.environ.get("XXX")），缺少 import 时补充；
4. 只输出修复后的完整代码片段（对应上面第 {start}-{end} 行的内容），不要输出解释，不要使用 Markdown 代码块。"""


def strip_code_fence(text: str) -> str:
    """去掉模型偶尔附带的 Markdown 代码块围栏。"""
    lines = text.strip().splitlines()
    if lines and lines[0].strip().startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip().startswith("```"):
        lines = lines[:-1]
    return "\n".join(lines).strip("\n")


def call_deepseek(api_key: str, prompt: str) -> str:
    """调用 DeepSeek 对话接口，返回修复后的代码。"""
    model = st.session_state.get("deepseek_model", DEEPSEEK_MODEL)
    response = requests.post(
        DEEPSEEK_API_URL,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "stream": False,
        },
        timeout=DEEPSEEK_TIMEOUT,
    )
    if response.status_code != 200:
        raise RuntimeError(f"DeepSeek 接口返回 {response.status_code}：{response.text[:200]}")
    try:
        content = response.json()["choices"][0]["message"]["content"]
    except (KeyError, IndexError, ValueError) as exc:
        raise RuntimeError(f"无法解析 DeepSeek 响应：{response.text[:200]}") from exc
    fixed = strip_code_fence(content)
    if not fixed.strip():
        raise RuntimeError("DeepSeek 返回了空内容")
    return fixed


def _fix_cache_key(source: str, rule: str, line: int) -> str:
    """用文件内容哈希 + 规则 + 行号作为修复结果缓存键。"""
    digest = hashlib.sha1(source.encode("utf-8", errors="replace")).hexdigest()[:12]
    return f"{digest}:{rule}:{line}"


def render_ai_fix(report: ScanReport, source: str, filename: str, api_key: str) -> None:
    """在漏洞表格下方提供「一键 AI 修复」并展示修复前后对比。"""
    high_issues = [
        issue
        for file_report in report.files
        for issue in file_report.issues
        if issue.severity is Severity.HIGH
    ]
    if not high_issues:
        return

    st.divider()
    st.subheader("🤖 AI 一键修复")
    st.caption(
        f"检测到 **{len(high_issues)}** 个高危问题，可调用 DeepSeek 自动生成修复代码；"
        "右侧修复结果可直接复制替换原片段。"
    )

    if not api_key:
        st.warning(
            "尚未配置 DeepSeek API Key：请在左侧侧边栏填写，"
            "或设置环境变量 `DEEPSEEK_API_KEY`（也支持 `.streamlit/secrets.toml` 中的 `deepseek_api_key`）。"
        )

    cache: dict[str, dict] = st.session_state.setdefault("ai_fix_cache", {})
    clicked = st.button(
        "🔧 一键 AI 修复",
        type="primary",
        use_container_width=True,
        disabled=not api_key,
        help="逐个提取高危代码片段，调用 DeepSeek 生成修复版本。",
    )

    if clicked:
        errors = 0
        progress = st.progress(0.0, text="正在调用 DeepSeek...")
        for index, issue in enumerate(high_issues, start=1):
            key = _fix_cache_key(source, issue.rule, issue.line)
            if key in cache:
                progress.progress(index / len(high_issues), text=f"已完成 {index}/{len(high_issues)}")
                continue
            start, end, snippet = extract_code_snippet(source, issue.line)
            try:
                fixed = call_deepseek(api_key, build_fix_prompt(filename, start, end, snippet, [issue]))
                cache[key] = {"start": start, "end": end, "before": snippet, "after": fixed}
            except Exception as exc:  # 单个问题失败不影响其他问题
                errors += 1
                cache[key] = {"start": start, "end": end, "before": snippet, "error": str(exc)}
            progress.progress(index / len(high_issues), text=f"已完成 {index}/{len(high_issues)}")
        progress.empty()
        if errors:
            st.error(f"有 {errors} 个问题修复失败，详情见下方。")
        else:
            st.success("AI 修复完成，请在下方对比并复制代码。")

    shown = 0
    for position, issue in enumerate(high_issues):
        entry = cache.get(_fix_cache_key(source, issue.rule, issue.line))
        if entry is None:
            continue
        shown += 1
        st.markdown(f"#### 第 {issue.line if issue.line > 0 else '文件级'} 行 · {issue.name}（{issue.rule}）")
        st.caption(f"{issue.message} · 修复建议：{issue.suggestion}")
        if "error" in entry:
            st.error(f"修复失败：{entry['error']}")
            continue

        before_col, after_col = st.columns(2)
        with before_col:
            st.markdown("**❌ 修复前**")
            st.code(entry["before"], language="python", line_numbers=True)
        with after_col:
            st.markdown("**✅ 修复后（点击右上角复制）**")
            st.code(entry["after"], language="python", line_numbers=True)

        st.download_button(
            "⬇️ 下载修复后的代码片段",
            data=entry["after"],
            file_name=f"{Path(filename).stem}_fixed_L{entry['start']}-{entry['end']}.py",
            mime="text/x-python",
            key=f"download_fix_{position}_{issue.rule}_{issue.line}",
        )

    if shown == 0 and not clicked:
        st.caption("点击上方按钮开始修复。")


def main() -> None:
    """页面入口。"""
    st.set_page_config(page_title=APP_TITLE, page_icon="🛡️", layout="centered")

    if not is_authenticated():
        render_login()
        st.stop()

    render_header()
    api_key = render_api_config()

    uploaded = st.file_uploader(
        "上传需要预检的 Python 文件（仅支持 .py）",
        type=["py"],
        accept_multiple_files=False,
    )

    if uploaded is None:
        st.info("请上传一个 .py 文件开始扫描。")
        st.caption("提示：本工具只做静态分析，不会执行上传的代码。")
        return

    filename = Path(uploaded.name).name or "uploaded.py"
    content = uploaded.getvalue()
    source = content.decode("utf-8", errors="replace")
    with st.spinner("正在扫描，请稍候..."):
        try:
            report = scan_uploaded_file(filename, content)
        except Exception as exc:  # 页面不应因单次扫描异常而崩溃
            st.error(f"扫描失败：{exc}")
            return

    st.caption(
        f"已扫描 **{filename}** · "
        f"{report.files[0].line_count if report.files else 0} 行 · "
        f"耗时 {report.elapsed:.3f}s"
    )
    render_summary(report)
    st.divider()
    render_issues(report)
    render_ai_fix(report, source, filename, api_key)
    st.caption("⚠️ 预检结果与 AI 修复建议仅供参考，请结合人工复核后再合并代码。")


main()
