"""AI 代码安全预检 Agent 的 Streamlit 演示界面（双引擎）。

启动方式:
    streamlit run app.py

双引擎：
1. 安全扫描与修复：上传的 .py 文件会先写入临时目录，再交给
   checker.CheckEngine 做 AST 静态扫描，不会执行上传的代码；
2. 上下文健康检查：扫描项目目录内的 .py 文件，统计行数与体积，
   对超过 300 行的大文件给出上下文污染预警，并汇总 TODO / FIXME 债务。
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import os
import tempfile
from pathlib import Path

import altair as alt
import pandas as pd
import requests
import streamlit as st

from checker import CheckEngine, ScanReport, Severity
from checker.context_health import (
    LINE_THRESHOLD,
    ContextHealthReport,
    resolve_target,
    scan_context_health,
)

APP_TITLE = "AI代码安全预检Agent"
APP_SUBTITLE = "上传 Python 文件，快速发现安全风险与代码异味"

PAGE_SCAN = "🛡️ 安全扫描与修复"
PAGE_CONTEXT = "📊 上下文健康检查"
PAGE_META = {
    PAGE_SCAN: ("🛡️", APP_TITLE, APP_SUBTITLE),
    PAGE_CONTEXT: (
        "📊",
        "AI 上下文健康检查",
        "扫描目录体积与 TODO / FIXME 债务，防止代码撑爆 AI 的 Token 窗口",
    ),
}

PROJECT_ROOT = Path(__file__).resolve().parent
_scan_root_env = os.getenv("CONTEXT_SCAN_ROOT", "").strip()
CONTEXT_SCAN_ROOT = (
    Path(_scan_root_env).expanduser().resolve() if _scan_root_env else PROJECT_ROOT
)

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
DEBT_STYLE = {
    "TODO": "background-color: #fff4e0; color: #b26a00; font-weight: 600;",
    "FIXME": "background-color: #fdecea; color: #c62828; font-weight: 600;",
}

# 图表配色：级别颜色沿用页面已有的红/橙/绿语义色，
# 普通柱使用中性蓝，仅超限柱切换为红色（强调而不是分类）。
SEVERITY_ORDER = [
    SEVERITY_TEXT[Severity.HIGH],
    SEVERITY_TEXT[Severity.MEDIUM],
    SEVERITY_TEXT[Severity.LOW],
]
SEVERITY_COLORS = {
    SEVERITY_TEXT[Severity.HIGH]: "#c62828",
    SEVERITY_TEXT[Severity.MEDIUM]: "#b26a00",
    SEVERITY_TEXT[Severity.LOW]: "#2e7d32",
}
CHART_BLUE = "#2a78d6"
CHART_RED = "#c62828"
CHART_INK = "#374151"
CHART_MUTED = "#6b7280"
CHART_GRID = "#e5e7eb"
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


def render_sidebar() -> str:
    """渲染左侧功能导航，返回当前选中的页面。"""
    with st.sidebar:
        st.markdown("### 🧭 功能导航")
        page = st.radio(
            "功能导航",
            list(PAGE_META),
            key="active_page",
            label_visibility="collapsed",
        )
    return page


def render_header(page: str) -> None:
    """渲染当前页面的标题与说明。"""
    icon, title, subtitle = PAGE_META[page]
    st.markdown(
        f"""
        <div style="text-align: center; padding: 1.2rem 0 0.4rem 0;">
            <h1 style="margin-bottom: 0.3rem;">{icon} {title}</h1>
            <p style="color: #6b7280; font-size: 1.05rem; margin-top: 0;">{subtitle}</p>
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


def build_severity_chart(report: ScanReport) -> alt.LayerChart | None:
    """构建高/中/低危漏洞占比环形图；没有问题时返回 None。"""
    counts = report.counts
    data = pd.DataFrame(
        {
            "级别": SEVERITY_ORDER,
            "数量": [counts["high"], counts["medium"], counts["low"]],
        }
    )
    total = int(data["数量"].sum())
    if total == 0:
        return None
    data["占比"] = data["数量"] / total
    data["排序"] = range(len(data))
    visible = data[data["数量"] > 0]

    arcs = (
        alt.Chart(visible)
        .mark_arc(innerRadius=62, outerRadius=102, stroke="#ffffff", strokeWidth=2)
        .encode(
            theta=alt.Theta("数量:Q", stack=True),
            order=alt.Order("排序:Q"),
            color=alt.Color(
                "级别:N",
                scale=alt.Scale(
                    domain=SEVERITY_ORDER,
                    range=[SEVERITY_COLORS[level] for level in SEVERITY_ORDER],
                ),
                legend=alt.Legend(
                    title=None,
                    orient="bottom",
                    direction="horizontal",
                    symbolType="circle",
                    symbolSize=110,
                    labelFontSize=12,
                    labelColor=CHART_INK,
                ),
            ),
            tooltip=[
                alt.Tooltip("级别:N", title="级别"),
                alt.Tooltip("数量:Q", title="问题数"),
                alt.Tooltip("占比:Q", title="占比", format=".1%"),
            ],
        )
    )
    labels = (
        alt.Chart(visible)
        .mark_text(
            radius=121,
            fontSize=11,
            fontWeight="bold",
            color=CHART_INK,
        )
        .encode(
            theta=alt.Theta("数量:Q", stack=True),
            order=alt.Order("排序:Q"),
            text=alt.Text("占比:Q", format=".0%"),
        )
    )
    return (
        alt.layer(arcs, labels)
        .resolve_scale(theta="shared")
        .properties(height=280, background="transparent")
        .configure_view(strokeWidth=0)
    )


def render_severity_chart(report: ScanReport) -> None:
    """展示漏洞级别分布饼图。"""
    st.subheader("🥧 漏洞级别分布")
    chart = build_severity_chart(report)
    if chart is None:
        st.info("未发现漏洞，暂无可展示的级别分布。")
        return
    st.altair_chart(chart, width="stretch", theme=None)
    st.caption(
        f"共 {report.total_issues} 个问题：高危 {report.counts['high']} · "
        f"中危 {report.counts['medium']} · 低危 {report.counts['low']}。"
    )


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
    return typed.strip() or env_key


def render_account_panel() -> None:
    """在侧边栏展示当前账号与退出登录按钮（两个页面都可见）。"""
    with st.sidebar:
        st.divider()
        st.caption(f"当前账号：{st.session_state.get('login_user', '')}")
        if st.button("退出登录", use_container_width=True):
            st.session_state.pop("authenticated", None)
            st.session_state.pop("login_user", None)
            st.session_state.pop("active_page", None)
            st.rerun()


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


def _format_size(size_bytes: int) -> str:
    """把字节数格式化为易读的体积。"""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes / (1024 * 1024):.2f} MB"


def build_context_table(report: ContextHealthReport) -> pd.DataFrame:
    """把文件体积与债务统计转换为表格。"""
    rows = [
        {
            "文件": item.path,
            "总行数": item.line_count,
            "文件大小": _format_size(item.size_bytes),
            "TODO": item.todo_count,
            "FIXME": item.fixme_count,
            "状态": f"⚠️ 超过 {LINE_THRESHOLD} 行" if item.is_oversized else item.status,
        }
        for item in report.files
    ]
    return pd.DataFrame(rows)


def build_debt_table(report: ContextHealthReport) -> pd.DataFrame:
    """把 TODO / FIXME 明细转换为表格。"""
    rows = [
        {
            "文件": item.file,
            "行号": item.line,
            "类型": item.kind,
            "注释内容": item.text,
        }
        for item in report.debt_items
    ]
    return pd.DataFrame(rows)


def _style_context_row(row: pd.Series) -> list[str]:
    """超过阈值的文件整行标红。"""
    status = str(row.get("状态", ""))
    if status.startswith("⚠️") or status == "读取失败":
        return ["background-color: #fdecea; color: #b71c1c; font-weight: 600;"] * len(row)
    return [""] * len(row)


def render_context_summary(report: ContextHealthReport) -> None:
    """展示文件数量、代码总量与代码债务的统计卡片。"""
    oversized = len(report.oversized_files)
    warn_bg, warn_fg = ("#fdecea", "#c62828") if oversized else ("#e8f5e9", "#2e7d32")

    first, second, third = st.columns(3)
    with first:
        render_stat_card(
            "扫描文件", f"{len(report.files)} 个", "#f8fafc", "#1f2937", f"目录：{report.target}"
        )
    with second:
        render_stat_card(
            "代码总量",
            f"{report.total_lines:,} 行",
            "#f8fafc",
            "#1f2937",
            f"合计体积 {_format_size(report.total_size_bytes)}",
        )
    with third:
        render_stat_card(
            f"超过 {LINE_THRESHOLD} 行",
            f"{oversized} 个",
            warn_bg,
            warn_fg,
            "大文件会严重挤占 Token 窗口",
        )

    todo_col, fixme_col = st.columns(2)
    with todo_col:
        render_stat_card("TODO 债务", str(report.todo_count), "#fff4e0", "#b26a00", "待完成事项")
    with fixme_col:
        render_stat_card("FIXME 债务", str(report.fixme_count), "#fdecea", "#c62828", "待修复缺陷")


def build_file_line_chart(report: ContextHealthReport) -> alt.LayerChart:
    """构建文件行数横向柱状图，超过阈值的柱子标红。"""
    data = pd.DataFrame(
        [
            {
                "文件": item.path,
                "行数": item.line_count,
                "状态": f"超过 {LINE_THRESHOLD} 行" if item.is_oversized else "正常",
                "文件大小": _format_size(item.size_bytes),
            }
            for item in report.files
        ]
    )
    max_lines = max(int(data["行数"].max()), LINE_THRESHOLD)
    x_scale = alt.Scale(domain=[0, max(LINE_THRESHOLD * 1.12, max_lines * 1.12)])
    base = alt.Chart(data).encode(
        y=alt.Y(
            "文件:N",
            sort="-x",
            title=None,
            axis=alt.Axis(
                labelLimit=240,
                labelPadding=8,
                labelColor=CHART_INK,
                labelFontSize=12,
                ticks=False,
                domain=False,
            ),
        ),
        x=alt.X(
            "行数:Q",
            title=None,
            scale=x_scale,
            axis=alt.Axis(
                grid=True,
                gridColor=CHART_GRID,
                gridWidth=1,
                domain=False,
                ticks=False,
                labelColor=CHART_MUTED,
                labelFontSize=11,
            ),
        ),
    )
    bars = base.mark_bar(
        size=20,
        cornerRadiusTopRight=4,
        cornerRadiusBottomRight=4,
    ).encode(
        color=alt.Color(
            "状态:N",
            scale=alt.Scale(
                domain=["正常", f"超过 {LINE_THRESHOLD} 行"],
                range=[CHART_BLUE, CHART_RED],
            ),
            legend=alt.Legend(
                title=None,
                orient="bottom",
                direction="horizontal",
                symbolType="square",
                symbolSize=100,
                labelFontSize=12,
                labelColor=CHART_INK,
            ),
        ),
        tooltip=[
            alt.Tooltip("文件:N", title="文件"),
            alt.Tooltip("行数:Q", title="行数"),
            alt.Tooltip("文件大小:N", title="文件大小"),
            alt.Tooltip("状态:N", title="状态"),
        ],
    )
    threshold = (
        alt.Chart(pd.DataFrame({"阈值": [LINE_THRESHOLD]}))
        .mark_rule(color="#9ca3af", strokeDash=[5, 4], strokeWidth=1)
        .encode(x=alt.X("阈值:Q", scale=x_scale))
    )
    layers = [bars, threshold]
    if len(data) <= 12:
        layers.append(
            base.mark_text(
                align="left",
                baseline="middle",
                dx=5,
                color=CHART_INK,
                fontSize=11,
            ).encode(text=alt.Text("行数:Q"))
        )
    height = min(max(220, 30 * len(data) + 30), 620)
    return (
        alt.layer(*layers)
        .properties(height=height, background="transparent")
        .configure_view(strokeWidth=0)
    )


def render_file_line_chart(report: ContextHealthReport) -> None:
    """展示每个 .py 文件的行数柱状图。"""
    st.subheader("📏 文件行数分布")
    if not report.files:
        st.info("没有可展示的 .py 文件。")
        return
    st.altair_chart(build_file_line_chart(report), width="stretch", theme=None)
    st.caption(
        f"红色柱子表示超过 {LINE_THRESHOLD} 行；虚线为 {LINE_THRESHOLD} 行拆分阈值。"
    )


def render_oversize_warnings(report: ContextHealthReport) -> None:
    """对超过行数阈值的文件逐条给出红色预警。"""
    st.subheader("🚨 上下文污染预警")
    if not report.oversized_files:
        st.success(f"全部文件均未超过 {LINE_THRESHOLD} 行，上下文体积健康 ✅")
        return
    for item in report.oversized_files:
        st.error(
            f"【上下文污染预警】{item.path} 超过 {LINE_THRESHOLD} 行，"
            "会严重挤占 AI 的 Token 窗口，建议拆分！"
        )


def render_context_files(report: ContextHealthReport) -> None:
    """用表格展示每个文件的行数、体积与债务数量。"""
    st.subheader("📁 文件体积与债务概览")
    frame = build_context_table(report)
    if frame.empty:
        st.warning("没有可展示的 .py 文件。")
        return
    st.dataframe(
        frame.style.apply(_style_context_row, axis=1),
        width="stretch",
        hide_index=True,
    )
    for item in report.files:
        if item.read_error:
            st.warning(f"无法读取 {item.path}：{item.read_error}")


def render_context_debt(report: ContextHealthReport) -> None:
    """展示所有 TODO / FIXME 注释明细。"""
    st.subheader("🧾 代码债务明细")
    frame = build_debt_table(report)
    if frame.empty:
        st.success("未发现 TODO / FIXME 注释 ✅")
        return
    styled = frame.style.map(lambda value: DEBT_STYLE.get(value, ""), subset=["类型"])
    st.dataframe(styled, width="stretch", hide_index=True)
    st.caption(
        f"共 {report.total_debt} 条代码债务：TODO {report.todo_count} 条 · "
        f"FIXME {report.fixme_count} 条。"
    )


def render_context_page() -> None:
    """渲染上下文健康检查页面。"""
    with st.form("context_health_form"):
        folder = st.text_input(
            "要扫描的文件夹路径",
            value="sample_code",
            placeholder="例如 sample_code",
            help="相对路径按项目根目录解析；为保证部署安全，不允许扫描项目目录之外的位置。",
        )
        submitted = st.form_submit_button(
            "🔍 开始上下文健康检查",
            type="primary",
            use_container_width=True,
        )

    if not submitted:
        st.info("输入项目内的文件夹路径（例如 `sample_code`）后开始检查。")
        st.caption(
            f"检查规则：统计每个 .py 文件的行数与体积；超过 {LINE_THRESHOLD} 行立即预警；"
            "并扫描所有 TODO / FIXME 注释。"
        )
        return

    try:
        target = resolve_target(folder, CONTEXT_SCAN_ROOT)
    except ValueError as exc:
        st.error(str(exc))
        return

    with st.spinner("正在检查上下文健康度..."):
        try:
            report = scan_context_health(target)
        except (OSError, ValueError) as exc:
            st.error(f"检查失败：{exc}")
            return

    if not report.files:
        st.warning("该文件夹下没有找到 .py 文件。")
        return

    st.caption(
        f"已扫描 **{report.target}** · {len(report.files)} 个文件 · "
        f"耗时 {report.elapsed:.3f}s"
    )
    render_context_summary(report)
    st.divider()
    render_file_line_chart(report)
    st.divider()
    render_oversize_warnings(report)
    st.divider()
    render_context_files(report)
    st.divider()
    render_context_debt(report)
    st.caption("⚠️ 上下文健康建议仅供参考，请结合项目实际情况决定是否拆分文件。")


def render_scan_page(api_key: str) -> None:
    """渲染安全扫描与修复页面（原有功能）。"""
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
    render_severity_chart(report)
    st.divider()
    render_issues(report)
    render_ai_fix(report, source, filename, api_key)
    st.caption("⚠️ 预检结果与 AI 修复建议仅供参考，请结合人工复核后再合并代码。")


def main() -> None:
    """页面入口。"""
    st.set_page_config(page_title=APP_TITLE, page_icon="🛡️", layout="centered")

    if not is_authenticated():
        render_login()
        st.stop()

    page = render_sidebar()
    render_header(page)

    if page == PAGE_CONTEXT:
        render_context_page()
        render_account_panel()
        return

    api_key = render_api_config()
    render_account_panel()
    render_scan_page(api_key)


main()
