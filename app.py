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
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import altair as alt
import pandas as pd
import requests
import streamlit as st

from checker import (
    CheckEngine,
    ReviewPriority,
    ScanReport,
    Severity,
    render_context_markdown,
    render_scan_markdown,
)
from checker.adversarial import (
    BLUE_SYSTEM_PROMPT,
    MAX_ROUNDS,
    RED_SYSTEM_PROMPT,
    build_blue_prompt,
    build_red_prompt,
    extract_python_code,
    is_defense_success,
)
from checker.archive import extract_python_files
from checker.custom_rules import parse_custom_terms
from checker.dependencies import (
    DependencyReport,
    ImportReference,
    PackageStatus,
    extract_imports,
    verify_dependencies,
)
from checker.dependency_graph import (
    build_dependency_figure,
    build_project_dependency_graph,
)
from checker.review import (
    REVIEW_INSTRUCTION,
    REVIEW_SYSTEM_PROMPT,
    build_review_payload,
)
from checker.context_health import (
    LINE_THRESHOLD,
    ContextHealthReport,
    resolve_target,
    scan_context_health,
)

APP_TITLE = "AI代码安全预检Agent"
APP_SUBTITLE = "上传 Python 文件或 ZIP，发现安全风险、代码异味与幻觉依赖"

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
PRIORITY_STYLE = {
    "P0": "background-color: #fdecea; color: #c62828; font-weight: 700;",
    "P1": "background-color: #fff4e0; color: #b26a00; font-weight: 600;",
    "P2": "background-color: #e8f5e9; color: #2e7d32; font-weight: 600;",
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
DEPENDENCY_STYLE = {
    "✅ 存在": "background-color: #e8f5e9; color: #2e7d32; font-weight: 600;",
    "❌ 幻觉依赖风险": "background-color: #fdecea; color: #c62828; font-weight: 600;",
    "⚠️ 未验证": "background-color: #fff4e0; color: #b26a00; font-weight: 600;",
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


@dataclass
class UploadedScan:
    """一次上传扫描的结果，附带后续 AI 修复需要的文件源码。"""

    report: ScanReport
    sources: dict[str, str]
    is_archive: bool = False


def scan_uploaded_file(
    filename: str,
    content: bytes,
    custom_terms: list[str] | None = None,
) -> UploadedScan:
    """扫描上传的单个 .py 文件或 .zip 压缩包，返回汇总报告与源码映射。"""
    safe_name = Path(filename).name or "uploaded.py"
    suffix = Path(safe_name).suffix.lower()
    if suffix not in {".py", ".zip"}:
        raise ValueError("仅支持 .py 文件或 .zip 压缩包。")

    with tempfile.TemporaryDirectory(prefix="precheck_") as tmp_dir:
        root = Path(tmp_dir)

        if suffix == ".zip":
            paths = extract_python_files(content, root)
            report = CheckEngine(
                display_root=root, custom_terms=custom_terms
            ).run(root)
            if not report.files:
                raise ValueError(
                    "压缩包内没有可扫描的 .py 文件（可能都位于被排除的目录中）。"
                )
            sources = {
                path.relative_to(root).as_posix(): path.read_text(
                    encoding="utf-8", errors="replace"
                )
                for path in paths
            }
            return UploadedScan(report, sources, is_archive=True)

        path = root / safe_name
        path.write_bytes(content)
        report = CheckEngine(
            display_root=root, custom_terms=custom_terms
        ).run(path)
        return UploadedScan(
            report,
            {safe_name: content.decode("utf-8", errors="replace")},
        )


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


def build_severity_chart(report: ScanReport) -> alt.Chart | None:
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
    data["图例"] = [
        f"{level} {int(count)} ({ratio:.0%})"
        for level, count, ratio in zip(
            data["级别"], data["数量"], data["占比"]
        )
    ]
    data["排序"] = range(len(data))

    # 不再把百分比文字画在扇区外侧，避免小扇区（如 17%）标签被裁切；
    # 数量与占比统一放到底部图例中展示。
    return (
        alt.Chart(data)
        .mark_arc(
            innerRadius=68,
            outerRadius=112,
            stroke="#ffffff",
            strokeWidth=2,
        )
        .encode(
            theta=alt.Theta("数量:Q", stack=True),
            order=alt.Order("排序:Q"),
            color=alt.Color(
                "图例:N",
                scale=alt.Scale(
                    domain=data["图例"].tolist(),
                    range=[SEVERITY_COLORS[level] for level in SEVERITY_ORDER],
                ),
                legend=alt.Legend(
                    title=None,
                    orient="bottom",
                    direction="horizontal",
                    columns=3,
                    labelLimit=220,
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
        .properties(
            height=350,
            padding={"left": 30, "right": 30, "top": 20, "bottom": 20},
            background="transparent",
        )
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
        f"共 {report.total_issues} 个问题；底部图例展示各级别的数量与占比。"
    )


def build_issue_table(report: ScanReport) -> pd.DataFrame:
    """把扫描结果转换为表格数据，并按审查优先级排序。"""
    issues = [
        issue
        for file_report in report.files
        for issue in file_report.issues
    ]
    issues.sort(
        key=lambda issue: (
            issue.priority.rank,
            -issue.severity.weight,
            issue.file,
            issue.line,
            issue.rule,
        )
    )
    rows = [
        {
            "文件": issue.file,
            "级别": SEVERITY_TEXT[issue.severity],
            "审查优先级": issue.priority.value,
            "行号": issue.line if issue.line > 0 else "文件级",
            "规则": issue.rule,
            "检查项": issue.name,
            "问题描述": issue.message,
            "代码片段": issue.evidence,
            "修复建议": issue.suggestion,
        }
        for issue in issues
    ]
    return pd.DataFrame(rows)


def render_issues(report: ScanReport) -> None:
    """用表格展示漏洞明细；严重程度与审查优先级分别标色。"""
    st.subheader("漏洞明细")
    frame = build_issue_table(report)

    if frame.empty:
        st.success("未发现任何问题，代码预检通过 ✅")
        return

    styled = frame.style.map(
        lambda value: SEVERITY_STYLE.get(value, ""),
        subset=["级别"],
    ).map(
        lambda value: PRIORITY_STYLE.get(value, ""),
        subset=["审查优先级"],
    )
    st.dataframe(styled, width="stretch", hide_index=True)
    st.caption(
        f"共 {len(frame)} 条问题，默认按审查优先级排序；"
        "点击「审查优先级」表头可重新排序。"
        "P0=阻断合并，P1=优先审查，P2=常规审查。"
    )


def render_merge_block_banner(report: ScanReport) -> None:
    """存在 P0 问题时在结果页顶部显示阻断合并横幅。"""
    p0_issues = [
        issue
        for file_report in report.files
        for issue in file_report.issues
        if issue.priority is ReviewPriority.P0
    ]
    if not p0_issues:
        return
    files = {issue.file for issue in p0_issues}
    st.error(
        f"🚨 **存在阻断合并的风险**：检测到 **{len(p0_issues)}** 个 P0 级问题"
        f"（硬编码密钥），涉及 **{len(files)}** 个文件，请修复后再合并代码。"
    )


def _format_dependency_locations(
    references: list[ImportReference], limit: int = 5
) -> str:
    """把依赖引用位置压缩成一行。"""
    locations = [f"{item.file}:{item.line}" for item in references]
    if not locations:
        return "—"
    if len(locations) > limit:
        return "、".join(locations[:limit]) + f" 等 {len(locations)} 处"
    return "、".join(locations)


def build_dependency_table(result: DependencyReport) -> pd.DataFrame:
    """把依赖校验结果转换为表格。"""
    rows = [
        {
            "依赖": item.name,
            "PyPI 包名": item.distribution,
            "状态": item.label,
            "引用位置": _format_dependency_locations(
                result.references_for(item.name), limit=3
            ),
        }
        for item in sorted(
            result.statuses.values(), key=lambda status: status.name.casefold()
        )
    ]
    return pd.DataFrame(rows)


def render_dependency_check(sources: dict[str, str]) -> DependencyReport:
    """展示第三方依赖真实性校验结果；网络异常不影响主扫描流程。"""
    st.divider()
    st.subheader("📦 依赖真实性校验")

    try:
        references = extract_imports(sources)
    except Exception as exc:  # 依赖提取失败同样不能影响主扫描结果
        st.warning(f"依赖提取失败，已跳过：{exc}")
        return DependencyReport()

    if not references:
        st.info(
            "未发现需要校验的第三方依赖"
            "（已跳过标准库、相对导入和可识别的本地模块）。"
        )
        st.caption("依赖校验是独立步骤，不会影响主扫描结果。")
        return DependencyReport()

    cache = st.session_state.setdefault("dependency_fetch_cache", {})
    unique_count = len({item.name.casefold() for item in references})
    with st.spinner(f"正在向 PyPI 校验 {unique_count} 个第三方依赖..."):
        try:
            result = verify_dependencies(references, cache=cache)
        except Exception as exc:  # 依赖校验失败不能影响主扫描结果
            st.warning(f"依赖校验发生异常，已跳过：{exc}")
            result = DependencyReport(
                references=references,
                statuses={
                    item.name.casefold(): PackageStatus(
                        name=item.name,
                        distribution=item.distribution,
                        exists=None,
                        detail=f"校验异常：{exc}",
                    )
                    for item in references
                },
            )

    missing = result.missing
    unknown = result.unknown
    existing = result.existing

    first, second, third = st.columns(3)
    with first:
        render_stat_card(
            "第三方依赖",
            str(len(result.statuses)),
            "#f8fafc",
            "#1f2937",
            f"已确认存在 {len(existing)} 个",
        )
    with second:
        missing_bg, missing_fg = (
            ("#fdecea", "#c62828") if missing else ("#e8f5e9", "#2e7d32")
        )
        render_stat_card(
            "幻觉依赖风险", str(len(missing)), missing_bg, missing_fg, "PyPI 返回 404"
        )
    with third:
        unknown_bg, unknown_fg = (
            ("#fff4e0", "#b26a00") if unknown else ("#e8f5e9", "#2e7d32")
        )
        render_stat_card(
            "未验证", str(len(unknown)), unknown_bg, unknown_fg, "网络超时或接口异常"
        )

    frame = build_dependency_table(result)
    if not frame.empty:
        st.dataframe(
            frame.style.map(
                lambda value: DEPENDENCY_STYLE.get(value, ""), subset=["状态"]
            ),
            width="stretch",
            hide_index=True,
        )

    if missing:
        st.markdown("#### 🚨 幻觉依赖风险")
        for item in sorted(missing, key=lambda status: status.name.casefold()):
            refs = result.references_for(item.name)
            st.error(
                f"【幻觉依赖风险】`{item.name}` 在 PyPI 上不存在"
                f"（查询包名：`{item.distribution}`）；"
                f"引用位置：{_format_dependency_locations(refs, limit=8)}"
            )
    else:
        st.success("未发现已确认的幻觉依赖风险 ✅")

    if unknown:
        names = "、".join(
            item.name
            for item in sorted(unknown, key=lambda status: status.name.casefold())
        )
        st.warning(f"以下依赖因网络超时或接口异常未能完成校验：{names}")

    st.caption(
        "依赖校验调用 PyPI JSON API（服务器需可访问 pypi.org），"
        "单次总等待上限约 6 秒；网络异常只会标记为未验证，不会影响主扫描结果。"
    )
    if st.button("🔄 重新校验依赖", key="rerun_dependency_check"):
        st.session_state.pop("dependency_fetch_cache", None)
        st.rerun()
    return result


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
            _cleanup_fix_workspace()
            st.session_state.pop("ai_fix_scan_id", None)
            st.session_state["ai_fix_cache"] = {}
            st.session_state["red_blue_cache"] = {}
            st.session_state.pop("code_review_guide", None)
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


def call_deepseek(
    api_key: str,
    prompt: str,
    system_prompt: str = SYSTEM_PROMPT,
    temperature: float = 0.2,
    strip_fences: bool = True,
) -> str:
    """调用 DeepSeek 对话接口，返回修复代码、审查指南或对抗日志。"""
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
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "temperature": temperature,
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
    text = strip_code_fence(content) if strip_fences else content.strip()
    if not text.strip():
        raise RuntimeError("DeepSeek 返回了空内容")
    return text


def _fix_cache_key(source: str, rule: str, line: int, file: str = "") -> str:
    """用文件内容哈希 + 文件 + 规则 + 行号作为修复结果缓存键。"""
    digest = hashlib.sha1(source.encode("utf-8", errors="replace")).hexdigest()[:12]
    return f"{digest}:{file}:{rule}:{line}"


def _sources_digest(sources: dict[str, str]) -> str:
    """为一次扫描的源码集合生成稳定标识，避免跨文件复用旧备份。"""
    digest = hashlib.sha256()
    for name in sorted(sources):
        digest.update(name.encode("utf-8", errors="replace"))
        digest.update(b"\0")
        digest.update(sources[name].encode("utf-8", errors="replace"))
        digest.update(b"\0")
    return digest.hexdigest()


def _cleanup_fix_workspace() -> None:
    """清理本次会话的临时修复工作区和备份。"""
    state = st.session_state
    tmp = state.pop("fix_workspace_tmp", None)
    if tmp is not None:
        try:
            tmp.cleanup()
        except Exception:
            pass
    state.pop("fix_workspace_path", None)
    state.pop("fix_workspace_scan_id", None)
    state.pop("fix_rollback_notice", None)
    state["fix_backups"] = {}
    state["fix_backup_scan_id"] = None


def _sync_fix_scan_state(scan_id: str) -> None:
    """扫描内容变化时清理旧的修复缓存和工作区。"""
    state = st.session_state
    if state.get("ai_fix_scan_id") == scan_id:
        return
    _cleanup_fix_workspace()
    state["ai_fix_scan_id"] = scan_id
    state["ai_fix_cache"] = {}
    state["red_blue_cache"] = {}


def _ensure_fix_workspace(sources: dict[str, str], scan_id: str) -> Path:
    """创建并返回本次扫描的临时修复工作区。"""
    state = st.session_state
    root_value = state.get("fix_workspace_path")
    root = Path(root_value) if root_value else None
    if (
        state.get("fix_workspace_scan_id") == scan_id
        and root is not None
        and root.is_dir()
    ):
        return root

    _cleanup_fix_workspace()
    tmp = tempfile.TemporaryDirectory(prefix="precheck_fix_")
    root = Path(tmp.name).resolve()
    for relative, source in sources.items():
        target = (root / relative).resolve()
        if root not in target.parents:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source, encoding="utf-8")
    state["fix_workspace_tmp"] = tmp
    state["fix_workspace_path"] = str(root)
    state["fix_workspace_scan_id"] = scan_id
    return root


def _backup_fix_sources(sources: dict[str, str], scan_id: str) -> dict[str, str]:
    """在调用 AI 修复前，把原文件备份为 .bak 文件。"""
    state = st.session_state
    existing = state.get("fix_backups")
    root_value = state.get("fix_workspace_path")
    root = Path(root_value) if root_value else None
    if (
        state.get("fix_backup_scan_id") == scan_id
        and existing
        and root is not None
        and root.is_dir()
        and all(Path(path).exists() for path in existing.values())
    ):
        return dict(existing)
    if state.get("fix_backup_scan_id") == scan_id and existing:
        # 备份或工作区不完整时从当前扫描的原始源码重建，避免备份被污染。
        _cleanup_fix_workspace()

    root = _ensure_fix_workspace(sources, scan_id)
    backups: dict[str, str] = {}
    for relative, source in sources.items():
        target = (root / relative).resolve()
        if root not in target.parents:
            continue
        if not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source, encoding="utf-8")
        backup = target.with_name(target.name + ".bak")
        shutil.copy2(target, backup)
        backups[relative] = str(backup)

    if not backups:
        raise OSError("没有可备份的源文件。")
    state["fix_backups"] = backups
    state["fix_backup_scan_id"] = scan_id
    return backups


def _rollback_fix_files(scan_id: str) -> tuple[bool, str]:
    """用 .bak 备份覆盖工作区当前文件，并清空修复结果。"""
    state = st.session_state
    backups = state.get("fix_backups") or {}
    if not backups or state.get("fix_backup_scan_id") != scan_id:
        return False, "没有可回滚的备份。"

    root_value = state.get("fix_workspace_path")
    if not root_value:
        return False, "修复工作区不存在，无法回滚。"
    root = Path(root_value)

    restored = 0
    for relative, backup_value in backups.items():
        backup = Path(backup_value)
        if not backup.exists():
            continue
        target = (root / relative).resolve()
        if root not in target.parents:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(backup, target)
        restored += 1

    if restored == 0:
        return False, "备份文件不存在，无法回滚。"
    state["ai_fix_cache"] = {}
    state["red_blue_cache"] = {}
    state["fix_rollback_notice"] = True
    return True, ""


def _render_issue_heading(issue) -> None:
    """渲染单个高危问题的标题和说明。"""
    st.markdown(
        f"#### `{issue.file}` · "
        f"第 {issue.line if issue.line > 0 else '文件级'} 行 · "
        f"{issue.name}（{issue.rule}）"
    )
    st.caption(f"{issue.message} · 修复建议：{issue.suggestion}")


def _render_battle_event(event: dict) -> None:
    """渲染一条红蓝对抗日志。"""
    role = event.get("role")
    content = event.get("content", "")
    if role == "red":
        with st.chat_message("红方攻击", avatar="⚔️"):
            st.markdown(content)
    elif role == "blue":
        with st.chat_message("蓝方防御", avatar="🛡️"):
            st.markdown(content)
    else:
        st.warning(content)


def _render_battle_log(entry: dict) -> None:
    """从缓存中重放完整的对战日志。"""
    for event in entry.get("events", []):
        _render_battle_event(event)


def _run_red_blue_issue(issue, source: str, api_key: str) -> dict:
    """对单个高危问题执行最多 MAX_ROUNDS 轮红蓝对抗。"""
    start, end, snippet = extract_code_snippet(source, issue.line)
    entry: dict = {
        "start": start,
        "end": end,
        "before": snippet,
        "fixed": snippet,
        "events": [],
        "status": "max_rounds",
        "rounds": 0,
        "verified_round": None,
        "error": "",
    }
    if not source:
        entry["status"] = "error"
        entry["error"] = f"无法读取源码：{issue.file}"
        error_event = {"role": "system", "content": entry["error"]}
        entry["events"].append(error_event)
        _render_battle_event(error_event)
        return entry

    current_code = snippet
    for round_no in range(1, MAX_ROUNDS + 1):
        entry["rounds"] = round_no

        try:
            red = call_deepseek(
                api_key,
                build_red_prompt(current_code),
                system_prompt=RED_SYSTEM_PROMPT,
                temperature=0.4,
                strip_fences=False,
            )
        except Exception as exc:
            entry["status"] = "error"
            entry["error"] = f"红方调用失败：{exc}"
            error_event = {"role": "system", "content": entry["error"]}
            entry["events"].append(error_event)
            _render_battle_event(error_event)
            break

        red_event = {"role": "red", "round": round_no, "content": red}
        entry["events"].append(red_event)
        _render_battle_event(red_event)

        if round_no > 1 and is_defense_success(red):
            entry["status"] = "defended"
            entry["verified_round"] = round_no
            break

        try:
            blue = call_deepseek(
                api_key,
                build_blue_prompt(current_code, red),
                system_prompt=BLUE_SYSTEM_PROMPT,
                temperature=0.2,
                strip_fences=False,
            )
        except Exception as exc:
            entry["status"] = "error"
            entry["error"] = f"蓝方调用失败：{exc}"
            error_event = {"role": "system", "content": entry["error"]}
            entry["events"].append(error_event)
            _render_battle_event(error_event)
            break

        blue_event = {"role": "blue", "round": round_no, "content": blue}
        entry["events"].append(blue_event)
        _render_battle_event(blue_event)

        fixed = extract_python_code(blue)
        if not fixed.strip():
            entry["status"] = "blue_failed"
            entry["error"] = "蓝方未返回可用的修复代码"
            error_event = {"role": "system", "content": entry["error"]}
            entry["events"].append(error_event)
            _render_battle_event(error_event)
            break
        current_code = fixed

    entry["fixed"] = current_code
    return entry


def _render_red_blue_result(issue, entry: dict, position: int) -> None:
    """渲染单个问题的最终状态和修复代码。"""
    status = entry.get("status")
    if status == "defended":
        st.success(
            f"✅ 防守成功：红方在第 {entry.get('verified_round')} 轮表示无法攻破。"
        )
    elif status == "max_rounds":
        st.warning(
            f"⚠️ 已达到 {MAX_ROUNDS} 轮上限，最后一轮修复尚未被红方验证，"
            "建议人工复核。"
        )
    elif status == "blue_failed":
        st.error(f"❌ 蓝方修复失败：{entry.get('error', '未返回可用代码')}")
    else:
        st.error(f"❌ 红蓝对抗失败：{entry.get('error', '未知错误')}")

    if entry.get("before"):
        with st.expander("查看被修复的原始代码"):
            st.code(entry["before"], language="python", line_numbers=True)

    if status in {"defended", "max_rounds"}:
        st.markdown("**🛡️ 最终修复代码**")
        st.code(entry["fixed"], language="python", line_numbers=True)
        st.download_button(
            "⬇️ 下载最终修复代码",
            data=entry["fixed"],
            file_name=(
                f"{Path(issue.file).stem}_redblue_"
                f"L{entry['start']}-{entry['end']}.py"
            ),
            mime="text/x-python",
            key=f"download_redblue_{position}_{issue.rule}_{issue.line}",
        )


def render_red_blue_fix(
    report: ScanReport,
    sources: dict[str, str],
    api_key: str,
) -> None:
    """对高危问题执行红蓝对抗修复并展示实时对战日志。"""
    high_issues = [
        issue
        for file_report in report.files
        for issue in file_report.issues
        if issue.severity is Severity.HIGH
    ]
    if not high_issues:
        return

    scan_id = _sources_digest(sources)
    _sync_fix_scan_state(scan_id)
    state = st.session_state

    st.divider()
    st.subheader("🔥 红蓝对抗修复")
    if state.pop("fix_rollback_notice", False):
        st.success("已回滚，请重新扫描确认")
    st.caption(
        f"检测到 **{len(high_issues)}** 个高危问题，涉及 "
        f"**{len({issue.file for issue in high_issues})}** 个文件。"
        f"每个问题最多进行 **{MAX_ROUNDS}** 轮红蓝对抗，每轮会调用两次 DeepSeek。"
    )
    st.caption(
        "⚔️ 红方输出仅用于授权的防御性验证，请勿在任何真实系统上执行。"
    )

    if not api_key:
        st.warning(
            "尚未配置 DeepSeek API Key：请在左侧侧边栏填写，"
            "或设置环境变量 `DEEPSEEK_API_KEY`（也支持 `.streamlit/secrets.toml` 中的 `deepseek_api_key`）。"
        )

    cache: dict[str, dict] = state.setdefault("red_blue_cache", {})
    clicked = st.button(
        "🔥 开启红蓝对抗修复",
        type="primary",
        use_container_width=True,
        disabled=not api_key,
        help="红方尝试构造攻击，蓝方修复，再由红方验证；最多 3 轮。",
    )

    backup_ok = False
    if clicked:
        try:
            _backup_fix_sources(sources, scan_id)
            backup_ok = True
        except Exception as exc:
            st.error(f"备份原文件失败，已停止修复：{exc}")

    backups = state.get("fix_backups") or {}
    if backups and state.get("fix_backup_scan_id") == scan_id:
        st.caption(
            f"已备份 **{len(backups)}** 个原文件为 `.bak`"
            "（位于本次会话的服务器临时工作区，不会修改你本地的文件）。"
        )
        if st.button(
            "⏪ 回滚到修复前",
            key="rollback_ai_fix",
            use_container_width=True,
        ):
            ok, message = _rollback_fix_files(scan_id)
            if ok:
                st.rerun()
            else:
                st.error(message)

    rendered_live: set[str] = set()
    if clicked and backup_ok and api_key:
        errors = 0
        unverified = 0
        progress = st.progress(0.0, text="红蓝对抗进行中...")
        for index, issue in enumerate(high_issues, start=1):
            source = sources.get(issue.file, "")
            key = _fix_cache_key(
                source, issue.rule, issue.line, issue.file
            )
            if key in cache:
                progress.progress(
                    index / len(high_issues),
                    text=f"已完成 {index}/{len(high_issues)}（已有结果）",
                )
                continue
            _render_issue_heading(issue)
            entry = _run_red_blue_issue(issue, source, api_key)
            cache[key] = entry
            _render_red_blue_result(issue, entry, index - 1)
            rendered_live.add(key)
            if entry.get("status") in {"error", "blue_failed"}:
                errors += 1
            elif entry.get("status") == "max_rounds":
                unverified += 1
            progress.progress(
                index / len(high_issues),
                text=f"已完成 {index}/{len(high_issues)}",
            )
        progress.empty()
        if errors:
            st.warning(f"有 {errors} 个问题对抗失败，详见上方对战日志。")
        elif unverified:
            st.warning("部分问题达到最大轮次，建议人工复核最终修复代码。")
        else:
            st.success("红蓝对抗修复完成，请查看对战日志和最终代码。")

    shown = 0
    for position, issue in enumerate(high_issues):
        source = sources.get(issue.file, "")
        key = _fix_cache_key(
            source, issue.rule, issue.line, issue.file
        )
        entry = cache.get(key)
        if entry is None or key in rendered_live:
            continue
        shown += 1
        _render_issue_heading(issue)
        _render_battle_log(entry)
        _render_red_blue_result(issue, entry, position)

    if shown == 0 and not clicked:
        st.caption("点击上方按钮开始红蓝对抗修复。")


def render_code_review_guide(
    report: ScanReport,
    sources: dict[str, str],
    filename: str,
    api_key: str,
) -> None:
    """在报告底部生成并展示团队 Code Review 指南。"""
    scan_id = _sources_digest(sources)
    state = st.session_state.get("code_review_guide")
    if state and state.get("scan_id") != scan_id:
        st.session_state.pop("code_review_guide", None)

    st.divider()
    st.subheader("🧭 Code Review 指南")
    st.caption(
        "让 DeepSeek 从资深架构师视角生成核心功能总结、建议审查顺序和人工核对风险点。"
    )

    if not api_key:
        st.warning(
            "生成 Code Review 指南需要 DeepSeek API Key，请在左侧侧边栏配置。"
        )

    clicked = st.button(
        "生成 Code Review 指南",
        type="primary",
        use_container_width=True,
        disabled=not api_key,
        key="generate_code_review_guide",
    )

    if clicked:
        payload, truncated = build_review_payload(
            sources,
            [file_report.path for file_report in report.files],
        )
        if not payload:
            st.error("没有可提交给模型的代码。")
        else:
            prompt = f"{REVIEW_INSTRUCTION}\n\n代码如下：\n\n{payload}"
            with st.spinner("正在生成 Code Review 指南..."):
                try:
                    guide = call_deepseek(
                        api_key,
                        prompt,
                        system_prompt=REVIEW_SYSTEM_PROMPT,
                        temperature=0.3,
                    )
                except Exception as exc:
                    st.error(f"生成 Code Review 指南失败：{exc}")
                else:
                    st.session_state["code_review_guide"] = {
                        "scan_id": scan_id,
                        "text": guide,
                        "truncated": truncated,
                        "generated_at": datetime.now(),
                        "model": st.session_state.get(
                            "deepseek_model", DEEPSEEK_MODEL
                        ),
                    }

    guide_state = st.session_state.get("code_review_guide")
    if guide_state and guide_state.get("scan_id") == scan_id:
        if guide_state.get("truncated"):
            st.caption("代码超过长度上限，已截断后提交给模型。")
        with st.container(border=True):
            st.markdown(guide_state["text"])
        generated = guide_state["generated_at"]
        stem = Path(filename).stem or "scan"
        st.download_button(
            "⬇️ 下载 Code Review 指南",
            data=guide_state["text"],
            file_name=f"code_review_guide_{stem}_{generated:%Y%m%d_%H%M%S}.md",
            mime="text/markdown",
            key="download_code_review_guide",
        )
        st.caption(
            f"生成时间：{generated:%Y-%m-%d %H:%M:%S} · "
            f"模型：{guide_state.get('model', DEEPSEEK_MODEL)} · "
            "AI 生成内容，请结合人工审查。"
        )


def render_security_export(
    report: ScanReport,
    filename: str,
    dependencies: DependencyReport | None = None,
) -> None:
    """在安全扫描页底部提供 Markdown 诊断报告下载。"""
    generated = datetime.now()
    stem = Path(filename).stem.replace(" ", "_") or "scan"
    st.caption("报告包含综合得分、风险等级、问题清单、依赖校验和修复建议。")
    st.download_button(
        "📥 导出诊断报告",
        data=render_scan_markdown(
            report,
            generated_at=generated,
            target=filename,
            dependencies=dependencies,
        ),
        file_name=f"security_report_{stem}_{generated:%Y%m%d_%H%M%S}.md",
        mime="text/markdown",
        use_container_width=True,
        key="download_security_report",
    )


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


def render_project_dependency_graph(target: Path) -> None:
    """展示项目内 .py 文件之间的 import 依赖网络图。"""
    st.subheader("🕸️ 项目依赖关系图谱")
    with st.spinner("正在分析文件之间的 import 关系..."):
        try:
            graph_data = build_project_dependency_graph(target)
        except (OSError, ValueError) as exc:
            st.warning(f"依赖关系分析失败：{exc}")
            return

    if not graph_data.nodes:
        st.info("没有可分析的 .py 文件。")
        return
    if not graph_data.has_edges:
        st.info(
            "当前目录的 .py 文件之间没有 import 引用关系，"
            "图谱仅展示全部文件节点。"
        )

    st.plotly_chart(
        build_dependency_figure(graph_data),
        width="stretch",
        theme=None,
        config={"displayModeBar": False},
    )
    if graph_data.core_nodes:
        names = "、".join(graph_data.core_nodes)
        st.caption(
            f"红色放大节点为被引用最多的核心文件：{names}。"
            "箭头方向表示 A → B（A 引用 B）。"
        )
    else:
        st.caption("箭头方向表示 A → B（A 引用 B）；当前没有文件间的核心引用节点。")


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


def render_context_export(report: ContextHealthReport) -> None:
    """在上下文健康检查页底部提供 Markdown 诊断报告下载。"""
    generated = datetime.now()
    stem = Path(report.target).name.replace(" ", "_") or "context"
    st.caption("报告包含文件体积、超限预警和 TODO / FIXME 明细。")
    st.download_button(
        "📥 导出诊断报告",
        data=render_context_markdown(report, generated_at=generated),
        file_name=f"context_health_report_{stem}_{generated:%Y%m%d_%H%M%S}.md",
        mime="text/markdown",
        use_container_width=True,
        key="download_context_report",
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
    render_project_dependency_graph(target)
    st.divider()
    render_oversize_warnings(report)
    st.divider()
    render_context_files(report)
    st.divider()
    render_context_debt(report)
    st.caption("⚠️ 上下文健康建议仅供参考，请结合项目实际情况决定是否拆分文件。")
    st.divider()
    render_context_export(report)


def render_scan_page(api_key: str) -> None:
    """渲染安全扫描与修复页面（原有功能）。"""
    with st.expander("⚙️ 自定义规则配置", expanded=False):
        raw_terms = st.text_area(
            "禁用函数名或关键词",
            placeholder="例如：eval, exec, os.system",
            help=(
                "支持逗号、分号或换行分隔；按整词匹配，大小写不敏感，"
                "注释和字符串中的关键词也会命中。"
            ),
            key="custom_rule_terms",
        )
        custom_terms = parse_custom_terms(raw_terms)
        if custom_terms:
            preview = "、".join(custom_terms[:8])
            more = f" 等 {len(custom_terms)} 项" if len(custom_terms) > 8 else ""
            st.caption(f"已启用自定义规则：{preview}{more}")
        else:
            st.caption("留空则不启用自定义规则。")

    uploaded = st.file_uploader(
        "上传需要预检的 Python 文件或 .zip 压缩包",
        type=["py", "zip"],
        accept_multiple_files=False,
        help=(
            "支持单个 .py 文件，或包含多个 .py 文件的 .zip 压缩包；"
            "压缩包会安全解压到临时目录后汇总扫描。"
        ),
    )

    if uploaded is None:
        st.info("请上传一个 .py 文件或 .zip 压缩包开始扫描。")
        st.caption(
            "提示：本工具只做静态分析，不会执行上传的代码；"
            "压缩包内只提取 .py 文件。"
        )
        return

    filename = Path(uploaded.name).name or "uploaded.py"
    content = uploaded.getvalue()
    with st.spinner("正在扫描，请稍候..."):
        try:
            bundle = scan_uploaded_file(
                filename, content, custom_terms=custom_terms
            )
        except Exception as exc:  # 页面不应因单次扫描异常而崩溃
            st.error(f"扫描失败：{exc}")
            return

    report = bundle.report
    total_lines = sum(item.line_count for item in report.files)
    if bundle.is_archive:
        st.caption(
            f"已扫描压缩包 **{filename}** · {len(report.files)} 个 .py 文件 · "
            f"{total_lines:,} 行 · 耗时 {report.elapsed:.3f}s"
        )
    else:
        st.caption(
            f"已扫描 **{filename}** · {total_lines} 行 · "
            f"耗时 {report.elapsed:.3f}s"
        )
    render_merge_block_banner(report)
    render_summary(report)
    st.divider()
    render_severity_chart(report)
    st.divider()
    render_issues(report)
    dependency_report = render_dependency_check(bundle.sources)
    render_red_blue_fix(report, bundle.sources, api_key)
    render_code_review_guide(report, bundle.sources, filename, api_key)
    st.caption(
        "⚠️ 预检结果、AI 修复/红蓝对抗建议与 Code Review 指南仅供参考，"
        "请结合人工复核后再合并代码。"
    )
    st.divider()
    render_security_export(report, filename, dependency_report)


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
