"""项目内部依赖关系图谱：文件级 import 分析与 Plotly 网络图。"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import networkx as nx
import plotly.graph_objects as go

from .context_health import iter_python_files

NODE_COLOR = "#2a78d6"
CORE_COLOR = "#c62828"
EDGE_COLOR = "#cbd5e1"
EDGE_ARROW_COLOR = "#94a3b8"
TEXT_COLOR = "#374151"


@dataclass
class ProjectDependencyGraph:
    """项目内 .py 文件的 import 依赖图。"""

    graph: nx.DiGraph
    in_degrees: dict[str, int]
    core_nodes: list[str]

    @property
    def nodes(self) -> list[str]:
        """全部文件节点（按路径排序）。"""
        return sorted(self.graph.nodes)

    @property
    def edges(self) -> list[tuple[str, str]]:
        """全部依赖边（source 引用 target）。"""
        return sorted(self.graph.edges)

    @property
    def has_edges(self) -> bool:
        """是否存在文件之间的引用关系。"""
        return self.graph.number_of_edges() > 0


def build_project_dependency_graph(target: str | Path) -> ProjectDependencyGraph:
    """扫描目录并构建 .py 文件之间的 import 依赖图。"""
    root = Path(target).expanduser().resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"目标不是文件夹: {root}")

    sources: dict[str, str] = {}
    for path in iter_python_files(root):
        relative = path.relative_to(root).as_posix()
        try:
            sources[relative] = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            sources[relative] = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return build_dependency_graph_from_sources(sources)


def build_dependency_graph_from_sources(
    sources: dict[str, str],
) -> ProjectDependencyGraph:
    """从 {相对路径: 源码} 构建文件级依赖图。"""
    module_index = _module_index(sources)
    graph = nx.DiGraph()
    graph.add_nodes_from(sources)

    for filename, source in sources.items():
        try:
            tree = ast.parse(source, filename=filename)
        except (SyntaxError, ValueError, RecursionError):
            continue
        package = _package_parts(filename)
        targets: set[str] = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    target = _resolve_module(alias.name.split("."), module_index)
                    if target is not None:
                        targets.add(target)
            elif isinstance(node, ast.ImportFrom):
                base = _import_from_base(node, package)
                if base is None:
                    continue
                if base:
                    target = _resolve_module(base, module_index)
                    if target is not None:
                        targets.add(target)
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    target = _resolve_module(
                        base + alias.name.split("."), module_index
                    )
                    if target is not None:
                        targets.add(target)

        for target in targets:
            if target != filename:
                graph.add_edge(filename, target)

    in_degrees = {
        node: int(graph.in_degree(node)) for node in graph.nodes
    }
    max_in_degree = max(in_degrees.values(), default=0)
    core_nodes = sorted(
        node
        for node, degree in in_degrees.items()
        if max_in_degree > 0 and degree == max_in_degree
    )
    return ProjectDependencyGraph(graph, in_degrees, core_nodes)


def build_dependency_figure(data: ProjectDependencyGraph) -> go.Figure:
    """把依赖图渲染为 Plotly 网络图；核心节点红色放大。"""
    graph = data.graph
    if graph.number_of_nodes() == 0:
        return _empty_figure()

    if graph.number_of_edges() == 0 or graph.number_of_nodes() <= 2:
        positions = nx.circular_layout(graph)
    else:
        positions = nx.spring_layout(
            graph,
            seed=42,
            k=1.6 / max(1, graph.number_of_nodes()) ** 0.5,
        )

    labels = _labels(data.nodes)
    core = set(data.core_nodes)
    edge_x: list[float | None] = []
    edge_y: list[float | None] = []
    annotations: list[dict] = []

    for source, target in graph.edges:
        x0, y0 = positions[source]
        x1, y1 = positions[target]
        edge_x.extend([float(x0), float(x1), None])
        edge_y.extend([float(y0), float(y1), None])
        annotations.append(
            {
                "x": float(x1),
                "y": float(y1),
                "ax": float(x0),
                "ay": float(y0),
                "xref": "x",
                "yref": "y",
                "axref": "x",
                "ayref": "y",
                "showarrow": True,
                "arrowhead": 2,
                "arrowsize": 1,
                "arrowwidth": 1.2,
                "arrowcolor": EDGE_ARROW_COLOR,
                "text": "",
                "standoff": 16,
            }
        )

    traces: list[go.Scatter] = []
    if graph.number_of_edges():
        traces.append(
            go.Scatter(
                x=edge_x,
                y=edge_y,
                mode="lines",
                line={"width": 1.5, "color": EDGE_COLOR},
                hoverinfo="none",
                name="import 引用",
            )
        )

    normal_nodes = [node for node in data.nodes if node not in core]
    core_nodes = [node for node in data.nodes if node in core]
    if normal_nodes:
        traces.append(
            _node_trace(data, positions, labels, normal_nodes, NODE_COLOR, 28, "项目文件", TEXT_COLOR)
        )
    if core_nodes:
        traces.append(
            _node_trace(
                data,
                positions,
                labels,
                core_nodes,
                CORE_COLOR,
                58,
                "核心节点（被引用最多）",
                "#b71c1c",
            )
        )

    figure = go.Figure(data=traces)
    figure.update_layout(
        height=440,
        margin={"l": 12, "r": 12, "t": 28, "b": 12},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        showlegend=True,
        legend={
            "orientation": "h",
            "yanchor": "bottom",
            "y": 1.02,
            "x": 0,
            "font": {"size": 11},
        },
        hovermode="closest",
        annotations=annotations,
        dragmode="pan",
        uirevision="project-dependency-graph",
    )
    xs = [float(positions[node][0]) for node in data.nodes]
    ys = [float(positions[node][1]) for node in data.nodes]
    figure.update_xaxes(
        visible=False,
        fixedrange=True,
        range=[min(xs) - 0.35, max(xs) + 0.35],
    )
    figure.update_yaxes(
        visible=False,
        fixedrange=True,
        range=[min(ys) - 0.4, max(ys) + 0.25],
    )
    return figure


def _node_trace(
    data: ProjectDependencyGraph,
    positions: dict,
    labels: dict[str, str],
    nodes: list[str],
    color: str,
    size: int,
    name: str,
    text_color: str,
) -> go.Scatter:
    """构建一个节点轨迹。"""
    return go.Scatter(
        x=[float(positions[node][0]) for node in nodes],
        y=[float(positions[node][1]) for node in nodes],
        mode="markers+text",
        name=name,
        text=[labels[node] for node in nodes],
        textposition="bottom center",
        textfont={"size": 11, "color": text_color},
        marker={
            "size": size,
            "color": color,
            "line": {"width": 2, "color": "#ffffff"},
        },
        customdata=[
            [data.in_degrees.get(node, 0), data.graph.out_degree(node)]
            for node in nodes
        ],
        hovertemplate=(
            "<b>%{text}</b><br>"
            "被引用：%{customdata[0]} 次<br>"
            "引用其他文件：%{customdata[1]} 个"
            "<extra></extra>"
        ),
    )


def _empty_figure() -> go.Figure:
    """没有 .py 文件时返回空图。"""
    figure = go.Figure()
    figure.update_layout(
        height=220,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        xaxis={"visible": False},
        yaxis={"visible": False},
        annotations=[
            {
                "text": "没有可分析的 .py 文件",
                "xref": "paper",
                "yref": "paper",
                "x": 0.5,
                "y": 0.5,
                "showarrow": False,
                "font": {"size": 13, "color": TEXT_COLOR},
            }
        ],
    )
    return figure


def _module_index(sources: dict[str, str]) -> dict[str, str]:
    """建立 Python 模块名到文件路径的映射。"""
    index: dict[str, str] = {}
    for filename in sources:
        path = PurePosixPath(filename)
        parts = list(path.with_suffix("").parts)
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        if parts:
            index[".".join(parts)] = filename
    return index


def _package_parts(filename: str) -> list[str]:
    """返回文件所在包的路径片段。"""
    parts = list(PurePosixPath(filename).parent.parts)
    return [part for part in parts if part not in {"", "."}]


def _import_from_base(
    node: ast.ImportFrom,
    package: list[str],
) -> list[str] | None:
    """计算 ImportFrom 的模块基础路径；越界相对导入返回 None。"""
    if node.level:
        drop = node.level - 1
        if drop > len(package):
            return None
        prefix = package[: len(package) - drop] if drop else list(package)
        if node.module:
            prefix.extend(node.module.split("."))
        return prefix
    if node.module:
        return node.module.split(".")
    return []


def _resolve_module(
    parts: list[str],
    module_index: dict[str, str],
) -> str | None:
    """把模块路径解析为本地文件；优先最长匹配。"""
    if not parts:
        return None
    for length in range(len(parts), 0, -1):
        candidate = ".".join(parts[:length])
        if candidate in module_index:
            return module_index[candidate]
    return None


def _labels(nodes: list[str]) -> dict[str, str]:
    """生成节点标签；重名文件使用完整相对路径。"""
    names = {node: PurePosixPath(node).name for node in nodes}
    if len(set(names.values())) == len(names):
        return names
    return {node: node for node in nodes}
