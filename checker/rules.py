"""内置检查规则。

每条规则通过 ``@rule`` 装饰器登记，函数接收 ``RuleContext`` 并产生
``Finding``；引擎负责把 ``Finding`` 补全为带规则元数据的 ``Issue``。
新增规则只需在本模块追加一个装饰器函数，无需修改引擎。
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Callable, Iterable

from .models import Severity

MAX_LINE_LENGTH = 100
MAX_FUNCTION_LINES = 40
MAX_PARAMS = 5
MAX_COMPLEXITY = 10
MAX_FILE_LINES = 400

_SECRET_NAME = re.compile(
    r"(pass(word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)",
    re.IGNORECASE,
)
_SECRET_PLACEHOLDER = re.compile(
    r"^(\*+|<.*>|x{3,}|change[_-]?me|your[_-].*)$",
    re.IGNORECASE,
)
_TODO = re.compile(r"#.*\b(TODO|FIXME|XXX|HACK)\b", re.IGNORECASE)
_DANGEROUS_CALLS = frozenset({"eval", "exec"})
_MUTABLE_FACTORIES = frozenset({"list", "dict", "set"})
_EXTERNAL_HTTP_METHODS = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options", "request"}
)
_EXTERNAL_HTTP_MODULES = frozenset({"requests", "httpx", "aiohttp"})
_SUBPROCESS_METHODS = frozenset(
    {"run", "call", "check_call", "check_output", "Popen"}
)
_TRY_NODES = (ast.Try, ast.TryStar) if hasattr(ast, "TryStar") else (ast.Try,)


@dataclass
class RuleContext:
    """规则运行所需的只读上下文。"""

    path: str
    source: str
    tree: ast.Module
    lines: list[str]

    def evidence(self, line: int) -> str:
        """返回指定行的去空白源码，行号越界时返回空串。"""
        if 1 <= line <= len(self.lines):
            return self.lines[line - 1].strip()[:120]
        return ""


@dataclass(frozen=True)
class Finding:
    """规则上报的原始结论，此时还没有规则元数据。"""

    line: int
    message: str
    suggestion: str = ""


@dataclass(frozen=True)
class Rule:
    """一条可执行规则。"""

    code: str
    name: str
    severity: Severity
    check: Callable[[RuleContext], Iterable[Finding]]
    description: str = ""


RULES: list[Rule] = []


def rule(code: str, name: str, severity: Severity, description: str = ""):
    """把检查函数登记为一条规则。"""

    def decorator(func):
        RULES.append(Rule(code, name, severity, func, description))
        return func

    return decorator


@rule("PE001", "行长超限", Severity.LOW)
def check_line_length(ctx: RuleContext) -> Iterable[Finding]:
    for number, line in enumerate(ctx.lines, start=1):
        if len(line) > MAX_LINE_LENGTH:
            yield Finding(
                number,
                f"该行 {len(line)} 字符，超过 {MAX_LINE_LENGTH} 字符上限",
                "拆分表达式或提取中间变量",
            )


@rule("PE002", "行尾空白", Severity.LOW)
def check_trailing_whitespace(ctx: RuleContext) -> Iterable[Finding]:
    for number, line in enumerate(ctx.lines, start=1):
        if line.strip() and line != line.rstrip():
            yield Finding(number, "行尾存在多余空白", "删除行尾空白")


@rule("PE003", "模块缺少文档字符串", Severity.LOW)
def check_module_docstring(ctx: RuleContext) -> Iterable[Finding]:
    if not ast.get_docstring(ctx.tree):
        yield Finding(
            1,
            "模块缺少文档字符串",
            '在文件顶部添加 """模块职责说明"""',
        )


@rule("PE004", "公共函数缺少文档字符串", Severity.LOW)
def check_function_docstring(ctx: RuleContext) -> Iterable[Finding]:
    for node in ast.walk(ctx.tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name.startswith("_"):
            continue
        if ast.get_docstring(node) is None:
            yield Finding(
                node.lineno,
                f"公共函数 {node.name}() 缺少文档字符串",
                "补充参数、返回值与异常说明",
            )


@rule("PE005", "裸 except", Severity.HIGH)
def check_bare_except(ctx: RuleContext) -> Iterable[Finding]:
    for node in ast.walk(ctx.tree):
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            yield Finding(
                node.lineno,
                "使用裸 except，会吞掉 KeyboardInterrupt 等所有异常",
                "捕获具体异常类型，或至少写 except Exception as exc",
            )


@rule("PE006", "异常捕获过宽", Severity.MEDIUM)
def check_broad_except(ctx: RuleContext) -> Iterable[Finding]:
    for node in ast.walk(ctx.tree):
        if not isinstance(node, ast.ExceptHandler) or node.type is None:
            continue
        name = None
        if isinstance(node.type, ast.Name):
            name = node.type.id
        elif isinstance(node.type, ast.Attribute):
            name = node.type.attr
        if name in {"Exception", "BaseException"}:
            yield Finding(
                node.lineno,
                f"捕获范围过宽（{name}），可能掩盖真实错误",
                "缩小异常类型范围，并记录异常信息",
            )


@rule("PE007", "函数过长", Severity.MEDIUM)
def check_function_length(ctx: RuleContext) -> Iterable[Finding]:
    for node in ast.walk(ctx.tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        end = getattr(node, "end_lineno", None) or node.lineno
        length = end - node.lineno + 1
        if length > MAX_FUNCTION_LINES:
            yield Finding(
                node.lineno,
                f"函数 {node.name}() 共 {length} 行，建议不超过 {MAX_FUNCTION_LINES} 行",
                "按职责拆分为多个小函数",
            )


@rule("PE008", "参数过多", Severity.MEDIUM)
def check_too_many_params(ctx: RuleContext) -> Iterable[Finding]:
    for node in ast.walk(ctx.tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        args = node.args
        names = [arg.arg for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs)]
        if names and names[0] in {"self", "cls"}:
            names = names[1:]
        if len(names) > MAX_PARAMS:
            yield Finding(
                node.lineno,
                f"函数 {node.name}() 有 {len(names)} 个参数，建议不超过 {MAX_PARAMS} 个",
                "把相关参数封装为配置对象",
            )


def _is_mutable_default(node: ast.expr) -> bool:
    if isinstance(node, (ast.List, ast.Dict, ast.Set, ast.ListComp, ast.DictComp, ast.SetComp)):
        return True
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in _MUTABLE_FACTORIES
    )


@rule("PE009", "可变默认参数", Severity.MEDIUM)
def check_mutable_default(ctx: RuleContext) -> Iterable[Finding]:
    for node in ast.walk(ctx.tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        args = node.args
        positional = [*args.posonlyargs, *args.args]
        paired = list(zip(positional[len(positional) - len(args.defaults):], args.defaults))
        paired += [
            (arg, default)
            for arg, default in zip(args.kwonlyargs, args.kw_defaults)
            if default is not None
        ]
        bad = [arg.arg for arg, default in paired if _is_mutable_default(default)]
        if bad:
            yield Finding(
                node.lineno,
                f"函数 {node.name}() 的可变默认参数 {', '.join(bad)} 会在多次调用间共享",
                "默认值改为 None，在函数体内创建新容器",
            )


@rule("PE010", "调试输出", Severity.MEDIUM)
def check_print(ctx: RuleContext) -> Iterable[Finding]:
    for node in ast.walk(ctx.tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "print":
                yield Finding(
                    node.lineno,
                    "检测到 print 调试输出",
                    "改用 logging，生产代码不要直接 print",
                )


@rule("PE011", "硬编码敏感信息", Severity.HIGH)
def check_hardcoded_secret(ctx: RuleContext) -> Iterable[Finding]:
    for node in ast.walk(ctx.tree):
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        else:
            continue
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            continue
        raw = value.value.strip()
        if len(raw) < 8 or _SECRET_PLACEHOLDER.match(raw):
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                name = target.id
            else:
                name = getattr(target, "attr", "")
            if name and _SECRET_NAME.search(name):
                yield Finding(
                    node.lineno,
                    f"变量 {name} 疑似保存硬编码凭据",
                    "改用环境变量或密钥管理服务，并轮换已泄露的值",
                )


@rule("PE012", "未使用的导入", Severity.MEDIUM)
def check_unused_imports(ctx: RuleContext) -> Iterable[Finding]:
    used = {
        node.id
        for node in ast.walk(ctx.tree)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
    }
    for node in ast.walk(ctx.tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            used.update(re.findall(r"[A-Za-z_]\w*", node.value))
    for node in ast.walk(ctx.tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".")[0]
                if bound not in used:
                    yield Finding(node.lineno, f"导入的 {bound} 未被使用", "删除未使用的导入")
        elif isinstance(node, ast.ImportFrom):
            if node.module == "__future__":
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                bound = alias.asname or alias.name
                if bound not in used:
                    yield Finding(
                        node.lineno,
                        f"从 {node.module} 导入的 {bound} 未被使用",
                        "删除未使用的导入",
                    )


@rule("PE013", "动态执行", Severity.HIGH)
def check_dangerous_calls(ctx: RuleContext) -> Iterable[Finding]:
    for node in ast.walk(ctx.tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in _DANGEROUS_CALLS:
                yield Finding(
                    node.lineno,
                    f"调用 {node.func.id}() 执行动态代码，存在注入风险",
                    "改用显式解析逻辑，并对输入做白名单校验",
                )


def _iter_function_nodes(node: ast.AST) -> Iterable[ast.AST]:
    """遍历函数体内的节点，但不进入嵌套函数或类。"""
    stack = list(ast.iter_child_nodes(node))
    while stack:
        child = stack.pop()
        yield child
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        stack.extend(ast.iter_child_nodes(child))


def _complexity(node: ast.AST) -> int:
    score = 1
    for child in _iter_function_nodes(node):
        if isinstance(child, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.IfExp, ast.ExceptHandler)):
            score += 1
        elif isinstance(child, ast.BoolOp):
            score += len(child.values) - 1
        elif isinstance(child, ast.comprehension):
            score += 1 + len(child.ifs)
    return score


@rule("PE014", "圈复杂度过高", Severity.MEDIUM)
def check_complexity(ctx: RuleContext) -> Iterable[Finding]:
    for node in ast.walk(ctx.tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        score = _complexity(node)
        if score > MAX_COMPLEXITY:
            yield Finding(
                node.lineno,
                f"函数 {node.name}() 圈复杂度为 {score}，建议不超过 {MAX_COMPLEXITY}",
                "拆分条件分支，提取辅助函数",
            )


@rule("PE015", "待办标记", Severity.LOW)
def check_todo(ctx: RuleContext) -> Iterable[Finding]:
    for number, line in enumerate(ctx.lines, start=1):
        match = _TODO.search(line)
        if match:
            yield Finding(
                number,
                f"发现 {match.group(1).upper()} 标记，功能可能尚未完成",
                "在合并前处理，或登记为可跟踪的任务",
            )


@rule("PE016", "文件过长", Severity.LOW)
def check_file_length(ctx: RuleContext) -> Iterable[Finding]:
    if len(ctx.lines) > MAX_FILE_LINES:
        yield Finding(
            1,
            f"文件共 {len(ctx.lines)} 行，建议不超过 {MAX_FILE_LINES} 行",
            "按职责拆分模块",
        )


def _dotted_name(node: ast.AST) -> str:
    """还原调用表达式的点分名称，无法还原时返回空串。"""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _is_external_call(node: ast.Call) -> bool:
    """判断是否为常见网络/外部进程调用。"""
    name = _dotted_name(node.func)
    if not name:
        return False
    root = name.split(".")[0]
    last = name.rsplit(".", 1)[-1]
    if root in _EXTERNAL_HTTP_MODULES and last in _EXTERNAL_HTTP_METHODS:
        return True
    if name in {"urlopen", "urllib.request.urlopen", "urllib3.urlopen"}:
        return True
    if root == "socket" and last == "create_connection":
        return True
    if root == "subprocess" and last in _SUBPROCESS_METHODS:
        return True
    if root == "os" and last in {"system", "popen"}:
        return True
    return False


def _build_parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    """构建 AST 父节点映射。"""
    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    return parents


def _is_caught(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    """判断节点是否位于带 except 的 try 语句体中。"""
    child = node
    current = parents.get(child)
    while current is not None:
        if isinstance(
            current,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef),
        ):
            # 外层 try 无法捕获嵌套函数/类真正执行时才发生的异常。
            return False
        if (
            isinstance(current, _TRY_NODES)
            and current.handlers
            and child in current.body
        ):
            return True
        child = current
        current = parents.get(current)
    return False


@rule("PE017", "未捕获外部调用", Severity.MEDIUM)
def check_uncaught_external_call(ctx: RuleContext) -> Iterable[Finding]:
    parents = _build_parents(ctx.tree)
    for node in ast.walk(ctx.tree):
        if not isinstance(node, ast.Call):
            continue
        if not _is_external_call(node):
            continue
        if _is_caught(node, parents):
            continue
        name = _dotted_name(node.func) or "外部调用"
        yield Finding(
            node.lineno,
            f"外部调用 {name}() 未被 try/except 捕获，失败时可能导致流程中断",
            "使用 try/except 捕获网络或进程异常，并设置超时与重试",
        )
