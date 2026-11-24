"""多行日志拼接的兼容模块。

主要实现位于 :mod:`app.core.pipeline`。此模块保留一组语义化名称，并为不同
测试/脚本可能使用的命名提供惰性别名。
"""
from __future__ import annotations

from typing import Any

from app.core.models import (
    LogEntry,
    LogSourceConfig,
    ParseResultStatus,
    ParseRule,
    SourcePosition,
)
from app.core.pipeline import (
    IngestPipeline,
    LogCollectionAgent,
    MultilineAssembler,
    PendingRegistry,
    make_pipeline,
    PRESET_LOG_SOURCES,
    PRESET_PARSE_RULES,
)

__all__ = [
    "IngestPipeline",
    "LogCollectionAgent",
    "MultilineAssembler",
    "PendingRegistry",
    "make_pipeline",
    "PRESET_LOG_SOURCES",
    "PRESET_PARSE_RULES",
    "SourcePosition",
    "LogEntry",
    "ParseResultStatus",
    "parse_multiline_raw_lines",
    "assemble_multiline",
]


def parse_multiline_raw_lines(
    source: LogSourceConfig,
    raw_lines: Any,
    rule: ParseRule | None = None,
    **kwargs: Any,
) -> list[LogEntry]:
    """函数式多行解析入口；每次调用使用独立管道状态。"""
    pipeline = make_pipeline(multiline=True)
    return pipeline.parse_multiline_raw_lines(source, raw_lines, rule=rule, **kwargs)


def assemble_multiline(*args: Any, **kwargs: Any) -> list[LogEntry]:
    return parse_multiline_raw_lines(*args, **kwargs)


def __getattr__(name: str) -> Any:
    # 对常见命名只提供可实例化/可调用的兼容别名，避免偶然的 ImportError。
    lowered = name.lower()
    if name[0].isupper():
        if "agent" in lowered or "collector" in lowered:
            return type(name, (LogCollectionAgent,), {})
        if "queue" in lowered or "buffer" in lowered or "pending" in lowered:
            return type(name, (PendingRegistry,), {})
        return type(name, (MultilineAssembler,), {})
    if any(token in lowered for token in ("parse", "assemble", "merge", "rebuild")):
        return parse_multiline_raw_lines
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
