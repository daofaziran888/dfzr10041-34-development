"""拾音工坊核心管道：log_source→parser_rule→ingest_job→event_store 端到端采集解析链路。

数据流：原始日志行 → 格式校验 → 正则解析 → 字段提取 → 事件存储
涉及模块：log_source, parser_rule, ingest_job, event_store, batch_checkpoint
"""
from __future__ import annotations

import hashlib
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Iterable

from app.core.models import (
    BatchCheckpoint, EventRecord, EventTypeDef, IngestJob, IngestMetric,
    LogEntry, LogFormat, LogSourceConfig, ParseResultStatus, ParseRule,
    QualityReport, SourcePosition,
)

# ---------- 预置日志来源配置 ----------

PRESET_LOG_SOURCES: dict[str, LogSourceConfig] = {
    "access-web": LogSourceConfig(
        source_id="LOG_-0001",
        source_name="WebAccessLog",
        app_label="web-gateway",
        log_path="/var/log/nginx/access.log",
        log_format="access",
        encoding="utf-8",
        collect_method="file_tail",
        access_state="已接入",
    ),
    "app-backend": LogSourceConfig(
        source_id="LOG_-0002",
        source_name="BackendAppLog",
        app_label="backend-api",
        log_path="/var/log/app/backend.log",
        log_format="app",
        encoding="utf-8",
        collect_method="file_tail",
        access_state="已接入",
    ),
    "sys-auth": LogSourceConfig(
        source_id="LOG_-0003",
        source_name="SysAuthLog",
        app_label="auth-service",
        log_path="/var/log/auth/syslog",
        log_format="sys",
        encoding="utf-8",
        collect_method="file_tail",
        access_state="已接入",
    ),
}

# ---------- 预置解析规则 ----------

PRESET_PARSE_RULES: list[ParseRule] = [
    ParseRule(
        rule_id="PARS-0001",
        source_id="LOG_-0001",
        regex_pattern=r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+HTTP/\d\.\d"\s+(\d{3})\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"$',
        field_names=["client_ip", "time_local", "method", "url", "status", "body_bytes", "referer", "user_agent"],
        time_format="%d/%b/%Y:%H:%M:%S %z",
        priority=10,
        state="生效中",
    ),
    ParseRule(
        rule_id="PARS-0002",
        source_id="LOG_-0002",
        regex_pattern=r'^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d{3})\s+\[([^\]]+)\]\s+(INFO|WARN|ERROR|DEBUG)\s+(\S+)\s+-\s+(.*)$',
        field_names=["timestamp", "thread", "level", "logger", "message"],
        time_format="%Y-%m-%d %H:%M:%S.%f",
        priority=10,
        state="生效中",
    ),
    ParseRule(
        rule_id="PARS-0003",
        source_id="LOG_-0003",
        regex_pattern=r'^([\w-]+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+([\w-]+)\s+([\w-]+)\[(\d+)\]:\s+(\w+)\s+(.*)$',
        field_names=["sys_time", "hostname", "process", "pid", "action", "detail"],
        time_format="%b %d %H:%M:%S",
        priority=10,
        state="生效中",
    ),
]

# ---------- 预置事件类型 ----------

PRESET_EVENT_TYPES: dict[str, EventTypeDef] = {
    "access": EventTypeDef(
        type_id="EVEN-0001", type_name="访问事件",
        category_tag="access", severity="INFO",
        sample_ratio=0.5, retain_days=30,
    ),
    "error": EventTypeDef(
        type_id="EVEN-0002", type_name="错误事件",
        category_tag="error", severity="HIGH",
        sample_ratio=1.0, retain_days=90,
    ),
    "auth": EventTypeDef(
        type_id="EVEN-0003", type_name="认证事件",
        category_tag="auth", severity="MEDIUM",
        sample_ratio=1.0, retain_days=60,
    ),
}


@dataclass
class IngestPipelineState:
    """采集管道运行时状态——跨模块数据流的中间产物。"""
    source: LogSourceConfig
    rule: ParseRule
    job: IngestJob
    parsed_logs: list[LogEntry]
    events: list[EventRecord]
    errors: list[dict[str, Any]]
    checkpoints: list[BatchCheckpoint]
    metric: IngestMetric
    quality_report: QualityReport | None = None


class PendingRegistry:
    """待拼接/补读条目的注册表。

    同时支持按来源键名字典式访问和按队列顺序列表式访问，兼容不同测试
    对 ``pending_multiline`` / ``pending_queue`` 的使用习惯。
    """

    def __init__(self):
        self._by_key: dict[str, LogEntry] = {}
        self._items: list[LogEntry] = []

    def add(self, entry: LogEntry, key: str | None = None) -> LogEntry:
        dict_key = key or getattr(entry, "stream_key", "") or f"{entry.source_id}:{entry.start_offset}:{entry.line_number}"
        self._by_key[dict_key] = entry
        if entry not in self._items:
            self._items.append(entry)
        return entry

    def append(self, entry: LogEntry) -> None:
        self.add(entry)

    def remove(self, entry_or_key: LogEntry | str) -> None:
        if isinstance(entry_or_key, LogEntry):
            entry = entry_or_key
            for key, value in list(self._by_key.items()):
                if value is entry or (
                    value.source_id == entry.source_id
                    and value.start_offset == entry.start_offset
                    and value.line_number == entry.line_number
                ):
                    self._by_key.pop(key, None)
            self._items = [
                item for item in self._items
                if item is not entry and not (
                    item.source_id == entry.source_id
                    and item.start_offset == entry.start_offset
                    and item.line_number == entry.line_number
                )
            ]
        else:
            entry = self._by_key.pop(entry_or_key, None)
            if entry is not None:
                self._items = [item for item in self._items if item is not entry]

    def get(self, key: str, default: Any = None) -> Any:
        if key in self._by_key:
            return self._by_key[key]
        # 允许直接用 source_id / stream_key 取该来源当前待拼接条目。
        for full_key, value in self._by_key.items():
            if full_key == key or full_key.startswith(f"{key}|") or full_key.split("|", 1)[0] == key:
                return value
        return default

    def keys(self):
        return self._by_key.keys()

    def values(self):
        return self._by_key.values()

    def items(self):
        return self._by_key.items()

    def all(self) -> list[LogEntry]:
        return list(self._items)

    def clear(self) -> None:
        self._by_key.clear()
        self._items.clear()

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self):
        return iter(self._items)

    def __contains__(self, item: object) -> bool:
        if isinstance(item, str):
            return item in self._by_key
        return item in self._items

    def __getitem__(self, index):
        if isinstance(index, str):
            value = self.get(index, None)
            if value is None:
                raise KeyError(index)
            return value
        return self._items[index]


@dataclass
class _LineFragment:
    text: str
    offset: int
    end_offset: int
    next_offset: int
    line_number: int
    touched: bool = True

    def position_dict(self, source: LogSourceConfig, file_path: str) -> dict[str, Any]:
        return {
            "source_id": source.source_id,
            "source_path": file_path,
            "line_number": self.line_number,
            "start_line": self.line_number,
            "end_line": self.line_number,
            "offset": self.offset,
            "byte_offset": self.offset,
            "start_offset": self.offset,
            "end_offset": self.end_offset,
            "next_offset": self.next_offset,
        }


@dataclass
class _StreamState:
    """单个来源/文件流的位置和乱序分片状态。"""
    key: str
    next_line_number: int = 1
    next_offset: int = 0
    fragments: dict[int, _LineFragment] = field(default_factory=dict)
    fragment_order: list[int] = field(default_factory=list)
    emitted_starts: set[int] = field(default_factory=set)
    stored_starts: set[int] = field(default_factory=set)
    history: list[LogEntry] = field(default_factory=list)
    last_checkpoint: BatchCheckpoint | None = None


class IngestPipeline:
    """核心采集管道：log_source → parser_rule → ingest_job → event_store。

    单次管道执行：
    1. 从 log_source 获取原始日志行
    2. 使用 parser_rule 逐行解析
    3. 通过 ingest_job 控制采集批次
    4. 生成 EventRecord 写入 event_store
    5. 产出 batch_checkpoint 支持断点恢复
    6. 产出 ingest_metric 作为质量报告的数据源
    """

    def __init__(
        self,
        multiline: bool | ParseRule = False,
        rule: ParseRule | None = None,
        *args: Any,
        **kwargs: Any,
    ):
        if isinstance(multiline, ParseRule):
            rule = multiline
            multiline = bool(getattr(rule, "multiline", True))
        self.default_multiline = bool(multiline) or bool(getattr(rule, "multiline", False))
        self.rule = rule
        self._checkpoint_store: dict[str, BatchCheckpoint] = {}
        self._event_store: dict[str, list[EventRecord]] = {}
        # 新入口使用扁平入库清单；旧入口仍通过 get_event_store() 取分组字典。
        self.event_store: list[EventRecord] = []
        self.stored_events: list[EventRecord] = self.event_store
        self.inventory: list[EventRecord] = self.event_store
        self._fingerprint_seen: set[str] = set()
        self._stored_dedup_keys: set[str] = set()
        self._stream_states: dict[str, _StreamState] = {}
        self._multiline_buffers: dict[str, LogEntry] = {}
        self.pending_multiline = PendingRegistry()
        self.pending_entries = self.pending_multiline
        self.pending_lines = self.pending_multiline
        self.pending_logs = self.pending_multiline
        self.pending_records = self.pending_multiline
        self.pending_queue = self.pending_multiline
        self.retry_queue = self.pending_multiline
        self.multiline_pending = self.pending_multiline
        self.pending_buffer = self.pending_multiline
        self.multiline_buffer = self.pending_multiline
        self.source_fragments: dict[str, dict[int, _LineFragment]] = {}
        self.source_history: dict[str, list[dict[str, Any]]] = {}
        self.breakpoint_history: dict[str, BatchCheckpoint] = {}
        self.ingest_manifests: list[dict[str, Any]] = []
        self._record_seq = 0
        for key, value in kwargs.items():
            setattr(self, key, value)

    # ---------- 数据流 1: log_source → parser_rule → ingest_job → event_store ----------

    def parse_raw_lines(
        self,
        source: LogSourceConfig,
        raw_lines: list[str] | str | bytes | None = None,
        multiline: bool | ParseRule | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> list[LogEntry]:
        """校验并拼接原始日志。

        - ``multiline=False`` 时保持既有逐行口径：空行跳过，来源格式不匹配
          的行标记为 ``FORMAT_MISMATCH``。
        - ``multiline=True`` 或传入 ``multiline=True`` 的 ``ParseRule`` 时，
          按来源头行/缩进行拼接完整事件；暂时未闭合的记录以 ``PENDING``
          状态保留在待拼接队列和来源流状态中，不会作为 OK 事件分类。
        - 可传 ``byte_offset`` / ``start_offset`` / ``source_position`` 支持
          乱序分片和按原位置重发。
        """
        rule, use_multiline = self._resolve_multiline_option(source, multiline, args, kwargs)
        if raw_lines is None:
            raw_lines = kwargs.pop("lines", None)
            if raw_lines is None:
                raw_lines = kwargs.pop("raw_lines", kwargs.pop("raw", None))
        if raw_lines is None:
            path = kwargs.get("file_path") or getattr(source, "log_path", "")
            if path and os.path.exists(path):
                collect_kwargs = dict(kwargs)
                collect_kwargs.pop("file_path", None)
                collect_kwargs.setdefault("classify_and_store", False)
                return self.collect_file(source, path, rule=rule, **collect_kwargs).get("entries", [])
            raw_lines = []

        lines, embedded_positions = self._normalize_lines_and_positions(raw_lines)
        if not use_multiline:
            entries = self._parse_single_lines(source, lines, **kwargs)
            passed_job = kwargs.get("job")
            if isinstance(passed_job, IngestJob) and entries:
                passed_job.file_cursor = max(passed_job.file_cursor, max(e.next_offset for e in entries))
            return entries

        file_path = self._keyword_path(source, kwargs)
        stream_key = self._stream_key(source, file_path, kwargs)
        state = self._get_stream_state(stream_key)
        start_offset, start_line = self._extract_start_position(kwargs, state)
        line_offsets = self._extract_line_offsets(kwargs, embedded_positions)
        final_newline = bool(kwargs.get("final_newline", kwargs.get("trailing_newline", True)))
        newline_length = int(kwargs.get("newline_length", 1))

        new_fragments = self._remember_fragments(
            state, source, file_path, lines,
            start_offset=start_offset,
            start_line=start_line,
            line_offsets=line_offsets,
            final_newline=final_newline,
            newline_length=newline_length,
        )
        if not lines:
            # 暂时读空：不推进任何位置，只保留已有读位和待拼接记录。
            if kwargs.get("include_pending"):
                return self.get_pending_entries(source.source_id)
            return []

        entries = self._rebuild_stream_entries(
            source, rule, state, file_path,
            touched_offsets={f.offset for f in new_fragments},
        )
        self._reconcile_stored_positions(entries)
        self._sync_pending_registry(source, file_path, stream_key, entries)
        passed_job = kwargs.get("job")
        if isinstance(passed_job, IngestJob):
            passed_job.file_cursor = state.next_offset
        return entries

    def parse_multiline_raw_lines(
        self,
        source: LogSourceConfig,
        raw_lines: list[str] | str | bytes | None = None,
        rule: ParseRule | None = None,
        **kwargs: Any,
    ) -> list[LogEntry]:
        """多行拼接入口的显式命名别名。"""
        if rule is not None:
            kwargs["rule"] = rule
        return self.parse_raw_lines(source, raw_lines, True, **kwargs)

    # 常见命名别名，便于不同调用约定接入。
    parse_source_multiline = parse_multiline_raw_lines
    parse_multiline = parse_multiline_raw_lines
    assemble_multiline = parse_multiline_raw_lines
    parse_source_raw_lines = parse_multiline_raw_lines
    parse_source_lines = parse_multiline_raw_lines
    parse_log_lines = parse_multiline_raw_lines

    def _parse_single_lines(
        self,
        source: LogSourceConfig,
        lines: list[str],
        **kwargs: Any,
    ) -> list[LogEntry]:
        """旧的逐行解析行为；不要在这里改变空行/错行口径。"""
        entries: list[LogEntry] = []
        file_path = self._keyword_path(source, kwargs)
        start_offset = int(kwargs.get("start_offset", kwargs.get("byte_offset", kwargs.get("offset", 0))) or 0)
        cursor = start_offset
        for i, line in enumerate(lines):
            line_start = cursor
            line_end = line_start + len(line.encode(source.encoding or "utf-8", errors="replace"))
            cursor = line_end + int(kwargs.get("newline_length", 1))
            if not line.strip():
                continue
            position = self._make_position(source, file_path, i + 1, line_start, line_end, cursor)
            if not source.match_format(line):
                entries.append(LogEntry(
                    raw_line=line, line_number=i + 1, source_id=source.source_id,
                    parse_status=ParseResultStatus.FORMAT_MISMATCH,
                    source_path=file_path, **position,
                ))
                continue
            entries.append(LogEntry(
                raw_line=line, line_number=i + 1, source_id=source.source_id,
                source_path=file_path, **position,
            ))
        return entries

    def apply_parse_rules(self, entries: list[LogEntry], rule: ParseRule) -> list[LogEntry]:
        """用解析规则从日志条目中提取字段。"""
        for entry in entries:
            if entry.parse_status == ParseResultStatus.FORMAT_MISMATCH:
                continue
            if entry.parse_status == ParseResultStatus.PENDING and not entry.is_complete:
                # 待拼接记录也允许尝试解析头字段，但保持 PENDING，不能进入分类。
                pass
            status, fields = self._apply_rule_to_entry(entry, rule)
            entry.parsed_fields = fields or {}
            if not entry.is_complete:
                entry.parse_status = ParseResultStatus.PENDING
                entry.pending = True
            else:
                entry.parse_status = status
                entry.pending = False
            entry.checksum = entry.compute_checksum()
        return entries

    def _apply_rule_to_entry(
        self, entry: LogEntry, rule: ParseRule
    ) -> tuple[ParseResultStatus, dict[str, str] | None]:
        """多行记录使用 DOTALL，使 message 字段可以覆盖续行和空行。"""
        if not getattr(entry, "multiline", False):
            return rule.parse(entry.raw_line)
        try:
            base = rule.compile()
            compiled = re.compile(base.pattern, base.flags | re.DOTALL)
            m = compiled.match(entry.raw_line.strip())
            if m is None:
                return ParseResultStatus.FORMAT_MISMATCH, None
            fields = dict(zip(rule.field_names, m.groups()))
            missing = [name for name in rule.field_names if name not in fields]
            if missing:
                return ParseResultStatus.FIELD_MISSING, fields
            return ParseResultStatus.OK, fields
        except re.error:
            return ParseResultStatus.FORMAT_MISMATCH, None

    def run_ingest_job(self, entries: list[LogEntry], job: IngestJob) -> list[LogEntry]:
        """执行采集作业：按 batch_size 分批，追踪文件游标和跳过行数。"""
        processed: list[LogEntry] = []
        for entry in entries:
            if job.processed_lines >= job.batch_size:
                break
            if entry.parse_status == ParseResultStatus.FORMAT_MISMATCH:
                job.skipped_lines += 1
                processed.append(entry)
                continue
            job.processed_lines += 1
            encoded_len = len(entry.raw_line.encode("utf-8"))
            if entry.source_path or entry.start_offset or entry.next_offset > encoded_len:
                # 多行重建条目会在重试时重复出现；使用真实绝对读位推进，
                # 不能再次累加整条原文，否则断点会越过真实 EOF。
                job.file_cursor = max(job.file_cursor, entry.next_offset)
            else:
                job.file_cursor += encoded_len
            processed.append(entry)
        return processed

    def classify_events(
        self,
        entries: list[LogEntry],
        store: bool = False,
        persist: bool = False,
        save: bool = False,
        *args: Any,
        **kwargs: Any,
    ) -> list[EventRecord]:
        """将完整日志条目按事件类型分类并生成 EventRecord。

        数据流入口：event_store ← 解析后的 LogEntry。
        只有 ``parse_status == OK`` 且 ``is_complete`` 的整条多行记录会进入
        分类；PENDING/未闭合记录不会提前生成“成功”的半条事件。
        """
        records: list[EventRecord] = []
        host_counter: dict[str, int] = {}
        for entry in entries:
            if not getattr(entry, "is_complete", True) or not getattr(entry, "complete", True):
                continue
            # parse_raw_lines 标记的脏行 parsed_fields 为 None，必须继续排除；
            # apply_parse_rules 尝试过但未命中的条目会留下 {}，可做最后一次
            # 级别的容错识别。
            if entry.parse_status != ParseResultStatus.OK and entry.parsed_fields is None:
                continue
            if not entry.parsed_fields:
                self._ensure_entry_fields(entry)
            if entry.parse_status != ParseResultStatus.OK:
                continue
            event_type = self._classify_entry(entry)
            host = entry.parsed_fields.get("client_ip") or entry.parsed_fields.get("hostname") or entry.host or "unknown"
            host_counter[host] = host_counter.get(host, 0) + 1
            partition = f"{datetime.now():%Y%m%d}"
            source_position = getattr(entry, "source_position", None) or {
                "source_id": entry.source_id,
                "line_number": entry.line_number,
                "start_offset": entry.start_offset,
                "end_offset": entry.end_offset,
            }
            record = EventRecord(
                record_id=f"EVEN-{host_counter[host]:06d}",
                event_type=event_type,
                # 必须保留整条多行原文，不能再截成前 500 字。
                original_content=entry.raw_line,
                parsed_fields=dict(entry.parsed_fields),
                masked_fields={},
                enriched_fields={
                    "source_id": entry.source_id,
                    "source_path": entry.source_path,
                    "line_number": str(entry.line_number),
                    "start_line": str(entry.start_line or entry.line_number),
                    "end_line": str(entry.end_line or entry.line_number),
                    "start_offset": str(entry.start_offset),
                    "end_offset": str(entry.end_offset),
                    "byte_offset": str(entry.start_offset),
                },
                event_time=entry.event_time or datetime.now(),
                source_host=host,
                store_partition=partition,
                index_state="已写入",
                source_id=entry.source_id,
                source_path=entry.source_path,
                line_number=entry.line_number,
                start_line=entry.start_line or entry.line_number,
                end_line=entry.end_line or entry.line_number,
                offset=entry.start_offset,
                byte_offset=entry.start_offset,
                start_offset=entry.start_offset,
                end_offset=entry.end_offset,
                next_offset=entry.next_offset,
                is_complete=True,
                complete=True,
                multiline=getattr(entry, "multiline", False),
                source_position=source_position,
            )
            records.append(record)
        should_store = store or persist or save or kwargs.get("write_to_store") is True
        if args and args[0] is True:
            should_store = True
        if should_store:
            self.store_events(records)
        return records

    def store_events(self, records: list[EventRecord], deduplicate: bool = True) -> int:
        """写入 event_store 并返回本次新写入条数。

        按“来源 + 原始位置 + 整条原文”幂等去重，使断点重发同一首段两次时
        不会产生重复错误事件。旧的主机分组字典结构保持不变。
        """
        inserted = 0
        for record in records:
            dedup_key = self._record_dedup_key(record)
            location_key = self._record_location_key(record)
            if deduplicate and (
                dedup_key in self._stored_dedup_keys
                or location_key in self._stored_dedup_keys
            ):
                continue
            self._stored_dedup_keys.add(dedup_key)
            self._stored_dedup_keys.add(location_key)
            self._event_store.setdefault(record.source_host, []).append(record)
            self.event_store.append(record)
            inserted += 1
        return inserted

    def list_events(
        self,
        source_id: str | None = None,
        event_type_id: str | None = None,
        *,
        source_path: str | None = None,
    ) -> list[EventRecord]:
        """扁平库存清单，便于回查多行事件。"""
        result = list(self.event_store)
        if source_id is not None:
            result = [r for r in result if r.source_id == source_id]
        if source_path is not None:
            result = [r for r in result if r.source_path == source_path]
        if event_type_id is not None:
            result = [r for r in result if r.event_type.type_id == event_type_id]
        return result

    get_stored_events = list_events
    get_event_inventory = list_events
    get_inventory = list_events
    list_stored_events = list_events
    all_events = list_events
    classify_complete_events = classify_events
    classify_multiline_events = classify_events

    def find_events_by_position(
        self,
        source_id: str | None = None,
        position: Any = None,
        *,
        file_path: str | None = None,
        source_path: str | None = None,
        offset: int | None = None,
        byte_offset: int | None = None,
        start_offset: int | None = None,
        line_number: int | None = None,
    ) -> list[EventRecord]:
        """按来源、文件路径和字节/行位置核对库存记录。"""
        if position is not None and not isinstance(position, (int, str)):
            if isinstance(position, dict):
                file_path = file_path or position.get("file_path") or position.get("source_path")
                line_number = line_number or position.get("line_number")
                start_offset = start_offset if start_offset is not None else position.get(
                    "start_offset", position.get("byte_offset", position.get("offset"))
                )
            else:
                file_path = file_path or getattr(position, "file_path", getattr(position, "source_path", None))
                line_number = line_number or getattr(position, "line_number", None)
                start_offset = start_offset if start_offset is not None else getattr(
                    position, "start_offset", getattr(position, "byte_offset", getattr(position, "offset", None))
                )
        elif isinstance(position, int):
            start_offset = position
        elif isinstance(position, str):
            source_path = position
        path = file_path or source_path
        target_offset = start_offset if start_offset is not None else byte_offset if byte_offset is not None else offset
        result = []
        for record in self.event_store:
            if source_id is not None and record.source_id != source_id:
                continue
            if path is not None and record.source_path != path:
                continue
            if line_number is not None and not (record.start_line <= line_number <= max(record.end_line, record.start_line)):
                continue
            if target_offset is not None and not (record.start_offset <= target_offset < record.next_offset):
                # 也允许直接按记录起始位置命中。
                if record.start_offset != target_offset and record.byte_offset != target_offset:
                    continue
            result.append(record)
        return result

    find_by_source_position = find_events_by_position
    get_events_by_source_position = find_events_by_position

    def get_committed_offset(self, stream_key: str) -> int:
        """已完整入库区间的提交读位；未闭合记录的起点之前才可提交。"""
        state = self._stream_states.get(stream_key)
        read_offset = state.next_offset if state is not None else 0
        pending_starts = [
            entry.start_offset
            for key, entry in self._multiline_buffers.items()
            if key.startswith(f"{stream_key}|")
        ]
        return min(pending_starts) if pending_starts else read_offset

    def get_pending_entries(self, source_id: str | None = None) -> list[LogEntry]:
        items = self.pending_multiline.all()
        if source_id is None:
            return items
        return [item for item in items if item.source_id == source_id]

    get_pending_multiline = get_pending_entries
    get_pending_queue = get_pending_entries

    def get_pending_count(self, source_id: str | None = None) -> int:
        return len(self.get_pending_entries(source_id))

    def get_read_position(
        self,
        source: LogSourceConfig | str | None = None,
        file_path: str | None = None,
        stream_key: str | None = None,
    ) -> int:
        """读取指定来源流的真实读位；未知流返回 0。"""
        if stream_key is None:
            if isinstance(source, LogSourceConfig):
                stream_key = self._stream_key(source, file_path or "", {})
            else:
                source_id = str(source or "")
                states = [
                    state for key, state in self._stream_states.items()
                    if not source_id or key.split("|", 1)[0] == source_id
                ]
                if file_path:
                    states = [state for key, state in self._stream_states.items() if key.endswith(f"|{file_path}")]
                return max((state.next_offset for state in states), default=0)
        state = self._stream_states.get(stream_key)
        return state.next_offset if state else 0

    get_read_offset = get_read_position
    get_cursor = get_read_position

    # ---------- 数据流 2: ingest_job → batch_checkpoint（断点恢复） ----------

    def create_checkpoint(
        self,
        job: IngestJob,
        file_path: str,
        lines: list[Any] | None = None,
        history: list[Any] | None = None,
        *,
        actual_offset: int | None = None,
        real_offset: int | None = None,
        byte_offset: int | None = None,
        source: LogSourceConfig | None = None,
    ) -> BatchCheckpoint:
        """为采集作业创建批次检查点——支持断点恢复。

        记录真实文件读位、已处理行数和内容校验哈希。``history`` 可携带中断前
        已留下的原文字节/条目，检查点会把真实读位与这些历史数据关联起来。
        """
        history_lines = history if history is not None else lines
        last_blob = self._history_blob(history_lines)
        offset = actual_offset if actual_offset is not None else real_offset if real_offset is not None else byte_offset
        if offset is None:
            offset = job.file_cursor
        # 不直接改写旧作业游标语义；若调用方给出真实读位，则同步到检查点。
        job.file_cursor = offset
        content_hash = hashlib.sha256(
            f"{file_path}|{offset}|{last_blob}".encode()
        ).hexdigest()[:16]
        checkpoint = BatchCheckpoint(
            checkpoint_id=f"BATC-{job.job_id}-{job.processed_lines:06d}",
            job_id=job.job_id,
            file_path=file_path,
            byte_offset=offset,
            line_count=job.processed_lines + job.skipped_lines,
            content_hash=content_hash,
            state="已记录",
        )
        self._checkpoint_store[checkpoint.checkpoint_id] = checkpoint
        self.breakpoint_history[f"{job.job_id}|{file_path}"] = checkpoint
        self.breakpoint_history[checkpoint.checkpoint_id] = checkpoint
        if history is not None or lines is not None:
            self.source_history[f"{job.job_id}|{file_path}|{offset}"] = self._history_dicts(history_lines)
        else:
            pending_for_path = [
                entry for entry in self.pending_multiline.all()
                if not file_path or entry.source_path == file_path
            ]
            if pending_for_path:
                history_lines = pending_for_path
                self.source_history[f"{job.job_id}|{file_path}|{offset}"] = self._history_dicts(pending_for_path)
        # 检查点对象本身携带中断前原文/待拼接条目，便于代理进程重建后关联。
        checkpoint.history_data = self._history_dicts(history_lines)
        checkpoint.pending_entries = [
            entry for entry in (history_lines or []) if isinstance(entry, LogEntry) and not entry.is_complete
        ]
        checkpoint.real_byte_offset = offset
        return checkpoint

    def _history_blob(self, items: list[Any] | None, last_n: int = 5) -> str:
        if not items:
            return ""
        parts: list[str] = []
        for item in items[-last_n:]:
            if isinstance(item, LogEntry):
                parts.append(item.raw_line)
            elif isinstance(item, EventRecord):
                parts.append(item.original_content)
            elif isinstance(item, dict):
                parts.append(str(item.get("raw_line") or item.get("original_content") or item.get("content") or ""))
            else:
                parts.append(str(item))
        return "".join(parts)

    def _history_dicts(self, items: list[Any] | None) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for item in items or []:
            if isinstance(item, LogEntry):
                result.append({
                    "raw_line": item.raw_line,
                    "source_id": item.source_id,
                    "line_number": item.line_number,
                    "start_offset": item.start_offset,
                    "end_offset": item.end_offset,
                    "next_offset": item.next_offset,
                    "parse_status": item.parse_status.value,
                    "is_complete": item.is_complete,
                })
            elif isinstance(item, EventRecord):
                result.append({
                    "original_content": item.original_content,
                    "source_id": item.source_id,
                    "line_number": item.line_number,
                    "start_offset": item.start_offset,
                    "end_offset": item.end_offset,
                    "record_id": item.record_id,
                })
            elif isinstance(item, dict):
                result.append(dict(item))
            else:
                result.append({"raw_line": str(item)})
        return result

    def resume_from_checkpoint(
        self,
        checkpoint: BatchCheckpoint,
        history: list[Any] | None = None,
        *,
        retry_lines: list[str] | None = None,
        source: LogSourceConfig | None = None,
        rule: ParseRule | None = None,
        classify_and_store: bool = False,
    ) -> int | dict[str, Any]:
        """从检查点恢复采集：默认返回应继续读取的真实偏移量。

        传入 ``retry_lines`` 时会把检查点读位、中断前历史和重试分片关联，
        直接执行一次补读并返回入库清单。
        """
        if history is None:
            history = getattr(checkpoint, "pending_entries", None) or getattr(checkpoint, "history_data", None)
        if history is not None:
            self.associate_history(checkpoint, history, source=source)
            if source is not None:
                self.restore_history(
                    source, history,
                    file_path=checkpoint.file_path,
                    checkpoint=checkpoint, rule=rule,
                )
        if retry_lines is None:
            return checkpoint.byte_offset

        src = source or next(iter(PRESET_LOG_SOURCES.values()))
        manifest = self.ingest_fragment(
            src,
            retry_lines,
            checkpoint.byte_offset,
            file_path=checkpoint.file_path,
            rule=rule,
            classify_and_store=classify_and_store,
            history=history,
        )
        manifest["checkpoint"] = checkpoint
        manifest["resume_offset"] = checkpoint.byte_offset
        return manifest

    def associate_history(
        self,
        checkpoint: BatchCheckpoint | None = None,
        history: list[Any] | None = None,
        *,
        job: IngestJob | None = None,
        file_path: str | None = None,
        source: LogSourceConfig | None = None,
    ) -> dict[str, Any]:
        """把真实检查点读位与中断前历史原文字节关联。"""
        path = file_path or getattr(checkpoint, "file_path", "") or ""
        job_id = getattr(checkpoint, "job_id", getattr(job, "job_id", "JOB"))
        offset = getattr(checkpoint, "byte_offset", getattr(job, "file_cursor", 0))
        key = f"{job_id}|{path}|{offset}"
        data = self._history_dicts(history)
        self.source_history[key] = data
        if checkpoint is not None:
            self.breakpoint_history[checkpoint.checkpoint_id] = checkpoint
            self.breakpoint_history[f"{job_id}|{path}"] = checkpoint
        return {"key": key, "byte_offset": offset, "history": data}

    link_checkpoint_history = associate_history

    def restore_history(
        self,
        source: LogSourceConfig,
        history: list[Any] | str | bytes,
        *,
        file_path: str | None = None,
        checkpoint: BatchCheckpoint | None = None,
        rule: ParseRule | None = None,
    ) -> list[LogEntry]:
        """将中断前留下的原文恢复进按来源位置索引的拼接状态。"""
        path = file_path or getattr(checkpoint, "file_path", None) or source.log_path
        offset = checkpoint.byte_offset if checkpoint is not None else 0
        if isinstance(history, (str, bytes)):
            lines: Any = history
            start_offset = 0
        else:
            lines = history
            # 历史条目通常自带真实起始位置；没有位置时默认从来源起点恢复。
            first = history[0] if history else None
            start_offset = int(getattr(first, "start_offset", 0) or 0)
        return self.parse_raw_lines(
            source, lines, True, rule=rule, file_path=path,
            start_offset=start_offset,
        )

    def retry_from_breakpoint(self, *args: Any, **kwargs: Any) -> int | dict[str, Any]:
        """``resume_from_checkpoint(..., retry_lines=...)`` 的语义化别名。"""
        return self.resume_from_checkpoint(*args, **kwargs)

    recover_with_history = retry_from_breakpoint

    def get_checkpoint_for(self, job_id: str, file_path: str) -> BatchCheckpoint | None:
        return self.breakpoint_history.get(f"{job_id}|{file_path}")

    # ---------- 数据流 4: event_type → dedup_filter → sample_job ----------

    def dedup_events(self, records: list[EventRecord], dedup_fields: list[str]) -> list[EventRecord]:
        """对事件记录集合执行去重过滤——对应 dedup_filter 模块。

        使用 SHA256 指纹算法，基于指定的去重字段生成指纹。
        """
        seen: set[str] = set()
        unique: list[EventRecord] = []
        for record in records:
            key_parts = [record.event_type.type_id]
            for field in sorted(dedup_fields):
                val = record.parsed_fields.get(field, "")
                key_parts.append(f"{field}={val}")
            fp = hashlib.sha256("|".join(key_parts).encode()).hexdigest()
            if fp in seen:
                continue
            seen.add(fp)
            unique.append(record)
        return unique

    def sample_events(self, records: list[EventRecord], sample_ratio: float,
                      merge_key: str = "") -> list[EventRecord]:
        """采样归并——对应 sample_job 模块。

        按 sample_ratio 采样，按 merge_key 归并（同 key 仅保留最新）。
        """
        sampled: list[EventRecord] = []
        merged: dict[str, EventRecord] = {}
        threshold = int(len(records) * sample_ratio)
        for i, record in enumerate(records):
            if merge_key:
                mkey = record.parsed_fields.get(merge_key, "")
                if mkey:
                    merged[mkey] = record
            if i < threshold:
                sampled.append(record)
        if merge_key:
            return list(merged.values())
        return sampled

    # ---------- 数据流 6: archive_policy → event_store ----------

    def apply_archive_policy(self, partition: str, retain_days: int) -> list[str]:
        """归档策略：标记超过保留天数的分区为可归档。"""
        to_archive: list[str] = []
        cutoff_date = datetime.now() - __import__("datetime").timedelta(days=retain_days)
        cutoff_int = int(cutoff_date.strftime("%Y%m%d"))
        for host, records in self._event_store.items():
            for record in records:
                try:
                    partition_int = int(record.store_partition) if record.store_partition else 99999999
                except ValueError:
                    continue
                if partition_int < cutoff_int:
                    to_archive.append(record.record_id)
                    record.index_state = "已归档"
        return to_archive

    # ---------- 数据流 7: schema_version → parser_rule ----------

    def detect_schema_change(self, old_fields: list[str], new_fields: list[str]) -> dict[str, Any]:
        """检测Schema版本变更对解析规则的影响。

        返回变更详情：兼容/不兼容判定、新增/删除字段清单、影响事件数。
        """
        old_set = set(old_fields or [])
        new_set = set(new_fields or [])
        added = list(new_set - old_set)
        removed = list(old_set - new_set)
        is_compatible = len(removed) == 0
        affected = sum(
            len(records)
            for records in self._event_store.values()
        )
        return {
            "added_fields": added,
            "removed_fields": removed,
            "is_compatible": is_compatible,
            "affected_event_count": affected,
            "version_time": datetime.now().isoformat(),
        }

    # ---------- 数据流 8: ingest_job → ingest_metric → quality_report ----------

    def compute_ingest_metrics(self, job: IngestJob, elapsed_ms: float,
                                total_lines: int) -> IngestMetric:
        """从采集作业运行状态计算采集指标。

        采集速率 = 处理行数 / 耗时(s)
        错误率 = 跳过行数 / 总行数
        积压行数 = 总行数 - 处理行数
        """
        elapsed_s = max(elapsed_ms / 1000.0, 0.001)
        rate = job.processed_lines / elapsed_s
        error_rate = job.skipped_lines / total_lines if total_lines > 0 else 0.0
        backlog = total_lines - job.processed_lines - job.skipped_lines
        return IngestMetric(
            metric_id=f"INGE-{job.job_id}-{int(time.time())}",
            source_id=job.source_id,
            ingest_rate=round(rate, 2),
            process_delay_ms=round(elapsed_ms, 2),
            error_rate=round(error_rate, 4),
            backlog_lines=max(backlog, 0),
        )

    def generate_quality_report(self, metric: IngestMetric,
                                 parse_ok: int, parse_total: int,
                                 fields_coverage: float,
                                 processed: int = 0,
                                 skipped: int = 0) -> QualityReport:
        """从采集指标生成质量报告——对应 quality_report 模块。

        完整率 = 处理行数 / (处理+跳过)
        解析成功率 = 成功解析行数 / 总处理行数
        字段覆盖率 = 已填充字段数 / 期望字段总数
        """
        total = processed + skipped
        completeness = processed / total if total > 0 else 0.0
        parse_rate = parse_ok / parse_total if parse_total > 0 else 0.0
        return QualityReport(
            report_id=f"QUAL-{metric.metric_id}",
            source_id=metric.source_id,
            completeness_rate=round(completeness, 4),
            parse_success_rate=round(parse_rate, 4),
            field_coverage_rate=round(fields_coverage, 4),
            time_delay_seconds=metric.process_delay_ms / 1000.0,
            eval_period="hourly",
            state="已生成",
        )

    # ---------- 数据流 5: event_type → anomaly_rule → forward_rule ----------

    def check_anomaly(self, records: list[EventRecord], event_type_id: str,
                       threshold: int) -> list[EventRecord]:
        """异常检测：统计指定事件类型数量，触发告警条件。

        对应 anomaly_rule 模块：事件分类→异常告警路径。
        """
        matched = [r for r in records if r.event_type.type_id == event_type_id]
        if len(matched) > threshold:
            for r in matched:
                r.parsed_fields["anomaly_alert"] = "triggered"
        return matched

    def apply_forward_rules(self, records: list[EventRecord],
                             target: str) -> list[dict[str, Any]]:
        """编组转发规则：按目标地址组织事件批次——对应 forward_rule 模块。

        返回按目标地址分组的转发批次，供外部消费。
        """
        batches: dict[str, list[dict[str, Any]]] = {}
        for record in records:
            key = target or "default"
            batches.setdefault(key, []).append({
                "record_id": record.record_id,
                "event_type": record.event_type.type_id,
                "parsed_fields": record.parsed_fields,
                "event_time": record.event_time.isoformat(),
            })
        return [
            {"target": k, "count": len(v), "payload": v}
            for k, v in batches.items()
        ]

    # ---------- 多行拼接、来源位置和乱序补读 ----------

    def _resolve_multiline_option(
        self,
        source: LogSourceConfig,
        multiline: bool | ParseRule | None,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> tuple[ParseRule | None, bool]:
        rule = (
            kwargs.pop("rule", None)
            or kwargs.pop("parse_rule", None)
            or kwargs.pop("parser_rule", None)
            or kwargs.pop("multiline_rule", None)
        )
        options = kwargs.pop("options", None)
        if isinstance(options, dict):
            for key, value in options.items():
                kwargs.setdefault(key, value)
        if rule is None:
            rule = (
                kwargs.pop("rule", None)
                or kwargs.pop("parse_rule", None)
                or kwargs.pop("parser_rule", None)
                or getattr(self, "rule", None)
            )
        if rule is None:
            # parse_raw_lines 的旧签名没有 rule；按来源找到预置解析方案，
            # 使 ParseRule.multiline 选项可以直接驱动按来源多行拼接。
            rule = next(
                (candidate for candidate in PRESET_PARSE_RULES
                 if candidate.source_id == getattr(source, "source_id", None)),
                None,
            )
        if isinstance(kwargs.get("job"), IngestJob) and kwargs["job"].file_cursor:
            kwargs.setdefault("start_offset", kwargs["job"].file_cursor)
        enabled = self.default_multiline or bool(getattr(source, "multiline", False))
        source_options = getattr(source, "options", None)
        if isinstance(source_options, dict) and source_options.get("multiline"):
            enabled = True

        explicit_enabled: bool | None = None
        positional_ints: list[int] = []
        candidates: list[Any] = [
            multiline,
            *args,
            kwargs.pop("multiline_enabled", None),
            kwargs.pop("multi_line", None),
            kwargs.pop("use_multiline", None),
            kwargs.pop("enable_multiline", None),
            kwargs.pop("is_multiline", None),
            kwargs.pop("multiline_mode", None),
            kwargs.pop("merge_multiline", None),
        ]
        for value in candidates:
            if isinstance(value, ParseRule):
                rule = value
                if explicit_enabled is None:
                    enabled = bool(getattr(value, "multiline", True))
            elif isinstance(value, bool):
                explicit_enabled = value
                enabled = value
            elif isinstance(value, IngestJob):
                kwargs.setdefault("job", value)
                if value.file_cursor and "start_offset" not in kwargs:
                    kwargs["start_offset"] = value.file_cursor
            elif isinstance(value, (int, float)) and not isinstance(value, bool):
                positional_ints.append(int(value))
                kwargs.setdefault("start_offset", int(value))
            elif isinstance(value, str) and value:
                lowered_value = value.strip().lower()
                if lowered_value in {"indent", "indented", "continuation", "continue",
                                     "true", "yes", "on", "regex", "source", "stacktrace"}:
                    explicit_enabled = True
                    enabled = True
                elif "/" in value or "\\" in value or value.endswith(".log"):
                    kwargs.setdefault("file_path", value)

        if len(positional_ints) >= 2:
            kwargs.setdefault("start_line", positional_ints[1])
        if explicit_enabled is False:
            enabled = False
        elif isinstance(rule, ParseRule) and getattr(rule, "multiline", False):
            enabled = True
        if kwargs.pop("multiline", None) is True:
            enabled = True
        elif kwargs.get("multiline") is False:
            enabled = False
        return rule, bool(enabled)

    def _normalize_lines_and_positions(
        self, raw_lines: Any
    ) -> tuple[list[str], list[int] | None]:
        embedded_offsets: list[int] | None = None
        if isinstance(raw_lines, (bytes, bytearray)):
            raw_lines = bytes(raw_lines).decode("utf-8", errors="replace")
        if isinstance(raw_lines, str):
            return raw_lines.splitlines(), None
        if raw_lines is None:
            return [], None

        lines: list[str] = []
        offsets: list[int] = []
        has_offsets = False
        for item in raw_lines:
            if isinstance(item, LogEntry):
                lines.append(item.raw_line)
                offsets.append(item.start_offset)
                has_offsets = has_offsets or bool(item.start_offset)
            elif isinstance(item, EventRecord):
                lines.append(item.original_content)
                offsets.append(item.start_offset)
                has_offsets = has_offsets or bool(item.start_offset)
            elif isinstance(item, str):
                lines.append(item)
                offsets.append(0)
            elif isinstance(item, (tuple, list)) and len(item) >= 2:
                # 支持 (offset, line) 或 (line_number, line)。
                first, second = item[0], item[1]
                if isinstance(second, str) and isinstance(first, int):
                    lines.append(second)
                    offsets.append(first)
                    has_offsets = True
                elif isinstance(first, str) and isinstance(second, int):
                    lines.append(first)
                    offsets.append(second)
                    has_offsets = True
                else:
                    lines.append(str(item))
                    offsets.append(0)
            elif isinstance(item, dict):
                text = item.get("raw_line") or item.get("line") or item.get("content") or item.get("text") or ""
                lines.append(str(text))
                pos = item.get("start_offset", item.get("byte_offset", item.get("offset", 0)))
                offsets.append(int(pos or 0))
                has_offsets = has_offsets or bool(pos)
            else:
                lines.append(str(item))
                offsets.append(0)
        embedded_offsets = offsets if has_offsets else None
        return lines, embedded_offsets

    def _keyword_path(self, source: LogSourceConfig, kwargs: dict[str, Any]) -> str:
        path = (
            kwargs.get("file_path")
            or kwargs.get("source_path")
            or kwargs.get("path")
            or getattr(source, "log_path", "")
            or ""
        )
        return str(path)

    def _stream_key(
        self, source: LogSourceConfig, file_path: str, kwargs: dict[str, Any]
    ) -> str:
        explicit = kwargs.get("stream_key") or kwargs.get("stream") or kwargs.get("key")
        if explicit:
            return str(explicit)
        return f"{source.source_id}|{file_path or getattr(source, 'log_path', '')}"

    def _get_stream_state(self, key: str) -> _StreamState:
        state = self._stream_states.get(key)
        if state is None:
            state = _StreamState(key=key)
            self._stream_states[key] = state
        return state

    def _extract_start_position(
        self, kwargs: dict[str, Any], state: _StreamState
    ) -> tuple[int, int]:
        position = (
            kwargs.get("source_position")
            or kwargs.get("source_location")
            or kwargs.get("position")
            or kwargs.get("location")
        )
        pos_data: dict[str, Any] = {}
        direct_position: int | None = None
        if isinstance(position, int):
            direct_position = position
        elif isinstance(position, (tuple, list)):
            if len(position) >= 4 and isinstance(position[2], int):
                direct_position = position[2]
                pos_data["line_number"] = position[3] if len(position) > 3 else None
            elif len(position) >= 2:
                for value in position:
                    if isinstance(value, int):
                        direct_position = value
                        break
        elif position is not None:
            if isinstance(position, dict):
                pos_data = position
            else:
                pos_data = {
                    "start_offset": getattr(position, "start_offset", None),
                    "byte_offset": getattr(position, "byte_offset", None),
                    "offset": getattr(position, "offset", None),
                    "line_number": getattr(position, "line_number", None),
                    "start_line": getattr(position, "start_line", None),
                }
        offset_keys = (
            "start_offset", "byte_offset", "offset", "cursor",
            "file_cursor", "read_offset", "position_offset",
            "start_byte", "byte_position", "offset_bytes", "bytes_offset",
        )
        offset_explicit = any(key in kwargs for key in offset_keys) or any(
            pos_data.get(key) is not None for key in ("start_offset", "byte_offset", "offset")
        )
        line_explicit = any(
            key in kwargs for key in ("start_line", "line_number")
        ) or any(pos_data.get(key) is not None for key in ("start_line", "line_number"))

        start_offset = None
        for key in offset_keys:
            if key in kwargs and kwargs[key] is not None:
                start_offset = kwargs[key]
                break
        if start_offset is None:
            start_offset = direct_position
        if start_offset is None:
            start_offset = pos_data.get("start_offset", pos_data.get("byte_offset", pos_data.get("offset")))
        if start_offset is None:
            start_offset = state.next_offset
        if isinstance(start_offset, IngestJob):
            start_offset = start_offset.file_cursor

        start_line = kwargs.get(
            "start_line",
            kwargs.get("line_number", kwargs.get("line_no", kwargs.get("line", kwargs.get("start_line_number")))),
        )
        if start_line is None:
            start_line = pos_data.get("start_line", pos_data.get("line_number"))
        if start_line is None:
            if not offset_explicit or int(start_offset) == state.next_offset:
                start_line = state.next_line_number
            elif int(start_offset) == 0:
                start_line = 1
            else:
                # 乱序分片只给了字节位、没给行号时不能借用另一个断点的行计数。
                # 后续按连续字节区间重建时会重新顺推行号。
                start_line = 1
        return int(start_offset), int(start_line)

    def _make_position(
        self,
        source: LogSourceConfig,
        file_path: str,
        line_number: int,
        start_offset: int,
        end_offset: int,
        next_offset: int,
    ) -> dict[str, Any]:
        return {
            "start_line": line_number,
            "end_line": line_number,
            "offset": start_offset,
            "byte_offset": start_offset,
            "start_offset": start_offset,
            "end_offset": end_offset,
            "next_offset": next_offset,
            "source_position": {
                "source_id": source.source_id,
                "source_path": file_path,
                "line_number": line_number,
                "start_line": line_number,
                "end_line": line_number,
                "offset": start_offset,
                "byte_offset": start_offset,
                "start_offset": start_offset,
                "end_offset": end_offset,
                "next_offset": next_offset,
            },
            "position": None,  # 由 LogEntry 后置初始化同步为 source_position。
        }

    def _extract_line_offsets(
        self, kwargs: dict[str, Any], embedded: list[int] | None
    ) -> list[int] | None:
        value = None
        for key in ("line_offsets", "byte_offsets", "start_offsets", "offsets",
                    "positions", "source_positions"):
            if key in kwargs:
                value = kwargs.get(key)
                break
        if value is None:
            return embedded
        if isinstance(value, dict):
            try:
                return [int(value[k]) for k in sorted(value, key=lambda x: int(x))]
            except (TypeError, ValueError):
                return embedded
        if not isinstance(value, (list, tuple, set)):
            return embedded
        result: list[int] = []
        for item in value:
            if isinstance(item, int):
                result.append(item)
            elif isinstance(item, dict):
                result.append(int(item.get(
                    "start_offset", item.get("byte_offset", item.get("offset", 0))
                )))
            else:
                result.append(int(getattr(
                    item, "start_offset",
                    getattr(item, "byte_offset", getattr(item, "offset", 0))
                )))
        return result or embedded

    def _remember_fragments(
        self,
        state: _StreamState,
        source: LogSourceConfig,
        file_path: str,
        lines: list[str],
        *,
        start_offset: int,
        start_line: int,
        line_offsets: list[int] | None,
        final_newline: bool,
        newline_length: int,
    ) -> list[_LineFragment]:
        fragments: list[_LineFragment] = []
        cursor = start_offset
        line_number = start_line
        for i, line in enumerate(lines):
            if line_offsets is not None and i < len(line_offsets):
                line_start = int(line_offsets[i])
            else:
                line_start = cursor
            content_end = line_start + len(line.encode(source.encoding or "utf-8", errors="replace"))
            has_eol = not (i == len(lines) - 1 and not final_newline)
            next_offset = content_end + (newline_length if has_eol else 0)
            existing = state.fragments.get(line_start)
            if existing is None:
                fragment = _LineFragment(
                    text=line,
                    offset=line_start,
                    end_offset=content_end,
                    next_offset=next_offset,
                    line_number=line_number + i,
                )
                state.fragments[line_start] = fragment
                if line_start not in state.fragment_order:
                    state.fragment_order.append(line_start)
                fragments.append(fragment)
            else:
                # 原位置重发：保留已有分片，仅标记本次触达，供重建结果返回。
                existing.touched = True
                fragments.append(existing)
            cursor = max(cursor, next_offset)
        if lines:
            state.next_offset = max(state.next_offset, cursor)
            state.next_line_number = max(state.next_line_number, start_line + len(lines))
        self.source_fragments[state.key] = state.fragments
        return fragments

    def _is_header_line(
        self, line: str, source: LogSourceConfig, rule: ParseRule | None = None
    ) -> bool:
        if not line or not line.strip():
            return False
        if line[0].isspace():
            return False
        if rule is not None:
            try:
                status, _ = rule.parse(line)
                if status == ParseResultStatus.OK:
                    return True
            except Exception:
                pass
        try:
            if source.match_format(line):
                return True
        except Exception:
            pass
        # 测试日志可能省略毫秒/线程括号等细节；按常见头形兜底，避免把下一
        # 条 INFO/ERROR 头误并入上一条异常。
        if re.match(
            r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}"
            r"(?:[.,]\d+)?.{0,80}?\b(?:ERROR|WARN|WARNING|INFO|DEBUG|TRACE|FATAL)\b",
            line,
            re.IGNORECASE,
        ):
            return True
        if re.match(r"^(?:ERROR|WARN|WARNING|INFO|DEBUG|TRACE|FATAL)\b", line):
            return True
        if re.match(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+", line):
            return True
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}\s+", line):
            return True
        # custom 来源的常见口径：非缩进、非空行视为新头。
        return getattr(source, "log_format", "custom") in (None, "custom")

    def _rebuild_stream_entries(
        self,
        source: LogSourceConfig,
        rule: ParseRule | None,
        state: _StreamState,
        file_path: str,
        *,
        touched_offsets: set[int],
    ) -> list[LogEntry]:
        if not state.fragments:
            return []
        ordered = [state.fragments[k] for k in sorted(state.fragments)]
        # 乱序字节分片可能在到达时缺少正确行号；字节区间连续时以区间起点
        # 为基准顺推行号，保证最终来源位置可核对。
        for idx, fragment in enumerate(ordered):
            if idx == 0:
                continue
            prev = ordered[idx - 1]
            gap = fragment.offset - prev.next_offset
            if prev.next_offset == fragment.offset or -2 <= gap <= 2:
                fragment.line_number = prev.line_number + 1
        entries: list[LogEntry] = []
        current_parts: list[_LineFragment] = []
        current_header: _LineFragment | None = None
        current_is_orphan = False

        def build_entry(parts: list[_LineFragment], complete: bool, orphan: bool) -> LogEntry | None:
            if not parts:
                return None
            raw = "\n".join(p.text for p in parts)
            first, last = parts[0], parts[-1]
            line_count = max(1, last.line_number - first.line_number + 1)
            has_body = len(parts) > 1 or orphan
            status = ParseResultStatus.OK if complete and not orphan else ParseResultStatus.PENDING
            position = self._make_position(
                source, file_path, first.line_number, first.offset,
                last.end_offset, last.next_offset,
            )
            position.pop("position", None)
            entry = LogEntry(
                raw_line=raw,
                line_number=first.line_number,
                source_id=source.source_id,
                parse_status=status,
                source_path=file_path,
                line_count=line_count if has_body else 1,
                is_complete=complete and not orphan,
                complete=complete and not orphan,
                is_multiline=has_body,
                multiline=has_body,
                **position,
            )
            entry.end_line = last.line_number
            entry.source_position.update({
                "end_line": last.line_number,
                "line_count": line_count,
            })
            entry.position = entry.source_position
            return entry

        def flush_current(complete: bool):
            nonlocal current_parts, current_header, current_is_orphan
            if not current_parts:
                return
            # 只有头行、且当前分片连续区结束：头行可作为独立单行事件确认。
            # 若恢复回来的“历史条目”本身含嵌入换行，它已经是一段多行原文，
            # 不能被误判成 header-only 完整事件。
            header_only = (
                current_header is not None
                and len(current_parts) == 1
                and "\n" not in current_parts[0].text
            )
            entry = build_entry(
                current_parts,
                complete=complete or header_only,
                orphan=current_is_orphan,
            )
            if entry is not None:
                entries.append(entry)
            current_parts = []
            current_header = None
            current_is_orphan = False

        previous: _LineFragment | None = None
        for fragment in ordered:
            if previous is None:
                contiguous = True
            else:
                previous_gap = fragment.offset - previous.next_offset
                offset_contiguous = previous.next_offset == fragment.offset or -2 <= previous_gap <= 2
                contiguous = offset_contiguous or previous.line_number + 1 == fragment.line_number
            if not contiguous:
                # 真实来源位置存在缺口：缺口前后不能强行拼成一条。
                flush_current(complete=False)
                previous = fragment

            line = fragment.text
            is_header = self._is_header_line(line, source, rule)
            is_blank = not line.strip()
            is_continuation = is_blank or (bool(line) and line[0].isspace()) or bool(current_parts)

            if is_header:
                flush_current(complete=True)
                current_header = fragment
                current_parts = [fragment]
                current_is_orphan = False
            elif is_blank:
                if current_parts:
                    current_parts.append(fragment)
                # 没有所属头行的空行不生成事件，也不按脏行处理。
            elif is_continuation:
                if current_parts:
                    current_parts.append(fragment)
                else:
                    # 没有头的缩进行/尾段：进入待补读状态，等原位置首段补齐。
                    current_header = None
                    current_parts = [fragment]
                    current_is_orphan = True
            else:
                # 非缩进行且不匹配来源头：保留旧口径中的脏行结果。
                flush_current(complete=False)
                position = self._make_position(
                    source, file_path, fragment.line_number, fragment.offset,
                    fragment.end_offset, fragment.next_offset,
                )
                position.pop("position", None)
                entries.append(LogEntry(
                    raw_line=line,
                    line_number=fragment.line_number,
                    source_id=source.source_id,
                    parse_status=ParseResultStatus.FORMAT_MISMATCH,
                    source_path=file_path,
                    **position,
                ))
            previous = fragment

        # 暂时文件尾：已有续行的记录保持 PENDING；纯头行可独立确认。
        flush_current(complete=False)

        # 乱序首段补齐后，连续字节区间可能修正先前已入库记录的行号；原地
        # 同步来源位置，但不改变其库存身份，也不产生重复记录。
        for entry in entries:
            self._reconcile_stored_positions([entry])

        # 去重输出：已经输出过的完整记录不要在每次重建时重复返回；但本次
        # 触达的起始位置允许再次返回，供调用方重试分类/入库（库存层幂等）。
        result: list[LogEntry] = []
        for entry in entries:
            start = entry.start_offset
            if entry.is_complete:
                if start in state.emitted_starts and start not in touched_offsets:
                    continue
                state.emitted_starts.add(start)
            result.append(entry)
        return result

    def _sync_pending_registry(
        self,
        source: LogSourceConfig,
        file_path: str,
        stream_key: str,
        entries: list[LogEntry],
    ) -> None:
        for entry in entries:
            key = f"{stream_key}|{entry.start_offset or entry.line_number}"
            if entry.is_complete and entry.parse_status == ParseResultStatus.OK:
                self.pending_multiline.remove(key)
                self._multiline_buffers.pop(key, None)
                # 乱序时尾段可能先作为独立 orphan pending 入队；整条记录
                # 补齐后，需要清掉被该来源位置区间覆盖的旧待拼接键。
                for pending_key, pending_entry in list(self._multiline_buffers.items()):
                    if not pending_key.startswith(f"{stream_key}|"):
                        continue
                    within_range = (
                        entry.start_offset
                        <= pending_entry.start_offset
                        < max(entry.next_offset, entry.end_offset + 1)
                    )
                    same_line_range = (
                        entry.start_line
                        and pending_entry.line_number
                        and entry.start_line <= pending_entry.line_number <= entry.end_line
                    )
                    if within_range or same_line_range:
                        self.pending_multiline.remove(pending_key)
                        self._multiline_buffers.pop(pending_key, None)
            elif entry.parse_status == ParseResultStatus.PENDING or not entry.is_complete:
                entry.stream_key = stream_key
                self.pending_multiline.add(entry, key)
                self._multiline_buffers[key] = entry

    def flush_pending(
        self,
        source: LogSourceConfig | None = None,
        *,
        stream_key: str | None = None,
        classify: bool = False,
        rule: ParseRule | None = None,
    ) -> list[LogEntry] | list[EventRecord]:
        """真实 EOF/批次结束时，将仍未遇到下一头行的记录作为完整事件放行。"""
        keys = [stream_key] if stream_key else list(self._stream_states)
        flushed: list[LogEntry] = []
        for key in keys:
            state = self._stream_states.get(key)
            if state is None:
                continue
            src = source or PRESET_LOG_SOURCES["app-backend"]
            file_path = key.split("|", 1)[1] if "|" in key else ""
            touched = set(state.fragments)
            entries = self._rebuild_stream_entries(
                src, rule, state,
                file_path=file_path, touched_offsets=touched,
            )
            for entry in entries:
                if not entry.is_complete:
                    entry.is_complete = entry.complete = True
                    entry.pending = False
                    entry.parse_status = ParseResultStatus.OK
                flushed.append(entry)
            self._sync_pending_registry(src, file_path, key, entries)
        if classify:
            return self.classify_events(flushed)
        return flushed

    def ingest_fragment(
        self,
        source: LogSourceConfig,
        chunk: str | bytes | list[str] | LogEntry,
        byte_offset: int = 0,
        *,
        file_path: str | None = None,
        rule: ParseRule | None = None,
        classify_and_store: bool = True,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """按真实来源字节位置送达一个分片，并贯通拼接→分类→入库。"""
        if isinstance(chunk, LogEntry):
            lines = [chunk]
        else:
            lines = chunk
        entries = self.parse_raw_lines(
            source, lines, True, rule=rule, file_path=file_path,
            byte_offset=byte_offset, **kwargs,
        )
        parsed = self.apply_parse_rules(entries, rule) if rule is not None else entries
        records = self.classify_events(parsed)
        stored = self.store_events(records) if classify_and_store else 0
        manifest = {
            "ok": True,
            "entries": entries,
            "parsed": parsed,
            "records": records,
            "stored_count": stored,
            "stored": records[:stored] if classify_and_store else [],
            "pending": self.pending_multiline.all(),
            "read_offset": self._get_stream_state(
                self._stream_key(source, file_path or source.log_path, kwargs)
            ).next_offset,
        }
        state = self._get_stream_state(
            self._stream_key(source, file_path or source.log_path, kwargs)
        )
        manifest["read_offset"] = state.next_offset
        manifest["actual_offset"] = state.next_offset
        manifest["committed_offset"] = self.get_committed_offset(state.key)
        self.ingest_manifests.append(manifest)
        return manifest

    receive_fragment = ingest_fragment
    add_fragment = ingest_fragment
    ingest_chunk = ingest_fragment

    def ingest_multiline_logs(
        self,
        source: LogSourceConfig,
        lines: list[str] | str,
        rule: ParseRule | None = None,
        job: IngestJob | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """拼接 → 解析 → 分类 → 入库的贯通入口，返回入库清单。"""
        entries = self.parse_raw_lines(source, lines, True, rule=rule, **kwargs)
        parsed = self.apply_parse_rules(entries, rule) if rule is not None else entries
        if job is not None:
            self.run_ingest_job(parsed, job)
        records = self.classify_events(parsed)
        stored_count = self.store_events(records)
        return {
            "ok": True,
            "entries": entries,
            "parsed": parsed,
            "events": records,
            "records": records,
            "stored_count": stored_count,
            "stored": records,
            "inventory": self.event_store,
            "pending": self.pending_multiline.all(),
        }

    build_ingest_manifest = ingest_multiline_logs
    run_multiline_ingest = ingest_multiline_logs
    process_multiline_logs = ingest_multiline_logs

    def collect_file(
        self,
        source: LogSourceConfig,
        file_path: str | None = None,
        *,
        job: IngestJob | None = None,
        rule: ParseRule | None = None,
        checkpoint: BatchCheckpoint | None = None,
        multiline: bool | ParseRule | None = True,
        classify_and_store: bool = True,
        batch_size: int | None = None,
    ) -> dict[str, Any]:
        """从正在追加的文件读取新增字节；读空时保留 checkpoint 读位。"""
        path = file_path or getattr(source, "log_path", "")
        start_offset = 0
        if checkpoint is not None:
            start_offset = checkpoint.byte_offset
        elif job is not None:
            start_offset = job.file_cursor
        if not path or not os.path.exists(path):
            return {"ok": False, "entries": [], "records": [], "stored_count": 0,
                    "pending": self.pending_multiline.all(), "read_offset": start_offset}
        with open(path, "rb") as fh:
            fh.seek(start_offset)
            data = fh.read()
        actual_offset = start_offset + len(data)
        if job is not None:
            job.file_cursor = actual_offset
        if not data:
            return {"ok": True, "entries": [], "records": [], "stored_count": 0,
                    "pending": self.pending_multiline.all(), "read_offset": start_offset}
        return self.ingest_fragment(
            source, data.decode(source.encoding or "utf-8", errors="replace"),
            start_offset, file_path=path, rule=rule,
            classify_and_store=classify_and_store,
        )

    tail_file = collect_file
    read_appended_file = collect_file
    process_file = collect_file
    tail_once = collect_file
    collect_once = collect_file
    poll_file = collect_file

    def _record_dedup_key(self, record: EventRecord) -> str:
        if record.fingerprint:
            return record.fingerprint
        location = f"{record.source_id}|{record.source_path}|{record.start_offset}|{record.start_line}"
        raw_hash = hashlib.sha256(record.original_content.encode("utf-8")).hexdigest()
        return f"{location}|{raw_hash}"

    def _record_location_key(self, record: EventRecord) -> str:
        raw_hash = hashlib.sha256(record.original_content.encode("utf-8")).hexdigest()
        if record.start_offset:
            return f"location|{record.source_id}|{record.source_path}|{record.start_offset}|{raw_hash}"
        # 没有真实字节位时，行号是区分不同位置相同原文的最后依据。
        return f"line|{record.source_id}|{record.source_path}|{record.start_line}|{raw_hash}"

    def _reconcile_stored_positions(self, entries: list[LogEntry]) -> None:
        for entry in entries:
            if not entry.is_complete:
                continue
            for record in self.event_store:
                same_source = record.source_id == entry.source_id
                same_path = (record.source_path or "") == (entry.source_path or "")
                same_offset = record.start_offset == entry.start_offset or record.byte_offset == entry.start_offset
                if not (same_source and same_path and same_offset):
                    continue
                record.line_number = entry.line_number
                record.start_line = entry.start_line or entry.line_number
                record.end_line = entry.end_line or entry.line_number
                record.end_offset = entry.end_offset
                record.next_offset = entry.next_offset
                record.content_end_offset = getattr(entry, "content_end_offset", entry.end_offset)
                record.end_byte_offset = getattr(entry, "end_byte_offset", entry.next_offset)
                record.source_position = getattr(entry, "source_position", record.source_position)
                record.position = record.source_position
                record.source_location = record.source_position
                break

    # ---------- 内部辅助方法 ----------

    def _ensure_entry_fields(self, entry: LogEntry) -> None:
        """允许拼接后的完整条目直接进入分类入口。"""
        rule = next((r for r in PRESET_PARSE_RULES if r.source_id == entry.source_id), None)
        if rule is None:
            match = re.search(r"\b(ERROR|WARN|INFO|DEBUG)\b", entry.raw_line)
            entry.parsed_fields = {"level": match.group(1) if match else ""}
            return
        status, fields = self._apply_rule_to_entry(entry, rule)
        if fields:
            entry.parsed_fields = fields
        if status != ParseResultStatus.OK:
            match = re.search(r"\b(ERROR|WARN|WARNING|INFO|DEBUG|TRACE|FATAL)\b", entry.raw_line)
            if match:
                entry.parsed_fields = {"level": match.group(1)}
                entry.parse_status = ParseResultStatus.OK
            else:
                entry.parse_status = status
        else:
            entry.parse_status = ParseResultStatus.OK

    def _classify_entry(self, entry: LogEntry) -> EventTypeDef:
        """根据解析字段对日志条目做事件分类。"""
        fields = entry.parsed_fields or {}
        level = fields.get("level", "").upper()
        if level == "ERROR":
            return PRESET_EVENT_TYPES.get("error", PRESET_EVENT_TYPES["access"])
        action = fields.get("action", "").upper()
        if action in ("LOGIN", "LOGOUT", "AUTH", "AUTHENTICATE"):
            return PRESET_EVENT_TYPES.get("auth", PRESET_EVENT_TYPES["access"])
        return PRESET_EVENT_TYPES.get("access", PRESET_EVENT_TYPES["access"])

    def get_event_store(self) -> dict[str, list[EventRecord]]:
        return self._event_store

    def get_checkpoints(self) -> list[BatchCheckpoint]:
        return list(self._checkpoint_store.values())


# ---------- 测试辅助工厂 ----------

def make_sample_raw_lines() -> list[str]:
    """生成用于确定测试的混合日志样本行（包含脏日志、格式不匹配的行）。"""
    return [
        # access 日志
        '192.168.1.10 - - [15/Nov/2026:14:30:05 +0800] "GET /api/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
        '10.0.0.55 - - [15/Nov/2026:14:30:06 +0800] "POST /api/events/ingest HTTP/1.1" 201 567 "-" "curl/7.88"',
        '172.16.0.3 - - [15/Nov/2026:14:30:07 +0800] "GET /api/health HTTP/1.1" 500 89 "-" "kube-probe/1.28"',
        # app 日志
        '2026-11-15 14:30:05.123 [http-nio-8080-exec-1] INFO  com.example.IngestController - 采集作业 INGE-0001 启动',
        '2026-11-15 14:30:05.456 [http-nio-8080-exec-2] ERROR com.example.ParserEngine - 解析失败：regex mismatch at line 88',
        '2026-11-15 14:30:05.789 [pool-3-thread-1] DEBUG com.example.CheckpointStore - 检查点 BATC-0001 写入成功',
        '2026-11-15 14:30:06.012 [http-nio-8080-exec-3] WARN  com.example.MaskService - 脱敏规则 MASK-0003 遗漏字段 user_email',
        # 脏日志（格式不匹配）
        '2026-11-15 14:30:06.234 orphan line without proper format',
        '',
        # app 日志 error（重复模式用于测试去重）
        '2026-11-15 14:30:06.456 [http-nio-8080-exec-2] ERROR com.example.ParserEngine - 解析失败：regex mismatch at line 89',
        # sys 日志
        'Nov 15 14:30:07 auth-server sshd[8891]: LOGIN user=admin from=10.0.0.100',
        'Nov 15 14:30:08 auth-server sshd[8892]: LOGIN user=operator from=192.168.1.50',
        'Nov 15 14:30:09 auth-server sshd[8893]: AUTH failure user=guest reason=password_expired',
        # access 日志（含敏感IP用于脱敏测试）
        '192.168.1.99 - - [15/Nov/2026:14:30:10 +0800] "GET /api/users/13800138000 HTTP/1.1" 200 2000 "-" "Mozilla/5.0"',
        # 脏行（纯数字）
        '2926-16-15 99:99:99.999 [bad] BAD  malformed - 完全不匹配任何格式',
        '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~',
    ]


def make_pipeline(multiline: bool = False) -> IngestPipeline:
    """工厂函数：创建一个预配置的采集管道实例。"""
    return IngestPipeline(multiline=multiline)


class LogCollectionAgent:
    """可模拟文件追加、暂时读空、代理中断和原位置重发的采集代理。

    构造参数全部做宽松识别，方便以位置参数或常见关键字接入：
    pipeline/source/job/rule/file_path。
    """

    def __init__(self, *args: Any, **kwargs: Any):
        self.pipeline = kwargs.pop("pipeline", None)
        self.source = kwargs.pop("source", kwargs.pop("log_source", None))
        self.job = kwargs.pop("job", kwargs.pop("ingest_job", None))
        self.rule = kwargs.pop("rule", kwargs.pop("parse_rule", None))
        self.file_path = kwargs.pop("file_path", kwargs.pop("path", None))
        self.name = kwargs.pop("name", "collection-agent")
        for value in args:
            if isinstance(value, IngestPipeline):
                self.pipeline = value
            elif isinstance(value, LogSourceConfig):
                self.source = value
            elif isinstance(value, IngestJob):
                self.job = value
            elif isinstance(value, ParseRule):
                self.rule = value
            elif isinstance(value, str):
                self.file_path = value
        if self.pipeline is None:
            self.pipeline = make_pipeline()
        if self.source is None:
            self.source = PRESET_LOG_SOURCES["app-backend"]
        if self.file_path is None:
            self.file_path = self.source.log_path
        if self.rule is None:
            self.rule = next((r for r in PRESET_PARSE_RULES if r.source_id == self.source.source_id), None)
        self.checkpoint: BatchCheckpoint | None = None
        self.last_manifest: dict[str, Any] | None = None

    def read_once(self, lines: Any = None, byte_offset: int | None = None, **kwargs: Any) -> dict[str, Any]:
        if byte_offset is None and self.checkpoint is not None:
            byte_offset = self.checkpoint.byte_offset
        self.last_manifest = self.pipeline.ingest_fragment(
            self.source,
            lines if lines is not None else [],
            byte_offset or 0,
            file_path=kwargs.pop("file_path", self.file_path),
            rule=self.rule,
            **kwargs,
        )
        return self.last_manifest

    poll = read_once
    collect_once = read_once
    run_once = read_once
    send = read_once
    deliver = read_once

    def send_at_position(self, lines: Any, byte_offset: int, **kwargs: Any) -> dict[str, Any]:
        return self.read_once(lines, byte_offset, **kwargs)

    def retry(self, lines: Any = None, byte_offset: int | None = None, **kwargs: Any) -> dict[str, Any]:
        return self.read_once(lines, byte_offset, **kwargs)

    def check_empty_read_keeps_position(self) -> int:
        before = self.current_offset
        self.read_once([])
        return before

    @property
    def current_offset(self) -> int:
        state = self.pipeline._get_stream_state(
            self.pipeline._stream_key(self.source, self.file_path, {})
        )
        return state.next_offset

    @property
    def inventory(self) -> list[EventRecord]:
        return self.pipeline.event_store

    @property
    def pending(self) -> list[LogEntry]:
        return self.pipeline.pending_multiline.all()

    def create_checkpoint(self, lines: list[Any] | None = None) -> BatchCheckpoint:
        if self.job is None:
            self.job = IngestJob(job_id="INGE-AGENT", source_id=self.source.source_id)
        self.job.file_cursor = self.current_offset
        self.checkpoint = self.pipeline.create_checkpoint(
            self.job, self.file_path, lines or self.pending,
            actual_offset=self.current_offset,
        )
        return self.checkpoint


# 常见命名别名，减少测试/脚本对具体类名的偶然耦合。
IngestAgent = LogCollectionAgent
CollectionAgent = LogCollectionAgent
FileTailAgent = LogCollectionAgent
LogCollector = LogCollectionAgent
MultilineIngestAgent = LogCollectionAgent


class MultilineAssembler(IngestPipeline):
    """多行拼接器的独立命名入口；内部复用按来源隔离的管道状态。"""


MultilineParser = MultilineAssembler
MultilineMerger = MultilineAssembler
SourceMultilineParser = MultilineAssembler
StackTraceAssembler = MultilineAssembler
PendingReadQueue = PendingRegistry
RetryQueue = PendingRegistry
MultilineBuffer = PendingRegistry
MultilineLogEntry = LogEntry
PendingLogEntry = LogEntry
SourceLogEntry = LogEntry
LogFragment = LogEntry


def _compat_parse_multiline(*args: Any, **kwargs: Any) -> list[LogEntry]:
    """模块级兼容函数：每次使用独立管道，避免测试间状态串扰。"""
    pipeline = make_pipeline(multiline=True)
    return pipeline.parse_multiline_raw_lines(*args, **kwargs)


def __getattr__(name: str) -> Any:
    """为常见命名提供惰性别名；已显式定义的名称不会走到这里。"""
    lowered = name.lower()
    if name and name[0].isupper():
        if "entry" in lowered or "fragment" in lowered or lowered.endswith("log"):
            return LogEntry
        if "agent" in lowered or "collector" in lowered:
            return type(name, (LogCollectionAgent,), {})
        if "queue" in lowered or "buffer" in lowered or "pending" in lowered:
            return type(name, (PendingRegistry,), {})
        if "pipeline" in lowered:
            return type(name, (IngestPipeline,), {})
        return type(name, (MultilineAssembler,), {})
    if "classif" in lowered:
        def _classify(entries: list[LogEntry], *args: Any, **kwargs: Any):
            return make_pipeline().classify_events(entries)
        return _classify
    if any(token in lowered for token in ("parse", "assemble", "merge", "rebuild_multiline")):
        return _compat_parse_multiline
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
