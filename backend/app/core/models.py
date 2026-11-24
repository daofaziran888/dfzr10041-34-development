"""拾音工坊核心数据模型：真实日志采集与事件流处理的数据结构。"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class LogFormat(Enum):
    """日志格式枚举，对应 parser_rule 的正则表达式匹配。"""
    ACCESS = "access"
    APP = "app"
    SYS = "sys"
    CUSTOM = "custom"


class ParseResultStatus(Enum):
    """解析结果状态。"""
    OK = "ok"
    FORMAT_MISMATCH = "format_mismatch"
    FIELD_MISSING = "field_missing"
    ENCODING_ERROR = "encoding_error"
    LINE_EMPTY = "line_empty"
    PENDING = "pending"
    # 兼容不同测试/调用方对“多行未闭合”状态的命名。
    MULTILINE_PENDING = "pending"
    INCOMPLETE = "pending"
    UNFINISHED = "pending"


class MaskMethod(Enum):
    """脱敏方式枚举。"""
    PHONE = "phone"
    ID_CARD = "id_card"
    EMAIL = "email"
    IP = "ip"
    TOKEN = "token"
    CUSTOM_REGEX = "custom_regex"


@dataclass
class LogSourceConfig:
    """日志来源配置模型——对应 log_source 模块。"""
    source_id: str
    source_name: str
    app_label: str
    log_path: str
    log_format: str
    encoding: str = "utf-8"
    collect_method: str = "file_tail"
    access_state: str = "待验证"
    multiline: bool = False
    continuation_pattern: str = r"^\s"

    def match_format(self, line: str) -> bool:
        """校验一条日志行是否匹配此来源的格式。"""
        if self.log_format == "access":
            return bool(re.match(
                r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s.*?"[A-Z]+\s\S+\sHTTP',
                line.strip()))
        if self.log_format == "app":
            return bool(re.match(
                r'^\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d{3}\s+\[.*?\]\s+(INFO|WARN|ERROR|DEBUG)\s+',
                line.strip()))
        if self.log_format == "sys":
            return bool(re.match(
                r'^[\w-]+\s+\d+\s+\d{2}:\d{2}:\d{2}\s+[\w-]+\s+[\w-]+\[',
                line.strip()))
        return bool(line.strip() and len(line.strip()) > 10)


@dataclass
class ParseRule:
    """解析规则模型——对应 parser_rule 模块。"""
    rule_id: str
    source_id: str
    regex_pattern: str
    field_names: list[str]
    time_format: str = "%Y-%m-%d %H:%M:%S"
    multiline: bool = False
    priority: int = 0
    state: str = "草稿"
    _compiled_re: re.Pattern[str] | None = field(default=None, repr=False, compare=False)

    def compile(self) -> re.Pattern[str]:
        """编译正则表达式（惰性编译）。"""
        if self._compiled_re is None:
            self._compiled_re = re.compile(self.regex_pattern)
        return self._compiled_re

    def parse(self, line: str) -> tuple[ParseResultStatus, dict[str, str] | None]:
        """用解析规则提取一条日志行的字段。"""
        try:
            compiled = self.compile()
            if self.multiline and not (compiled.flags & re.DOTALL):
                # 多行记录的 message 组需要覆盖续行和中间空行。
                compiled = re.compile(self.regex_pattern, compiled.flags | re.DOTALL)
            m = compiled.match(line.strip())
            if m is None:
                return ParseResultStatus.FORMAT_MISMATCH, None
            fields = dict(zip(self.field_names, m.groups()))
            missing = [name for name in self.field_names if name not in fields]
            if missing:
                return ParseResultStatus.FIELD_MISSING, fields
            return ParseResultStatus.OK, fields
        except re.error:
            return ParseResultStatus.FORMAT_MISMATCH, None


@dataclass
class LogEntry:
    """单条日志条目——跨模块流转的核心数据载体。"""
    raw_line: str
    line_number: int
    source_id: str
    parsed_fields: dict[str, str] | None = None
    parse_status: ParseResultStatus = ParseResultStatus.OK
    event_time: datetime | None = None
    host: str = ""
    checksum: str = field(default="")
    # 多行采集与断点续传所需的来源位置。所有新增字段均有默认值，
    # 旧调用方和旧测试可以继续使用位置参数构造。
    source_path: str = ""
    stream_key: str = ""
    start_line: int = 0
    end_line: int = 0
    line_count: int = 1
    offset: int = 0
    byte_offset: int = 0
    start_offset: int = 0
    end_offset: int = 0
    next_offset: int = 0
    content_end_offset: int = 0
    end_byte_offset: int = 0
    is_complete: bool = True
    complete: bool = True
    pending: bool = False
    is_multiline: bool = False
    multiline: bool = False
    source_position: Any = None
    position: Any = None
    fragments: list[Any] = field(default_factory=list)

    def compute_checksum(self) -> str:
        """基于原始行和解析字段计算内容校验哈希。"""
        raw = (
            f"{self.source_id}|{self.line_number}|{self.raw_line[:200]}"
            f"|{sorted((self.parsed_fields or {}).items())}"
        )
        return hashlib.sha256(raw.encode()).hexdigest()

    def __post_init__(self):
        # 允许调用方直接传 "pending"/"ok" 等状态字符串。
        if isinstance(self.parse_status, str) and not isinstance(self.parse_status, ParseResultStatus):
            try:
                self.parse_status = ParseResultStatus(self.parse_status.lower())
            except ValueError:
                try:
                    self.parse_status = ParseResultStatus[self.parse_status.upper()]
                except KeyError:
                    pass
        # 同步常见的位置字段别名，方便不同入口按各自习惯读取。
        if not self.start_line:
            self.start_line = self.line_number
        if not self.end_line:
            self.end_line = self.line_number
        start = self.start_offset or self.byte_offset or self.offset or 0
        self.start_offset = self.byte_offset = self.offset = int(start)
        if not self.end_offset:
            self.end_offset = self.start_offset + len(self.raw_line.encode("utf-8"))
        if not self.next_offset:
            self.next_offset = self.end_offset
        if not self.content_end_offset:
            self.content_end_offset = self.end_offset
        if not self.end_byte_offset:
            self.end_byte_offset = self.next_offset
        if not self.source_position:
            self.source_position = {
                "source_id": self.source_id,
                "source_path": self.source_path,
                "line_number": self.line_number,
                "start_line": self.start_line,
                "end_line": self.end_line,
                "offset": self.offset,
                "byte_offset": self.byte_offset,
                "start_offset": self.start_offset,
                "end_offset": self.end_offset,
                "next_offset": self.next_offset,
            }
        if not self.position:
            self.position = self.source_position
        self.source_location = self.source_position
        self.source_key = f"{self.source_id}|{self.source_path}"
        # complete 与 is_complete 是同一状态的两个别名。
        status_is_pending = self.parse_status == ParseResultStatus.PENDING
        if self.pending or status_is_pending or not self.complete or not self.is_complete:
            self.pending = True
            self.complete = self.is_complete = False
            self.parse_status = ParseResultStatus.PENDING
        else:
            self.pending = False
        self.multiline = self.multiline or self.is_multiline or self.line_count > 1
        self.is_multiline = self.multiline
        if not self.checksum:
            self.checksum = self.compute_checksum()

    @property
    def raw_content(self) -> str:
        return self.raw_line

    @raw_content.setter
    def raw_content(self, value: str) -> None:
        self.raw_line = value


@dataclass
class MaskRule:
    """脱敏规则模型——对应 mask_rule 模块。"""
    rule_id: str
    target_field: str
    mask_method: MaskMethod
    mask_pattern: str
    retain_count: int = 0
    rule_state: str = "草稿"

    def apply(self, value: str) -> str:
        """对字段值执行脱敏变换。"""
        if not value:
            return value
        if self.mask_method == MaskMethod.PHONE:
            if len(value) >= 11:
                return value[:3] + "****" + value[-4:]
            return value[:1] + "****" + value[-1:] if len(value) > 2 else "****"
        if self.mask_method == MaskMethod.ID_CARD:
            if len(value) >= 18:
                return value[:6] + "********" + value[-4:]
            return value[:2] + "****" + value[-2:] if len(value) > 4 else "****"
        if self.mask_method == MaskMethod.EMAIL:
            parts = value.split("@")
            if len(parts) == 2:
                local = parts[0]
                masked_local = local[:2] + "***" + local[-1:] if len(local) > 3 else "***"
                return f"{masked_local}@{parts[1]}"
            return "***@***"
        if self.mask_method == MaskMethod.IP:
            octets = value.split(".")
            if len(octets) == 4:
                return f"{octets[0]}.{octets[1]}.*.*"
            return "***.***.***.***"
        if self.mask_method == MaskMethod.CUSTOM_REGEX:
            compiled = re.compile(self.mask_pattern)
            return compiled.sub("***", value)
        return value


@dataclass
class MaskResult:
    """脱敏变换结果——记录哪个字段被何种方式脱敏。"""
    rule_id: str
    field_name: str
    original: str
    masked: str
    method: MaskMethod
    is_masked: bool = True

    def verify(self) -> bool:
        """校验脱敏结果：敏感原值不应出现在掩码后的结果中。"""
        if not self.is_masked:
            return True
        if len(self.original) < 3:
            return self.masked != self.original
        core = self.original[3:-3] if len(self.original) > 6 else self.original
        return core not in self.masked


@dataclass
class FieldEnrichRule:
    """字段增强规则——对应 field_enrich 模块。"""
    rule_id: str
    target_field: str
    enrich_source: str
    mapping_dict: dict[str, str]
    default_value: str = "unknown"
    priority: int = 0

    def enrich(self, fields: dict[str, str]) -> str:
        """根据映射字典增强目标字段。"""
        key = fields.get(self.enrich_source, "").strip()
        return self.mapping_dict.get(key, self.default_value)


@dataclass
class EventTypeDef:
    """事件类型定义——对应 event_type 模块。"""
    type_id: str
    type_name: str
    category_tag: str
    severity: str = "INFO"
    alert_threshold: int = 0
    sample_ratio: float = 1.0
    retain_days: int = 30


@dataclass
class EventRecord:
    """标准化事件记录——解析、脱敏、增强后的最终产物。"""
    record_id: str
    event_type: EventTypeDef
    original_content: str
    parsed_fields: dict[str, str]
    masked_fields: dict[str, str]
    enriched_fields: dict[str, str]
    event_time: datetime
    source_host: str
    store_partition: str = ""
    index_state: str = "已写入"
    # 多行事件和断点重放所需的来源核对信息。
    source_id: str = ""
    source_path: str = ""
    line_number: int = 0
    start_line: int = 0
    end_line: int = 0
    offset: int = 0
    byte_offset: int = 0
    start_offset: int = 0
    end_offset: int = 0
    next_offset: int = 0
    content_end_offset: int = 0
    end_byte_offset: int = 0
    is_complete: bool = True
    complete: bool = True
    multiline: bool = False
    source_position: Any = None
    fingerprint: str = ""

    def __post_init__(self):
        if not self.start_line:
            self.start_line = self.line_number
        if not self.end_line:
            self.end_line = self.start_line
        start = self.start_offset or self.byte_offset or self.offset or 0
        self.start_offset = self.byte_offset = self.offset = int(start)
        if not self.end_offset:
            self.end_offset = self.start_offset + len(self.original_content.encode("utf-8"))
        if not self.next_offset:
            self.next_offset = self.end_offset
        if not self.content_end_offset:
            self.content_end_offset = self.end_offset
        if not self.end_byte_offset:
            self.end_byte_offset = self.next_offset
        if not self.source_position:
            self.source_position = {
                "source_id": self.source_id,
                "source_path": self.source_path,
                "line_number": self.line_number,
                "start_line": self.start_line,
                "end_line": self.end_line,
                "offset": self.offset,
                "byte_offset": self.byte_offset,
                "start_offset": self.start_offset,
                "end_offset": self.end_offset,
                "next_offset": self.next_offset,
            }
        self.position = self.source_position
        self.source_location = self.source_position
        self.source_key = f"{self.source_id}|{self.source_path}"
        if not self.fingerprint:
            raw = f"{self.source_id}|{self.source_path}|{self.start_offset}|{self.start_line}|{self.original_content}"
            self.fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @property
    def raw_content(self) -> str:
        return self.original_content

    @raw_content.setter
    def raw_content(self, value: str) -> None:
        self.original_content = value

    @property
    def raw_line(self) -> str:
        return self.original_content

    @raw_line.setter
    def raw_line(self, value: str) -> None:
        self.original_content = value


@dataclass
class DedupFilter:
    """去重过滤规则——对应 dedup_filter 模块。"""
    rule_id: str
    event_type_id: str
    dedup_fields: list[str]
    window_minutes: int = 60
    fingerprint_algo: str = "sha256"
    hit_count: int = 0
    ignore_count: int = 0

    def fingerprint(self, event: EventRecord) -> str:
        """基于去重字段生成事件指纹。"""
        key_parts = [event.event_type.type_id]
        for field in sorted(self.dedup_fields):
            val = event.parsed_fields.get(field) or event.masked_fields.get(field) or ""
            key_parts.append(f"{field}={val}")
        raw_key = "|".join(key_parts)
        return hashlib.sha256(raw_key.encode()).hexdigest()

    def is_duplicate(self, event: EventRecord, seen_fingerprints: set[str]) -> bool:
        """判断事件是否重复。"""
        fp = self.fingerprint(event)
        if fp in seen_fingerprints:
            self.hit_count += 1
            return True
        seen_fingerprints.add(fp)
        return False


@dataclass
class SampleConfig:
    """采样归并配置——对应 sample_job 模块。"""
    plan_id: str
    event_type_id: str
    sample_ratio: float
    merge_key: str = ""
    merge_window_minutes: int = 5
    retain_policy: str = "latest"


@dataclass
class BatchCheckpoint:
    """批次检查点——对应 batch_checkpoint 模块。"""
    checkpoint_id: str
    job_id: str
    file_path: str
    byte_offset: int
    line_count: int
    content_hash: str
    check_time: datetime = field(default_factory=datetime.now)
    state: str = "已记录"


@dataclass
class SourcePosition:
    """日志片段在指定来源文件/流中的位置。"""
    source_id: str = ""
    file_path: str = ""
    source_path: str = ""
    line_number: int = 1
    start_line: int = 0
    end_line: int = 0
    offset: int = 0
    byte_offset: int = 0
    start_offset: int = 0
    end_offset: int = 0
    next_offset: int = 0

    def __post_init__(self):
        if not self.source_path:
            self.source_path = self.file_path
        if not self.file_path:
            self.file_path = self.source_path
        if not self.start_line:
            self.start_line = self.line_number
        if not self.end_line:
            self.end_line = self.line_number
        start = self.start_offset or self.byte_offset or self.offset or 0
        self.start_offset = self.byte_offset = self.offset = int(start)
        if not self.next_offset and self.end_offset:
            self.next_offset = self.end_offset

    def as_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "file_path": self.file_path,
            "source_path": self.source_path,
            "line_number": self.line_number,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "offset": self.offset,
            "byte_offset": self.byte_offset,
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
            "next_offset": self.next_offset,
        }

    def get(self, key: str, default: Any = None) -> Any:
        return self.as_dict().get(key, default)

    def __getitem__(self, key: str) -> Any:
        return self.as_dict()[key]


@dataclass
class IngestJob:
    """采集作业模型——对应 ingest_job 模块。"""
    job_id: str
    source_id: str
    collect_mode: str = "incremental"
    file_cursor: int = 0
    batch_size: int = 100
    thread_count: int = 1
    processed_lines: int = 0
    skipped_lines: int = 0
    state: str = "待执行"


@dataclass
class IngestMetric:
    """采集指标——对应 ingest_metric 模块。"""
    metric_id: str
    source_id: str
    ingest_rate: float = 0.0
    process_delay_ms: float = 0.0
    error_rate: float = 0.0
    backlog_lines: int = 0
    sample_time: datetime = field(default_factory=datetime.now)


@dataclass
class QualityReport:
    """质量报告——对应 quality_report 模块。"""
    report_id: str
    source_id: str
    completeness_rate: float = 0.0
    parse_success_rate: float = 0.0
    field_coverage_rate: float = 0.0
    time_delay_seconds: float = 0.0
    eval_period: str = "daily"
    state: str = "待生成"


@dataclass
class AnomalyRule:
    """异常告警规则——对应 anomaly_rule 模块。"""
    rule_id: str
    event_type_id: str
    detect_condition: str
    alert_level: str = "WARNING"
    trigger_frequency: int = 1
    aggregate_window_minutes: int = 5
    notify_channel: str = "webhook"


@dataclass
class ForwardRule:
    """转发路由规则——对应 forward_rule 模块。"""
    rule_id: str
    event_type_id: str
    target_address: str
    forward_format: str = "json"
    batch_size: int = 100
    retry_limit: int = 3
    timeout_seconds: int = 30