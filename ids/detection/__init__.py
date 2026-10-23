"""Core Engine, context adapters và Detection Generator cho PCAP/live."""

from ids.detection.config import RuleConfig, RuleConfigError, load_rule_config
from ids.detection.loader import LoadReport, RuleLoadError, load_rules
from ids.detection.header_matcher import HeaderMatchResult, match_header
from ids.detection.flow_context import FlowContextResult, build_flow_context
from ids.detection.flow_matcher import FlowMatchResult, match_flow
from ids.detection.payload import PayloadResult, prepare_payload
from ids.detection.packet_matcher import PacketMatchResult, match_flags, match_dsize
from ids.detection.content_matcher import ContentMatchResult, ContentSearchLimits, match_contents
from ids.detection.matcher import match_rule
from ids.detection.engine import EvaluationEngine, EvaluationMetrics, EvaluationResult
from ids.detection.context import make_inspection_context
from ids.detection.generator import generate_detection
from ids.detection.session import DetectionSession

from ids.detection.models import (
    ContentCondition,
    ContentMatch,
    DSizeCondition,
    DetectionEvent,
    Diagnostic,
    FlagsCondition,
    FlowCondition,
    FlowContext,
    InspectionContext,
    MatchedInfo,
    MatchResult,
    MatchStatus,
    ParseResult,
    ParseStatus,
    PayloadStatus,
    PortSpec,
    Rule,
    RuleHeader,
    RuleSource,
)
from ids.detection.parser import parse_rule
from ids.detection.repository import RuleRepository

__all__ = [
    "ContentCondition", "ContentMatch", "DSizeCondition", "DetectionEvent",
    "Diagnostic", "FlagsCondition", "FlowCondition", "FlowContext",
    "InspectionContext", "MatchedInfo", "MatchResult", "MatchStatus",
    "ParseResult", "ParseStatus", "PayloadStatus", "PortSpec", "Rule",
    "RuleHeader", "RuleSource", "parse_rule",
    "RuleConfig", "RuleConfigError", "load_rule_config",
    "LoadReport", "RuleLoadError", "load_rules",
    "RuleRepository",
    "HeaderMatchResult", "match_header",
    "FlowContextResult", "build_flow_context", "FlowMatchResult", "match_flow",
    "PayloadResult", "prepare_payload", "PacketMatchResult", "match_flags", "match_dsize",
    "ContentMatchResult", "ContentSearchLimits", "match_contents",
    "match_rule", "EvaluationEngine", "EvaluationMetrics", "EvaluationResult",
    "make_inspection_context", "generate_detection", "DetectionSession",
]
