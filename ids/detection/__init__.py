"""Core Engine models và Snort 2-style rule parser; chưa có evaluation."""

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

__all__ = [
    "ContentCondition", "ContentMatch", "DSizeCondition", "DetectionEvent",
    "Diagnostic", "FlagsCondition", "FlowCondition", "FlowContext",
    "InspectionContext", "MatchedInfo", "MatchResult", "MatchStatus",
    "ParseResult", "ParseStatus", "PayloadStatus", "PortSpec", "Rule",
    "RuleHeader", "RuleSource", "parse_rule",
]
