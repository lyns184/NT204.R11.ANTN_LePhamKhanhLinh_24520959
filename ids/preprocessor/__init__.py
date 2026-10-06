"""Preprocessor cho IDSEvent; xem README.md về hợp đồng dữ liệu.

preprocess_event chạy sau Decoder trong pipeline chung của live/PCAP.
"""

from ids.preprocessor.validation import ValidationIssue, ValidationResult, validate_event
from ids.preprocessor.normalization import NormalizationError, normalize_event
from ids.preprocessor.policy import PreprocessDecision, decide_processing, fill_missing_data
from ids.preprocessor.processor import preprocess_event

__all__ = [
    "ValidationIssue", "ValidationResult", "validate_event",
    "NormalizationError", "normalize_event",
    "PreprocessDecision", "decide_processing", "fill_missing_data",
    "preprocess_event",
]
