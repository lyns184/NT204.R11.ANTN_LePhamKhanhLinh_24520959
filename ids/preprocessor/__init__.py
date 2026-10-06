"""Preprocessor cho IDSEvent; xem README.md về hợp đồng dữ liệu.

Đã có preprocess_event điều phối các bước; chưa tích hợp capture pipeline.
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
