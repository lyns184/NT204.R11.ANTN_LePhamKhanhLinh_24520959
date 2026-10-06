"""Preprocessor cho IDSEvent; xem README.md về hợp đồng dữ liệu.

Đã có validation, normalization và chính sách missing/unsupported riêng;
chưa triển khai preprocess_event hoặc tích hợp pipeline.
"""

from ids.preprocessor.validation import ValidationIssue, ValidationResult, validate_event
from ids.preprocessor.normalization import NormalizationError, normalize_event
from ids.preprocessor.policy import PreprocessDecision, decide_processing, fill_missing_data

__all__ = [
    "ValidationIssue", "ValidationResult", "validate_event",
    "NormalizationError", "normalize_event",
    "PreprocessDecision", "decide_processing", "fill_missing_data",
]
