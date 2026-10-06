"""Preprocessor cho IDSEvent; xem README.md về hợp đồng dữ liệu.

Đã có validation riêng; chưa triển khai preprocess_event hoặc tích hợp pipeline.
"""

from ids.preprocessor.validation import ValidationIssue, ValidationResult, validate_event

__all__ = ["ValidationIssue", "ValidationResult", "validate_event"]
