"""Điều phối Preprocessor; chỉ cập nhật normalized và metadata của IDSEvent."""

import json

from ids.core.config import PreprocessorConfig
from ids.core.event import IDSEvent, NormalizedEvent
from ids.preprocessor.normalization import normalize_event
from ids.preprocessor.policy import decide_processing, fill_missing_data
from ids.preprocessor.validation import validate_event


def _empty_normalized() -> NormalizedEvent:
    """Biểu diễn rỗng khi input invalid hoặc xử lý thất bại, không đoán dữ liệu."""
    return {
        "timestamp": None,
        "network": {"protocol": None, "src_ip": None, "dst_ip": None},
        "transport": {
            "protocol": None, "src_port": None, "dst_port": None,
            "payload_length": None,
        },
        "application": {"protocol": None, "fields": {}},
        "payload_length": None,
        "packet_length": None,
    }


def preprocess_event(
    event: IDSEvent,
    config: PreprocessorConfig | None = None,
) -> IDSEvent:
    """Validate -> normalize -> missing data -> metadata, trả lại cùng event.

    Dữ liệu Parser/Decoder và raw payload không bị sửa. Field invalid hoặc
    lỗi xử lý tạo normalized rỗng, status invalid và reason; action theo config.
    Unsupported không tự thành invalid. Skip vẫn trả event để ghi output.
    Caller phải truyền IDSEvent, không truyền packet Scapy/dictionary.
    """
    if not isinstance(event, IDSEvent):
        raise TypeError("preprocess_event expects IDSEvent")

    stage = "configuration"
    try:
        config = config if config is not None else PreprocessorConfig()
        if not isinstance(config, PreprocessorConfig):
            raise TypeError("Expected PreprocessorConfig")

        stage = "validation"
        validation = validate_event(event)
        stage = "policy"
        decision = decide_processing(validation, config)

        if validation.errors:
            normalized = _empty_normalized()
        else:
            stage = "normalization"
            normalized = normalize_event(event)
            stage = "missing data"
            normalized = fill_missing_data(normalized)

        stage = "serialization check"
        json.dumps(normalized, allow_nan=False)
    except Exception as error:
        # Không để dữ liệu cũ hoặc kết quả dở dang được module sau sử dụng.
        event.normalized = _empty_normalized()
        event.preprocess_status = "invalid"
        event.processing_action = (
            config.invalid_action if isinstance(config, PreprocessorConfig) else "skip"
        )
        event.reason = f"Preprocessor {stage} error: {type(error).__name__}: {error}"
        return event

    event.normalized = normalized
    event.preprocess_status = decision.status
    event.processing_action = decision.action
    event.reason = decision.reason
    return event
