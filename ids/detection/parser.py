"""Parser/Validator cho một rule Snort 2-style trong phạm vi MVP.

Không đọc file, không matching packet. Lỗi rule trả ParseResult kèm source;
caller truyền sai kiểu API gây TypeError. Không thực thi một phần rule lỗi.
"""

import re
from ipaddress import IPv4Address, IPv4Network, IPv6Network
from typing import Any

from ids.detection.models import (
    FLAG_LETTERS, MAX_DSIZE_VALUE, MAX_RULE_NUMBER,
    ContentCondition, Diagnostic, DSizeCondition, FlagsCondition, FlowCondition,
    ParseResult, ParseStatus, PortSpec, Rule, RuleHeader, RuleSource,
)


_MODIFIERS = frozenset(("nocase", "offset", "depth", "distance", "within"))
_KEYWORDS = _MODIFIERS | frozenset(("msg", "sid", "rev", "classtype", "priority",
                                     "content", "flow", "flags", "dsize"))
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


class _Issue(Exception):
    def __init__(self, code: str, reason: str, keyword: str | None = None,
                 category: str = "invalid") -> None:
        super().__init__(reason)
        self.code, self.reason, self.keyword, self.category = code, reason, keyword, category


def _unsupported(code: str, reason: str, keyword: str | None = None) -> _Issue:
    return _Issue(code, reason, keyword, "unsupported")


def _envelope(text: str) -> tuple[str, str]:
    """Nhận biết comment, quote, escape và đúng một cặp ngoặc ngoài."""
    line = text.rstrip("\r\n")
    if "\n" in line or "\r" in line:
        raise _unsupported("unsupported_multiline", "Only one physical rule line is supported")
    if re.match(r"\s*include\s+", line):
        raise _unsupported("unsupported_directive", "include is outside the rule parser MVP")
    quoted, escaped = False, False
    opening = closing = None
    limit = len(line)
    for index, char in enumerate(line):
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
            continue
        if char == "#":
            limit = index
            break
        if closing is not None:
            if not char.isspace():
                raise _Issue("trailing_text", "Unexpected text after the closing rule parenthesis")
        elif char == '"':
            if opening is None:
                raise _Issue("invalid_header", "Quotes are not supported in a rule header")
            quoted = True
        elif char == "(":
            if opening is not None:
                raise _Issue("nested_parenthesis", "Unquoted nested parentheses are not rule options")
            opening = index
        elif char == ")":
            if opening is None:
                raise _Issue("unexpected_parenthesis", "Closing parenthesis has no opening parenthesis")
            closing = index
        elif char == "\\" and not line[index + 1:].strip():
            raise _unsupported("unsupported_continuation", "Rule continuation is outside the MVP")
    if quoted:
        raise _Issue("unterminated_string", "Unterminated quoted string or dangling escape")
    if not line[:limit].strip():
        raise _Issue("empty_rule", "Expected one rule; the loader must skip blank/comment lines")
    if opening is None or closing is None:
        raise _Issue("missing_parenthesis", "Rule must contain a complete parenthesized option list")
    return line[:opening].strip(), line[opening + 1:closing]


def _header_tokens(text: str) -> list[str]:
    # List selectors ngoài MVP vẫn phải được nhận diện là một token dù có space.
    tokens, start, brackets = [], None, 0
    for index, char in enumerate(text):
        if char.isspace() and brackets == 0:
            if start is not None:
                tokens.append(text[start:index])
                start = None
            continue
        if start is None:
            start = index
        if char == "[":
            brackets += 1
        elif char == "]":
            brackets -= 1
            if brackets < 0:
                raise _Issue("invalid_selector", "Unbalanced selector brackets")
    if brackets:
        raise _Issue("invalid_selector", "Unbalanced selector brackets")
    if start is not None:
        tokens.append(text[start:])
    if len(tokens) != 7:
        raise _Issue("invalid_header", "Traditional rule header must have seven fields")
    return tokens


def _selector_extension(token: str, keyword: str) -> None:
    if token.startswith("$"):
        if not _IDENTIFIER.fullmatch(token[1:]):
            raise _Issue("invalid_variable", "Malformed rule variable", keyword)
        raise _unsupported("unsupported_variable", "Rule variables are outside the MVP", keyword)
    if token.startswith("!") or token.startswith("["):
        if token in ("!", "[]", "[ ]"):
            raise _Issue("invalid_selector", "Empty selector or missing negated selector", keyword)
        raise _unsupported("unsupported_selector", "Lists/negated selectors are outside the MVP", keyword)
    if token.lower() == "any" and token != "any":
        raise _unsupported("unsupported_case", "Use lowercase any in this MVP", keyword)


def _decimal(text: str, keyword: str, low: int, high: int,
             overflow_category: str = "invalid") -> int:
    if re.fullmatch(r"[0-9]+", text) is None:
        raise _Issue("invalid_integer", "Expected a decimal integer literal", keyword)
    digits = text.lstrip("0") or "0"
    bound = str(high)
    # Không gọi int() trên literal hàng nghìn chữ số vượt giới hạn Python.
    if len(digits) > len(bound) or (len(digits) == len(bound) and digits > bound):
        raise _Issue("unsupported_value" if overflow_category == "unsupported" else "out_of_range",
                     f"{keyword} exceeds supported maximum {high}", keyword, overflow_category)
    value = int(digits)
    if value < low:
        raise _Issue("out_of_range", f"{keyword} must be at least {low}", keyword)
    return value


def _address(token: str, keyword: str) -> IPv4Network | None:
    if token == "any":
        return None
    _selector_extension(token, keyword)
    if ":" in token:
        try:
            IPv6Network(token, strict=False)
        except ValueError as error:
            raise _Issue("invalid_address", str(error), keyword) from error
        raise _unsupported("unsupported_ipv6", "Only IPv4 selectors are supported", keyword)
    if re.fullmatch(r"[0-9.]+(?:/[0-9.]+)?", token):
        address, separator, prefix = token.partition("/")
        try:
            IPv4Address(address)
            network = IPv4Network(token, strict=False)
        except ValueError as error:
            raise _Issue("invalid_address", str(error), keyword) from error
        if separator and "." in prefix:
            raise _unsupported("unsupported_netmask", "Use a numeric CIDR prefix in this MVP", keyword)
        return network
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", token):
        raise _unsupported("unsupported_hostname", "Hostnames are outside the MVP", keyword)
    raise _Issue("invalid_address", "Expected any, an IPv4 address, or an IPv4 CIDR", keyword)


def _port(token: str, keyword: str) -> PortSpec:
    if token == "any":
        return PortSpec()
    _selector_extension(token, keyword)
    if ":" not in token:
        value = _decimal(token, keyword, 0, 65535)
        return PortSpec(value, value)
    if token.count(":") != 1 or token == ":":
        raise _Issue("invalid_port", "Expected a:b, :b, or a: port range", keyword)
    start, end = token.split(":")
    low = _decimal(start, keyword, 0, 65535) if start else 0
    high = _decimal(end, keyword, 0, 65535) if end else 65535
    if low > high:
        raise _Issue("invalid_port", "Port range start exceeds end", keyword)
    return PortSpec(low, high)


def _options(text: str) -> list[tuple[str, str | None]]:
    segments, start, quoted, escaped = [], 0, False, False
    for index, char in enumerate(text):
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char == ";":
            segment = text[start:index].strip()
            if not segment:
                raise _Issue("empty_option", "Empty rule option between semicolons")
            segments.append(segment)
            start = index + 1
    if text[start:].strip():
        raise _Issue("missing_semicolon", "Each rule option must end with a semicolon")
    result = []
    for segment in segments:
        key, colon, value = segment.partition(":")
        key = key.strip()
        if _IDENTIFIER.fullmatch(key) is None:
            raise _Issue("invalid_keyword", "Malformed rule option keyword")
        result.append((key, value.strip() if colon else None))
    return result


def _argument(value: str | None, keyword: str) -> str:
    if value is None or not value:
        raise _Issue("missing_argument", f"{keyword} requires an argument", keyword)
    return value


def _quoted(value: str, keyword: str) -> str:
    if not value.startswith('"'):
        raise _Issue("expected_string", "Expected a double-quoted string", keyword)
    escaped = False
    for index in range(1, len(value)):
        char = value[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            tail = value[index + 1:].strip()
            if tail:
                if keyword == "content" and tail.startswith(","):
                    raise _unsupported("unsupported_content_syntax", "Snort 3-style inline modifiers are outside the MVP", keyword)
                raise _Issue("trailing_argument", "Unexpected text after quoted string", keyword)
            return value[1:index]
    raise _Issue("unterminated_string", "Unterminated quoted string", keyword)


def _message(value: str) -> str:
    raw = _quoted(value, "msg")
    result, index = [], 0
    while index < len(raw):
        char = raw[index]
        if char == "\\":
            index += 1
            char = raw[index]
            if char not in ('"', "\\", ";"):
                raise _unsupported("unsupported_escape", "Unsupported msg escape", "msg")
        result.append(char)
        index += 1
    message = "".join(result)
    if not message.strip():
        raise _Issue("empty_message", "msg must not be empty", "msg")
    return message


def _content(value: str) -> bytes:
    raw = _quoted(value, "content")
    result, index = bytearray(), 0
    unsupported = None
    while index < len(raw):
        char = raw[index]
        if char == "\\":
            index += 1
            if index >= len(raw):
                raise _Issue("invalid_escape", "Content ends with an incomplete escape", "content")
            char = raw[index]
            if char not in ('"', "\\", ";", "|"):
                # Vẫn kiểm tra phần sau để hex malformed được ưu tiên invalid.
                # Không append ord(char): Unicode sau backslash có thể >255.
                if unsupported is None:
                    unsupported = _unsupported("unsupported_escape", "Unsupported content escape; use hex blocks for binary bytes", "content")
            else:
                result.append(ord(char))
        elif char == "|":
            end = raw.find("|", index + 1)
            if end < 0:
                raise _Issue("invalid_hex", "Unterminated content hex block", "content")
            digits = "".join(raw[index + 1:end].split())
            if not digits or len(digits) % 2 or re.fullmatch(r"[0-9A-Fa-f]+", digits) is None:
                raise _Issue("invalid_hex", "Hex blocks require complete hexadecimal byte pairs", "content")
            result.extend(bytes.fromhex(digits))
            index = end
        elif not 32 <= ord(char) <= 126:
            if unsupported is None:
                unsupported = _unsupported("unsupported_content_literal", "Use ASCII literals or hex bytes for content", "content")
        else:
            result.append(ord(char))
        index += 1
    if len(result) > 65535:
        raise _Issue("invalid_content_length", "Content must contain 1..65535 bytes", "content")
    if unsupported is not None:
        raise unsupported  # Không trả pattern đã bỏ các byte chưa hỗ trợ.
    if not result:
        raise _Issue("invalid_content_length", "Content must contain 1..65535 bytes", "content")
    return bytes(result)


def _modifier(value: str, keyword: str) -> int:
    if _IDENTIFIER.fullmatch(value) or re.fullmatch(r"\$[A-Za-z_][A-Za-z0-9_]*", value):
        raise _unsupported("unsupported_value", "Variable content modifiers are outside the MVP", keyword)
    if keyword in ("offset", "distance") and re.fullmatch(r"-[0-9]+", value):
        _decimal(value[1:], keyword, 0, 65535)
        raise _unsupported("unsupported_value", "Negative offsets/distances are outside the MVP", keyword)
    return _decimal(value, keyword, 1 if keyword in ("depth", "within") else 0, 65535)


def _flow(value: str) -> FlowCondition:
    tokens = [token.strip() for token in value.split(",")]
    if not all(tokens):
        raise _Issue("invalid_flow", "flow contains an empty token", "flow")
    directions = [token for token in tokens if token in ("to_server", "to_client")]
    states = [token for token in tokens if token in ("established", "not_established")]
    if len(directions) > 1 or len(states) > 1:
        raise _Issue("conflicting_flow", "flow has duplicate or conflicting direction/state", "flow")
    if len(directions) + len(states) != len(tokens):
        raise _unsupported("unsupported_flow", "Unsupported flow token", "flow")
    return FlowCondition(directions[0] if directions else None, states[0] if states else None)


def _flags(value: str) -> FlagsCondition:
    if value == "0":
        return FlagsCondition()
    if all(char in FLAG_LETTERS for char in value):
        # Snort 2.9.20 ParseTCPFlags OR từng bit, nên SS và S cùng nghĩa.
        # Rule.raw_text vẫn giữ nguyên biểu thức ban đầu, không mất provenance.
        return FlagsCondition(frozenset(value))
    letters = "FSRPAUCE"
    if (re.fullmatch(rf"(?:[+*!][{letters}]+|[{letters}]+[+*!])", value)
            or re.fullmatch(rf"[+*!]?[{letters}012]+[+*!]?\s*,\s*[{letters}12]+", value)
            or re.fullmatch(rf"(?=.*[12])[{letters}12]+", value)):
        raise _unsupported("unsupported_flags", "Only exact flag sets and flags:0 are supported", "flags")
    raise _Issue("invalid_flags", "Invalid TCP flags or malformed flags expression", "flags")


def _dsize(value: str) -> DSizeCondition:
    match = re.fullmatch(r"([<>]?)\s*([0-9]+)", value)
    if match:
        number = _decimal(match[2], "dsize", 0, MAX_DSIZE_VALUE, "unsupported")
        return DSizeCondition(match[1] or "=", number)
    if (re.fullmatch(r"(?:<=|>=|!=)\s*[0-9]+", value)
            or re.fullmatch(r"[0-9]+\s*(?:<>|<=>)\s*[0-9]+", value)):
        raise _unsupported("unsupported_dsize", "Only dsize:n, dsize:<n, dsize:>n are supported", "dsize")
    raise _Issue("invalid_dsize", "Expected a nonnegative literal with optional < or >", "dsize")


def parse_rule(text: str, source: RuleSource | None = None) -> ParseResult:
    """Parse một rule. Invalid có ưu tiên khi có cả lỗi và phần unsupported.

    Blank/comment-only lines do Loader lọc; truyền riêng vào đây là empty_rule.
    Header/options ngoài MVP không được trả partial Rule để caller thực thi.
    """
    if not isinstance(text, str):
        raise TypeError("parse_rule expects rule text as str")
    if source is not None and not isinstance(source, RuleSource):
        raise TypeError("parse_rule source must be RuleSource or None")
    diagnostics: list[Diagnostic] = []

    def record(issue: _Issue) -> None:
        diagnostics.append(Diagnostic(issue.code, issue.reason, issue.category, source, issue.keyword))

    def attempt(function, *args):
        try:
            return function(*args)
        except _Issue as issue:
            record(issue)
            return None

    def failed() -> ParseResult:
        status = (ParseStatus.INVALID if any(item.category == "invalid" for item in diagnostics)
                  else ParseStatus.UNSUPPORTED)
        return ParseResult(status, diagnostics=tuple(diagnostics))

    try:
        header_text, body = _envelope(text)
        tokens = _header_tokens(header_text)
        options = _options(body)
    except _Issue as issue:
        record(issue)
        return failed()

    action, protocol, src_ip, src_port, direction, dst_ip, dst_port = tokens
    header_values: dict[str, Any] = {"action": action, "protocol": protocol, "direction": direction}
    for keyword, value, accepted in (("action", action, ("alert",)),
                                      ("protocol", protocol, ("tcp", "udp", "ip")),
                                      ("direction", direction, ("->", "<>"))):
        if value not in accepted:
            if keyword == "direction" or (keyword == "protocol" and value.lower() == "any"):
                record(_Issue("invalid_header", f"Invalid {keyword}: {value}", keyword))
            elif _IDENTIFIER.fullmatch(value):
                record(_unsupported("unsupported_header", f"Unsupported {keyword}: {value}", keyword))
            else:
                record(_Issue("invalid_header", f"Malformed {keyword}", keyword))
    for keyword, value, function in (("src_ip", src_ip, _address), ("dst_ip", dst_ip, _address),
                                      ("src_port", src_port, _port), ("dst_port", dst_port, _port)):
        header_values[keyword] = attempt(function, value, keyword)
    if protocol == "ip" and (src_port != "any" or dst_port != "any"):
        record(_unsupported("unsupported_combination", "ip rules require any source/destination ports in the MVP", "protocol"))

    values: dict[str, Any] = {}
    present: set[str] = set()
    builders: list[dict[str, Any]] = []
    modifier_keys: list[set[str]] = []
    for key, argument in options:
        keyword = key.lower()
        if keyword in _KEYWORDS:
            if keyword not in _MODIFIERS and keyword != "content" and keyword in present:
                record(_Issue("duplicate_option", f"Duplicate {keyword}", keyword))
                continue
            present.add(keyword)
        if keyword not in _KEYWORDS:
            record(_unsupported("unsupported_keyword", f"Keyword {key} is outside the MVP", key))
            continue
        if key != keyword:
            record(_unsupported("unsupported_case", "Use lowercase rule option keywords in this MVP", key))
            if keyword == "content":
                builders.append({"pattern": None})
                modifier_keys.append(set())
            continue
        try:
            if keyword == "content":
                builders.append({"pattern": None})
                modifier_keys.append(set())
                value = _argument(argument, keyword)
                negated = value.startswith("!")
                builders[-1]["pattern"] = _content(value[1:].strip() if negated else value)
                if negated:
                    raise _unsupported("unsupported_content_negation", "Negated content is outside the MVP", keyword)
            elif keyword in _MODIFIERS:
                if not builders:
                    raise _Issue("orphan_modifier", "Content modifier requires preceding content", keyword)
                if keyword in modifier_keys[-1]:
                    raise _Issue("duplicate_modifier", f"Duplicate {keyword} on one content", keyword)
                modifier_keys[-1].add(keyword)
                if keyword == "nocase":
                    if argument is not None:
                        raise _Issue("unexpected_argument", "nocase does not take an argument", keyword)
                    builders[-1][keyword] = True
                else:
                    builders[-1][keyword] = _modifier(_argument(argument, keyword), keyword)
            elif keyword == "msg":
                values[keyword] = _message(_argument(argument, keyword))
            elif keyword in ("sid", "rev", "priority"):
                values[keyword] = _decimal(_argument(argument, keyword), keyword, 1, MAX_RULE_NUMBER)
            elif keyword == "classtype":
                value = _argument(argument, keyword)
                if re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", value) is None:
                    raise _Issue("invalid_classtype", "classtype must be an identifier", keyword)
                values[keyword] = value
            elif keyword == "flow":
                values[keyword] = _flow(_argument(argument, keyword))
            elif keyword == "flags":
                values[keyword] = _flags(_argument(argument, keyword))
            elif keyword == "dsize":
                values[keyword] = _dsize(_argument(argument, keyword))
        except _Issue as issue:
            record(issue)

    for required in ("msg", "sid", "rev"):
        if required not in present:
            record(_Issue("missing_identification", f"Missing required {required}", required))
    if protocol in ("udp", "ip"):
        for keyword in ("flow", "flags"):
            if keyword in present:
                record(_unsupported("unsupported_combination", f"{keyword} requires a tcp rule in this MVP", keyword))

    contents = []
    for index, builder in enumerate(builders):
        if builder["pattern"] is None:
            continue
        if index == 0 and ("distance" in builder or "within" in builder):
            record(_Issue("orphan_relative_content", "First content cannot reference a preceding content", "content"))
        try:
            contents.append(ContentCondition(**builder))
        except ValueError as error:
            record(_Issue("invalid_content", str(error), "content"))
    if diagnostics:
        return failed()

    # Phần unsupported đã được loại trước khi validate models của supported Rule.
    try:
        header = RuleHeader(**header_values)
        rule = Rule(header=header, contents=tuple(contents), source=source, raw_text=text, **values)
    except ValueError as error:
        record(_Issue("invalid_rule", str(error)))
        return failed()
    return ParseResult(ParseStatus.VALID, rule=rule)
