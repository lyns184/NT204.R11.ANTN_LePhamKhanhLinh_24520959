"""Lưu rule đã bật và chọn candidate theo protocol/port, chưa matching.

Index không đọc file, không nhận Scapy và không suy luận protocol từ flow.
Candidate có thể dư; Matcher vẫn phải kiểm tra đầy đủ header và conditions.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from ids.detection.models import InspectionContext, PortSpec, Rule


@dataclass(frozen=True)
class _PortIndex:
    all_ids: frozenset[int]
    any_ids: frozenset[int]
    exact: Mapping[int, frozenset[int]]
    ranges: tuple[tuple[int, int, int], ...]

    @classmethod
    def build(cls, selectors: Iterable[tuple[int, PortSpec]]) -> "_PortIndex":
        all_ids, any_ids = set(), set()
        exact: dict[int, set[int]] = {}
        ranges = []
        for position, spec in selectors:
            all_ids.add(position)
            if spec.is_any:
                any_ids.add(position)
            elif spec.start == spec.end:
                exact.setdefault(spec.start, set()).add(position)
            else:
                # Một record cho mỗi khoảng, không expand theo số port.
                ranges.append((spec.start, spec.end, position))
        return cls(frozenset(all_ids), frozenset(any_ids),
                   MappingProxyType({port: frozenset(ids) for port, ids in exact.items()}),
                   tuple(ranges))

    def select(self, port: int | None) -> frozenset[int]:
        if port is None:
            return self.all_ids
        selected = set(self.any_ids)
        selected.update(self.exact.get(port, ()))
        selected.update(position for low, high, position in self.ranges if low <= port <= high)
        return frozenset(selected)


@dataclass(frozen=True)
class _OrientationIndex:
    source: _PortIndex
    destination: _PortIndex

    def select(self, source: int | None, destination: int | None) -> frozenset[int]:
        return self.source.select(source) & self.destination.select(destination)


def _known_port(value: Any) -> int | None:
    # Không coi bool/string/float là port, không ép kiểu dữ liệu thiếu/lỗi.
    return value if type(value) is int and 0 <= value <= 65535 else None


@dataclass(frozen=True, init=False)
class RuleRepository:
    """Snapshot rule có thứ tự, tạo từ LoadReport.enabled_rules.

    Caller chịu trách nhiệm truyền duy nhất rule đã bật: Rule không có enabled
    flag để repository tự xác định config. Từ chối phần tử không phải Rule và
    SID trùng. Repository rỗng hợp lệ; Loader quyết định lỗi startup rỗng.

    Exact port dùng dictionary; any dùng bucket riêng; range dùng record
    inclusive và scan các khoảng, không scan toàn bộ rule hoặc bung port.
    """

    _rules: tuple[Rule, ...]
    _index: Mapping[str, tuple[_OrientationIndex, ...]] = field(repr=False)

    def __init__(self, rules: Iterable[Rule]) -> None:
        if isinstance(rules, (str, bytes, Mapping)) or not isinstance(rules, Iterable):
            raise TypeError("rules must be an iterable of Rule objects")
        snapshot = tuple(rules)
        seen = set()
        for rule in snapshot:
            if not isinstance(rule, Rule):
                raise TypeError("repository entries must be Rule objects")
            if rule.sid in seen:
                raise ValueError(f"Duplicate SID in repository input: {rule.sid}")
            seen.add(rule.sid)

        index = {}
        for protocol in ("tcp", "udp", "ip"):
            direct = [(position, rule.header.src_port, rule.header.dst_port)
                      for position, rule in enumerate(snapshot) if rule.header.protocol == protocol]
            reverse = [(position, rule.header.dst_port, rule.header.src_port)
                       for position, rule in enumerate(snapshot)
                       if rule.header.protocol == protocol and rule.header.direction == "<>"]
            index[protocol] = tuple(
                _OrientationIndex(_PortIndex.build((position, src) for position, src, dst in rows),
                                  _PortIndex.build((position, dst) for position, src, dst in rows))
                for rows in (direct, reverse)
            )
        object.__setattr__(self, "_rules", snapshot)
        object.__setattr__(self, "_index", MappingProxyType(index))

    @property
    def rules(self) -> tuple[Rule, ...]:
        return self._rules

    def __len__(self) -> int:
        return len(self._rules)

    def candidates(self, context: InspectionContext) -> tuple[Rule, ...]:
        """Trả candidate dedup theo thứ tự nạp; không xác nhận MATCH.

        Chỉ dùng normalized.transport.protocol/src_port/dst_port. Protocol
        canonical TCP/UDP chọn bucket tương ứng + ip; thiếu hoặc ngoài schema
        canonical thì giữ cả ba bucket. Port thiếu/sai kiểu giữ mọi selector
        ở đầu đó, nhưng vẫn lọc bằng đầu còn biết. Không tự normalize lại.

        processing_action=skip được engine xử lý sau này; việc tra index thuần
        túy không xét action, IP, flow, payload hoặc bất kỳ rule option nào.
        """
        if not isinstance(context, InspectionContext):
            raise TypeError("context must be InspectionContext")
        transport = context.normalized.get("transport")
        if not isinstance(transport, Mapping):
            transport = {}
        protocol = transport.get("protocol")
        if isinstance(protocol, str) and protocol in ("TCP", "UDP"):
            protocols = (protocol.lower(), "ip")
        else:
            protocols = ("tcp", "udp", "ip")
        source = _known_port(transport.get("src_port"))
        destination = _known_port(transport.get("dst_port"))
        selected: set[int] = set()
        for name in protocols:
            for orientation in self._index[name]:
                selected.update(orientation.select(source, destination))
        return tuple(self._rules[position] for position in sorted(selected))
