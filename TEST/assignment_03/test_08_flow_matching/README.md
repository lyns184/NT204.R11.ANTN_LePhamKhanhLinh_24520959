# Test 08 - Flow Matching

## Mục tiêu

Kiểm tra T08 trong mục 7 Bài tập 3: `flow:to_server,established` match đúng dựa trên bằng chứng từ Flow Tracker của từng packet.


## Dữ liệu

### Rule

`input.rules` có một rule hợp lệ:

```text
alert tcp any any <> any 80 (msg:"Established client request"; sid:100801; rev:1; flow:to_server,established; content:"admin";)
```

Header `<>` cho phép xét cả chiều request/response; flow condition chọn client→server đã established. Content admin giúp phân biệt ACK không payload với request có dữ liệu.

### PCAP

- `input.pcap`: sáu packet Scapy tự tạo, không capture từ mạng thật.
- Client A: `10.0.0.1:12345`; server: `10.0.0.2:80`; kết nối bắt giữa phiên dùng `10.0.0.3:12346` → server.
- MAC của `10.0.0.1`, `.2`, `.3` lần lượt là `02:00:00:00:00:01`, `02:00:00:00:00:02`, `02:00:00:00:00:03`.
- Ethernet/IPv4/TCP; IP/TCP headers mỗi loại `20` byte. Packet 1–5 cùng flow; packet 6 là flow khác.

| Packet | Timestamp | Chiều / nội dung | Flags | Seq / Ack | TCP payload | IPv4 length |
|---|---|---|---|---|---|---|
| 1 | `1700000000` | A → server: SYN | S | `1000 / 0` | `0` | `40` |
| 2 | `1700000001` | Server → A: SYN/ACK | SA | `2000 / 1001` | `0` | `40` |
| 3 | `1700000002` | A → server: ACK hoàn tất handshake | A | `1001 / 2001` | `0` | `40` |
| 4 | `1700000003` | A → server: GET /admin | PA | `1001 / 2001` | `39` | `79` |
| 5 | `1700000004` | Server → A: HTTP response admin | PA | `2001 / 1040` | `84` | `124` |
| 6 | `1700000005` | Flow khác: GET /admin, không thấy handshake | PA | `3000 / 4000` | `39` | `79` |

Request packet 4 và 6 giống nhau:

```http
GET /admin HTTP/1.1
Host: ids.test

```

Response packet 5:

```http
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Content-Length: 5

admin
```


### Snapshot và kết quả mong đợi

Script kiểm tra bốn tổ hợp flow condition trên mỗi snapshot: to_server/established, to_client/established, to_server/not_established, to_client/not_established.

| Packet | packet_direction | established_for_packet | Tổ hợp flow trả MATCH | Kết quả cả rule SID100801 |
|---|---|---|---|---|
| 1 | to_server | false | to_server,not_established | NO_MATCH vì chưa established |
| 2 | to_client | false | to_client,not_established | NO_MATCH vì chiều/state |
| 3 | to_server | true | to_server,established | NO_MATCH vì payload rỗng |
| 4 | to_server | true | to_server,established | MATCH |
| 5 | to_client | true | to_client,established | NO_MATCH vì sai chiều |
| 6 | unknown | null | Không có; cả bốn NOT_EVALUABLE | NOT_EVALUABLE |

Ở packet 1–5, ba tổ hợp flow còn lại trong mỗi hàng trả NO_MATCH. Packet 6 không được tự coi unknown là false để match not_established.

## Thực hiện

Chạy tại thư mục gốc project trong PowerShell:

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding

& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_03\test_08_flow_matching\check_flow_matching.py
if ($LASTEXITCODE -ne 0) { throw "T08 failed" }
```

Phần API replay PCAP qua `process_packet()` với một Flow Tracker thật. Callback sau tracking nhận event và `FlowTrackingResult.snapshot` của chính packet; gọi `build_flow_context()`, `prepare_payload()`, `make_inspection_context()` thật, rồi kiểm tra Header/Flow/full-rule matchers.

Script kiểm tra roles, true/false/unknown, 24 tổ hợp flow và sáu kết quả cả rule. Sau khi xử lý packet sau và flush, snapshot/context cũ vẫn phải giữ nguyên. Không dựng lại context từ flow summary hoặc lookup state cuối.

Phần CLI chạy `main.py` độc lập, kiểm tra event/flow/detection JSONL, diagnostics và counters. 
Console UTF-8 lưu stdout/stderr CLI và các bước kiểm tra. Thành công trả `0`, assertion/exception ghi FAIL và trả `1`.

## Kết quả

**PASS T08.** API, CLI và script thành công; đủ sáu event, hai flow summary, 24 kiểm tra flow condition đúng bảng và một detection cho packet 4.

Trong `result_matches.jsonl`, có sáu dòng từ replay API, mỗi dòng gồm:

- Snapshot gắn đúng packet_id/timestamp/flow_id, flow_context, candidate/header result.
- Bốn flow_checks, chứa condition/status/reason/evidence tương ứng.
- Một rule_result của toàn bộ rule SID100801.

Packet 1–2 có strict established/handshake false; packet 3–5 true; packet 6 null. Client/server endpoints được biết cho flow handshake, còn flow midstream có roles null và direction unknown. Packet 2/5 có header orientation reverse; flow direction vẫn xác định bằng Tracker, không suy từ orientation.

Packet 3 thỏa flow nhưng không có content. Packet 5 có admin nhưng sai chiều flow. Packet 6 có header/content phù hợp nhưng thiếu bằng chứng flow, nên rule_result NOT_EVALUABLE với diagnostics unknown_flow_direction/unknown_flow_established.

Trong `result.jsonl`, cả sáu event valid/process/tracked, parse/decode errors rỗng. Packet 1–5 cùng flow ID, packet 6 có ID khác.

Trong `result_flows.jsonl`, hai summary CLI đều có state ESTABLISHED và close_reason capture_end:

| Flow | packet_count | handshake_observed | capture_midstream |
|---|---|---|---|
| Packet 1–5 | `5` | true | false |
| Packet 6 | `1` | false | true |

TCP state trong summary có thể được suy ra từ ACK/data đầu capture. Giá trị này không thay thế `established_for_packet` của detection; flow midstream không được coi là đã chứng minh established.

Trong `result_detections.jsonl`, chỉ có `(packet_id = 4, sid = 100801)`: TCP/HTTP, msg/rev đúng rule, endpoint `10.0.0.1:12345 → 10.0.0.2:80`, timestamp/flow ID khớp event 4. Matched_info gồm header direct, flow to_server/established với roles và handshake đúng, content admin tại `[5,10)`.

CLI báo `events_evaluated = candidate_rules = 6`, `matches = detections_written = 1`, `rule_not_evaluable = 1`, skip/evaluation error đều `0`. Hai diagnostics unknown flow là thông tin thiếu bằng chứng, không phải lỗi crash. JSONL đọc lại được; inputs và snapshot/context cũ không đổi sau capture/flush.

## Tệp

- `input.rules`: rule flow to_server/established và content admin.
- `input.pcap`: handshake, request, response và flow midstream tự tạo.
- `check_flow_matching.py`: kiểm tra snapshot/adapters/matchers và CLI thật.
- `result.jsonl`: sáu IDS event của CLI.
- `result_flows.jsonl`: hai flow summary của CLI.
- `result_matches.jsonl`: sáu snapshot/flow-context records, 24 flow checks và sáu kết quả cả rule từ API replay.
- `result_detections.jsonl`: một detection của packet 4.
- `console.txt`: output CLI và các kiểm tra PASS/FAIL, UTF-8.
- `README.md`: dữ liệu, cách chạy và giải thích kết quả.
