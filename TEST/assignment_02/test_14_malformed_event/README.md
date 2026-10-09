# Test 14 - Malformed / Unsupported Event

## Mục tiêu

Kiểm tra T14 trong mục 6 Bài tập 2: event invalid/unsupported không làm chương trình crash; status/reason phù hợp và event hợp lệ phía sau vẫn được xử lý.

Test gồm PCAP cho protocol không hỗ trợ và script tạo event sai field để kiểm tra trực tiếp Preprocessor, Flow Tracker và JSONLWriter.

## Dữ liệu

### Phần PCAP

- File: `input.pcap`.
- Nguồn: fixture tự tạo bằng Scapy, không bắt từ mạng thật.
- Số packet: `2`; ARP request rồi IPv4/TCP SYN hợp lệ.
- Client: `10.0.0.1`, MAC `02:00:00:00:00:01`.
- Server: `10.0.0.2`, MAC `02:00:00:00:00:02`.

| Packet | Timestamp | Nội dung | Chi tiết |
|---|---|---|---|
| 1 | 1700000000 | ARP request | Who has `10.0.0.2`? Tell `10.0.0.1` |
| 2 | 1700000001 | TCP SYN | `10.0.0.1:12345` → `10.0.0.2:80`, seq `1000`, ack `0` |

ARP packet dùng Ethernet destination `ff:ff:ff:ff:ff:ff`, opcode `1`, sender hardware/IP là client, target hardware `00:00:00:00:00:00`, target IP là server. ARP nằm ngoài phạm vi IPv4/TCP/UDP của Parser hiện tại; packet ARP không bị làm hỏng trên wire.

TCP packet có IPv4 header `20` byte, TCP header `20` byte, payload `0` byte, IPv4 total length `40` byte. Chỉ có SYN để chứng minh packet hợp lệ sau ARP vẫn được xử lý; không có handshake hoàn chỉnh.

### Phần event trực tiếp

Script tạo sáu IDSEvent, mỗi event sai theo sau bởi một event hợp lệ:

| Dòng `direct_result.jsonl` | Trường hợp | Đầu vào | Kết quả mong đợi |
|---|---|---|---|
| 1 | IP sai | `network.src_ip = "abc"` | invalid/skip, reason nhắc `network.src_ip` |
| 2 | Hợp lệ sau IP sai | IPv4/TCP SYN | valid/process, tracked |
| 3 | Port sai kiểu | `transport.dst_port = "80"` (string) | invalid/skip, reason nhắc `transport.dst_port` |
| 4 | Hợp lệ sau port sai | IPv4/TCP SYN | valid/process, tracked |
| 5 | HTTP body sai kiểu | `application.fields.body = b"Hello \xff"` (bytes) | invalid/skip, reason nhắc `application.fields.body`; JSONL xuất an toàn |
| 6 | Hợp lệ sau body sai | IPv4/TCP SYN | valid/process, tracked |

Các event trực tiếp dùng timestamp `101` đến `106`, IPv4 source/destination `10.0.0.1`/`10.0.0.2`, total length `40`, TCP source/destination port `12345`/`80`, flags `S`, seq `1000`, ack `0`, payload length `0`, trừ field cố tình làm sai.

Event 5 có protocol HTTP, message type request, method GET, path `/`; body đáng lẽ là string nhưng được đặt thành bytes. Đây là event giả lập để thử validation/serialization, không phải HTTP packet hoàn chỉnh. Khác T04: T04 thử byte UTF-8 lỗi trong payload thật, còn ở đây lỗi chính là kiểu dữ liệu field trong event.

Chính sách mặc định là skip invalid/unsupported khỏi xử lý tiếp, nhưng vẫn ghi event vào JSONL. Skip không có nghĩa bỏ mất dòng log hoặc dừng chương trình.

## Thực hiện

Chạy tại thư mục gốc project trong PowerShell, dùng Python của virtual environment:

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding

& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_02\test_14_malformed_event\check_malformed_event.py
if ($LASTEXITCODE -ne 0) { throw "T14 failed" }
```

Script tự chạy `main.py` với PCAP, kiểm tra event/flow output, rồi chạy sáu event trực tiếp qua `preprocess_event()`, `FlowTracker.track()` và `JSONLWriter`. Script đọc lại JSONL để xác nhận log hợp lệ và giữ đủ event. Output CLI và kết quả kiểm tra lưu chung trong `console.txt` bằng UTF-8; thành công trả mã `0`, thất bại trả mã `1`.

## Kết quả

**PASS T14.** CLI xử lý đủ hai packet; script xử lý và xuất đủ sáu event trực tiếp. CLI và script trả mã thoát `0`.

Trong `result.jsonl`:

- Dòng 1: ARP được biểu diễn network/transport protocol UNKNOWN; `preprocess_status = partial`, `processing_action = skip`, reason có `unsupported_protocol`.
- Flow Tracker ghi `flow_tracking_status = skipped`, `flow_id = null` cho ARP.
- Dòng 2: SYN hợp lệ vẫn có `preprocess_status = valid`, `processing_action = process`, `flow_tracking_status = tracked` và flow ID.

`result_flows.jsonl` có một summary của SYN: `packet_count = 1`, `byte_count = 40`, state `HANDSHAKE`, `close_reason = capture_end`. ARP không tạo flow và không bị cộng vào thống kê TCP.

Trong `direct_result.jsonl`:

- Dòng 1, 3, 5: `preprocess_status = invalid`, `processing_action = skip`, có reason đúng field lỗi; tracking skipped, flow ID null.
- Dòng 2, 4, 6: `preprocess_status = valid`, `processing_action = process`, reason null, tracking tracked. Mỗi lỗi không ngăn event hợp lệ phía sau được lưu.
- Các field gốc không bị Preprocessor sửa. Dữ liệu body bytes ở dòng 5 được chuyển khi xuất JSON thành:

```json
{
  "type": "bytes",
  "encoding": "base64",
  "value": "SGVsbG8g/w=="
}
```

Field `serialization_errors` ghi nhận việc chuyển binary sang Base64; JSONL vẫn đọc được và dòng 6 vẫn tồn tại. Base64 ở đây là cách lưu an toàn dữ liệu lỗi, không phải kết quả SMTP MIME decoding.

Tracker riêng của phần trực tiếp chỉ đếm ba event hợp lệ (`3` packet, `120` byte); các event invalid không tạo hoặc cập nhật flow. Summary trực tiếp được kiểm tra trong script, không ghi thêm vào `result_flows.jsonl` của CLI. ID trực tiếp không so với ID của lần chạy CLI.

Kết quả cuối console:

```text
PASS T14: unsupported/invalid events retained; processing continued; statuses and reasons correct.
```

## Tệp

- `input.pcap`: ARP request rồi TCP SYN hợp lệ.
- `result.jsonl`: hai event của lần chạy CLI.
- `result_flows.jsonl`: một summary của TCP SYN.
- `direct_result.jsonl`: sáu event trực tiếp, gồm ba invalid và ba valid phía sau.
- `check_malformed_event.py`: script tái hiện và tự kiểm tra hai phần T14.
- `console.txt`: output CLI và kết quả kiểm tra trực tiếp, lưu UTF-8.
- `README.md`: dữ liệu đầu vào, cách chạy và giải thích kết quả test.
