# Test 10 - UDP Query / Response

## Mục tiêu

Kiểm tra T10 trong mục 6 Bài tập 2: DNS UDP hai chiều thuộc một flow, packet/byte count đúng.

## Dữ liệu

- File: `input.pcap`.
- Nguồn: fixture tự tạo bằng Scapy, không bắt từ mạng thật.
- Số packet: `2`; Ethernet/IPv4/UDP/DNS, gồm một query và một response.
- Endpoint A (client): `10.0.0.1:53000`, MAC `02:00:00:00:00:01`.
- Endpoint B (DNS server): `10.0.0.2:53`, MAC `02:00:00:00:00:02`.
- Query đi A→B, response đi B→A; IP, port và MAC được đảo chiều. UDP không có handshake TCP.

| Packet | Timestamp | Chiều | Nội dung | DNS payload | UDP length | IPv4 total length |
|---|---|---|---|---|---|---|
| 1 | 1700000000.0 | A → B | Query A cho `example.com.` | 29 byte | 37 byte | 57 byte |
| 2 | 1700000000.1 | B → A | Response: `example.com.` → `192.0.2.1` | 56 byte | 64 byte | 84 byte |


Các field DNS trong packet:

| Field | Query | Response |
|---|---|---|
| Transaction ID | `100` | `100` |
| QR | `0` (query) | `1` (response) |
| Opcode / response code | `0` / `0` | `0` / `0` |
| RD / RA | `1` / `0` | `1` / `1` |
| Question count | `1` | `1` |
| Answer count | `0` | `1` |
| Question name | `example.com.` | `example.com.` |
| Question type / class | A (`1`) / IN (`1`) | A (`1`) / IN (`1`) |
| Answer name / type | Không có | `example.com.` / A (`1`) |
| Answer TTL / data | Không có | `60` giây / `192.0.2.1` |

RD yêu cầu recursion, RA cho biết server hỗ trợ recursion. R

Kết quả mong đợi: hai event dùng cùng `flow_id`, query là `forward`, response là `backward`; một UDP flow có `packet_count = 2`, `byte_count = 57 + 84 = 141`.

## Thực hiện

Chạy tại thư mục gốc project trong PowerShell, dùng Python của virtual environment:

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding

$t10Console = & .\.venv\Scripts\python.exe -X utf8 main.py `
  --pcap TEST\assignment_02\test_10_udp_query_response\input.pcap `
  --output TEST\assignment_02\test_10_udp_query_response\result.jsonl `
  --flow-output TEST\assignment_02\test_10_udp_query_response\result_flows.jsonl `
  2>&1
$t10ExitCode = $LASTEXITCODE
$t10Console | Set-Content -Encoding UTF8 TEST\assignment_02\test_10_udp_query_response\console.txt
$t10Console
if ($t10ExitCode -ne 0) { throw "T10 execution failed: exit code $t10ExitCode" }
```

## Kết quả

**PASS T10.** Chương trình xử lý đủ `2` packet, trả mã thoát `0`; hai chiều được gom vào một UDP flow và packet/byte count đúng.

Trong `result.jsonl`:

- Dòng 1: `transport.protocol = UDP`, `application.protocol = DNS`, `message_type = query`, `transaction_id = 100`, direction `forward`; một question cho `example.com`, type A, answers rỗng.
- Dòng 2: DNS response cùng transaction ID, direction `backward`; answer là `example.com`, type A, TTL `60`, data `192.0.2.1`.
- Parser bỏ dấu chấm cuối tên DNS; `normalized` giữ domain/name là `example.com`.
- Hai event có cùng `flow_id`, `parse_errors = []`, `decode_errors = []`, `preprocess_status = valid`, `processing_action = process`, `flow_tracking_status = tracked`.
- `decode_status = not_processed` vì DNS không có nội dung cần Decoder giải mã trong test này.

Trong `result_flows.jsonl`, có đúng một summary:

| Field | Kết quả | Giải thích |
|---|---|---|
| `endpoint_a` / `endpoint_b` | Client / server ở phần Dữ liệu | Hai đầu flow UDP |
| `flow_id` | Giống ID của cả hai event | Query và response thuộc cùng flow |
| `protocol` / `application_protocol` | `UDP` / `DNS` | DNS chạy qua UDP |
| `packet_count` / `byte_count` | `2` / `141` | Tổng IPv4 length: `57 + 84` |
| `forward` | `1` packet, `57` byte | Query |
| `backward` | `1` packet, `84` byte | Response |
| `unknown_byte_count` | `0` | Cả hai packet có độ dài xác định |
| `duration` | Khoảng `0.1` giây | JSON ghi `0.09999990463256836` do biểu diễn số thực |
| `close_reason` | `capture_end` | Xuất summary khi đọc hết PCAP |
| `state`, `tcp_flags`, `handshake_observed`, `capture_midstream` | `null` | Đây là metadata TCP, không áp dụng cho UDP |

## Tệp

- `input.pcap`: hai packet DNS query/response qua UDP.
- `result.jsonl`: hai IDS event để đối chiếu DNS fields, flow ID và direction.
- `result_flows.jsonl`: một flow summary, gồm packet/byte count hai chiều.
- `console.txt`: stdout/stderr khi chạy chương trình, lưu UTF-8.
- `README.md`: dữ liệu đầu vào, cách chạy và giải thích kết quả test.
