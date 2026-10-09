# Test 08 - Bidirectional Flow

## Mục tiêu

Kiểm tra T08 trong mục 6 Bài tập 2: packet A→B và B→A có 5-tuple đảo chiều thuộc cùng `flow_id`, được gán đúng direction.

Ví dụ là client gửi HTTP GET và server trả HTTP response trên cùng kết nối TCP.

## Dữ liệu

- File: `input.pcap`.
- Nguồn: fixture tự tạo bằng Scapy, không bắt từ mạng thật.
- Số packet: `5`; Ethernet/IPv4/TCP, gồm bắt tay TCP, HTTP GET và HTTP response.
- Endpoint A (client): `10.0.0.1:12345`, MAC `02:00:00:00:00:01`.
- Endpoint B (server): `10.0.0.2:80`, MAC `02:00:00:00:00:02`.
- A là bên gửi packet đầu tiên. A→B là `forward`; B→A là `backward`.

5-tuple gồm IP nguồn, port nguồn, IP đích, port đích và transport protocol:

```text
Forward:  (10.0.0.1, 12345, 10.0.0.2, 80, TCP)
Backward: (10.0.0.2, 80, 10.0.0.1, 12345, TCP)
```

Hai tuple đảo chiều vẫn thuộc một flow.

| Packet | Timestamp | Chiều | Nội dung | TCP flags | Sequence | Acknowledgment | TCP payload | IPv4 total length |
|---|---|---|---|---|---|---|---|---|
| 1 | 1700000000.0 | A → B | SYN | S | 1000 | 0 | 0 byte | 40 byte |
| 2 | 1700000000.1 | B → A | SYN/ACK | SA | 2000 | 1001 | 0 byte | 40 byte |
| 3 | 1700000000.2 | A → B | ACK | A | 1001 | 2001 | 0 byte | 40 byte |
| 4 | 1700000000.3 | A → B | HTTP GET | PA | 1001 | 2001 | 39 byte | 79 byte |
| 5 | 1700000000.4 | B → A | HTTP response | PA | 2001 | 1040 | 84 byte | 124 byte |

Packet 4 chứa:

```http
GET /hello HTTP/1.1
Host: ids.test

```

Packet 5 chứa:

```http
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Content-Length: 5

Hello
```

Kết quả mong đợi: cả năm event có cùng `flow_id`, direction lần lượt `forward`, `backward`, `forward`, `forward`, `backward`; một summary ghi `3` packet forward và `2` packet backward.

## Thực hiện

Chạy tại thư mục gốc project trong PowerShell, dùng Python của virtual environment:

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding

$t08Console = & .\.venv\Scripts\python.exe -X utf8 main.py `
  --pcap TEST\assignment_02\test_08_bidirectional_flow\input.pcap `
  --output TEST\assignment_02\test_08_bidirectional_flow\result.jsonl `
  --flow-output TEST\assignment_02\test_08_bidirectional_flow\result_flows.jsonl `
  2>&1
$t08ExitCode = $LASTEXITCODE
$t08Console | Set-Content -Encoding UTF8 TEST\assignment_02\test_08_bidirectional_flow\console.txt
$t08Console
if ($t08ExitCode -ne 0) { throw "T08 execution failed: exit code $t08ExitCode" }
```

## Kết quả

**PASS T08.** Chương trình xử lý đủ `5` packet, trả mã thoát `0`; packet hai chiều được gom vào một flow và gán đúng direction.

Trong `result.jsonl`:

- Dòng 1–3: bắt tay TCP; `application.protocol = UNKNOWN`, `decode_status = not_processed` vì không có dữ liệu ứng dụng.
- Dòng 4: HTTP request `GET /hello`, direction `forward`.
- Dòng 5: HTTP response `200 OK`, body `Hello`, direction `backward`. `decoded.http.text.value = Hello`, status `ok`.
- Cả năm event có cùng `flow_id`; direction là `forward`, `backward`, `forward`, `forward`, `backward`.
- Cả năm event có `parse_errors = []`, `decode_errors = []`, `preprocess_status = valid`, `processing_action = process`, `flow_tracking_status = tracked`.

Trong `result_flows.jsonl`, có đúng một summary:

| Field | Kết quả | Giải thích |
|---|---|---|
| `endpoint_a` | `10.0.0.1:12345` | Client gửi packet đầu tiên |
| `endpoint_b` | `10.0.0.2:80` | Server |
| `flow_id` | Giống ID của cả năm event | Hai chiều thuộc cùng flow |
| `protocol` / `application_protocol` | `TCP` / `HTTP` | Có dữ liệu HTTP sau handshake |
| `packet_count` / `byte_count` | `5` / `323` | Tổng độ dài IPv4: `40 + 40 + 40 + 79 + 124` |
| `forward` | `3` packet, `159` byte | SYN + ACK + GET: `40 + 40 + 79` |
| `backward` | `2` packet, `164` byte | SYN/ACK + response: `40 + 124` |
| `state` | `ESTABLISHED` | Đã hoàn thành bắt tay, chưa thấy đóng TCP |
| `handshake_observed` / `capture_midstream` | `true` / `false` | Bắt từ SYN mở đầu |
| `tcp_flags.syn_count` / `ack_count` | `2` / `4` | SYN/ACK được tính vào cả hai bộ đếm |
| `tcp_flags.fin_count` / `rst_count` | `0` / `0` | Không có FIN/RST |
| `duration` | Khoảng `0.4` giây | JSON ghi `0.40000009536743164` do biểu diễn số thực |
| `close_reason` | `capture_end` | Xuất summary khi đọc hết PCAP |

Byte counters không gồm Ethernet header. Flow ID có thể thay đổi khi chạy lại; chỉ cần các ID giống nhau trong cùng lần chạy. `capture_end` là lý do xuất summary, không có nghĩa TCP đã đóng.

## Tệp

- `input.pcap`: năm packet đầu vào, gồm trao đổi HTTP hai chiều.
- `result.jsonl`: năm IDS event để đối chiếu flow ID và direction.
- `result_flows.jsonl`: một summary tổng hợp flow hai chiều.
- `console.txt`: stdout/stderr khi chạy chương trình, lưu UTF-8.
- `README.md`: dữ liệu đầu vào, cách chạy và giải thích kết quả test.
