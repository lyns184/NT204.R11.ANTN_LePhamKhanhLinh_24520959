# Test 13 - Flow Statistics

## Mục tiêu

Kiểm tra T13 trong mục 6 Bài tập 2: nhiều packet hai chiều có packet/byte/flag counters và duration đúng.

Test có một flow HTTP đóng bằng FIN và một flow đóng bằng RST, để đối chiếu đủ SYN, ACK, FIN và RST counters.

## Dữ liệu

- File: `input.pcap`.
- Nguồn: fixture tự tạo bằng Scapy, không bắt từ mạng thật.
- Số packet: `13`; Ethernet/IPv4/TCP.
- Client: `10.0.0.1`, MAC `02:00:00:00:00:01`.
- Server: `10.0.0.2:80`, MAC `02:00:00:00:00:02`.
- Flow 1: client port `12345`, gồm handshake, GET `/one`, response body `One`, đóng FIN/ACK.
- Flow 2: client port `12346`, gồm handshake và RST/ACK từ server; không có application payload.
- Client là endpoint A, server là endpoint B; A→B là forward, B→A là backward.

| Packet | Timestamp | Flow | Chiều | Nội dung | Flags | Sequence | Acknowledgment | TCP payload | IPv4 total length |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 1700000000 | 1 | A → B | SYN | S | 1000 | 0 | 0 byte | 40 byte |
| 2 | 1700000001 | 1 | B → A | SYN/ACK | SA | 2000 | 1001 | 0 byte | 40 byte |
| 3 | 1700000002 | 1 | A → B | ACK | A | 1001 | 2001 | 0 byte | 40 byte |
| 4 | 1700000003 | 1 | A → B | GET /one | PA | 1001 | 2001 | 37 byte | 77 byte |
| 5 | 1700000004 | 1 | B → A | Response One | PA | 2001 | 1038 | 82 byte | 122 byte |
| 6 | 1700000005 | 1 | A → B | FIN/ACK | FA | 1038 | 2083 | 0 byte | 40 byte |
| 7 | 1700000006 | 1 | B → A | ACK FIN client | A | 2083 | 1039 | 0 byte | 40 byte |
| 8 | 1700000007 | 1 | B → A | FIN/ACK | FA | 2083 | 1039 | 0 byte | 40 byte |
| 9 | 1700000008 | 1 | A → B | ACK FIN server | A | 1039 | 2084 | 0 byte | 40 byte |
| 10 | 1700000009 | 2 | A → B | SYN | S | 1000 | 0 | 0 byte | 40 byte |
| 11 | 1700000010 | 2 | B → A | SYN/ACK | SA | 2000 | 1001 | 0 byte | 40 byte |
| 12 | 1700000011 | 2 | A → B | ACK | A | 1001 | 2001 | 0 byte | 40 byte |
| 13 | 1700000012 | 2 | B → A | RST/ACK | RA | 2001 | 1001 | 0 byte | 40 byte |

HTTP request ở packet 4:

```http
GET /one HTTP/1.1
Host: ids.test

```

HTTP response ở packet 5:

```http
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Content-Length: 3

One
```
 IPv4/TCP headers mỗi loại dài `20` byte.

Kết quả mong đợi tính trực tiếp từ bảng packet:

| Thống kê | Flow 1 | Flow 2 |
|---|---|---|
| Tổng packet | `9` | `4` |
| Tổng byte IPv4 | `7 × 40 + 77 + 122 = 479` | `4 × 40 = 160` |
| Forward packet / byte | `5` / `4 × 40 + 77 = 237` | `2` / `80` |
| Backward packet / byte | `4` / `3 × 40 + 122 = 242` | `2` / `80` |
| SYN counter | `2` (packet 1, 2) | `2` (packet 10, 11) |
| ACK counter | `8` (packet 2–9) | `3` (packet 11–13) |
| FIN counter | `2` (packet 6, 8) | `0` |
| RST counter | `0` | `1` (packet 13) |
| Duration | `1700000008 - 1700000000 = 8` giây | `1700000012 - 1700000009 = 3` giây |

Byte count gồm IPv4/TCP header và payload, không gồm Ethernet header; không chỉ đếm dữ liệu HTTP. Packet có nhiều cờ được tính vào từng counter tương ứng: SYN/ACK tăng cả SYN và ACK, FIN/ACK tăng FIN và ACK, RST/ACK tăng RST và ACK.

## Thực hiện

Chạy tại thư mục gốc project trong PowerShell, dùng Python của virtual environment:

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding

$t13Console = & .\.venv\Scripts\python.exe -X utf8 main.py `
  --pcap TEST\assignment_02\test_13_statistics\input.pcap `
  --output TEST\assignment_02\test_13_statistics\result.jsonl `
  --flow-output TEST\assignment_02\test_13_statistics\result_flows.jsonl `
  2>&1
$t13ExitCode = $LASTEXITCODE
$t13Console | Set-Content -Encoding UTF8 TEST\assignment_02\test_13_statistics\console.txt
$t13Console
if ($t13ExitCode -ne 0) { throw "T13 execution failed: exit code $t13ExitCode" }
```

Đối chiếu summary với bảng thống kê mong đợi ở phần Dữ liệu; mã thoát `0` riêng lẻ chưa đủ kết luận counters đúng.

## Kết quả

**PASS T13.** Chương trình xử lý đủ `13` packet, trả mã thoát `0`. Đã đọc lại PCAP và đối chiếu tất cả counters, start/last timestamp và duration với hai summary; các giá trị đều khớp bảng mong đợi.

Trong `result.jsonl`:

- Dòng 1–9 cùng flow ID của port `12345`; dòng 10–13 cùng flow ID khác của port `12346`.
- Dòng 4–5 nhận diện HTTP; response có decoded text `One`, status `ok`. Các packet không chứa dữ liệu ứng dụng có protocol UNKNOWN, decode status not_processed.
- Cả 13 event có `parse_errors = []`, `decode_errors = []`, `preprocess_status = valid`, `processing_action = process`, `flow_tracking_status = tracked`.

Trong `result_flows.jsonl`:

- Dòng 1: flow HTTP `CLOSED`, `close_reason = tcp_fin`, `packet_count = 9`, `byte_count = 479`, `duration = 8.0`.
- Dòng 2: flow reset `RESET`, `close_reason = tcp_reset`, `packet_count = 4`, `byte_count = 160`, `duration = 3.0`.
- Forward/backward counts và SYN/ACK/FIN/RST counters đúng như bảng Dữ liệu; tổng hai chiều bằng tổng flow.
- `unknown_byte_count = 0` ở cả tổng và từng chiều vì mọi packet có IPv4 length xác định.
- Cả hai flow có `handshake_observed = true`, `capture_midstream = false`; flow 2 có `application_protocol = UNKNOWN` vì không có application payload.

## Tệp

- `input.pcap`: 13 packet của hai flow, dùng làm dữ liệu đối chiếu thống kê.
- `result.jsonl`: 13 IDS event, gồm độ dài, timestamp và TCP flags từng packet.
- `result_flows.jsonl`: hai summary chứa counters và duration.
- `console.txt`: stdout/stderr khi chạy chương trình, lưu UTF-8.
- `README.md`: dữ liệu đầu vào, phép tính thống kê, cách chạy và kết quả test.
