# Test 11 - Concurrent Flows

## Mục tiêu

Kiểm tra T11 trong mục 6 Bài tập 2: ít nhất hai flow có endpoint/port khác nhau không bị gộp nhầm.

Test dùng hai kết nối TCP cùng IP client/server và port server, chỉ khác port client. Packet hai kết nối xen kẽ nhau để kiểm tra theo dõi đồng thời.

## Dữ liệu

- File: `input.pcap`.
- Nguồn: fixture tự tạo bằng Scapy, không bắt từ mạng thật.
- Số packet: `10`; Ethernet/IPv4/TCP, mỗi flow có handshake, HTTP GET và HTTP response.
- Client: `10.0.0.1`, MAC `02:00:00:00:00:01`.
- Server: `10.0.0.2:80`, MAC `02:00:00:00:00:02`.
- Flow 1: client port `12345`; GET `/one`, response body `One`.
- Flow 2: client port `12346`; GET `/second`, response body `Second`.
- Trong mỗi flow, client là endpoint A; client→server là forward, server→client là backward.

| Packet | Timestamp | Flow | Chiều | Nội dung | Flags | Sequence | Acknowledgment | TCP payload | IPv4 total length |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 1700000000.0 | 1 | A → B | SYN | S | 1000 | 0 | 0 byte | 40 byte |
| 2 | 1700000000.1 | 2 | A → B | SYN | S | 1000 | 0 | 0 byte | 40 byte |
| 3 | 1700000000.2 | 1 | B → A | SYN/ACK | SA | 2000 | 1001 | 0 byte | 40 byte |
| 4 | 1700000000.3 | 2 | B → A | SYN/ACK | SA | 2000 | 1001 | 0 byte | 40 byte |
| 5 | 1700000000.4 | 1 | A → B | ACK | A | 1001 | 2001 | 0 byte | 40 byte |
| 6 | 1700000000.5 | 2 | A → B | ACK | A | 1001 | 2001 | 0 byte | 40 byte |
| 7 | 1700000000.6 | 1 | A → B | GET /one | PA | 1001 | 2001 | 37 byte | 77 byte |
| 8 | 1700000000.7 | 2 | A → B | GET /second | PA | 1001 | 2001 | 40 byte | 80 byte |
| 9 | 1700000000.8 | 1 | B → A | Response One | PA | 2001 | 1038 | 82 byte | 122 byte |
| 10 | 1700000000.9 | 2 | B → A | Response Second | PA | 2001 | 1041 | 85 byte | 125 byte |

Hai flow dùng cùng sequence mở đầu nhưng khác port client, nên vẫn là hai kết nối riêng. ACK response xác nhận request: `1001 + 37 = 1038` cho flow 1, `1001 + 40 = 1041` cho flow 2.

HTTP request của flow 1:

```http
GET /one HTTP/1.1
Host: ids.test

```

Flow 2 đổi đường dẫn thành `/second`, giữ header `Host: ids.test`.

HTTP response của flow 1:

```http
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Content-Length: 3

One
```

Flow 2 có cùng status/header Content-Type, đổi `Content-Length` thành `6` và body thành `Second`.


## Thực hiện

Chạy tại thư mục gốc project trong PowerShell, dùng Python của virtual environment:

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding

$t11Console = & .\.venv\Scripts\python.exe -X utf8 main.py `
  --pcap TEST\assignment_02\test_11_concurrent_flows\input.pcap `
  --output TEST\assignment_02\test_11_concurrent_flows\result.jsonl `
  --flow-output TEST\assignment_02\test_11_concurrent_flows\result_flows.jsonl `
  2>&1
$t11ExitCode = $LASTEXITCODE
$t11Console | Set-Content -Encoding UTF8 TEST\assignment_02\test_11_concurrent_flows\console.txt
$t11Console
if ($t11ExitCode -ne 0) { throw "T11 execution failed: exit code $t11ExitCode" }
```

## Kết quả

**PASS T11.** Chương trình xử lý đủ `10` packet, trả mã thoát `0`; hai flow xen kẽ không bị gộp nhầm.

Trong `result.jsonl`:

- Dòng 1, 3, 5, 7, 9 dùng cùng flow ID của client port `12345`.
- Dòng 2, 4, 6, 8, 10 dùng cùng flow ID khác của client port `12346`.
- Direction trong từng flow là `forward`, `backward`, `forward`, `forward`, `backward`.
- Dòng 7–8 là HTTP GET đúng đường dẫn; dòng 9–10 có decoded text `One`/`Second`, status `ok`.
- Sáu event handshake có `application.protocol = UNKNOWN`, `decode_status = not_processed` vì không có dữ liệu ứng dụng.
- Cả mười event có `parse_errors = []`, `decode_errors = []`, `preprocess_status = valid`, `processing_action = process`, `flow_tracking_status = tracked`.

Trong `result_flows.jsonl`, có đúng hai summary với ID khác nhau:

| Field | Flow 1 | Flow 2 |
|---|---|---|
| `endpoint_a` | `10.0.0.1:12345` | `10.0.0.1:12346` |
| `endpoint_b` | `10.0.0.2:80` | `10.0.0.2:80` |
| `protocol` / `application_protocol` | TCP / HTTP | TCP / HTTP |
| `packet_count` / `byte_count` | `5` / `319` | `5` / `325` |
| `forward` | `3` packet, `157` byte | `3` packet, `160` byte |
| `backward` | `2` packet, `162` byte | `2` packet, `165` byte |
| `state` | `ESTABLISHED` | `ESTABLISHED` |
| `handshake_observed` / `capture_midstream` | `true` / `false` | `true` / `false` |
| SYN / ACK / FIN / RST counters | `2` / `4` / `0` / `0` | `2` / `4` / `0` / `0` |
| `duration` | Khoảng `0.8` giây | Khoảng `0.8` giây |
| `close_reason` | `capture_end` | `capture_end` |

Byte count tính theo IPv4 length, không gồm Ethernet header:

- Flow 1: `40 + 40 + 40 + 77 + 122 = 319` byte.
- Flow 2: `40 + 40 + 40 + 80 + 125 = 325` byte.

Flow ID có thể thay đổi khi chạy lại; kiểm tra packet được phân nhóm đúng trong cùng lần chạy. `capture_end` là lý do xuất summary, không có nghĩa TCP đã đóng.

## Tệp

- `input.pcap`: mười packet xen kẽ của hai kết nối TCP.
- `result.jsonl`: mười IDS event để đối chiếu port, flow ID và direction.
- `result_flows.jsonl`: hai summary với thống kê riêng của từng flow.
- `console.txt`: stdout/stderr khi chạy chương trình, lưu UTF-8.
- `README.md`: dữ liệu đầu vào, cách chạy và giải thích kết quả test.
