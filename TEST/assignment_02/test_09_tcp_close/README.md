# Test 09 - TCP Close / Reset

## Mục tiêu

Kiểm tra T09 trong mục 6 Bài tập 2: đóng kết nối bằng FIN/ACK chuyển flow sang `CLOSED`; RST chuyển flow sang `RESET`.

Test gồm hai kết nối riêng để thử cả hai cách đóng. Mỗi flow chỉ được xuất summary một lần.

## Dữ liệu

- File: `input.pcap`.
- Nguồn: fixture tự tạo bằng Scapy, không bắt từ mạng thật.
- Số packet: `11`; Ethernet/IPv4/TCP, không có application payload.
- Client: `10.0.0.1`, MAC `02:00:00:00:00:01`; port `12345` cho phiên FIN, port `12346` cho phiên RST.
- Server: `10.0.0.2:80`, MAC `02:00:00:00:00:02`.
- Client là endpoint A, server là endpoint B; A→B là forward, B→A là backward.
- Mỗi packet có IPv4 header `20` byte, TCP header `20` byte, TCP payload `0` byte; IPv4 total length là `40` byte.

| Packet | Timestamp | Phiên | Chiều | TCP flags | Sequence | Acknowledgment | Ý nghĩa |
|---|---|---|---|---|---|---|---|
| 1 | 1700000000.0 | FIN | A → B | S | 1000 | 0 | Client mở kết nối |
| 2 | 1700000000.1 | FIN | B → A | SA | 2000 | 1001 | Server trả SYN/ACK |
| 3 | 1700000000.2 | FIN | A → B | A | 1001 | 2001 | Hoàn thành handshake |
| 4 | 1700000000.3 | FIN | A → B | FA | 1001 | 2001 | Client gửi FIN/ACK |
| 5 | 1700000000.4 | FIN | B → A | A | 2001 | 1002 | Server xác nhận FIN client |
| 6 | 1700000000.5 | FIN | B → A | FA | 2001 | 1002 | Server gửi FIN/ACK |
| 7 | 1700000000.6 | FIN | A → B | A | 1002 | 2002 | Client xác nhận FIN server |
| 8 | 1700000000.7 | RST | A → B | S | 1000 | 0 | Client mở kết nối khác |
| 9 | 1700000000.8 | RST | B → A | SA | 2000 | 1001 | Server trả SYN/ACK |
| 10 | 1700000000.9 | RST | A → B | A | 1001 | 2001 | Hoàn thành handshake |
| 11 | 1700000001.0 | RST | B → A | RA | 2001 | 1001 | Server reset bằng RST/ACK |

Kết quả mong đợi: packet 1–7 cùng một flow ID, packet 8–11 cùng một flow ID khác; có đúng hai summary, một `CLOSED`/`tcp_fin`, một `RESET`/`tcp_reset`.

## Thực hiện

Chạy tại thư mục gốc project trong PowerShell, dùng Python của virtual environment:

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding

$t09Console = & .\.venv\Scripts\python.exe -X utf8 main.py `
  --pcap TEST\assignment_02\test_09_tcp_close\input.pcap `
  --output TEST\assignment_02\test_09_tcp_close\result.jsonl `
  --flow-output TEST\assignment_02\test_09_tcp_close\result_flows.jsonl `
  2>&1
$t09ExitCode = $LASTEXITCODE
$t09Console | Set-Content -Encoding UTF8 TEST\assignment_02\test_09_tcp_close\console.txt
$t09Console
if ($t09ExitCode -ne 0) { throw "T09 execution failed: exit code $t09ExitCode" }
```

## Kết quả

**PASS T09.** Chương trình xử lý đủ `11` packet, trả mã thoát `0`; xuất đúng hai flow summary với trạng thái `CLOSED` và `RESET`.

Trong `result.jsonl`:

- Dòng 1–7 dùng cùng `flow_id` của phiên FIN; direction là `forward`, `backward`, `forward`, `forward`, `backward`, `backward`, `forward`.
- Dòng 8–11 dùng cùng `flow_id` của phiên RST; direction là `forward`, `backward`, `forward`, `backward`.
- Hai phiên có flow ID khác nhau vì port client khác nhau.
- Cả 11 event có `parse_errors = []`, `decode_errors = []`, `preprocess_status = valid`, `processing_action = process`, `flow_tracking_status = tracked`.
- `application.protocol = UNKNOWN`, `decode_status = not_processed` vì không có dữ liệu ứng dụng; port `80` không tự làm packet trở thành HTTP.

Trong `result_flows.jsonl`:

| Field | Dòng 1: phiên FIN | Dòng 2: phiên RST |
|---|---|---|
| `endpoint_a` | `10.0.0.1:12345` | `10.0.0.1:12346` |
| `endpoint_b` | `10.0.0.2:80` | `10.0.0.2:80` |
| `state` | `CLOSED` | `RESET` |
| `close_reason` | `tcp_fin` | `tcp_reset` |
| `packet_count` / `byte_count` | `7` / `280` | `4` / `160` |
| `forward` | `4` packet, `160` byte | `2` packet, `80` byte |
| `backward` | `3` packet, `120` byte | `2` packet, `80` byte |
| `tcp_flags.syn_count` | `2` | `2` |
| `tcp_flags.ack_count` | `6` | `3` |
| `tcp_flags.fin_count` | `2` | `0` |
| `tcp_flags.rst_count` | `0` | `1` |
| `handshake_observed` | `true` | `true` |
| `capture_midstream` | `false` | `false` |
| `duration` | Khoảng `0.6` giây | Khoảng `0.3` giây |
| `exported_at` | `1700000000.6`, packet 7 | `1700000001.0`, packet 11 |


## Tệp

- `input.pcap`: 11 packet đầu vào cho hai cách đóng/reset TCP.
- `result.jsonl`: 11 IDS event, dùng đối chiếu flags, flow ID và direction.
- `result_flows.jsonl`: hai summary với trạng thái CLOSED/RESET.
- `console.txt`: stdout/stderr khi chạy chương trình, lưu UTF-8.
- `README.md`: dữ liệu đầu vào, cách chạy và giải thích kết quả test.
