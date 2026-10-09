# Test 07 - TCP Three-way Handshake

## Mục tiêu

Kiểm tra T07 trong mục 6 Bài tập 2: SYN → SYN/ACK → ACK thuộc một flow, trạng thái sau bắt tay là `ESTABLISHED`.

## Dữ liệu

- File: `input.pcap`.
- Nguồn: File từ `TEST/assignment_01/test_01_tcp_handshake/input.pcap`
- Số packet: `3`; Ethernet/IPv4/TCP, không có application payload.
- Client (endpoint A): `172.16.16.128:2826`, MAC `00:21:6a:5b:7d:4a`.
- Server (endpoint B): `212.58.226.142:80`, MAC `00:05:5d:21:99:4c`.

| Packet | Timestamp | Chiều | TCP flags | Sequence | Acknowledgment | TCP header length | TCP payload | IPv4 total length |
|---|---|---|---|---|---|---|---|---|
| 1 | 1262893114.341715 | Client → Server | SYN (`S`) | 3691127924 | 0 | 32 byte | 0 byte | 52 byte |
| 2 | 1262893114.474342 | Server → Client | SYN/ACK (`SA`) | 233779340 | 3691127925 | 32 byte | 0 byte | 52 byte |
| 3 | 1262893114.474483 | Client → Server | ACK (`A`) | 3691127925 | 233779341 | 20 byte | 0 byte | 40 byte |

Packet 2 xác nhận SYN client bằng ACK `3691127924 + 1`. Packet 3 xác nhận SYN server bằng ACK `233779340 + 1`; sequence phía client cũng tăng một sau SYN. SYN chiếm một sequence number dù không có payload.



Kết quả mong đợi: cả ba event có cùng `flow_id`; một flow summary có `state = ESTABLISHED`, `handshake_observed = true`, `capture_midstream = false`.

## Thực hiện

Chạy tại thư mục gốc project trong PowerShell, dùng Python của virtual environment:

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding

$t07Console = & .\.venv\Scripts\python.exe -X utf8 main.py `
  --pcap TEST\assignment_02\test_07_tcp_handshake\input.pcap `
  --output TEST\assignment_02\test_07_tcp_handshake\result.jsonl `
  --flow-output TEST\assignment_02\test_07_tcp_handshake\result_flows.jsonl `
  2>&1
$t07ExitCode = $LASTEXITCODE
$t07Console | Set-Content -Encoding UTF8 TEST\assignment_02\test_07_tcp_handshake\console.txt
$t07Console
if ($t07ExitCode -ne 0) { throw "T07 execution failed: exit code $t07ExitCode" }
```


## Kết quả

**PASS T07.** Chương trình xử lý đủ `3` packet, trả mã thoát `0` và xuất một flow có trạng thái `ESTABLISHED`.

Trong `result.jsonl`:

- Dòng 1–3 tương ứng SYN, SYN/ACK, ACK; IP, port, sequence và acknowledgment khớp PCAP.
- Cả ba event có cùng `flow_id`; direction lần lượt là `forward`, `backward`, `forward`.
- `application.protocol = UNKNOWN`, `decode_status = not_processed` vì không có dữ liệu ứng dụng. Port `80` không đủ để kết luận là HTTP.
- Cả ba event có `parse_errors = []`, `decode_errors = []`, `preprocess_status = valid`, `processing_action = process`, `flow_tracking_status = tracked`.

Trong `result_flows.jsonl`, có đúng một dòng summary:

| Field | Kết quả | Ý nghĩa |
|---|---|---|
| `protocol` | `TCP` | Theo dõi kết nối TCP |
| `endpoint_a` / `endpoint_b` | Client / server ở phần Dữ liệu | Hai đầu kết nối |
| `flow_id` | Giống ID ở cả ba event | Cả ba packet thuộc một flow |
| `state` | `ESTABLISHED` | Đã hoàn thành bắt tay |
| `handshake_observed` | `true` | Đã quan sát đầy đủ bắt tay |
| `capture_midstream` | `false` | Có SYN mở đầu, không bắt từ giữa kết nối |
| `packet_count` / `byte_count` | `3` / `144` | Tổng độ dài IPv4: `52 + 52 + 40`, không gồm Ethernet header |
| `forward` | `2` packet, `92` byte | SYN và ACK từ client |
| `backward` | `1` packet, `52` byte | SYN/ACK từ server |
| `tcp_flags.syn_count` / `ack_count` | `2` / `2` | SYN/ACK được tính vào cả hai bộ đếm |
| `tcp_flags.fin_count` / `rst_count` | `0` / `0` | Không có packet đóng/reset kết nối |
| `duration` | `0.132767915725708` giây | Timestamp cuối trừ timestamp đầu, khoảng `0.133` giây |
| `close_reason` | `capture_end` | Pipeline xuất summary khi đọc hết PCAP |


## Tệp

- `input.pcap`: ba packet TCP handshake, dùng lại dữ liệu bài 1.
- `result.jsonl`: ba IDS event sau xử lý.
- `result_flows.jsonl`: một flow summary để kiểm tra trạng thái và handshake.
- `console.txt`: stdout/stderr khi chạy chương trình, lưu UTF-8.
- `README.md`: dữ liệu đầu vào, cách chạy và giải thích kết quả test.
