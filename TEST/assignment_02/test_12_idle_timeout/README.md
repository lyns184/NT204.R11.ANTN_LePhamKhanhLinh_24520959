# Test 12 - Idle Timeout

## Mục tiêu

Kiểm tra T12 trong mục 6 Bài tập 2: flow không có packet mới quá idle timeout hết hạn và bị loại khỏi bảng flow đang hoạt động.

Test kiểm tra thêm packet cùng 5-tuple sau timeout tạo flow ID mới và không xuất summary trùng.

## Dữ liệu

### Phần PCAP

- File: `input.pcap`.
- Nguồn: fixture tự tạo bằng Scapy, không bắt từ mạng thật.
- Số packet: `3`; Ethernet/IPv4/UDP/DNS.
- Client: `10.0.0.1:53000`, MAC `02:00:00:00:00:01`.
- DNS server: `10.0.0.2:53`, MAC `02:00:00:00:00:02`.
- Timeout TCP/UDP cấu hình `5` giây. PCAP dùng timestamp packet, không cần chờ thật.

| Packet | Timestamp | Chiều | Nội dung | DNS payload | UDP length | IPv4 total length |
|---|---|---|---|---|---|---|
| 1 | 1700000000.0 | Client → Server | Query `example.com.`, ID 100 | 29 byte | 37 byte | 57 byte |
| 2 | 1700000001.0 | Server → Client | Response ID 100, A = `192.0.2.1` | 56 byte | 64 byte | 84 byte |
| 3 | 1700000007.0 | Client → Server | Query `example.com.`, ID 101 | 29 byte | 37 byte | 57 byte |

Cả hai query có type A, class IN, RD = 1. Response có một question và một answer A cho `example.com.`, TTL `60`, RA = 1, response code `0`. IPv4 header dài `20` byte, UDP header dài `8` byte.

Packet 3 dùng cùng IP/port/protocol với packet 1, nhưng đến sau packet cuối của flow cũ `6` giây (`7 - 1`). Khoảng im lặng này vượt timeout `5` giây.

Kết quả mong đợi:

```text
t = 0: query tạo flow A
t = 1: response thuộc flow A, cập nhật last_seen
t = 7: query mới → flow A hết hạn → tạo flow B với ID mới
EOF:   xuất flow B còn hoạt động
```



### Phần kiểm tra bảng active

File `check_idle_timeout.py` kiểm tra trực tiếp `FlowTracker.active_flows` bằng hai tracker riêng:

- UDP: dùng packet 1–2 trong PCAP, tạo một flow có `last_seen = 1700000001`.
- TCP: tạo SYN ở `1700000000`, SYN/ACK ở `1700000000.5`, ACK ở `1700000001`; client `10.0.0.1:12345`, server `10.0.0.2:80`, sequence mở đầu `1000`/`2000`.

Với mỗi tracker, script thực hiện:

1. Gọi `expire(last_seen + 4.999)`: flow vẫn trong active table.
2. Gọi `expire(last_seen + 5)`: xuất một summary `idle_timeout`, bảng active rỗng.
3. Gọi expire lần nữa ở cùng timestamp: không xuất summary trùng.
4. Đưa packet mới cùng 5-tuple tại `last_seen + 6`: tạo flow ID mới, packet counter bắt đầu lại từ `1`.
5. Flush: chỉ xuất flow mới một lần, bảng active rỗng; flush tiếp không xuất thêm.

Các kiểm tra trực tiếp không ghi thêm event vào `result.jsonl`; kết quả nằm trong `console.txt`. Tracker trực tiếp có ID riêng, không so ID của nó với ID CLI.

## Thực hiện

Chạy tại thư mục gốc project trong PowerShell, dùng Python của virtual environment:

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding

& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_02\test_12_idle_timeout\check_idle_timeout.py
if ($LASTEXITCODE -ne 0) { throw "T12 failed" }
```

Script tự chạy `main.py` với PCAP và các tùy chọn `--tcp-idle-timeout 5 --udp-idle-timeout 5`, lưu event/flow JSONL, rồi kiểm tra active table TCP/UDP. Output CLI và kết quả kiểm tra được lưu chung trong `console.txt` bằng UTF-8. Thất bại trả mã `1`, thành công trả mã `0`.

PCAP chỉ kích hoạt kiểm tra timeout khi xử lý packet có timestamp mới; không có timer chạy tại giây 6 trong lần replay này. Kiểm tra expire trực tiếp chứng minh ngưỡng hết hạn chính xác ở `>= 5` giây.

## Kết quả

**PASS T12.** CLI xử lý đủ `3` packet; cả kiểm tra TCP/UDP trực tiếp đều đạt. CLI và script trả mã thoát `0`.

Trong `result.jsonl`:

- Dòng 1–2: cùng flow ID cũ, direction `forward`/`backward`.
- Dòng 3: flow ID mới dù cùng 5-tuple, direction `forward`.
- Cả ba event có protocol UDP/DNS, `parse_errors = []`, `decode_errors = []`, `preprocess_status = valid`, `processing_action = process`, `flow_tracking_status = tracked`.
- `decode_status = not_processed` vì test không có nội dung cần Decoder giải mã.

Trong `result_flows.jsonl`, có đúng hai summary:

| Field | Flow cũ, dòng 1 | Flow mới, dòng 2 |
|---|---|---|
| Endpoint / protocol | Client ↔ server ở phần Dữ liệu, UDP | Giống flow cũ |
| `flow_id` | Giống ID event 1–2 | Giống ID event 3, khác flow cũ |
| `close_reason` | `idle_timeout` | `capture_end` |
| `start_time` | `1700000000` | `1700000007` |
| `last_seen` | `1700000001` | `1700000007` |
| `exported_at` | `1700000007` | `1700000007` |
| `packet_count` / `byte_count` | `2` / `141` | `1` / `57` |
| `forward` | `1` packet, `57` byte | `1` packet, `57` byte |
| `backward` | `1` packet, `84` byte | `0` packet, `0` byte |
| `duration` | `1` giây | `0` giây |

Duration tính từ packet đầu đến packet cuối, không cộng thời gian chờ timeout. Byte counters tính theo IPv4 length. Các metadata TCP (`state`, `tcp_flags`, `handshake_observed`, `capture_midstream`) là `null` vì flow CLI là UDP.


## Tệp

- `input.pcap`: ba DNS UDP packet, có khoảng im lặng vượt timeout.
- `result.jsonl`: ba event của lần chạy CLI.
- `result_flows.jsonl`: summary flow hết hạn và flow mới khi EOF.
- `check_idle_timeout.py`: script tái hiện CLI và kiểm tra bảng active TCP/UDP.
- `console.txt`: output CLI và kết quả kiểm tra trực tiếp, lưu UTF-8.
- `README.md`: dữ liệu đầu vào, cách chạy và giải thích kết quả test.
