# Test 05 - Normalization

## Mục tiêu

Kiểm tra T05 trong mục 6 Bài tập 2: header, protocol và domain khác kiểu chữ hoặc format có cách biểu diễn sau preprocessing nhất quán.

Test gồm hai phần: PCAP đi qua pipeline thực tế và event được tạo trực tiếp để kiểm tra Preprocessor. Các dữ liệu gốc của Parser/Decoder phải được giữ nguyên.

## Dữ liệu

### Phần PCAP

- File: `input.pcap`.
- Nguồn: fixture tự tạo bằng Scapy, không bắt từ mạng thật.
- Số packet: `7`; Ethernet/IPv4, gồm ba packet TCP handshake, hai HTTP GET và hai DNS query UDP.
- Client: `10.0.0.1`, MAC `02:00:00:00:00:01`; port TCP `12345`, port UDP `53000`.
- Server: `10.0.0.2`, MAC `02:00:00:00:00:02`; port HTTP `80`, port DNS `53`.
- Packet SYN/ACK server gửi về client đảo IP, port và MAC tương ứng.

| Packet | Timestamp | Nội dung | Chiều | Transport | Flags | Sequence | Acknowledgment | Transport payload | IPv4 total length |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 1700000000.0 | SYN | Client → Server | TCP | S | 1000 | 0 | 0 byte | 40 byte |
| 2 | 1700000000.1 | SYN/ACK | Server → Client | TCP | SA | 2000 | 1001 | 0 byte | 40 byte |
| 3 | 1700000000.2 | ACK | Client → Server | TCP | A | 1001 | 2001 | 0 byte | 40 byte |
| 4 | 1700000000.3 | HTTP header `Host` | Client → Server | TCP | PA | 1001 | 2001 | 73 byte | 113 byte |
| 5 | 1700000000.4 | HTTP header `HOST` | Client → Server | TCP | PA | 1074 | 2001 | 73 byte | 113 byte |
| 6 | 1700000000.5 | DNS `example.com.` | Client → Server | UDP | — | — | — | 29 byte | 57 byte |
| 7 | 1700000000.6 | DNS `Example.COM.` | Client → Server | UDP | — | — | — | 29 byte | 57 byte |

Payload packet 4:

```http
GET /Search?q=hello%20world HTTP/1.1
Host: Example.COM
X-Token: AbC

```

Packet 5 có cùng request nhưng tên header là `HOST` thay cho `Host`. Mỗi dòng kết thúc bằng `CRLF`, sau headers có một dòng trống; không có body.

Packet 6 và 7 là DNS query, cùng transaction ID `100`, `RD = 1`, query type `A` (mã `1`) và class `IN` (mã `1`), khác kiểu chữ của qname. Fixture không chứa HTTP response, DNS response hoặc đóng TCP vì mục tiêu là normalization.

### Phần event trực tiếp

File `check_normalization.py` tạo ba biến thể HTTP và ba biến thể DNS trong bộ nhớ, đưa trực tiếp vào `preprocess_event()`:

| Biến thể | Network protocol | HTTP transport protocol | HTTP application protocol | Tên HTTP header | DNS application protocol | DNS domain | DNS query type |
|---|---|---|---|---|---|---|---|
| 1 | `"IPv4"` | `"TCP"` | `"HTTP"` | `"host"` | `"DNS"` | `"example.com"` | `"A"` |
| 2 | `"ipv4"` | `"tcp"` | `"http"` | `"HOST"` | `"dns"` | `"EXAMPLE.COM."` | `"a"` |
| 3 | `" IPV4 "` | `" Tcp "` | `" Http "` | `" Host "` | `" Dns "` | `" Example.COM. "` | `" A "` |



Phần này cần thiết vì Parser đã chuyển tên HTTP header thành chữ thường và bỏ dấu chấm cuối domain. Chỉ dùng PCAP sẽ chưa chứng minh được Preprocessor tự xử lý các đầu vào chưa chuẩn hóa.

## Thực hiện

Chạy tại thư mục gốc project trong PowerShell, dùng Python của virtual environment:

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding

& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_02\test_05_normalization\check_normalization.py
if ($LASTEXITCODE -ne 0) { throw "T05 failed" }
```

Script tự chạy `main.py` với `input.pcap`, lưu `result.jsonl`, kiểm tra PCAP output rồi chạy sáu event trực tiếp. Stdout/stderr của pipeline, dữ liệu event trực tiếp và kết quả PASS/FAIL được lưu chung trong `console.txt` bằng UTF-8. Nếu kiểm tra thất bại, script ghi FAIL và trả mã thoát `1`.


## Kết quả
PASS T05. Chương trình xử lý đủ 7 packet, script kiểm tra trả mã thoát 0.
Trong result.jsonl:
- Packet 1–3: bắt tay TCP, không có dữ liệu cần decode.
- Packet 4–5: tên HTTP header đều là host, x-token. Giá trị header và URL gốc được giữ nguyên.
- Packet 6–7: DNS domain sau chuẩn hóa đều là example.com; domain gốc Example.COM ở packet 7 không bị sửa.

Script kiểm tra thêm 6 event trực tiếp, xác nhận Preprocessor chuyển đúng:
" Http "          → "HTTP"
" Host "          → "host"
" Example.COM. "  → "example.com"
Cả 6 trường hợp đều PASS: các đầu vào tương đương cho kết quả chuẩn hóa giống nhau, dữ liệu gốc không bị thay đổi. Kết quả kiểm tra được lưu trong console.txt.

## Tệp

- `input.pcap`: bảy packet đầu vào để kiểm tra pipeline.
- `result.jsonl`: bảy IDS event do pipeline xuất.
- `console.txt`: output pipeline và kết quả sáu event trực tiếp, lưu UTF-8.
- `check_normalization.py`: script tái hiện và tự kiểm tra cả hai phần T05.
- `README.md`: dữ liệu đầu vào, cách chạy và giải thích kết quả test.
