# Test 01 - HTTP URL Decode

## Mục tiêu

Kiểm tra T01 trong mục 6 Bài tập 2: URI chứa percent-encoding được decode đúng và raw URI còn nguyên. Ví dụ là tìm kiếm cụm từ `hello world`, với khoảng trắng được mã hóa thành `%20`.

## Dữ liệu

- File: `input.pcap`.
- Nguồn: fixture tự tạo bằng Scapy, không bắt từ mạng thật.
- Số packet: `4`; giao thức Ethernet/IPv4/TCP, packet cuối chứa HTTP GET.
- Client: `10.0.0.1:12345`, MAC `02:00:00:00:00:01`.
- Server: `10.0.0.2:80`, MAC `02:00:00:00:00:02`.
- Packet server gửi về client đảo IP, port và MAC tương ứng.

| Packet | Timestamp | Chiều | TCP flags | Sequence | Acknowledgment | TCP payload | IPv4 total length |
|---|---|---|---|---|---|---|---|
| 1 | 1700000000.0 | Client → Server | SYN (`S`) | 1000 | 0 | 0 byte | 40 byte |
| 2 | 1700000000.1 | Server → Client | SYN/ACK (`SA`) | 2000 | 1001 | 0 byte | 40 byte |
| 3 | 1700000000.2 | Client → Server | ACK (`A`) | 1001 | 2001 | 0 byte | 40 byte |
| 4 | 1700000000.3 | Client → Server | PSH/ACK (`PA`) | 1001 | 2001 | 75 byte | 115 byte |

Payload packet 4 là HTTP request sau. Mỗi dòng kết thúc bằng `CRLF`; sau header có một dòng trống, không có body.

```http
GET /search?q=hello%20world HTTP/1.1
Host: ids.test
Connection: close

```

URI đầu vào và kết quả mong đợi:

```text
Raw URI:     /search?q=hello%20world
Decoded URI: /search?q=hello world
```

- `/search` là đường dẫn; `q` là tham số tìm kiếm.
- `hello%20world` → `hello world`: Decoder đổi `%20` thành khoảng trắng.
- Raw URI vẫn giữ `%20` để có thể đối chiếu dữ liệu gốc trong packet.

## Thực hiện

Chạy tại thư mục gốc project trong PowerShell, dùng Python của virtual environment. Đặt encoding UTF-8 trước khi nhận output Python và lưu console.

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
New-Item -ItemType Directory -Force output\t01_http_url_decode | Out-Null

$t01Console = & .\.venv\Scripts\python.exe -X utf8 main.py `
  --pcap TEST\assignment_02\test_01_http_url_decode\input.pcap `
  --output TEST\assignment_02\test_01_http_url_decode\result.jsonl `
  --flow-output output\t01_http_url_decode\flows.jsonl `
  2>&1
$t01ExitCode = $LASTEXITCODE
$t01Console | Set-Content -Encoding UTF8 TEST\assignment_02\test_01_http_url_decode\console.txt
$t01Console
if ($t01ExitCode -ne 0) { throw "T01 execution failed: exit code $t01ExitCode" }
```

Flow summary do pipeline tạo được lưu tạm trong `output/t01_http_url_decode/`, không thuộc bộ hồ sơ T01.

## Kết quả

**PASS T01.** CLI trả mã thoát `0`, xử lý đủ `4` packet. Đã đối chiếu raw URI, decoded URI, status và dữ liệu PCAP; kết quả đúng như mong đợi ở phần Dữ liệu.

Trong `result.jsonl`, mỗi dòng là một event, theo thứ tự packet trong PCAP:

- Dòng 1–3: các packet handshake, `application.protocol = UNKNOWN` và `decode_status = not_processed` vì không có dữ liệu HTTP để decode. Đây không phải lỗi Decoder.
- Dòng 4: `packet_id = 4`, `application.protocol = HTTP`, method `GET`, version `HTTP/1.1`, header `host = ids.test`, body rỗng và `body_length = 0`.
- `application.fields.path` của dòng 4 giữ raw URI: `/search?q=hello%20world`.
- `normalized.application.fields.path` cũng giữ nguyên URI này: Preprocessor không ghi đè hoặc decode lại path.
- `decoded.http.uri` của dòng 4 chứa kết quả Decoder:

```json
{
  "value": "/search?q=hello world",
  "status": "ok",
  "errors": []
}
```

Packet 4 có `decode_status = ok` và `decode_errors = []`. Cả bốn event có `parse_errors = []`, `preprocess_status = valid`, `processing_action = process` và `flow_tracking_status = tracked`.


## Tệp

- `input.pcap`: bốn packet đầu vào của test.
- `result.jsonl`: bốn IDS event, gồm dữ liệu Parser, Decoder, Preprocessor và metadata flow.
- `console.txt`: stdout/stderr khi chạy chương trình, lưu UTF-8.
- `README.md`: dữ liệu đầu vào, cách chạy và giải thích kết quả test.
