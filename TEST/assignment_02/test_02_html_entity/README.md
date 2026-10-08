# Test 02 - HTML Entity Decode

## Mục tiêu

Kiểm tra T02 trong mục 6 Bài tập 2: HTML entity trong text HTTP được decode đúng, không làm chương trình crash. Ví dụ là `&lt;p&gt;Hello&lt;/p&gt;`, với dấu `<` và `>` được mã hóa thành `&lt;` và `&gt;`.

## Dữ liệu

- File: `input.pcap`.
- Nguồn: fixture tự tạo bằng Scapy, không bắt từ mạng thật.
- Số packet: `4`; giao thức Ethernet/IPv4/TCP, packet cuối chứa HTTP response.
- Client: `10.0.0.1:12345`, MAC `02:00:00:00:00:01`.
- Server: `10.0.0.2:80`, MAC `02:00:00:00:00:02`.
- Packet server gửi về client đảo IP, port và MAC tương ứng.

| Packet | Timestamp | Chiều | TCP flags | Sequence | Acknowledgment | TCP payload | IPv4 total length |
|---|---|---|---|---|---|---|---|
| 1 | 1700000000.0 | Client → Server | SYN (`S`) | 1000 | 0 | 0 byte | 40 byte |
| 2 | 1700000000.1 | Server → Client | SYN/ACK (`SA`) | 2000 | 1001 | 0 byte | 40 byte |
| 3 | 1700000000.2 | Client → Server | ACK (`A`) | 1001 | 2001 | 0 byte | 40 byte |
| 4 | 1700000000.3 | Server → Client | PSH/ACK (`PA`) | 2001 | 1001 | 103 byte | 143 byte |

Payload packet 4 là HTTP response sau. Dòng status và các header kết thúc bằng `CRLF`; sau header có một dòng trống. Body không có newline ở cuối.

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 24

&lt;p&gt;Hello&lt;/p&gt;
```

- `Content-Type` xác định body là HTML, dùng charset UTF-8.
- `Content-Length: 24` là độ dài body gốc: `24` byte. Toàn bộ HTTP response dài `103` byte, gồm status line, headers, dòng trống và body.
- Fixture chỉ chứa handshake và response cần kiểm tra, không chứa HTTP request; đây là dữ liệu kiểm thử Decoder, không phải phiên truy cập web đầy đủ.

Body đầu vào và kết quả mong đợi:

```text
Body gốc:    &lt;p&gt;Hello&lt;/p&gt;
Sau decode:  <p>Hello</p>
```

- `&lt;` → `<`; `&gt;` → `>`.
- Kết quả `<p>Hello</p>` là chuỗi văn bản đã decode, không phải HTML được thực thi hay hiển thị bởi chương trình.
- Body gốc vẫn được giữ để đối chiếu với dữ liệu trong packet.

## Thực hiện

Chạy tại thư mục gốc project trong PowerShell, dùng Python của virtual environment. Đặt encoding UTF-8 trước khi nhận output Python và lưu console.

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
New-Item -ItemType Directory -Force output\t02_html_entity | Out-Null

$t02Console = & .\.venv\Scripts\python.exe -X utf8 main.py `
  --pcap TEST\assignment_02\test_02_html_entity\input.pcap `
  --output TEST\assignment_02\test_02_html_entity\result.jsonl `
  --flow-output output\t02_html_entity\flows.jsonl `
  2>&1
$t02ExitCode = $LASTEXITCODE
$t02Console | Set-Content -Encoding UTF8 TEST\assignment_02\test_02_html_entity\console.txt
$t02Console
if ($t02ExitCode -ne 0) { throw "T02 execution failed: exit code $t02ExitCode" }
```


## Kết quả

**PASS T02.** CLI trả mã thoát `0`, xử lý đủ `4` packet. Đã đối chiếu body gốc, decoded text, status và dữ liệu PCAP; kết quả đúng như mong đợi ở phần Dữ liệu.

Trong `result.jsonl`, mỗi dòng là một event, theo thứ tự packet trong PCAP:

- Dòng 1–3: các packet handshake, `application.protocol = UNKNOWN` và `decode_status = not_processed` vì không có dữ liệu HTTP để decode. Đây không phải lỗi Decoder.
- Dòng 4: `packet_id = 4`, `application.protocol = HTTP`, `message_type = response`, version `HTTP/1.1`, `status_code = 200`, `reason = OK`.
- `application.fields.headers` có `content-type = text/html; charset=utf-8` và `content-length = "24"`.
- `application.fields.body` giữ body gốc `&lt;p&gt;Hello&lt;/p&gt;`, `body_length = 24`.
- `normalized.application.fields.body` cũng giữ nguyên body này: Preprocessor không ghi đè bằng kết quả decode.
- `decoded.http.html` của dòng 4 chứa kết quả Decoder:

```json
{
  "value": "<p>Hello</p>",
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
