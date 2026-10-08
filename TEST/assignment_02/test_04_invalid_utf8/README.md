# Test 04 - Invalid UTF-8 Bytes

## Mục tiêu

Kiểm tra T04 trong mục 6 Bài tập 2: payload không phải UTF-8 hợp lệ được đánh dấu lỗi/partial; chương trình tiếp tục xử lý packet sau.

Ví dụ là HTTP body `b"Hello \xff"`, theo sau bởi HTTP body hợp lệ `b"Hello"`.

## Dữ liệu

- File: `input.pcap`.
- Nguồn: fixture tự tạo bằng Scapy, không bắt từ mạng thật.
- Số packet: `5`; Ethernet/IPv4/TCP, gồm bắt tay TCP và hai HTTP response cùng kết nối.
- Client: `10.0.0.1:12345`, MAC `02:00:00:00:00:01`.
- Server: `10.0.0.2:80`, MAC `02:00:00:00:00:02`.
- Packet server gửi về client đảo IP, port và MAC tương ứng.

| Packet | Timestamp | Chiều | Nội dung | TCP flags | Sequence | Acknowledgment | TCP payload | IPv4 total length |
|---|---|---|---|---|---|---|---|---|
| 1 | 1700000000.0 | Client → Server | SYN | S | 1000 | 0 | 0 byte | 40 byte |
| 2 | 1700000000.1 | Server → Client | SYN/ACK | SA | 2000 | 1001 | 0 byte | 40 byte |
| 3 | 1700000000.2 | Client → Server | ACK | A | 1001 | 2001 | 0 byte | 40 byte |
| 4 | 1700000000.3 | Server → Client | HTTP body lỗi UTF-8 | PA | 2001 | 1001 | 86 byte | 126 byte |
| 5 | 1700000000.4 | Server → Client | HTTP body hợp lệ | PA | 2087 | 1001 | 84 byte | 124 byte |

Packet 4 có payload chính xác dưới dạng Python bytes literal:

```python
b"HTTP/1.1 200 OK\r\n"
b"Content-Type: text/plain; charset=utf-8\r\n"
b"Content-Length: 7\r\n"
b"\r\n"
b"Hello \xff"
```

Các literal trên được nối liền thành một payload. Body gồm các byte hex `48 65 6c 6c 6f 20 ff`; `FF` là một byte thực trong PCAP, không phải bốn ký tự `\xff`. Byte này không hợp lệ trong UTF-8.

Packet 5 chứa HTTP response:

```http
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Content-Length: 5

Hello
```

Dòng status và headers kết thúc bằng `CRLF`; giữa headers và body có một dòng trống. Cả hai body không có newline ở cuối. `Content-Length` tính theo byte gốc: packet 4 có `7` byte, packet 5 có `5` byte.


Kết quả mong đợi:

| Packet | Body đầu vào | Decoded value | Decode status |
|---|---|---|---|
| 4 | `b"Hello \xff"` | `Hello �` | `partial`, có thông báo lỗi UTF-8 |
| 5 | `b"Hello"` | `Hello` | `ok`, không có lỗi |

Ký tự `�` là ký tự thay thế U+FFFD cho byte lỗi. Raw byte `FF` vẫn có trong PCAP để đối chiếu; JSONL lưu chuỗi text sau khi chuyển bytes sang ký tự.

## Thực hiện

Chạy tại thư mục gốc project trong PowerShell, dùng Python của virtual environment. Đặt encoding UTF-8 trước khi nhận output Python và lưu console.

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
New-Item -ItemType Directory -Force output\t04_invalid_utf8 | Out-Null

$t04Console = & .\.venv\Scripts\python.exe -X utf8 main.py `
  --pcap TEST\assignment_02\test_04_invalid_utf8\input.pcap `
  --output TEST\assignment_02\test_04_invalid_utf8\result.jsonl `
  --flow-output output\t04_invalid_utf8\flows.jsonl `
  2>&1
$t04ExitCode = $LASTEXITCODE
$t04Console | Set-Content -Encoding UTF8 TEST\assignment_02\test_04_invalid_utf8\console.txt
$t04Console
if ($t04ExitCode -ne 0) { throw "T04 execution failed: exit code $t04ExitCode" }
```


## Kết quả

**PASS T04.** CLI trả mã thoát `0`, xử lý đủ `5` packet. Packet 4 được đánh dấu `partial`, packet 5 phía sau vẫn được decode thành công.

Trong `result.jsonl`, mỗi dòng là một event, theo thứ tự packet trong PCAP:

- Dòng 1–3: handshake, `application.protocol = UNKNOWN`, `decode_status = not_processed` vì không có dữ liệu HTTP để decode.
- Dòng 4–5: `application.protocol = HTTP`, `message_type = response`, version `HTTP/1.1`, `status_code = 200`, `reason = OK`.
- Dòng 4: Parser biểu diễn `application.fields.body` bằng `Hello �`, `body_length = 7`. `parse_errors = []` vì Parser đọc được cấu trúc HTTP; Decoder kiểm tra raw bytes và ghi lỗi UTF-8.
- `normalized.application.fields.body` ở dòng 4 cũng là `Hello �`; không thể dùng chuỗi này để khôi phục byte `FF`, cần đối chiếu PCAP.
- Dòng 5: body là `Hello`, `body_length = 5`, không có lỗi decode.

`decoded.http.text` ở dòng 4:

```json
{
  "value": "Hello �",
  "status": "partial",
  "errors": ["Invalid bytes for charset utf-8"]
}
```

Event này có `decode_status = partial` và:

```json
"decode_errors": ["HTTP text: Invalid bytes for charset utf-8"]
```

Preprocessor ghi `preprocess_status = partial` và `reason` nêu lỗi từ Decoder. `processing_action = process` cho phép tiếp tục xử lý theo chính sách mặc định; `flow_tracking_status = tracked`.

`decoded.http.text` ở dòng 5:

```json
{
  "value": "Hello",
  "status": "ok",
  "errors": []
}
```

Packet 5 có `decode_status = ok`, `decode_errors = []`, `preprocess_status = valid`, `processing_action = process` và `reason = null`. Cả năm event có `parse_errors = []` và `flow_tracking_status = tracked`.


## Tệp

- `input.pcap`: năm packet đầu vào, gồm body lỗi và body hợp lệ phía sau.
- `result.jsonl`: năm IDS event, gồm dữ liệu Parser, Decoder, Preprocessor và metadata flow.
- `console.txt`: stdout/stderr khi chạy chương trình, lưu UTF-8.
- `README.md`: dữ liệu đầu vào, cách chạy và giải thích kết quả test.
