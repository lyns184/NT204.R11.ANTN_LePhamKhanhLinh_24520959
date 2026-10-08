# Test 03 - SMTP Base64 / Quoted-Printable Decode

## Mục tiêu

Kiểm tra T03 trong mục 6 Bài tập 2: MIME body có Content-Transfer-Encoding Base64 hoặc Quoted-Printable được decode đúng và ghi `decode_status` phù hợp.

Ví dụ Base64 là `SGVsbG8=` → `Hello`; ví dụ Quoted-Printable là `1+1=3D2` → `1+1=2`.

## Dữ liệu

- File: `input.pcap`.
- Nguồn: fixture tự tạo bằng Scapy, không bắt từ mạng thật.
- Số packet: `14`; Ethernet/IPv4/TCP, gồm hai phiên SMTP, mỗi phiên có 7 packet.
- Client: `10.0.0.1`, MAC `02:00:00:00:00:01`; port `12345` cho Base64, port `12346` cho Quoted-Printable.
- Server: `10.0.0.2:25`, MAC `02:00:00:00:00:02`.
- Packet server gửi về client đảo IP, port và MAC tương ứng.
- Mỗi phiên chứa bắt tay TCP, command `DATA`, response `354`, MIME message kết thúc bằng dòng `.`, rồi response `250`.
- Fixture tập trung vào SMTP DATA decoding; không chứa các bước greeting, EHLO, MAIL FROM, RCPT TO hoặc đóng TCP của một phiên gửi email đầy đủ.

| Packet | Timestamp | Phiên | Chiều | Nội dung | TCP flags | Sequence | Acknowledgment | TCP payload | IPv4 total length |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 1700000000.0 | Base64 | Client → Server | SYN | S | 1000 | 0 | 0 byte | 40 byte |
| 2 | 1700000000.1 | Base64 | Server → Client | SYN/ACK | SA | 2000 | 1001 | 0 byte | 40 byte |
| 3 | 1700000000.2 | Base64 | Client → Server | ACK | A | 1001 | 2001 | 0 byte | 40 byte |
| 4 | 1700000000.3 | Base64 | Client → Server | DATA | PA | 1001 | 2001 | 6 byte | 46 byte |
| 5 | 1700000000.4 | Base64 | Server → Client | 354 | PA | 2001 | 1007 | 22 byte | 62 byte |
| 6 | 1700000000.5 | Base64 | Client → Server | MIME message + terminator | PA | 1007 | 2023 | 110 byte | 150 byte |
| 7 | 1700000000.6 | Base64 | Server → Client | 250 | PA | 2023 | 1117 | 8 byte | 48 byte |
| 8 | 1700000000.7 | Quoted-Printable | Client → Server | SYN | S | 1000 | 0 | 0 byte | 40 byte |
| 9 | 1700000000.8 | Quoted-Printable | Server → Client | SYN/ACK | SA | 2000 | 1001 | 0 byte | 40 byte |
| 10 | 1700000000.9 | Quoted-Printable | Client → Server | ACK | A | 1001 | 2001 | 0 byte | 40 byte |
| 11 | 1700000001.0 | Quoted-Printable | Client → Server | DATA | PA | 1001 | 2001 | 6 byte | 46 byte |
| 12 | 1700000001.1 | Quoted-Printable | Server → Client | 354 | PA | 2001 | 1007 | 22 byte | 62 byte |
| 13 | 1700000001.2 | Quoted-Printable | Client → Server | MIME message + terminator | PA | 1007 | 2023 | 119 byte | 159 byte |
| 14 | 1700000001.3 | Quoted-Printable | Server → Client | 250 | PA | 2023 | 1126 | 8 byte | 48 byte |

Các payload command/response là `DATA\r\n`, `354 Start mail input\r\n` và `250 OK\r\n`. Các dòng MIME cũng kết thúc bằng `CRLF`; giữa headers và body có một dòng trống.

Payload packet 6:

```text
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: base64

SGVsbG8=
.
```

Payload packet 13:

```text
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: quoted-printable

1+1=3D2
.
```

- Dòng `.` kết thúc SMTP DATA, không thuộc nội dung body đã decode.
- Base64: `SGVsbG8=` biểu diễn `Hello`; newline dùng để xuống dòng dữ liệu Base64 được bỏ qua khi decode.
- Quoted-Printable: `=3D` biểu diễn dấu `=`; dấu `+` giữ nguyên. CRLF kết thúc dòng body vẫn thuộc nội dung text.

Kết quả mong đợi, viết dưới dạng JSON string để thấy ký tự xuống dòng:

| Packet | Encoding | Body encoded trước terminator | Decoded value |
|---|---|---|---|
| 6 | Base64 | `"SGVsbG8=\r\n"` | `"Hello"` |
| 13 | Quoted-Printable | `"1+1=3D2\r\n"` | `"1+1=2\r\n"` |

## Thực hiện

Chạy tại thư mục gốc project trong PowerShell, dùng Python của virtual environment. Đặt encoding UTF-8 trước khi nhận output Python và lưu console.

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
New-Item -ItemType Directory -Force output\t03_smtp_base64_qp | Out-Null

$t03Console = & .\.venv\Scripts\python.exe -X utf8 main.py `
  --pcap TEST\assignment_02\test_03_smtp_base64_qp\input.pcap `
  --output TEST\assignment_02\test_03_smtp_base64_qp\result.jsonl `
  --flow-output output\t03_smtp_base64_qp\flows.jsonl `
  2>&1
$t03ExitCode = $LASTEXITCODE
$t03Console | Set-Content -Encoding UTF8 TEST\assignment_02\test_03_smtp_base64_qp\console.txt
$t03Console
if ($t03ExitCode -ne 0) { throw "T03 execution failed: exit code $t03ExitCode" }
```

Flow summary do pipeline tạo được lưu tạm trong `output/t03_smtp_base64_qp/`, không thuộc bộ hồ sơ T03.

## Kết quả

**PASS T03.** CLI trả mã thoát `0`, xử lý đủ `14` packet. Đã đối chiếu dữ liệu PCAP và kết quả MIME của cả hai encoding.

Trong `result.jsonl`, mỗi dòng là một event, theo thứ tự packet trong PCAP:

- Dòng 1–3 và 8–10: handshake, `application.protocol = UNKNOWN`, `decode_status = not_processed` vì chưa có dữ liệu cần decode.
- Dòng 4 và 11: Parser nhận SMTP command `DATA`; Decoder bắt đầu theo dõi phiên DATA.
- Dòng 5 và 12: Parser nhận SMTP response `354`; Decoder xác nhận server sẵn sàng nhận nội dung email.
- Dòng 6 và 13: nhận trọn MIME message và terminator, xuất kết quả ở `decoded.smtp.mime`.
- Dòng 7 và 14: Parser nhận SMTP response `250 OK`; không có MIME body mới để decode.
- Những dòng không xuất kết quả MIME có `decode_status = not_processed`.

Kết quả chính ở dòng 6:

```json
{
  "value": "Hello",
  "status": "ok",
  "errors": [],
  "part_id": "0",
  "content_type": "text/plain",
  "charset": "utf-8",
  "transfer_encoding": "base64",
  "remaining_bytes": 0
}
```

Kết quả chính ở dòng 13:

```json
{
  "value": "1+1=2\r\n",
  "status": "ok",
  "errors": [],
  "part_id": "0",
  "content_type": "text/plain",
  "charset": "utf-8",
  "transfer_encoding": "quoted-printable",
  "remaining_bytes": 0
}
```

Ở dòng 6 và 13, `application.protocol = UNKNOWN` và `application.fields = {}` vì Parser chỉ nhận diện SMTP command/response, không phân tích trực tiếp nội dung DATA. Decoder vẫn giải mã được nhờ trạng thái phiên đã tạo từ `DATA` và `354`; kết quả nằm riêng ở `decoded.smtp.mime`. 



## Tệp

- `input.pcap`: 14 packet đầu vào, gồm hai phiên SMTP DATA.
- `result.jsonl`: 14 IDS event, gồm dữ liệu Parser, Decoder, Preprocessor và metadata flow.
- `console.txt`: stdout/stderr khi chạy chương trình, lưu UTF-8.
- `README.md`: dữ liệu đầu vào, cách chạy và giải thích kết quả test.
