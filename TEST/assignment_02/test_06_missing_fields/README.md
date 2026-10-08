# Test 06 - Missing Optional Fields

## Mục tiêu

Kiểm tra T06 trong mục 6 Bài tập 2: event thiếu field không bắt buộc được xử lý `null`/`[]` nhất quán, không gây exception.

Test kiểm tra thêm dictionary thiếu được biểu diễn bằng `{}`, các giá trị đã có và dữ liệu gốc không bị sửa.

## Dữ liệu

- Nguồn: sáu `IDSEvent` được tạo trong bộ nhớ bởi `check_missing_fields.py`, không lấy từ packet thật.
- Không có PCAP: script đưa event trực tiếp vào Preprocessor để chủ động bỏ field hoặc đặt field thành `None` (xuất JSON là `null`).
- Mỗi protocol HTTP, DNS và SMTP có hai trường hợp: **omitted** (không có field tùy chọn) và **null** (field tùy chọn có giá trị `None`).


| Dòng JSONL / packet_id | Trường hợp | Transport / port đích | Application fields có giá trị |
|---|---|---|---|
| 1 | HTTP omitted | TCP / 80 | `message_type = request`, `method = GET`, `path = /` |
| 2 | HTTP null | TCP / 80 | Như dòng 1; field tùy chọn là `null` |
| 3 | DNS omitted | UDP / 53 | `message_type = query` |
| 4 | DNS null | UDP / 53 | Như dòng 3; field tùy chọn là `null` |
| 5 | SMTP omitted | TCP / 25 | `message_type = command`, `command = NOOP` |
| 6 | SMTP null | TCP / 25 | Như dòng 5; field tùy chọn là `null` |


Field tùy chọn được bỏ hoặc đặt `null`:

| Nhóm | Các field |
|---|---|
| IPv4 | `version`, `header_length`, `total_length`, `identification`, `flags`, `fragment_offset`, `ttl`, `next_protocol`, `checksum` |
| TCP | `payload_length`, `sequence_number`, `acknowledgment_number`, `header_length`, `flags`, `window_size`, `checksum`, `urgent_pointer`, `flags_detail` |
| UDP | `payload_length`, `length`, `checksum` |
| HTTP | `version`, `status_code`, `reason`, `body`, `body_length`, `headers` |
| DNS | `transaction_id`, `opcode`, `authoritative`, `truncated`, `recursion_desired`, `recursion_available`, `response_code`, `question_count`, `answer_count`, `questions`, `answers` |
| SMTP | `argument`, `address`, `status_code`, `message`, `multiline`, `lines` |

Các event giữ mặc định `payload_length = 0`, `packet_length = null`. Raw payload thử nghiệm là `b"original bytes"`, chỉ để kiểm tra Preprocessor không sửa bytes; không phải message trên wire, không dùng suy ra độ dài hoặc decode.



## Thực hiện

Chạy tại thư mục gốc project trong PowerShell, dùng Python của virtual environment:

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding

& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_02\test_06_missing_fields\check_missing_fields.py
if ($LASTEXITCODE -ne 0) { throw "T06 failed" }
```

Script tạo sáu event, gọi `preprocess_event()`, kiểm tra kết quả, rồi dùng `JSONLWriter` của project để ghi `result.jsonl`. Script đọc lại JSONL để đối chiếu với event đã xử lý. Đầu vào application, kết quả chuẩn hóa và PASS/FAIL được lưu trong `console.txt` bằng UTF-8. Nếu kiểm tra thất bại, script trả mã thoát `1`.

## Kết quả

**PASS T06.** Sáu event được xử lý và ghi JSONL thành công; script trả mã thoát `0`.

Trong `result.jsonl`:

- Dòng 1–2: HTTP request giữ `GET /`; các field chưa có như `version`, `body`, `body_length` là `null`, `headers = {}` trong normalized.
- Dòng 3–4: DNS giữ `message_type = query`; `questions = []`, `answers = []`, các field đơn chưa có là `null` trong normalized. `question_count`/`answer_count` vẫn là `null`, không tự suy ra `0` từ danh sách rỗng.
- Dòng 5–6: SMTP giữ command `NOOP`; `lines = []`, các field đơn chưa có là `null` trong normalized.
- Field IPv4/TCP/UDP tùy chọn được điền đúng `null`; TCP `flags_detail = {}`.
- Hai event omitted/null của mỗi protocol có normalized giống nhau. Field gốc bị bỏ vẫn không có, field gốc `null` vẫn là `null`.

Cả sáu event có `preprocess_status = valid`, `processing_action = process`, `reason = null`. `decode_status = not_processed` và `flow_tracking_status = not_processed` vì script chỉ kiểm tra Preprocessor, không chạy Decoder hoặc Flow Tracker. Đây không phải lỗi.

Kết quả cuối trong `console.txt`:

```text
PASS T06: 6 events; null/[]/{} defaults correct; originals preserved; JSONL roundtrip passed.
```

Test xác nhận điền field thiếu nhất quán, giữ dữ liệu gốc và không exception; không khẳng định event này tương ứng packet thực đã capture.

## Tệp

- `check_missing_fields.py`: tạo sáu event và tự kiểm tra T06.
- `result.jsonl`: sáu event sau preprocessing, mỗi dòng một event.
- `console.txt`: dữ liệu kiểm tra và kết quả PASS/FAIL, lưu UTF-8.
- `README.md`: dữ liệu đầu vào, cách chạy và giải thích kết quả test.
