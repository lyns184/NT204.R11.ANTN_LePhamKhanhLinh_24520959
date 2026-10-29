# Test 12 - Flags / Dsize

## Mục tiêu

Kiểm tra T12 Bài tập 3: match đúng bộ cờ TCP, kích thước raw payload và phép AND giữa flags/dsize. Dsize đếm byte payload, không tính Ethernet/IP/TCP header hoặc số ký tự sau decode.

## Dữ liệu

`input.rules` có sáu rule hợp lệ, cùng header TCP `any any -> any 80`, revision 1:

| Rule / SID | Điều kiện |
|---|---|
| R1 / 101201 | `flags:S; dsize:0;` |
| R2 / 101202 | `flags:SA; dsize:0;` |
| R3 / 101203 | `flags:PA; dsize:5;` |
| R4 / 101204 | `dsize:<5;` |
| R5 / 101205 | `dsize:>5;` |
| R6 / 101206 | `flags:0; dsize:0;` |

Flags dùng so khớp chính xác tám control bits theo phạm vi hiện tại: S là SYN, SA là SYN+ACK, PA là PSH+ACK; flags:0 là cả tám bit đều tắt. R4/R5 không có điều kiện flags. Không rule nào có flow/content.

`input.pcap` có chín packet Scapy tự tạo, không capture từ mạng thật:

- Ethernet/IPv4/TCP; MAC `02:00:00:00:00:01` → `02:00:00:00:00:02`.
- `10.0.0.1:12345–12353` → `10.0.0.2:80`, mỗi packet có port nguồn riêng.
- Seq 1001, ack 2001; timestamp `1700000000`–`1700000008`.
- IP/TCP headers mỗi loại 20 byte; không có TCP options hoặc HTTP header. Các packet độc lập phục vụ matching, không mô phỏng một phiên handshake.

| Packet | Flags | TCP payload | Payload / IPv4 byte | Rule phải MATCH |
|---|---|---|---|---|
| 1 | S | Rỗng | 0 / 40 | R1, R4 |
| 2 | SA | Rỗng | 0 / 40 | R2, R4 |
| 3 | PA | `1234` | 4 / 44 | R4 |
| 4 | PA | `12345` | 5 / 45 | R3 |
| 5 | PA | `123456` | 6 / 46 | R5 |
| 6 | A | `12345` | 5 / 45 | Không có |
| 7 | S | `12345` | 5 / 45 | Không có |
| 8 | Không bật cờ | Rỗng | 0 / 40 | R4, R6 |
| 9 | PA | UTF-8 `éABC` | 5 / 45 | R3 |

P1/P2 chứng minh flags:S không match SA. P3–P5 kiểm tra 4/5/6 byte; giá trị bằng 5 không thỏa `<5` hoặc `>5`. P6 đúng size nhưng sai flags; P7 đúng flags của R1 nhưng sai size nên không có detection. P8 có đầy đủ flags_detail với mọi bit false, không phải thiếu dữ liệu flags. Payload rỗng trong P1/P2/P8 là dữ liệu đầy đủ dài 0, không phải payload missing.

P9 chứa bytes `c3 a9 41 42 43`: năm byte UTF-8 nhưng chỉ bốn ký tự `éABC`. Dsize phải bằng 5 mà không cần decode payload. Payload này không chứa HTTP message.

## Thực hiện

Chạy tại thư mục gốc project trong PowerShell:

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding

& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_03\test_12_flags_dsize\check_flags_dsize.py
if ($LASTEXITCODE -ne 0) { throw "T12 failed" }
```

Script nạp rule bằng Loader thật, kiểm tra flags và toán tử/giá trị dsize, đọc PCAP để đối chiếu flags/raw bytes/độ dài/header/timestamp. Sau đó chạy `main.py` thật để ghi event/detection JSONL.

Phần API tạo InspectionContext từ normalized event của CLI và complete raw TCP payload đã xác minh trong PCAP, kể cả bytes rỗng; gọi `match_rule()` thật cho cả sáu rule trên từng packet. Expected status, rejection stage và các cặp packet/SID được khai báo độc lập với output Matcher. Script kiểm tra 54 kết quả, positive evidence, đúng mười detection và metadata tương ứng; xác nhận input/context/raw bytes không đổi và đọc lại được các JSONL. Assertion thất bại trả mã thoát 1 và ghi FAIL vào console.

## Kết quả

**PASS T12.** CLI và script trả mã thoát `0`: chín event, 54 kết quả full-rule (10 MATCH/44 NO_MATCH), đúng mười detection theo bảng Dữ liệu.

Trong `result.jsonl`, chín event đều valid/process/tracked, parse/decode errors rỗng. Payload length đúng bảng Dữ liệu; IP total length lớn hơn payload 40 byte do IP/TCP headers. Application protocol UNKNOWN và decode_status not_processed vì fixture không chứa HTTP message; các packet vẫn được đánh giá bình thường.

P8 có transport.flags là chuỗi rỗng và flags_detail đầy đủ với mọi bit false. Preprocessor chấp nhận đúng chuỗi rỗng biểu diễn TCP không bật cờ; không áp dụng ngoại lệ này cho các field text khác. P1/P2/P8 có payload đầy đủ dài 0 và tạo đúng detection dsize:0. P9 tạo detection SID101203 với dsize.actual = 5, không tính thành bốn ký tự.

Trong `result_matches.jsonl`, mỗi packet có sáu dòng theo thứ tự SID101201–101206. Các dòng ghi case, candidate_sids, payload_source, observed_flags, payload_length và MatchResult. NO_MATCH có reason_code flags_no_match hoặc dsize_no_match theo bước từ chối, matched_info null; không giữ evidence một phần, không có ERROR hoặc NOT_EVALUABLE.

Trong `result_detections.jsonl`, evidence flags/dsize gồm expression của điều kiện và actual quan sát được. Ví dụ:

- P2/SID101202: flags = `{expression: SA, actual: SA}`, dsize = `{expression: 0, actual: 0}`.
- P4/SID101203 và P9/SID101203: flags = `{expression: PA, actual: PA}`, dsize = `{expression: 5, actual: 5}`.
- P5/SID101205: flags null vì rule không có điều kiện flags; dsize = `{expression: >5, actual: 6}`.
- P8/SID101206: flags = `{expression: 0, actual: 0}`, dsize = `{expression: 0, actual: 0}`.

Header orientation direct, flow evidence null, contents rỗng vì không có điều kiện flow/content. IP/port/timestamp/flow ID khớp event cùng lần chạy; revision/msg đúng rule. P6/P7 không tạo detection dù lần lượt thỏa size hoặc flags của rule liên quan.

CLI báo events_evaluated `9`, candidate_rules `54`, matches/detections_written `10`; skip/evaluation error/not-evaluable đều `0`. Script cũng xác nhận input/context/raw bytes không đổi và các JSONL đọc lại được.

## Tệp

- `input.rules`: sáu rule flags/dsize và các toán tử =, <, >.
- `input.pcap`: chín packet TCP tự tạo với payload rỗng/ASCII/UTF-8.
- `check_flags_dsize.py`: kiểm tra fixture, CLI, full-rule Matcher và detection.
- `result.jsonl`: chín IDS event của CLI.
- `result_matches.jsonl`: 54 kết quả full-rule API, gồm cả NO_MATCH.
- `result_detections.jsonl`: mười detection của CLI khi kiểm tra thành công.
- `console.txt`: output CLI và kết quả kiểm tra PASS/FAIL, UTF-8.
- `README.md`: dữ liệu, cách chạy và giải thích kết quả.
