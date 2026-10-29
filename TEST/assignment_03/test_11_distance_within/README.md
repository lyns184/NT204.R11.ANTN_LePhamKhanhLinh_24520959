# Test 11 - Distance / Within

## Mục tiêu

Kiểm tra T11 Bài tập 3: hai content kết hợp distance/within trên raw TCP payload. Content thứ hai phải nằm trọn vùng tìm tính từ cuối content thứ nhất. Khi cặp đầu thất bại, Matcher cần thử lần xuất hiện content thứ nhất tiếp theo nếu còn khả năng match.

## Dữ liệu

`input.rules` gồm ba rule hợp lệ, header TCP `any any -> any 80`, revision 1. Mỗi rule có `content:"ABC";` rồi `content:"XYZ";`; modifier chỉ gắn với XYZ:

| Rule / SID | Modifier của XYZ | Vùng tìm, với E là cuối ABC và N là độ dài payload |
|---|---|---|
| R1 / 101101 | `within:3;` | `[E,min(N,E+3))` |
| R2 / 101102 | `distance:2;` | `[E+2,N)` |
| R3 / 101103 | `distance:2; within:5;` | `[E+2,min(N,E+7))` |

Byte đếm từ 0; khoảng `[start,end)` không gồm byte tại end. Distance là khoảng cách tối thiểu trước vùng tìm, không bắt buộc XYZ xuất hiện ngay tại đầu vùng. Within giới hạn độ dài vùng sau khi dịch distance. Không có offset/depth/nocase/flow/flags/dsize.

`input.pcap` gồm bảy packet Scapy tự tạo, không capture từ mạng thật:

- Ethernet/IPv4/TCP, MAC `02:00:00:00:00:01` → `02:00:00:00:00:02`.
- `10.0.0.1:12345–12351` → `10.0.0.2:80`, mỗi packet có port nguồn riêng.
- Flags PA, seq 1001, ack 2001; timestamp `1700000000`–`1700000006`.
- IP/TCP headers mỗi loại 20 byte; không có handshake hoặc HTTP header. TCP payload chính là chuỗi ASCII trong bảng.

| Packet | Raw payload | Payload / IPv4 byte | R1 | R2 | R3 |
|---|---|---|---|---|---|
| 1 | `ABCXYZ` | 6 / 46 | MATCH | NO_MATCH | NO_MATCH |
| 2 | `ABC12XYZ` | 8 / 48 | NO_MATCH | MATCH | MATCH |
| 3 | `ABC1234XYZ` | 10 / 50 | NO_MATCH | MATCH | MATCH |
| 4 | `ABC12345XYZ` | 11 / 51 | NO_MATCH | MATCH | NO_MATCH |
| 5 | `XYZ12ABC` | 8 / 48 | NO_MATCH | NO_MATCH | NO_MATCH |
| 6 | `ABC12XY` | 7 / 47 | NO_MATCH | NO_MATCH | NO_MATCH |
| 7 | `ABC12345ABC12XYZ` | 16 / 56 | NO_MATCH | MATCH | MATCH |

Packet 1 kiểm tra within dùng riêng. Packet 2 match đúng đầu vùng distance; packet 3 match sát cuối vùng within. Packet 4 vượt cuối vùng một byte, R3 phải NO_MATCH. Packet 5 có hai chuỗi nhưng đảo thứ tự; packet 6 chỉ có XY nên không match toàn bộ XYZ.

Packet 7 kiểm tra việc chọn lại ABC: R2 dùng ABC đầu `[0,3)` và XYZ `[13,16)` vì không giới hạn cuối vùng. R3 không thỏa với ABC đầu, phải chọn ABC thứ hai `[8,11)` rồi tìm XYZ `[13,16)` trong vùng `[13,16)` sau khi giới hạn bởi cuối payload. Không được giữ evidence ABC đầu khi đổi sang cặp thành công.

## Thực hiện

Chạy tại thư mục gốc project trong PowerShell:

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding

& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_03\test_11_distance_within\check_distance_within.py
if ($LASTEXITCODE -ne 0) { throw "T11 failed" }
```

Script dùng Loader thật để kiểm tra thứ tự content và modifier, đọc PCAP để đối chiếu bytes/header/độ dài/timestamp rồi chạy `main.py` thật. Phần API tạo InspectionContext từ normalized event của CLI và raw TCP payload PCAP đã xác minh đầy đủ độ dài; gọi `match_rule()` thật cho ba rule trên từng packet.

Expected status và vị trí của cả hai content được khai báo riêng trong script, không lấy từ Matcher. Script đối chiếu 21 kết quả, evidence hai content, đúng tám detection và metadata tương ứng. NO_MATCH phải có reason từ content stage, không giữ evidence một phần; input/context/raw bytes không được sửa. Các JSONL được đọc lại để kiểm tra. Assertion thất bại trả mã thoát 1 và ghi FAIL vào console.


## Kết quả

**PASS T11.** CLI và script trả mã thoát `0`: bảy event, 21 kết quả full-rule (8 MATCH/13 NO_MATCH), đúng tám detection.

Trong `result.jsonl`, bảy event đều valid/process/tracked, parse/decode errors rỗng, độ dài đúng bảng Dữ liệu. Application protocol UNKNOWN và decode_status not_processed vì đây là raw TCP payload; packet vẫn được đánh giá content bình thường.

Trong `result_matches.jsonl`, mỗi packet có ba dòng theo thứ tự SID101101–101103. Các dòng ghi case, candidate_sids, payload_source, distance/within của content thứ hai và MatchResult. Mọi NO_MATCH có reason_code content_no_match, reason từ content stage và matched_info null; không có evidence dở dang, ERROR hoặc NOT_EVALUABLE.

Trong `result_detections.jsonl`:

| Packet | SID | ABC | XYZ |
|---|---|---|---|
| 1 | 101101 | `[0,3)` | `[3,6)` |
| 2 | 101102, 101103 | `[0,3)` | `[5,8)` |
| 3 | 101102, 101103 | `[0,3)` | `[7,10)` |
| 4 | 101102 | `[0,3)` | `[8,11)` |
| 7 | 101102 | `[0,3)` | `[13,16)` |
| 7 | 101103 | `[8,11)` | `[13,16)` |

Packet 5–6 không có detection. Mỗi detection giữ đúng hai content theo thứ tự index 0/1, pattern_hex/matched_hex `414243` (ABC) và `58595a` (XYZ), buffer payload, nocase false. Header orientation direct; flow/flags/dsize evidence null vì rule không có các điều kiện này. IP/port/timestamp/flow ID khớp event cùng lần chạy, revision/msg đúng rule.

P7/SID101103 xác nhận Matcher đã chọn lại ABC thứ hai và giữ đúng evidence của cặp thành công; P7/SID101102 vẫn dùng ABC đầu tiên. Mỗi cặp packet/rule chỉ tạo một detection.

CLI báo events_evaluated `7`, candidate_rules `21`, matches/detections_written `8`; skip/evaluation error/not-evaluable đều `0`. Script cũng xác nhận input/context/raw bytes không bị sửa và các JSONL đọc lại được.

## Tệp

- `input.rules`: ba rule hai content với within/distance/kết hợp cả hai.
- `input.pcap`: bảy raw TCP payload tự tạo.
- `check_distance_within.py`: kiểm tra fixture, CLI, Matcher và detection.
- `result.jsonl`: bảy IDS event của CLI.
- `result_matches.jsonl`: 21 kết quả full-rule API, gồm cả NO_MATCH.
- `result_detections.jsonl`: tám detection của CLI khi kiểm tra thành công.
- `console.txt`: output CLI và kết quả kiểm tra PASS/FAIL, UTF-8.
- `README.md`: dữ liệu, cách chạy và giải thích kết quả.
