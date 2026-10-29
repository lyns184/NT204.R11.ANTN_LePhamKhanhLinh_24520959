# Test 10 - Offset / Depth

## Mục tiêu

Kiểm tra T10 Bài tập 3: tìm content trong đúng vùng byte của raw TCP payload theo offset/depth. Offset đếm từ 0, là vị trí bắt đầu tìm; depth giới hạn số byte tính từ offset (hoặc từ 0 nếu không có offset). Toàn bộ pattern phải nằm trong vùng tìm.

## Dữ liệu

`input.rules` gồm bốn rule hợp lệ, cùng header TCP `any any -> any 80`, pattern `admin`, revision 1:

| Rule / SID | Điều kiện content | Vùng tìm với payload dài N byte |
|---|---|---|
| R1 / 101001 | `content:"admin";` | `[0,N)` |
| R2 / 101002 | `content:"admin"; offset:4;` | `[4,N)` |
| R3 / 101003 | `content:"admin"; depth:5;` | `[0,min(N,5))` |
| R4 / 101004 | `content:"admin"; offset:4; depth:5;` | `[4,min(N,9))` |

Không có nocase/flow/flags/dsize hoặc content tương đối. Các giá trị depth đều bằng độ dài pattern (5 byte), là rule hợp lệ; NO_MATCH trong bảng dưới là kết quả matching trên packet.

`input.pcap` có sáu packet Scapy tự tạo, không capture từ mạng thật:

- Ethernet/IPv4/TCP, MAC `02:00:00:00:00:01` → `02:00:00:00:00:02`.
- `10.0.0.1:12345–12350` → `10.0.0.2:80`, mỗi packet có port nguồn riêng.
- Flags `PA`, seq `1001`, ack `2001`, timestamp `1700000000`–`1700000005`.
- IP/TCP headers mỗi loại 20 byte; không có handshake hay HTTP header. TCP payload chính là chuỗi ASCII trong bảng.

| Packet | Raw payload | Payload / IPv4 byte | R1 | R2 | R3 | R4 |
|---|---|---|---|---|---|---|
| 1 | `admin1234` | 9 / 49 | MATCH | NO_MATCH | MATCH | NO_MATCH |
| 2 | `1234admin` | 9 / 49 | MATCH | MATCH | NO_MATCH | MATCH |
| 3 | `12345admin` | 10 / 50 | MATCH | MATCH | NO_MATCH | NO_MATCH |
| 4 | `123admin` | 8 / 48 | MATCH | NO_MATCH | NO_MATCH | NO_MATCH |
| 5 | `1234admiX` | 9 / 49 | NO_MATCH | NO_MATCH | NO_MATCH | NO_MATCH |
| 6 | `1234adm` | 7 / 47 | NO_MATCH | NO_MATCH | NO_MATCH | NO_MATCH |

Packet 2 có `admin` tại `[4,9)`, vừa khít R4. Packet 3 có pattern tại `[5,10)`: R2 vẫn match dù pattern không bắt đầu ngay tại offset; R4 không match vì pattern vượt cuối vùng. Packet 4 bắt đầu pattern trước offset; phần còn lại trong vùng không đủ để match. Packet 5 sai byte cuối; packet 6 chỉ có `adm`, vùng tìm bị giới hạn bởi cuối payload.

## Thực hiện

Chạy tại thư mục gốc project trong PowerShell:

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding

& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_03\test_10_offset_depth\check_offset_depth.py
if ($LASTEXITCODE -ne 0) { throw "T10 failed" }
```

Script nạp rule bằng Loader thật, kiểm tra offset/depth sau parse và đọc PCAP để đối chiếu chính xác bytes, độ dài, header và timestamp. Sau đó chạy `main.py` thật để tạo event/detection JSONL.

Phần API tạo InspectionContext từ normalized event của CLI và raw TCP payload PCAP đã kiểm tra đầy đủ độ dài; gọi `match_rule()` thật cho cả bốn rule trên từng packet. Bảng kỳ vọng và vị trí match được khai báo riêng trong script, không lấy từ kết quả Matcher. Script kiểm tra cả status, reason, evidence, metadata detection, context/input không đổi và đọc lại các JSONL. Assertion thất bại trả mã thoát 1 và ghi FAIL vào console.


## Kết quả

**PASS T10.** CLI và script trả mã thoát `0`: sáu event, 24 kết quả full-rule (8 MATCH/16 NO_MATCH), tám detection.

Trong `result.jsonl`, sáu event đều valid/process/tracked, parse/decode errors rỗng, độ dài payload đúng bảng Dữ liệu. Application protocol UNKNOWN và decode_status not_processed vì đây là raw TCP payload, không phải HTTP message; không ảnh hưởng việc đánh giá content.

Trong `result_matches.jsonl`, mỗi packet có bốn dòng theo thứ tự SID101001–101004. Các dòng ghi case, candidate_sids, payload_source, offset/depth và MatchResult. Mọi NO_MATCH đều do content stage, có reason_code content_no_match và matched_info null. Không có ERROR hoặc NOT_EVALUABLE; payload ngắn vẫn xử lý bình thường.

Trong `result_detections.jsonl`:

| Packet | SID phát hiện | Vị trí admin |
|---|---|---|
| 1 | 101001, 101003 | `[0,5)` |
| 2 | 101001, 101002, 101004 | `[4,9)` |
| 3 | 101001, 101002 | `[5,10)` |
| 4 | 101001 | `[3,8)` |
| 5–6 | Không có | — |

Mỗi detection có pattern_hex/matched_hex `61646d696e`, buffer payload, index 0, nocase false, header orientation direct; flow/flags/dsize evidence null vì rule không có các điều kiện này. IP/port/timestamp/flow ID khớp event trong cùng lần chạy, revision/msg đúng rule. Không có detection cho pattern nằm ngoài vùng tìm hoặc chỉ khớp một phần.

CLI báo events_evaluated `6`, candidate_rules `24`, matches/detections_written `8`; skip/evaluation error/not-evaluable đều `0`. Script cũng xác nhận input/context/raw payload không bị sửa và đọc lại được các JSONL.

## Tệp

- `input.rules`: bốn rule đối chứng/offset/depth/offset kết hợp depth.
- `input.pcap`: sáu raw TCP payload tự tạo.
- `check_offset_depth.py`: kiểm tra fixture, CLI, full-rule matcher và detection.
- `result.jsonl`: sáu IDS event của CLI.
- `result_matches.jsonl`: 24 kết quả full-rule API, gồm cả NO_MATCH.
- `result_detections.jsonl`: tám detection của CLI khi kiểm tra thành công.
- `console.txt`: output CLI và kết quả kiểm tra PASS/FAIL, UTF-8.
- `README.md`: dữ liệu, cách chạy và giải thích kết quả.
