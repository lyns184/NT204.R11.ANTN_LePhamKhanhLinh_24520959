# Test 09 - Content / Nocase

## Mục tiêu

Kiểm tra T09 trong mục 7 Bài tập 3: content mặc định phân biệt hoa/thường; thêm nocase thì so khớp không phân biệt hoa/thường ASCII.



## Dữ liệu

### Rules

`input.rules` có hai rule hợp lệ, cùng pattern `b"admin"`, khác nocase và identification:

```text
alert tcp any any -> any 80 (msg:"Case sensitive admin"; sid:100901; rev:1; content:"admin";)
alert tcp any any -> any 80 (msg:"Case insensitive admin"; sid:100902; rev:1; content:"admin"; nocase;)
```

Không có flow/flags/dsize hoặc giới hạn vị trí content. Cả hai rule phải là candidate cho mọi packet trong fixture.

### PCAP

- `input.pcap`: sáu packet Scapy tự tạo, không capture từ mạng thật.
- Client/server: `10.0.0.1` → `10.0.0.2:80`, MAC `02:00:00:00:00:01` → `02:00:00:00:00:02`.
- Port nguồn lần lượt `12345`–`12350`; timestamp `1700000000`–`1700000005`.
- Ethernet/IPv4/TCP, flags `PA`, seq `1001`, ack `2001`; IP/TCP headers mỗi loại `20` byte, không có handshake trong PCAP.

| Packet | Payload / raw URI | Payload byte | IPv4 length | SID100901 | SID100902 |
|---|---|---|---|---|---|
| 1 | HTTP GET `/admin` | `39` | `79` | MATCH | MATCH |
| 2 | HTTP GET `/ADMIN` | `39` | `79` | NO_MATCH | MATCH |
| 3 | HTTP GET `/AdMiN` | `39` | `79` | NO_MATCH | MATCH |
| 4 | HTTP GET `/public` | `40` | `80` | NO_MATCH | NO_MATCH |
| 5 | HTTP GET `/%61dmin` | `41` | `81` | NO_MATCH | NO_MATCH |
| 6 | Binary `b"\x00AdMiN\xff"` | `7` | `47` | NO_MATCH | MATCH |

Các HTTP request có cùng version/header, chỉ khác URI. Ví dụ packet 1; mỗi dòng kết thúc bằng CRLF và cuối headers có một dòng trống:

```http
GET /admin HTTP/1.1
Host: ids.test

```

Packet 6 có bytes `00 41 64 4d 69 4e ff`, không phải UTF-8 hợp lệ. Content Matcher vẫn làm việc trực tiếp trên bytes; không cần decode thành text.

## Thực hiện

Chạy tại thư mục gốc project trong PowerShell:

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding

& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_03\test_09_content_nocase\check_content_nocase.py
if ($LASTEXITCODE -ne 0) { throw "T09 failed" }
```

Script nạp hai rule bằng Loader thật, kiểm tra pattern/nocase và đọc lại PCAP để đối chiếu payload/độ dài. Sau đó chạy `main.py` thật, đọc event/detection JSONL.

Phần API tạo InspectionContext từ normalized event của CLI và raw TCP payload trong PCAP đã kiểm tra đầy đủ độ dài; gọi `match_rule()` thật cho cả hai rule trên từng packet. Expected status/bytes/byte range được khai báo riêng trong script, không lấy từ output Matcher.

Script đối chiếu 12 kết quả API, mọi positive evidence và đúng năm detection của CLI; kiểm tra context/raw payload/input không đổi và JSONL đọc lại được. 

## Kết quả

**PASS T09.** CLI và script trả mã thoát `0`; đủ sáu event, 12 kết quả cả rule (5 MATCH/7 NO_MATCH), đúng năm detection.

Trong `result.jsonl`:

- Cả sáu event valid/process/tracked, parse/decode errors rỗng; payload length đúng bảng Dữ liệu.
- Packet 1–5 nhận diện HTTP, normalized path giữ nguyên hoa/thường và percent-encoding.
- Packet 5 có raw/normalized path `/%61dmin`, còn `decoded.http.uri.value = /admin`; hai rule vẫn NO_MATCH vì raw payload chưa có literal admin.
- Packet 6 có application protocol UNKNOWN, decode_status not_processed. Đây không phải lỗi; packet vẫn được đánh giá content theo TCP payload bytes.

Trong `result_matches.jsonl`, mỗi packet có hai dòng theo thứ tự SID100901 rồi SID100902. Các dòng ghi case, candidate_sids, payload_source, nocase và MatchResult. Cả hai rule đều là candidate; NO_MATCH có reason_code content_no_match, reason từ content stage, matched_info null. Không có ERROR hoặc NOT_EVALUABLE.

Trong `result_detections.jsonl`:

| Dòng | Packet / SID | matched_hex | Byte range | nocase |
|---|---|---|---|---|
| 1 | `1 / 100901` | `61646d696e` (admin) | `[5,10)` | false |
| 2 | `1 / 100902` | `61646d696e` (admin) | `[5,10)` | true |
| 3 | `2 / 100902` | `41444d494e` (ADMIN) | `[5,10)` | true |
| 4 | `3 / 100902` | `41644d694e` (AdMiN) | `[5,10)` | true |
| 5 | `6 / 100902` | `41644d694e` (AdMiN) | `[1,6)` | true |


IP/port/timestamp/flow ID khớp event trong cùng lần chạy, revision/msg đúng rule. Protocol TCP; application_protocol HTTP cho packet 1–3 và UNKNOWN cho packet 6. Không có detection cho packet 4–5 hoặc SID100901 trên payload hoa/thường khác admin.

CLI báo events_evaluated `6`, candidate_rules `12`, matches/detections_written `5`, skip/evaluation error/not-evaluable đều `0`. 

## Tệp

- `input.rules`: hai rule content admin có/không nocase.
- `input.pcap`: sáu payload gồm HTTP và binary tự tạo.
- `check_content_nocase.py`: tự kiểm tra fixture, CLI, API matching và evidence.
- `result.jsonl`: sáu IDS event của CLI.
- `result_matches.jsonl`: 12 kết quả full-rule API, gồm cả NO_MATCH.
- `result_detections.jsonl`: năm detection của CLI.
- `console.txt`: output CLI và các kiểm tra PASS/FAIL, UTF-8.
- `README.md`: dữ liệu, cách chạy và giải thích kết quả.
