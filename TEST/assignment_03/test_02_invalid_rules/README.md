# Test 02 - Invalid Rules

## Mục tiêu

Kiểm tra T02 trong mục 7 Bài tập 3: rule sai cú pháp/giá trị được đánh dấu invalid, có lý do; chương trình vẫn nạp và chạy các rule hợp lệ còn lại.

Test gồm kiểm tra trực tiếp Loader/Parser và chạy CLI với PCAP để chứng minh hai rule hợp lệ nằm trước/sau các dòng lỗi vẫn sinh detection.

## Dữ liệu

### File rules

- File: `input.rules`, sáu dòng, mã hóa UTF-8; fixture viết riêng cho test.
- Không truyền config, không disable rule hoặc file nào.

| Dòng | Nội dung | Kết quả mong đợi |
|---|---|---|
| 1 | TCP port đích `80`, SID `100201`, msg `Valid before errors` | Enabled |
| 2 | Thiếu dấu `)` cuối rule | Invalid, `missing_parenthesis` |
| 3 | Port đích `99999`, vượt `65535` | Invalid, `out_of_range`, keyword `dst_port` |
| 4 | Có msg/rev nhưng thiếu SID | Invalid, `missing_identification`, keyword `sid` |
| 5 | Chuỗi msg thiếu dấu nháy đóng | Invalid, `unterminated_string` |
| 6 | TCP port đích `8080`, SID `100206`, msg `Valid after errors` | Enabled |

Hai rule hợp lệ có action `alert`, source/destination IP `any`, source port `any`, direction `->`, revision `1`; không có content, flags, dsize hoặc flow condition.

### PCAP

- File: `input.pcap`, hai packet tự tạo bằng Scapy, không capture từ mạng thật.
- Client: `10.0.0.1`, MAC `02:00:00:00:00:01`.
- Server: `10.0.0.2`, MAC `02:00:00:00:00:02`.
- Ethernet/IPv4/TCP; mỗi packet có IP header `20` byte, TCP header `20` byte, không có payload.

| Packet | Timestamp | Client port | Server port | Flags | Sequence / Acknowledgment | IPv4 total length | SID mong đợi |
|---|---|---|---|---|---|---|---|
| 1 | `1700000000` | `12345` | `80` | S | `1000` / `0` | `40` byte | `100201` |
| 2 | `1700000001` | `12346` | `8080` | S | `1000` / `0` | `40` byte | `100206` |

Hai SYN mở hai kết nối riêng, chưa có handshake hoàn chỉnh. Rule chỉ kiểm tra header nên vẫn có thể match, không cần established hoặc dữ liệu HTTP.

## Thực hiện

Chạy tại thư mục gốc project trong PowerShell:

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding

& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_03\test_02_invalid_rules\check_invalid_rules.py
if ($LASTEXITCODE -ne 0) { throw "T02 failed" }
```

Script gọi Loader/Parser thật, kiểm tra status/diagnostic của từng dòng và tập rule enabled, rồi ghi/đọc lại `result_rules.json`. Các assertion dùng diagnostic code/keyword/source và reason không rỗng, không cố định nguyên văn thông báo lỗi.

Sau khi đọc lại PCAP để kiểm tra fixture, script chạy `main.py` với `--rules`, `--output`, `--detection-output` và `--flow-output`. Script kiểm tra exit code, diagnostics/counters CLI, event và detection JSONL; timestamp/flow ID được đối chiếu trong cùng lần chạy.

Flow summary phụ lưu ở `output/t02_invalid_rules/flows.jsonl`, không thuộc hồ sơ T02. Stdout/stderr CLI và các bước kiểm tra lưu trong `console.txt` UTF-8. Script thành công trả `0`; assertion/CLI thất bại ghi FAIL và trả `1`.

## Kết quả

**PASS T02.** CLI và script trả mã thoát `0`; hai packet được xử lý và sinh đúng hai detection mặc dù file có bốn rule lỗi.

Trong `result_rules.json`:

- `rules_total = 6`, `rules_enabled = 2`, `rules_invalid = 4`; unsupported/disabled/duplicate đều `0`.
- `entries` có status lần lượt `enabled`, `invalid`, `invalid`, `invalid`, `invalid`, `enabled`.
- Bốn entry invalid có `rule = null` và diagnostic `category = invalid`, lý do đúng loại lỗi trong bảng Dữ liệu, source trỏ đúng dòng `2`–`5`.
- `enabled_rules` chỉ có SID `100201` rồi `100206`, source line `1` và `6`. Các rule lỗi không được đưa sang Engine để chạy.
- `source.file` và `files[].path` là đường dẫn tuyệt đối của `input.rules`, có thể thay đổi khi chạy ở thư mục khác.

Trong `result.jsonl`, có đúng hai event:

- Packet `1`: TCP SYN đến port `80`; packet `2`: TCP SYN đến port `8080`.
- Cả hai `preprocess_status = valid`, `processing_action = process`, `flow_tracking_status = tracked`; parse/decode errors rỗng.
- `application.protocol = UNKNOWN`, `decode_status = not_processed` vì không có application payload; đây không phải lỗi.
- Hai flow ID khác nhau vì endpoint/port khác nhau; không so UUID với giá trị cố định.

Trong `result_detections.jsonl`:

| Dòng | `packet_id` | `sid` | `msg` | `src_port` → `dst_port` |
|---|---|---|---|---|
| 1 | `1` | `100201` | `Valid before errors` | `12345` → `80` |
| 2 | `2` | `100206` | `Valid after errors` | `12346` → `8080` |

Cả hai detection có protocol TCP, revision `1`, timestamp/flow ID giống event tương ứng. `matched_info.header` là matched/direct; flow/flags/dsize là `null`, contents là `[]` vì rule chỉ có header. Không có detection từ bốn dòng invalid.

CLI in đủ diagnostic của bốn rule lỗi và báo `events_evaluated = candidate_rules = matches = detections_written = 2`, `events_skipped = rule_evaluation_errors = rule_not_evaluable = 0`. `rules_invalid = 4` là lỗi khi nạp rule, khác với `rule_evaluation_errors` khi Engine đánh giá packet.

Các output JSON đọc lại thành công và hai file đầu vào không bị sửa.

## Tệp

- `input.rules`: hai rule hợp lệ xen bốn rule lỗi.
- `input.pcap`: hai TCP SYN tự tạo, dùng kiểm tra Engine qua CLI.
- `check_invalid_rules.py`: tái hiện và tự kiểm tra Loader, PCAP, CLI, events/detections.
- `result_rules.json`: báo cáo nạp sáu dòng rule, gồm diagnostics và hai rule enabled.
- `result.jsonl`: hai IDS event từ PCAP.
- `result_detections.jsonl`: hai detection của hai rule hợp lệ.
- `console.txt`: stdout/stderr CLI và dữ liệu kiểm tra PASS/FAIL, lưu UTF-8.
- `README.md`: mục tiêu, dữ liệu, cách chạy và giải thích kết quả.
