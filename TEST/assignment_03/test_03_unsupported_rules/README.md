# Test 03 - Unsupported Rules

## Mục tiêu

Kiểm tra T03 trong mục 7 Bài tập 3: rule có keyword ngoài phạm vi được đánh dấu unsupported, có lý do và không làm chương trình dừng.

Test xác nhận toàn bộ rule unsupported bị loại khỏi Engine; hai rule hợp lệ nằm trước/sau vẫn chạy và sinh detection.

## Dữ liệu

### File rules

- File: `input.rules`, năm dòng, UTF-8; fixture viết riêng cho test.
- Các dòng có đủ msg/sid/rev và dấu đóng ngoặc/chuỗi. Không truyền config.

| Dòng | SID | Nội dung | Mong đợi |
|---|---|---|---|
| 1 | `100301` | TCP port đích `80`, msg `Valid before unsupported` | Enabled |
| 2 | `100302` | Dùng `pcre` | Unsupported |
| 3 | `100303` | Có `content:"admin"; http_uri;` | Unsupported toàn bộ rule |
| 4 | `100304` | Dùng `byte_test` | Unsupported |
| 5 | `100305` | TCP port đích `8080`, msg `Valid after unsupported` | Enabled |

Cả ba rule unsupported có header TCP port đích `80`. Parser ghi nhận keyword ngoài MVP, không thực thi hoặc khẳng định đã kiểm tra đầy đủ ngữ nghĩa của keyword đó.

### PCAP

- File: `input.pcap`, hai packet tự tạo bằng Scapy, không capture từ mạng thật.
- Client/server: `10.0.0.1` → `10.0.0.2`, MAC `02:00:00:00:00:01` → `02:00:00:00:00:02`.
- Ethernet/IPv4/TCP; flags `PA`, seq `1001`, ack `2001`, IPv4/TCP headers mỗi loại `20` byte.

| Packet | Timestamp | Client port | Server port | TCP payload | IPv4 total length | SID mong đợi |
|---|---|---|---|---|---|---|
| 1 | `1700000000` | `12345` | `80` | `39` byte | `79` byte | `100301` |
| 2 | `1700000001` | `12346` | `8080` | `39` byte | `79` byte | `100305` |

Cả hai có cùng HTTP request; mỗi dòng kết thúc bằng CRLF, cuối headers có một dòng trống:

```http
GET /admin HTTP/1.1
Host: ids.test

```

Packet 1 khớp header của ba rule unsupported và chứa `admin` ở vị trí byte `[5,10)`. Nếu bỏ qua `http_uri` rồi chạy riêng content, SID `100303` có thể sinh detection sai; kết quả mong đợi là không có SID này.

Không có handshake trong fixture. Hai rule hợp lệ chỉ kiểm tra header, không yêu cầu established hoặc flow direction.

## Thực hiện

Chạy tại thư mục gốc project trong PowerShell:

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding

& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_03\test_03_unsupported_rules\check_unsupported_rules.py
if ($LASTEXITCODE -ne 0) { throw "T03 failed" }
```

Script gọi Loader/Parser thật, kiểm tra status/diagnostic/source/keyword và tập rule enabled, rồi ghi/đọc lại `result_rules.json`. Reason phải không rỗng; không cố định nguyên văn thông báo lỗi.

Script đọc lại PCAP để kiểm tra packet/payload, sau đó chạy `main.py` với file rules. CLI stdout/stderr, counters và kết quả assertions lưu trong `console.txt` UTF-8; thành công trả `0`, thất bại ghi FAIL và trả `1`.

Flow output phụ lưu ở `output/t03_unsupported_rules/flows.jsonl`, không thuộc hồ sơ T03.

## Kết quả

**PASS T03.** CLI và script trả mã thoát `0`; cả ba keyword ngoài phạm vi được báo unsupported, hai packet vẫn được xử lý và sinh đúng hai detection.

Trong `result_rules.json`:

- `rules_total = 5`, `rules_enabled = 2`, `rules_unsupported = 3`; invalid/disabled/duplicate đều `0`.
- `entries` lần lượt là enabled, unsupported, unsupported, unsupported, enabled.
- Dòng `2`–`4` có `rule = null`; diagnostic `code = unsupported_keyword`, category unsupported, keyword lần lượt pcre/http_uri/byte_test; reason có nội dung và source đúng file/dòng.
- `enabled_rules` chỉ có SID `100301` rồi `100305`, source line `1` và `5`. Không có partial rule từ ba dòng unsupported.
- Source/file path là đường dẫn tuyệt đối của fixture, có thể thay đổi khi chạy ở thư mục khác.

Trong `result.jsonl`, hai event có HTTP path `/admin`, payload length `39`, preprocess valid/process và flow tracked; parse/decode errors rỗng. Hai packet thuộc hai kết nối riêng; không cần so UUID cố định.

Trong `result_detections.jsonl`:

| Dòng | `packet_id` | `sid` | `msg` | Port nguồn → đích |
|---|---|---|---|---|
| 1 | `1` | `100301` | `Valid before unsupported` | `12345` → `80` |
| 2 | `2` | `100305` | `Valid after unsupported` | `12346` → `8080` |

Cả hai có revision `1`, protocol TCP, application_protocol HTTP; timestamp/flow ID khớp event tương ứng. `matched_info.header` là matched/direct; flow/flags/dsize là null, contents là `[]` vì hai rule enabled chỉ kiểm tra header.

Không có detection SID `100302`, `100303` hoặc `100304`. CLI báo `events_evaluated = candidate_rules = matches = detections_written = 2`; skip/evaluation error/not-evaluable đều `0`. Ba unsupported rule không trở thành candidate hoặc match từng phần.


## Tệp

- `input.rules`: hai rule hợp lệ xen ba rule có keyword ngoài phạm vi.
- `input.pcap`: hai HTTP request tự tạo, payload chứa admin.
- `check_unsupported_rules.py`: tự kiểm tra Loader, PCAP, CLI và events/detections.
- `result_rules.json`: báo cáo nạp rule và diagnostics unsupported.
- `result.jsonl`: hai IDS event từ PCAP.
- `result_detections.jsonl`: hai detection từ các rule enabled.
- `console.txt`: stdout/stderr CLI và các kiểm tra PASS/FAIL, UTF-8.
- `README.md`: mục tiêu, dữ liệu, cách chạy và giải thích kết quả.
