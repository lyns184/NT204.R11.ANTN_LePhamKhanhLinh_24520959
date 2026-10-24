# Test 07 - Header Short-Circuit

## Mục tiêu

Kiểm tra T07 trong mục 7 Bài tập 3: rule có header không match bị loại trước khi Content Matcher được gọi.

Test theo dõi full-rule matcher thật và đối chiếu CLI thật. Chỉ không có detection chưa đủ chứng minh short-circuit; phải kiểm tra số lần gọi content.

## Dữ liệu

### Rule

`input.rules` có một rule hợp lệ:

```text
alert tcp 10.0.0.1 any -> 10.0.0.2 80 (msg:"Header before content"; sid:100701; rev:1; content:"admin";)
```

Rule chỉ có header và một content admin; không có flow, flags, dsize hoặc content modifiers.

### PCAP

- `input.pcap`: ba packet Scapy tự tạo, không capture từ mạng thật.
- Ethernet/IPv4/TCP, flags `PA`, seq `1001`, ack `2001`; IP/TCP headers mỗi loại `20` byte, payload `39` byte, IPv4 total length `79` byte.
- MAC của `10.0.0.1`, `10.0.0.2`, `10.0.0.3`, `10.0.0.9` lần lượt là `02:00:00:00:00:01`, `02:00:00:00:00:02`, `02:00:00:00:00:03`, `02:00:00:00:00:09`.

| Packet | Timestamp | Nguồn → đích | Kết quả cả rule | Header calls | Content calls |
|---|---|---|---|---|---|
| 1 | `1700000000` | `10.0.0.9:12345 → 10.0.0.2:80` | NO_MATCH, sai IP nguồn | `1` | `0` |
| 2 | `1700000001` | `10.0.0.1:12346 → 10.0.0.3:80` | NO_MATCH, sai IP đích | `1` | `0` |
| 3 | `1700000002` | `10.0.0.1:12347 → 10.0.0.2:80` | MATCH | `1` | `1` |

Cả ba packet chứa cùng raw HTTP request; mỗi dòng kết thúc bằng CRLF, cuối headers có một dòng trống:

```http
GET /admin HTTP/1.1
Host: ids.test

```


## Thực hiện

Chạy tại thư mục gốc project trong PowerShell:

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding

& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_03\test_07_header_short_circuit\check_header_short_circuit.py
if ($LASTEXITCODE -ne 0) { throw "T07 failed" }
```

Script nạp rule và kiểm tra PCAP rồi chạy `main.py` thật, lưu event/detection JSONL. Sau đó tạo `InspectionContext` từ normalized event của CLI và raw TCP payload đã đọc/kiểm tra độ dài trong PCAP; không lấy decoded URI làm payload, không đưa Scapy packet trực tiếp vào Matcher.

Mỗi context được kiểm tra là candidate của Repository rồi đưa vào `match_rule()` thật. Spy `wraps` trên `ids.detection.matcher.match_header` và `match_contents` chỉ ghi nhận lời gọi/thứ tự, vẫn chạy matcher thật và không trả kết quả giả.

## Kết quả

**PASS T07.** CLI và script trả mã thoát `0`; đủ ba event, ba candidate, kết quả matcher và call order đúng bảng Dữ liệu, duy nhất một detection cho packet 3.

Trong `result.jsonl`, cả ba event preprocess valid/process, flow tracked, HTTP path `/admin`, payload length `39`, parse/decode errors rỗng.

Trong `result_matches.jsonl`, mỗi dòng là kết quả full-rule API kèm candidate SID và số/thứ tự lời gọi matcher:

- Dòng 1–2: `candidate_sids = [100701]`, status NO_MATCH, `header_matcher_calls = 1`, `content_matcher_calls = 0`, `matcher_calls = ["header"]`. Reason_code là `header_no_match`, reason bắt đầu `header:`, matched_info là null.
- Dòng 3: status MATCH, `header_matcher_calls = 1`, `content_matcher_calls = 1`, `matcher_calls = ["header","content"]`. Header orientation direct; content index `0` có pattern_hex/matched_hex `61646d696e` (admin), start `5`/end `10`, nocase false.
- Cả ba không có matcher diagnostics. Context/payload và hai file input được giữ nguyên; kết quả JSONL đọc lại đúng dữ liệu đã xuất.

Trong `result_detections.jsonl` có đúng một dòng:

| Field | Kết quả |
|---|---|
| packet_id / sid / rev | `3` / `100701` / `1` |
| msg | `Header before content` |
| Source → destination | `10.0.0.1:12347 → 10.0.0.2:80` |
| protocol / application_protocol | TCP / HTTP |
| timestamp / flow_id | Giống event packet 3 trong cùng lần chạy |
| matched_info | Header direct, content admin ở `[5,10)`; flow/flags/dsize null |

Không có detection cho packet 1–2 dù payload vẫn có admin. CLI báo `events_evaluated = candidate_rules = 3`, `matches = detections_written = 1`, skip/evaluation error/not-evaluable đều `0`. 

## Tệp

- `input.rules`: một rule header + content admin.
- `input.pcap`: ba HTTP packet cùng payload, khác IP/port nguồn hoặc IP đích.
- `check_header_short_circuit.py`: tự kiểm tra fixture, CLI và matcher thật với wraps spies.
- `result.jsonl`: ba IDS event từ PCAP.
- `result_matches.jsonl`: ba kết quả full-rule API, candidate SID, call counts và call order.
- `result_detections.jsonl`: một detection của packet 3.
- `console.txt`: stdout/stderr CLI và các kiểm tra PASS/FAIL, UTF-8.
- `README.md`: dữ liệu, cách chạy và giải thích kết quả.
