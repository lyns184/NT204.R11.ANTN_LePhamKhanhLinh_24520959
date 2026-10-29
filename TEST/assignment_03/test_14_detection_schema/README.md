# Test 14 - Detection Schema

## Mục tiêu

Kiểm tra T14 Bài tập 3: detection có đủ field, đúng kiểu dữ liệu và giá trị của rule/packet đã MATCH. Kiểm tra nullable metadata, protocol thực tế của rule IP, endpoint khi match reverse, message tiếng Việt và content binary khi ghi JSONL. Generator phải từ chối NO_MATCH.

## Dữ liệu

`input.rules` có ba rule hợp lệ:

| Rule / SID | Header và content | Metadata |
|---|---|---|
| R1 / 101401 | TCP `10.0.0.1 any -> 10.0.0.2 80`, content admin | rev 2, msg Phát hiện admin, classtype web-application-attack, priority 1 |
| R2 / 101402 | IP `any any -> any any`, content example | rev 1, msg DNS marker; không khai báo classtype/priority |
| R3 / 101403 | TCP `10.0.0.1 12345 <> 10.0.0.2 8080`, content `\|00 FF 41\|` | rev 3, msg Binary response; không khai báo classtype/priority |

Ba rule đều chỉ có một content, không modifier hoặc flow/flags/dsize condition. Metadata classtype/priority không khai báo phải xuất key với null.

`input.pcap` gồm bốn packet Scapy tự tạo, không capture từ mạng thật:

| Packet | Nguồn → đích | Payload | Payload / IPv4 byte | Candidate | Detection |
|---|---|---|---|---|---|
| 1 | TCP `10.0.0.1:12345 → 10.0.0.2:80` | HTTP GET /admin | 39 / 79 | R1, R2 | R1 |
| 2 | UDP `10.0.0.3:53000 → 10.0.0.2:53` | DNS query example.test | 30 / 58 | R2 | R2 |
| 3 | TCP `10.0.0.2:8080 → 10.0.0.1:12345` | Binary `00 FF 41` | 3 / 43 | R2, R3 | R3, reverse |
| 4 | TCP `10.0.0.1:12346 → 10.0.0.2:80` | HTTP GET /public | 40 / 80 | R1, R2 | Không có |

- Timestamp `1700000000`–`1700000003`; Ethernet MAC tương ứng IP .1/.2/.3 là `02:00:00:00:00:01`/`02`/`03`.
- IP header 20 byte; TCP header 20 byte, flags PA, không có handshake. TCP seq/ack 1001/2001 ở P1/P4 và 2001/1001 ở P3.
- HTTP request dùng version HTTP/1.1, header Host: ids.test và CRLF kết thúc header; chỉ khác path.
- P2 có DNS transaction ID `0x1402`, RD=1, một question A/IN, qname example.test.; UDP length 38 byte.
- P3 chứa byte FF không phải UTF-8 hợp lệ; application UNKNOWN/decode not_processed, Matcher vẫn dùng raw bytes.

Có thêm **một ca API mô phỏng riêng**, không phải packet thứ năm: lấy normalized metadata và raw payload đã xác minh của P1 để tạo InspectionContext không có packet_id hoặc flow context. Context này được match thật với R1 trước khi gọi Generator. Detection được ghi riêng vào `direct_detections.jsonl`, packet_id/flow_id phải null; không trộn vào event/detection/summary CLI.

## Thực hiện

Chạy tại thư mục gốc project trong PowerShell:

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding

& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_03\test_14_detection_schema\check_detection_schema.py
if ($LASTEXITCODE -ne 0) { throw "T14 failed" }
```

Script dùng Loader thật để kiểm tra header/content/metadata, đọc PCAP để đối chiếu bytes/độ dài/IP/port/timestamp, rồi chạy `main.py` thật. Phần Matcher API dùng normalized event CLI và complete raw TCP/UDP payload PCAP; đối chiếu bảy candidate results với kỳ vọng khai báo riêng.

Ba detection CLI và một detection API riêng phải có đúng 15 key:

```text
timestamp, packet_id, sid, rev, msg, classtype, priority,
src_ip, dst_ip, src_port, dst_port, protocol, application_protocol,
flow_id, matched_info
```

Script kiểm tra kiểu dữ liệu (không coi bool hoặc numeric string là integer), kiểu nullable, IPv4 canonical, schema con của matched_info, hex và byte range. Toàn bộ giá trị được đối chiếu với expected metadata/evidence độc lập, flow ID chỉ đối chiếu với event trong cùng lần chạy, không dùng UUID cố định. Key thiếu hoặc thêm raw payload đều bị từ chối.

Generator/JSONLWriter thật tạo detection API riêng; script kiểm tra packet_id/flow_id null, thay đổi dictionary xuất ra không sửa DetectionEvent/context gốc, và Generator ném ValueError với NO_MATCH thật của P4/R1. JSONL được đọc UTF-8, mỗi dòng một object, không nhận duplicate key hoặc NaN/Infinity; message tiếng Việt phải roundtrip đúng sau Unicode escaping. Input/context/raw bytes không được sửa. Assertion thất bại trả mã thoát 1 và ghi FAIL vào console.

## Kết quả

**PASS T14.** CLI và script trả mã thoát `0`: bốn event, bảy kết quả full-rule (3 MATCH/4 NO_MATCH), ba detection CLI và một detection API riêng.

Trong `result.jsonl`, bốn event đều valid/process/tracked, parse/decode errors rỗng; P4 vẫn có event dù không rule nào MATCH. Application protocol lần lượt HTTP/DNS/UNKNOWN/HTTP.

Trong `result_matches.jsonl`, các candidate đúng bảng Dữ liệu. Mọi NO_MATCH do content stage, reason_code content_no_match, matched_info null. Không có ERROR hoặc NOT_EVALUABLE.

Trong `result_detections.jsonl` có đúng ba dòng, đủ 15 key đúng kiểu và giá trị:

| Packet / SID | Protocol / application | Orientation | Content hex | Byte range |
|---|---|---|---|---|
| 1 / 101401 | TCP / HTTP | direct | `61646d696e` (admin) | `[5,10)` |
| 2 / 101402 | UDP / DNS | direct | `6578616d706c65` (example) | `[13,20)` |
| 3 / 101403 | TCP / UNKNOWN | reverse | `00ff41` | `[0,3)` |

P1 giữ đúng rev 2, msg Phát hiện admin, classtype web-application-attack và priority 1. P2/P3 có classtype/priority null; P3 giữ rev 3. P2 dùng rule IP nhưng protocol detection vẫn là UDP. P3 giữ nguồn 10.0.0.2:8080 và đích 10.0.0.1:12345 theo packet, không đảo endpoint theo header rule. Timestamp/packet ID/flow ID khớp event cùng lần chạy.

Matched_info có header matched true, flow/flags/dsize null và một content có index 0, buffer payload, nocase false. Binary chỉ xuất evidence hex/range, không dump raw payload. File detection escape Unicode bằng ASCII nhưng JSON decode khôi phục đúng message tiếng Việt.

`direct_detections.jsonl` có đúng một detection R1, packet_id/flow_id null, các field khác vẫn đúng như ca API đã mô tả. Ca này dùng MATCH thật; NO_MATCH của P4/R1 bị Generator từ chối bằng ValueError. Dictionary xuất ra có thể thay đổi mà không ảnh hưởng object gốc.

CLI báo events_evaluated 4, candidate_rules 7, matches/detections_written 3; skip/evaluation error/not-evaluable đều 0. Input/context/raw bytes giữ nguyên, cả bốn file JSONL đọc lại được.

## Tệp

- `input.rules`: ba rule TCP/IP và metadata đầy đủ/tùy chọn.
- `input.pcap`: bốn packet HTTP/DNS/binary tự tạo.
- `check_detection_schema.py`: kiểm tra fixture, CLI, Matcher, Generator, schema và JSONL.
- `result.jsonl`: bốn IDS event của CLI.
- `result_matches.jsonl`: bảy full-rule MatchResult API, gồm NO_MATCH.
- `result_detections.jsonl`: ba detection của CLI.
- `direct_detections.jsonl`: một detection từ ca context API mô phỏng thiếu ID, lưu riêng.
- `console.txt`: output CLI và kết quả kiểm tra PASS/FAIL, UTF-8.
- `README.md`: dữ liệu, cách chạy và giải thích kết quả.
