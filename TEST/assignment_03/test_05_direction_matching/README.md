# Test 05 - Direction Matching

## Mục tiêu

Kiểm tra T05 trong mục 7 Bài tập 3: header direction `->` chỉ match chiều khai báo, `<>` match cả hai chiều khi toàn bộ endpoint IP/port được đảo đúng.

Test kiểm tra trực tiếp Header Matcher trên normalized event từ CLI, đồng thời đối chiếu Detection JSONL để xác nhận orientation và metadata packet được giữ đúng.

## Dữ liệu

### Rules

File `input.rules` có hai rule hợp lệ:

```text
alert tcp 10.0.0.1 12345 -> 10.0.0.2 80 (msg:"Forward only"; sid:100501; rev:1;)
alert tcp 10.0.0.1 12345 <> 10.0.0.2 80 (msg:"Both directions"; sid:100502; rev:1;)
```

Gọi endpoint A là `10.0.0.1:12345`, B là `10.0.0.2:80`. Hai rule chỉ kiểm tra header, không có content/flags/dsize/flow condition.

### PCAP

- `input.pcap`: năm packet tự tạo bằng Scapy, không capture từ mạng thật.
- Ethernet/IPv4/TCP; mỗi packet có IP/TCP headers mỗi loại `20` byte, payload `0`, IPv4 total length `40` byte.
- MAC của `10.0.0.1`, `10.0.0.2`, `10.0.0.9` lần lượt là `02:00:00:00:00:01`, `02:00:00:00:00:02`, `02:00:00:00:00:09`.

| Packet | Timestamp | Nguồn → đích | Flags | Seq / Ack | Ý nghĩa |
|---|---|---|---|---|---|
| 1 | `1700000000` | `10.0.0.1:12345 → 10.0.0.2:80` | S | `1000 / 0` | A→B đúng header |
| 2 | `1700000001` | `10.0.0.2:80 → 10.0.0.1:12345` | SA | `2000 / 1001` | B→A, đảo đầy đủ endpoint |
| 3 | `1700000002` | `10.0.0.1:12345 → 10.0.0.2:81` | S | `1000 / 0` | Sai port đích |
| 4 | `1700000003` | `10.0.0.2:12345 → 10.0.0.1:80` | S | `1000 / 0` | IP đảo nhưng port chưa đảo |
| 5 | `1700000004` | `10.0.0.9:12345 → 10.0.0.2:80` | S | `1000 / 0` | Sai IP nguồn |

Các packet đều hợp lệ về cấu trúc. Packet 3–5 không khớp rule vì endpoint khác yêu cầu, không phải packet malformed. Fixture không có handshake hoàn chỉnh; hai rule không yêu cầu established.

Ma trận header mong đợi:

| Packet | SID `100501` (`->`) | SID `100502` (`<>`) |
|---|---|---|
| 1 | MATCH / direct | MATCH / direct |
| 2 | NO_MATCH | MATCH / reverse |
| 3 | NO_MATCH | NO_MATCH |
| 4 | NO_MATCH | NO_MATCH |
| 5 | NO_MATCH | NO_MATCH |

## Thực hiện

Chạy tại thư mục gốc project trong PowerShell:

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding

& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_03\test_05_direction_matching\check_direction_matching.py
if ($LASTEXITCODE -ne 0) { throw "T05 failed" }
```

Script kiểm tra rules và PCAP, chạy `main.py` thật rồi đọc event/detection JSONL. Từ normalized của năm event, script tạo `InspectionContext` và gọi `match_header()` thật cho cả hai rule trên mỗi event; không đưa Scapy packet trực tiếp vào Matcher.

Mười kết quả được đối chiếu với ma trận expected khai báo riêng rồi lưu vào `result_matches.jsonl`. Script cũng kiểm tra đúng ba detection, orientation, timestamp/flow ID và endpoint thực tế, đọc lại JSONL và xác nhận input không bị sửa.


## Kết quả

**PASS T05.** CLI và script trả mã thoát `0`; đủ năm event, mười kết quả header đúng ma trận và chính xác ba detection.

Trong `result.jsonl`, cả năm event có preprocess valid/process, flow tracked, parse/decode errors rỗng và payload length `0`. Application protocol UNKNOWN, decode status not_processed vì không có application payload; đây không phải lỗi.

Trong `result_matches.jsonl`, mỗi dòng là một kết quả API header, gồm packet_id, sid, status, orientation, reason và diagnostics:

- Dòng 1–2: packet 1 match cả hai SID, orientation direct.
- Dòng 3: packet 2 NO_MATCH với SID `100501`; dòng 4 MATCH/reverse với SID `100502`.
- Dòng 5–10: packet 3–5 NO_MATCH với cả hai rule.
- Tổng `3` MATCH và `7` NO_MATCH; NO_MATCH có orientation null, reason_code `header_no_match` và reason có nội dung. Diagnostics đều rỗng.

Trong `result_detections.jsonl`:

| Dòng | `packet_id` | `sid` | Orientation | Endpoint xuất trong detection |
|---|---|---|---|---|
| 1 | `1` | `100501` | direct | `10.0.0.1:12345 → 10.0.0.2:80` |
| 2 | `1` | `100502` | direct | `10.0.0.1:12345 → 10.0.0.2:80` |
| 3 | `2` | `100502` | reverse | `10.0.0.2:80 → 10.0.0.1:12345` |

Orientation reverse thể hiện chiều so với header rule; không đổi src/dst IP/port của packet khi xuất detection. Timestamp/flow ID khớp event tương ứng, protocol TCP, application_protocol UNKNOWN, revision `1`, msg đúng rule. 

`matched_info.header` là matched với orientation như bảng; flow/flags/dsize là null, contents là `[]` vì rule không có các điều kiện này. Không có detection cho packet 3–5.

CLI báo `events_evaluated = 5`, `candidate_rules = 7`, `matches = detections_written = 3`, skip/evaluation error/not-evaluable đều `0`. API header kiểm tra đủ `10` cặp rule/event; CLI đánh giá `7` candidate sau Indexer. 

## Tệp

- `input.rules`: hai rule chỉ khác direction và identification.
- `input.pcap`: năm TCP packet tự tạo cho chiều đúng/đảo và các endpoint không khớp.
- `check_direction_matching.py`: tự kiểm tra fixture, CLI, Header Matcher và detections.
- `result.jsonl`: năm IDS event từ PCAP.
- `result_matches.jsonl`: mười kết quả Header Matcher, gồm cả NO_MATCH.
- `result_detections.jsonl`: ba detection từ CLI.
- `console.txt`: stdout/stderr CLI và các kiểm tra PASS/FAIL, UTF-8.
- `README.md`: dữ liệu, cách chạy và giải thích kết quả.
