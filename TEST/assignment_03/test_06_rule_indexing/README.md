# Test 06 - Rule Indexing

## Mục tiêu

Kiểm tra T06 trong mục 7 Bài tập 3: Repository/Indexer chọn đúng candidate rules theo protocol TCP/UDP/ip và port/any.

Test kiểm tra thêm thứ tự theo file rules, không trùng SID, range gồm hai biên, direction `<>` và dữ liệu thiếu port. Candidate chưa phải kết quả MATCH; Matcher sẽ kiểm tra đầy đủ rule ở bước sau.

## Dữ liệu

### Rules

- `input.rules`: sáu rule hợp lệ, fixture viết riêng cho test; mỗi rule có action alert, msg, SID và revision `1`.
- Nạp bằng Loader thật, không truyền config; sáu rule đều enabled, không diagnostics.

| SID | Header | Mục đích |
|---|---|---|
| `100601` | `tcp any any -> any 80` | TCP port đơn |
| `100602` | `tcp any any -> any 8000:8080` | TCP port range |
| `100603` | `udp any any -> any 53` | UDP port đơn |
| `100604` | `ip any any -> any any` | Bucket ip cho cả TCP/UDP |
| `100605` | `tcp any any -> any any` | Wildcard port TCP |
| `100606` | `tcp any any <> any 443` | Chọn theo hai chiều |

`any` là wildcard IP/port, không phải protocol riêng. Indexer hiện lọc protocol/port; IP và điều kiện khác do Matcher kiểm tra sau.

### Context trực tiếp

Script tạo 11 `InspectionContext` trong bộ nhớ, không có PCAP hoặc traffic capture. Mọi context có normalized.network IPv4, source `10.0.0.1`, destination `10.0.0.2`; transport theo bảng dưới. Không dùng payload hoặc flow để chọn candidate.

| Case | Protocol / port nguồn → đích | Candidate SID mong đợi theo thứ tự |
|---|---|---|
| `tcp_port_80` | TCP `12345 → 80` | `100601, 100604, 100605` |
| `tcp_range_start` | TCP `12345 → 8000` | `100602, 100604, 100605` |
| `tcp_range_end` | TCP `12345 → 8080` | `100602, 100604, 100605` |
| `tcp_below_range` | TCP `12345 → 7999` | `100604, 100605` |
| `tcp_above_range` | TCP `12345 → 8081` | `100604, 100605` |
| `udp_dns` | UDP `53000 → 53` | `100603, 100604` |
| `udp_other_port` | UDP `53000 → 9999` | `100604` |
| `tcp_443_forward` | TCP `12345 → 443` | `100604, 100605, 100606` |
| `tcp_443_reverse` | TCP `443 → 12345` | `100604, 100605, 100606` |
| `tcp_443_both_orientations` | TCP `443 → 443` | `100604, 100605, 100606` |
| `tcp_missing_dst_port` | TCP source `12345`, không có dst_port | `100601, 100602, 100604, 100605, 100606` |

Case port `443 → 443` phù hợp cả hai orientation của SID100606, nhưng candidate chỉ chứa SID này một lần. Case thiếu dst_port không được tự coi port là `0` hoặc kết luận không match; vẫn loại rule UDP vì protocol TCP đã biết.

## Thực hiện

Chạy tại thư mục gốc project trong PowerShell:

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding

& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_03\test_06_rule_indexing\check_rule_indexing.py
if ($LASTEXITCODE -ne 0) { throw "T06 failed" }
```

Script gọi Loader thật, kiểm tra fixture rules rồi tạo `RuleRepository`. Mỗi context được truy vấn bằng `repository.candidates(context)` thật và so sánh với danh sách expected khai báo riêng trong `CASES`.

Script kiểm tra thứ tự, không trùng SID, context/input và snapshot rules không đổi. Sau đó ghi/đọc lại `result_candidates.json`; console UTF-8 lưu vào `console.txt`. Thành công trả `0`, sai assertion/exception ghi FAIL và trả `1`.

## Kết quả

**PASS T06.** Script trả mã thoát `0`; cả 11 candidate list đúng bảng Dữ liệu.

Trong `result_candidates.json`:

- `input_kind = direct_simulated_context`, không phải packet/event từ capture.
- `rules`: sáu Rule Object theo thứ tự SID100601–100606, kèm header/metadata/source.
- `counts`: `rules_loaded = 6`, `cases_total = cases_passed = 11`.
- `cases`: mỗi case có context, expected_sids, candidate_sids và result PASS; hai danh sách SID giống nhau và không duplicate.

SID100604 xuất hiện trong cả context TCP/UDP. Range8000:8080 nhận hai biên8000/8080 và không nhận7999/8081. SID100605 chỉ áp dụng TCP, không lọt sang UDP. SID100606 được chọn theo cả hai chiều port và chỉ xuất hiện một lần khi cả hai orientation phù hợp.

Thứ tự candidate theo thứ tự rules trong file, kể cả khi rule tcp và ip nằm ở các bucket khác nhau. Context thiếu dst_port vẫn giữ năm rule TCP/ip có khả năng phù hợp. Tất cả context và rules được giữ nguyên sau truy vấn; input.rules không đổi, JSON đọc lại đúng dữ liệu đã xuất.

Các timestamp trong context do script đặt để thử model, không phải thời gian capture. Source.file của Rule Object là đường dẫn tuyệt đối tới fixture, có thể thay đổi khi chạy ở thư mục khác. T06 không chạy Matching Engine hoặc sinh Detection Event, không đo benchmark hiệu năng.

## Tệp

- `input.rules`: sáu rule cho protocol, exact/range/any port và direction.
- `check_rule_indexing.py`: tạo context và tự kiểm tra Repository/Indexer.
- `result_candidates.json`: rules, 11 context, expected và candidate thực tế.
- `console.txt`: kết quả đối chiếu từng context và PASS/FAIL, UTF-8.
- `README.md`: mục tiêu, dữ liệu, cách chạy và giải thích kết quả.
