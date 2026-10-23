# Test 04 - Header Parsing

## Mục tiêu

Kiểm tra T04 trong mục 7 Bài tập 3: Parser chuyển header TCP với any/IPv4 đơn/CIDR và port đơn/range thành Internal Rule Object đúng.

Test bổ sung range mở, direction `<>` và header UDP; kiểm tra metadata/source và xuất JSON của các object đã parse.

## Dữ liệu

- File: `input.rules`, năm dòng UTF-8, fixture viết riêng cho test.
- Mỗi dòng có action `alert`, một header dưới đây và đủ msg/sid/rev, revision `1`.
- Không có PCAP/event: script đưa từng dòng trực tiếp vào `parse_rule()`.

| Dòng / SID | Header đầu vào | Trường hợp |
|---|---|---|
| 1 / `100401` | `tcp any any -> any any` | Any cho IP và port |
| 2 / `100402` | `tcp 10.0.0.1 12345 -> 10.0.0.2 80` | IPv4 đơn, port đơn |
| 3 / `100403` | `tcp 10.0.0.0/24 1000:2000 -> 192.168.1.0/24 80:90` | CIDR, range đóng |
| 4 / `100404` | `tcp any :1023 <> 10.0.0.2 8080:` | Range mở, hai chiều |
| 5 / `100405` | `udp any 53000 -> 10.0.0.2 53` | UDP |



- IP `any` là `None`; IPv4 đơn là `IPv4Network` prefix `/32`; CIDR giữ đúng network/prefix.
- Port là `PortSpec`: any có `(start, end) = (None, None)`; port đơn có hai đầu bằng nhau; range giữ đúng hai biên.
- `:1023` có biên `(0, 1023)`, `8080:` có biên `(8080, 65535)`.
- Action/protocol/direction, SID/msg/rev và file/dòng nguồn đúng input; raw_text giữ nguyên.

## Thực hiện

Chạy tại thư mục gốc project trong PowerShell:

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding

& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_03\test_04_header_parsing\check_header_parsing.py
if ($LASTEXITCODE -ne 0) { throw "T04 failed" }
```

Script gọi Parser thật cho từng dòng, yêu cầu status valid/không diagnostics và kiểm tra kiểu `Rule`, `RuleHeader`, `IPv4Network`, `PortSpec` cùng các giá trị expected. Script cũng đối chiếu header xuất JSON, ghi/đọc lại báo cáo và xác nhận input không đổi.

`console.txt` ghi input, header đã kiểm tra và PASS/FAIL bằng UTF-8. Thành công trả `0`; assertion/exception ghi FAIL và trả `1`.

## Kết quả

**PASS T04.** Script trả mã thoát `0`; cả năm dòng đều valid, không có diagnostics.

Trong `result_rules.json`:

- `counts`: `rules_total = rules_valid = 5`, `rules_invalid = rules_unsupported = 0`.
- `results` giữ năm `ParseResult` theo thứ tự input; SID lần lượt `100401`–`100405`.
- Mỗi result có `status = valid`, `diagnostics = []` và `rule` chứa Internal Rule Object.

Các selector quan trọng trong `rule.header`:

| SID | IP nguồn → đích khi xuất JSON | Port nguồn `(start,end)` | Port đích `(start,end)` | Direction |
|---|---|---|---|---|
| `100401` | `null` → `null` | `(null,null)` | `(null,null)` | `->` |
| `100402` | `10.0.0.1/32` → `10.0.0.2/32` | `(12345,12345)` | `(80,80)` | `->` |
| `100403` | `10.0.0.0/24` → `192.168.1.0/24` | `(1000,2000)` | `(80,90)` | `->` |
| `100404` | `null` → `10.0.0.2/32` | `(0,1023)` | `(8080,65535)` | `<>` |
| `100405` | `null` → `10.0.0.2/32` | `(53000,53000)` | `(53,53)` | `->` |

Action là alert; bốn rule đầu protocol tcp, rule cuối udp. Msg/rev/SID được giữ đúng fixture, source.line lần lượt `1`–`5`, raw_text bằng dòng gốc. Source.file và input_file trong report là đường dẫn tuyệt đối, có thể thay đổi khi chạy ở thư mục khác.

`None` xuất thành JSON `null`; `IPv4Network` xuất thành chuỗi CIDR; port có object `start`/`end`. Bảng trên dùng cặp số để trình bày gọn, không phải kiểu dữ liệu tuple trong JSON.


## Tệp

- `input.rules`: năm rule hợp lệ với các kiểu header cần kiểm tra.
- `check_header_parsing.py`: gọi Parser và tự đối chiếu typed object/JSON với expected.
- `result_rules.json`: counts và năm kết quả parse, kèm Rule Object/source.
- `console.txt`: input/header đã kiểm tra và PASS/FAIL, UTF-8.
- `README.md`: mục tiêu, dữ liệu, cách chạy và giải thích kết quả.
