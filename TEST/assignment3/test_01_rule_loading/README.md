# Test 01 - Rule Loading

## Mục tiêu

Kiểm tra T01 trong mục 7 Bài tập 3: Loader đọc file có rule hợp lệ, comment và dòng trống; chỉ các dòng rule được chuyển sang Parser.

Test xác nhận thêm số rule enabled, thứ tự SID, metadata và khả năng xuất/đọc lại báo cáo JSON.

## Dữ liệu

- File: `input.rules`, gồm sáu dòng, mã hóa UTF-8.
- Nguồn: fixture viết riêng cho test, không phải bộ rule Snort đầy đủ.
- Không có PCAP hoặc event: test gọi trực tiếp Rule Loader và Parser, chưa chạy matching.

| Dòng | Nội dung | Kết quả mong đợi |
|---|---|---|
| 1 | Comment bắt đầu bằng `#` | Không gọi Parser |
| 2 | Dòng trống | Không gọi Parser |
| 3 | Rule TCP, SID `100001` | Parse hợp lệ, enabled |
| 4 | Dòng trống | Không gọi Parser |
| 5 | Comment có bốn khoảng trắng trước `#` | Không gọi Parser |
| 6 | Rule UDP, SID `100002` | Parse hợp lệ, enabled |

Hai rule trong fixture:

```text
alert tcp any any -> any 80 (msg:"HTTP test"; sid:100001; rev:1;)
alert udp any any -> any 53 (msg:"DNS test"; sid:100002; rev:1;)
```

Cả hai có action `alert`, source/destination IP `any`, source port `any`, direction `->`, revision `1`. Port đích lần lượt `80` và `53`. Không truyền config nên không disable rule nào.

Các message HTTP/DNS là nhãn của rule; test không khẳng định đã nhận diện hoặc bắt traffic HTTP/DNS.

## Thực hiện

Chạy tại thư mục gốc project trong PowerShell:

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding

& .\.venv\Scripts\python.exe -X utf8 TEST\assignment3\test_01_rule_loading\check_rule_loading.py
if ($LASTEXITCODE -ne 0) { throw "T01 failed" }
```

Script gọi `load_rules()` thật và theo dõi lời gọi `ids.detection.loader.parse_rule` bằng `wraps`: Parser thật vẫn xử lý các rule, không thay kết quả bằng dữ liệu giả.

Script kiểm tra chính xác dòng được đưa vào Parser, counters, thứ tự SID và các field của rule. Sau đó ghi `LoadReport.to_dict()` vào `result_rules.json`, đọc lại để đối chiếu và xác nhận `input.rules` không bị sửa. Console UTF-8 lưu vào `console.txt`; thành công trả `0`, thất bại ghi FAIL và trả `1`.

## Kết quả

**PASS T01.** Script trả mã thoát `0`. Parser được gọi đúng hai lần, với nguyên văn rule tại dòng `3` và `6`; không nhận hai comment hoặc hai dòng trống.

Trong `result_rules.json`:

- `files`: một file có status `loaded`, `lines_read = 6`.
- `counts`: `files_requested = files_loaded = 1`, `rules_total = rules_enabled = 2`; counters disabled/duplicate/invalid/unsupported đều `0`.
- `enabled_rules`: SID `100001` rồi `100002`, giữ thứ tự trong file; `entries` đều có status `enabled`.
- `diagnostics = []`, không có cảnh báo hoặc lỗi nạp rule.

Các giá trị rule đã đối chiếu:

| Field | Rule dòng 3 | Rule dòng 6 |
|---|---|---|
| `sid` / `rev` | `100001` / `1` | `100002` / `1` |
| `msg` | `HTTP test` | `DNS test` |
| `header.protocol` | `tcp` | `udp` |
| `header.dst_port` | `start = end = 80` | `start = end = 53` |
| `source.line` | `3` | `6` |

IP `any` được biểu diễn bằng `null`; source port `any` có `start = end = null`. Action/direction là `alert`/`->`; `raw_text` giữ đúng dòng rule đầu vào. `source.file` và `files[].path` là đường dẫn tuyệt đối của fixture, có thể thay đổi khi clone/chạy ở thư mục khác.

Báo cáo JSON đọc lại giống dữ liệu Loader đã xuất; file đầu vào được giữ nguyên. `result_rules.json` là báo cáo nạp rule, không phải IDS event hay detection.

## Tệp

- `input.rules`: hai rule hợp lệ xen hai comment và hai dòng trống.
- `check_rule_loading.py`: gọi Loader/Parser và tự kiểm tra T01.
- `result_rules.json`: báo cáo Loader, gồm rules, source, diagnostics và counters.
- `console.txt`: dữ liệu kiểm tra và PASS/FAIL, lưu UTF-8.
- `README.md`: mục tiêu, đầu vào, cách chạy và giải thích kết quả.
