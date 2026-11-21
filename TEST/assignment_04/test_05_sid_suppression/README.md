# Test 05 - SID Suppression

## Mục tiêu

Kiểm tra TC05 Bài tập 4: detection có SID trong danh sách suppression bị loại trước khi lưu hoặc gom nhóm. Nếu cùng lúc dưới ngưỡng severity, event được ghi nhận đúng một lần với lý do `sid_suppressed`.

## Dữ liệu

Script tạo sáu Detection Event TCP mô phỏng từ `192.0.2.10` đến `198.51.100.20`. File `alert_config.json` đặt ngưỡng `HIGH` và suppress các SID `104052`, `104053`. Test dùng mapping priority và cửa sổ gom nhóm 60 giây mặc định.

| Giây kể từ `1700000000.0` | SID | Severity | Kết quả mong đợi | Lý do |
|---:|---:|---|---|---|
| 0 | 104051 | CRITICAL | `created` | — |
| 1 | 104052 | CRITICAL | `filtered` | `sid_suppressed` |
| 2 | 104053 | LOW | `filtered` | `sid_suppressed` |
| 3 | 104054 | LOW | `filtered` | `below_min_severity` |
| 4 | 104052 | CRITICAL | `filtered` | `sid_suppressed` |
| 5 | 104051 | CRITICAL | `aggregated` | — |

Hai SID `104051` và `104052` đều là CRITICAL. Chỉ SID `104052` nằm trong cấu hình suppression. SID `104053` kiểm tra thứ tự ưu tiên giữa hai bộ lọc.

## Thực hiện

Chạy từ thư mục gốc project trong PowerShell:

```powershell
& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_04\test_05_sid_suppression\check_sid_suppression.py
if ($LASTEXITCODE -ne 0) { throw "TC05 failed" }
```

Script dùng bộ nạp cấu hình và AlertManager thật để kiểm tra status, lý do và bộ đếm. SQLite tạm được mở lại ở chế độ chỉ đọc để đối chiếu dữ liệu thực sự đã lưu.

## Kết quả

**PASS TC05.** Script trả mã thoát `0`. Trong sáu detection, ba lượt bị loại do SID và một lượt bị loại do severity. SQLite chỉ lưu một nhóm của SID `104051` với `count = 2`, `first_seen = 1700000000.0` và `last_seen = 1700000005.0`. Hai lượt hợp lệ giữ cùng `alert_id`. JSON kết quả đọc lại khớp dữ liệu đã kiểm tra.

## Tệp

- `alert_config.json`: ngưỡng severity và danh sách SID bị suppress.
- `check_sid_suppression.py`: tạo detection, chạy AlertManager và truy vấn SQLite.
- `result_sid_suppression.json`: quyết định, bộ đếm và nhóm đọc từ SQLite.
- `console.txt`: kết quả từng ca và kết luận PASS/FAIL, lưu UTF-8.
