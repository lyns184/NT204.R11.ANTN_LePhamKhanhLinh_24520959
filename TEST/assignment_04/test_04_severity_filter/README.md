# Test 04 - Severity Filter

## Mục tiêu

Kiểm tra TC04 Bài tập 4: Alert dưới `min_severity` bị loại trước khi lưu và gom nhóm. Alert đúng bằng ngưỡng hoặc cao hơn vẫn được xử lý.

## Dữ liệu

Script tạo năm Detection Event TCP mô phỏng trong bộ nhớ, cùng IP nguồn `192.0.2.10` và IP đích `198.51.100.20`. File `alert_config.json` đặt `min_severity = HIGH`. Mapping priority và cửa sổ gom nhóm 60 giây dùng mặc định. SID suppression để trống.

| Giây kể từ `1700000000.0` | SID | Priority | Severity | Kết quả mong đợi |
|---:|---:|---:|---|---|
| 0 | 104042 | 2 | HIGH | `created` |
| 1 | 104043 | 3 | MEDIUM | `filtered` |
| 2 | 104044 | 4 | LOW | `filtered` |
| 3 | 104041 | 1 | CRITICAL | `created` |
| 4 | 104042 | 2 | HIGH | `aggregated` |

Hai event HIGH dùng cùng SID và endpoint để kiểm tra rằng mức bằng ngưỡng có thể tạo nhóm và gom lượt tiếp theo.

## Thực hiện

Chạy từ thư mục gốc project trong PowerShell:

```powershell
& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_04\test_04_severity_filter\check_severity_filter.py
if ($LASTEXITCODE -ne 0) { throw "TC04 failed" }
```

Script nạp cấu hình bằng `load_alert_config()`, gọi `AlertManager.process()` cho từng event và đối chiếu status với kỳ vọng. Sau đó script mở lại DB SQLite tạm ở chế độ chỉ đọc và kiểm tra các nhóm thực sự đã lưu.

## Kết quả

**PASS TC04.** Script trả mã thoát `0`. Hai event dưới ngưỡng trả `filtered` với reason `below_min_severity`. Bộ đếm ghi nhận năm event, hai bị lọc, hai nhóm mới và một lượt gom. SQLite chỉ lưu hai nhóm sau:

| SID | Severity | Count | First seen | Last seen |
|---:|---|---:|---:|---:|
| 104042 | HIGH | 2 | 1700000000.0 | 1700000004.0 |
| 104041 | CRITICAL | 1 | 1700000003.0 | 1700000003.0 |

Kết quả JSON đọc lại thành công và khớp dữ liệu đã kiểm tra trong lần chạy.

## Tệp

- `alert_config.json`: cấu hình ngưỡng HIGH dành cho test.
- `check_severity_filter.py`: tạo detection, chạy AlertManager và đối chiếu SQLite.
- `result_severity_filter.json`: quyết định từng event, bộ đếm và hai nhóm đã lưu.
- `console.txt`: kết quả từng ca và kết luận PASS/FAIL, lưu UTF-8.
