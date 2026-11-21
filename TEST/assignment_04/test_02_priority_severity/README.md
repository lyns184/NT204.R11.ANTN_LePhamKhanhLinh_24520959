# Test 02 - Priority to Severity

## Mục tiêu

Kiểm tra TC02 Bài tập 4: Alert nhận mức severity đúng theo priority của Detection Event và cấu hình đang dùng. Priority không có trong mapping, bằng `null` hoặc không có key dùng `default_severity`.

## Dữ liệu

Script tạo tám Detection Event mô phỏng trong bộ nhớ với cùng SID `104020`, endpoint `192.0.2.10 → 198.51.100.20` và protocol TCP. Chỉ giá trị hoặc sự hiện diện của priority thay đổi. Timestamp cố định từ `1700000001` đến `1700000008`. Dữ liệu được tạo riêng cho testcase.

Hai cấu hình được kiểm tra là mặc định của ứng dụng và file `alert_config.json` có mapping riêng, với severity mặc định là `HIGH`.

| Priority | Severity mong đợi với cấu hình mặc định | Severity mong đợi với cấu hình riêng |
|---|---|---|
| 1 | CRITICAL | MEDIUM |
| 2 | HIGH | CRITICAL |
| 3 | MEDIUM | HIGH (mức mặc định) |
| 4 | LOW | HIGH |
| 7 | LOW (mức mặc định) | LOW |
| 8 | LOW (mức mặc định) | HIGH (mức mặc định) |
| `null` | LOW (mức mặc định) | HIGH (mức mặc định) |
| Không có key | LOW (mức mặc định) | HIGH (mức mặc định) |

Priority `3` kiểm tra rằng mapping riêng thay thế mapping mặc định. Priority `7` kiểm tra một khóa mới chỉ có trong cấu hình riêng.

## Thực hiện

Chạy từ thư mục gốc project trong PowerShell:

```powershell
& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_04\test_02_priority_severity\check_priority_severity.py
if ($LASTEXITCODE -ne 0) { throw "TC02 failed" }
```

Script dùng `load_alert_config()` và `convert_detection()` thật. Mỗi event được chuyển đổi với cả hai cấu hình và đối chiếu với bảng kỳ vọng. Script cũng kiểm tra priority gốc, file cấu hình và khả năng đọc lại kết quả JSON.

## Kết quả

**PASS TC02.** Script trả mã thoát `0`. Cả tám ca được chấp nhận với cả hai cấu hình. File `result_severity.json` có **16 kết quả**, đều có `expected` bằng `actual`. Các ca priority thiếu, `null` hoặc ngoài mapping lấy đúng mức mặc định. Dữ liệu đầu vào và file cấu hình giữ nguyên.

## Tệp

- `alert_config.json`: mapping và severity mặc định dùng riêng cho test.
- `check_priority_severity.py`: tạo detection mô phỏng và đối chiếu kết quả.
- `result_severity.json`: priority đầu vào, cấu hình, severity kỳ vọng và severity thực tế theo từng lần chuyển đổi.
- `console.txt`: kết quả từng ca và kết luận PASS/FAIL, lưu UTF-8.
