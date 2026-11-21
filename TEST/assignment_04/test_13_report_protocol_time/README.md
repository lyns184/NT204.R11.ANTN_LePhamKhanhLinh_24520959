# Test 13 - Report Protocol and Time Statistics

## Mục tiêu

Kiểm tra TC13 Bài tập 4: báo cáo thống kê số nhóm Alert theo transport protocol, application protocol và từng giờ UTC. Giờ được xác định bằng `first_seen`, kể cả khi `last_seen` thuộc giờ kế tiếp.

## Dữ liệu

Script ghi chín nhóm Alert mô phỏng trực tiếp vào SQLite. Kỳ chính là `[2023-11-14T22:00:00Z, 2023-11-15T02:00:00Z)`. Bảng dùng offset giây từ `1699999200.0` (22:00 UTC).

| Nhóm | First seen (s) | Last seen (s) | Transport | Application | Count |
|---:|---:|---:|---|---|---:|
| 1 | −5 | 5 | TCP | HTTP | 3 |
| 2 | 0 | 8 | TCP | HTTP | 2 |
| 3 | 3590 | 3610 | TCP | SMTP | 4 |
| 4 | Ngay trước 3600 | 3600 | `null` | `null` | 2 |
| 5 | 3600 | 3600 | UDP | DNS | 1 |
| 6 | 3650 | 3660 | UDP | DNS | 3 |
| 7 | 3720 | 3720 | TCP | `null` | 1 |
| 8 | 10810 | 10810 | UDP | `null` | 1 |
| 9 | 14400 | 14400 | TCP | HTTP | 1 |

Nhóm 4 dùng giá trị float biểu diễn được ngay trước mốc 23:00 UTC để kiểm tra phân giờ sát biên. Nhóm 1 và 9 nằm ngoài kỳ theo `first_seen`. Nhóm 3–4 thuộc giờ 22:00 dù kết thúc lúc hoặc sau 23:00.

## Thực hiện

Chạy từ thư mục gốc project trong PowerShell:

```powershell
& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_04\test_13_report_protocol_time\check_report_protocol_time.py
if ($LASTEXITCODE -ne 0) { throw "TC13 failed" }
```

Script mở lại SQLite tạm ở chế độ chỉ đọc và gọi `generate_report()` cho toàn kỳ và hai giờ liền nhau. Kỳ vọng được khai báo riêng cho từng phân bố, giờ và tổng lượt. DB tạm được dọn sau lần chạy.

## Kết quả

**PASS TC13.** Script trả mã thoát `0`. Toàn kỳ có **7 nhóm, 14 lượt**. Thống kê giao thức đếm theo nhóm:

- Transport: TCP 3, UDP 3, UNKNOWN 1.
- Application: DNS 2, HTTP 1, SMTP 1, UNKNOWN 3.

| Giờ UTC | Số nhóm | Số lượt thuộc các nhóm |
|---|---:|---:|
| 2023-11-14 22:00 | 3 | 8 |
| 2023-11-14 23:00 | 3 | 5 |
| 2023-11-15 00:00 | 0 | 0 |
| 2023-11-15 01:00 | 1 | 1 |

Giờ 00:00 không xuất hiện trong JSON vì không có nhóm nào bắt đầu trong giờ đó. Hai báo cáo giờ 22:00 và 23:00 xác nhận các nhóm tại và ngay trước biên vào đúng kỳ. JSON kết quả đọc lại thành công.

## Tệp

- `check_report_protocol_time.py`: ghi fixture SQLite và đối chiếu thống kê giao thức, thời gian.
- `result_protocol_time.json`: báo cáo toàn kỳ và hai báo cáo giờ liền nhau.
- `console.txt`: kết quả từng phần và kết luận PASS/FAIL, lưu UTF-8.
