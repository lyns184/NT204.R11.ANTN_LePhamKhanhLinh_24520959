# Test 11 - Report Severity Statistics

## Mục tiêu

Kiểm tra TC11 Bài tập 4: báo cáo phân biệt tổng số nhóm Alert với tổng lượt phát hiện. Phân bố severity đếm số nhóm ở từng mức, gồm cả mức có giá trị 0.

## Dữ liệu

Script ghi bảy nhóm Alert mô phỏng vào SQLite. Mốc `t = 0` là Unix timestamp `1700000000.0`, tương ứng `2023-11-14T22:13:20Z`. Kỳ chính là `[t+0, t+60)`, lọc theo `first_seen`.

| First seen (s) | Last seen (s) | Severity | Count | Run | Thuộc kỳ chính |
|---:|---:|---|---:|---|---|
| -5 | 5 | HIGH | 3 | A | Không |
| 0 | 12 | CRITICAL | 4 | A | Có |
| 15 | 18 | HIGH | 2 | A | Có |
| 20 | 20 | HIGH | 1 | B | Có |
| 25 | 32 | MEDIUM | 3 | B | Có |
| 35 | 35 | LOW | 1 | A | Có |
| 60 | 60 | CRITICAL | 7 | B | Không |

Run A và B dùng ID lần lượt là `fixture-tc11-a` và `fixture-tc11-b`. Nhóm đầu bắt đầu trước kỳ dù `last_seen` nằm trong kỳ. Nhóm cuối nằm đúng biên phải. Cả hai được loại khi tính kỳ chính.

## Thực hiện

Chạy từ thư mục gốc project trong PowerShell:

```powershell
& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_04\test_11_report_severity_statistics\check_report_severity_statistics.py
if ($LASTEXITCODE -ne 0) { throw "TC11 failed" }
```

Script mở lại SQLite ở chế độ chỉ đọc và gọi `generate_report()` cho kỳ chính, kỳ chính chỉ lấy run A và kỳ rỗng `[t+120, t+180)`. Kỳ vọng được tính từ fixture và khai báo riêng. Ngoài giá trị từng bộ đếm, script kiểm tra tổng phân bố severity bằng số nhóm. DB tạm được dọn sau lần chạy.

## Kết quả

**PASS TC11.** Script trả mã thoát `0`. Cả ba báo cáo khớp số liệu kỳ vọng:

| Báo cáo | Nhóm | Lượt | CRITICAL | HIGH | MEDIUM | LOW |
|---|---:|---:|---:|---:|---:|---:|
| Kỳ chính, tất cả run | 5 | 11 | 1 | 2 | 1 | 1 |
| Kỳ chính, chỉ run A | 3 | 7 | 1 | 1 | 0 | 1 |
| Kỳ rỗng | 0 | 0 | 0 | 0 | 0 | 0 |

Kỳ chính hiển thị đúng hai mốc UTC. Báo cáo rỗng vẫn có đủ bốn mức severity. JSON kết quả đọc lại thành công.

## Tệp

- `check_report_severity_statistics.py`: tạo fixture SQLite, gọi generator và đối chiếu thống kê.
- `result_severity_statistics.json`: dữ liệu của ba báo cáo trong lần chạy chính thức.
- `console.txt`: kết quả từng ca và kết luận PASS/FAIL, lưu UTF-8.
