# Test 14 - Report Output

## Mục tiêu

Kiểm tra TC14 Bài tập 4: lệnh `report` tạo được báo cáo text và JSON, hai định dạng nhất quán với các Alert đã lưu. Kỳ có dữ liệu và kỳ rỗng đều xuất đủ mục và trả mã thoát thành công.

## Dữ liệu

Script ghi ba nhóm Alert mô phỏng vào SQLite tạm. Cả ba có IP đích `198.51.100.20`. Cấu hình tạm đặt `top_n = 2`.

| SID | First seen (UTC) | Severity | Transport / application | IP nguồn | Classtype | Count |
|---:|---|---|---|---|---|---:|
| 104141 | 2023-11-14 22:13:20 | HIGH | TCP / HTTP | 192.0.2.1 | lab-http | 3 |
| 104142 | 2023-11-14 23:13:20 | LOW | UDP / DNS | 192.0.2.2 | `null` | 1 |
| 104143 | 2023-11-15 00:13:20 | CRITICAL | TCP / HTTP | 192.0.2.3 | lab-http | 7 |

Kỳ chính có hai mốc `2023-11-15T05:13:20+07:00` và `2023-11-15T00:13:20Z`. Khi đổi sang UTC, mốc đầu là `2023-11-14T22:13:20Z`. Theo khoảng `[from, to)`, SID `104143` ở biên phải bị loại. Kỳ rỗng từ 00:00 đến 01:00 UTC ngày 2023-11-16 có số nhóm và số lượt bằng 0.

## Thực hiện

Chạy từ thư mục gốc project trong PowerShell:

```powershell
& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_04\test_14_report_output\check_report_output.py
if ($LASTEXITCODE -ne 0) { throw "TC14 failed" }
```

Script kiểm tra hai nhóm của kỳ chính bằng repository chỉ đọc rồi chạy `main.py report` trong hai tiến trình riêng. Script đối chiếu JSON với kỳ vọng tính từ fixture, đọc lại tiêu đề và từng bảng text để so với JSON. Cả hai lần chạy dùng `--text-output` và `--json-output`. SQLite và cấu hình tạm được dọn sau khi kiểm tra.

## Kết quả

**PASS TC14.** Cả hai lệnh report và script trả mã thoát `0`. Báo cáo kỳ chính có **2 nhóm, 4 lượt**, gồm HIGH 1 và LOW 1. Hai nhóm thuộc hai giờ UTC khác nhau. IP đích đứng đầu với hai nhóm, còn hai IP nguồn có một nhóm mỗi IP.

Báo cáo kỳ rỗng ghi 0 nhóm và 0 lượt, đủ bốn mức severity với giá trị 0. Các mục không có dữ liệu hiện `(none)` trong bản text và collection rỗng trong JSON. Tất cả tiêu đề, kỳ báo cáo, phân bố và bảng xếp hạng đều nhất quán. SQLite giữ nguyên sau hai lượt đọc.

## Tệp

- `check_report_output.py`: tạo SQLite, gọi CLI và đối chiếu hai định dạng.
- `result_report_period.txt` và `result_report_period.json`: báo cáo thực tế cho kỳ chính.
- `result_report_empty.txt` và `result_report_empty.json`: báo cáo thực tế cho kỳ rỗng.
- `console.txt`: lệnh CLI, exit code và kết luận PASS/FAIL, lưu UTF-8.
