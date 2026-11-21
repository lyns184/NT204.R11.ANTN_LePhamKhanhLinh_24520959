# Test 06 - Distinct Alert Groups

## Mục tiêu

Kiểm tra TC06 Bài tập 4: detection khác khóa gom phải tạo nhóm Alert độc lập dù đến trong cùng cửa sổ thời gian.

## Dữ liệu

Script tạo sáu Detection Event mô phỏng trong bộ nhớ. Cấu hình mặc định bật gom nhóm với cửa sổ 60 giây. Detection cách nhau một giây, từ `1700000000.0` đến `1700000005.0`. Tất cả có priority `2`, port nguồn `53000` và port đích `53`.

| Giây kể từ mốc đầu | Ca | SID | IP nguồn | IP đích | Transport | Application |
|---:|---|---:|---|---|---|---|
| 0 | Mốc đối chiếu | 104061 | 192.0.2.10 | 198.51.100.20 | UDP | DNS |
| 1 | Khác SID | 104062 | 192.0.2.10 | 198.51.100.20 | UDP | DNS |
| 2 | Khác IP nguồn | 104061 | 192.0.2.11 | 198.51.100.20 | UDP | DNS |
| 3 | Khác IP đích | 104061 | 192.0.2.10 | 198.51.100.21 | UDP | DNS |
| 4 | Khác transport | 104061 | 192.0.2.10 | 198.51.100.20 | TCP | DNS |
| 5 | Không nhận diện application | 104061 | 192.0.2.10 | 198.51.100.20 | UDP | UNKNOWN |

Mỗi biến thể khác đúng một thành phần của khóa so với mốc đối chiếu. Giá trị `UNKNOWN` ở ca cuối được chuẩn hóa thành `null`. Kỳ vọng chung là cả sáu detection đều trả `created`, mỗi nhóm có `count = 1` và một `alert_id` riêng.

## Thực hiện

Chạy từ thư mục gốc project trong PowerShell:

```powershell
& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_04\test_06_distinct_alert_groups\check_distinct_alert_groups.py
if ($LASTEXITCODE -ne 0) { throw "TC06 failed" }
```

Script gọi AlertManager thật, kiểm tra khóa, timestamp, status và bộ đếm, rồi mở lại SQLite ở chế độ chỉ đọc để đối chiếu đủ sáu nhóm. DB tạm được dọn sau khi chạy.

## Kết quả

**PASS TC06.** Script trả mã thoát `0`. Trong sáu event nhận vào, `created = 6` và `aggregated = 0`. SQLite lưu đúng sáu nhóm với sáu `alert_id` khác nhau. Mỗi nhóm có `count = 1` và `first_seen = last_seen` bằng timestamp của detection tương ứng. JSON kết quả đọc lại thành công.

## Tệp

- `check_distinct_alert_groups.py`: tạo detection, chạy AlertManager và đối chiếu SQLite.
- `result_distinct_groups.json`: khóa kỳ vọng, ID thực tế, bộ đếm và sáu nhóm đọc từ SQLite.
- `console.txt`: kết quả từng ca và kết luận PASS/FAIL, lưu UTF-8.
