# Test 08 - Aggregation Outside Window

## Mục tiêu

Kiểm tra TC08 Bài tập 4: detection cùng khóa đến đúng biên phải hoặc sau cửa sổ gom phải tạo nhóm mới. Đồng thời xác nhận cửa sổ tính từ `first_seen` của nhóm, dù `last_seen` vừa được cập nhật.

## Dữ liệu

Script tạo sáu Detection Event TCP/HTTP mô phỏng, cùng SID `104081`, nguồn `192.0.2.10:12345` và đích `198.51.100.20:80`. Cấu hình mặc định bật cửa sổ 60 giây. Timestamp đầu là `1700000000.0`.

| Giây kể từ mốc đầu | Nhóm mong đợi | Status mong đợi | Count của nhóm sau lượt |
|---:|---|---|---:|
| 0 | A | `created` | 1 |
| 59.5 | A | `aggregated` | 2 |
| 60 | B | `created` | 1 |
| 119.5 | B | `aggregated` | 2 |
| 121 | C | `created` | 1 |
| 180.5 | C | `aggregated` | 2 |

Mốc giây 60 đúng bằng biên phải của A. Mốc giây 121 vượt biên phải của B một giây dù chỉ cách lượt gần nhất của B 1,5 giây.

## Thực hiện

Chạy từ thư mục gốc project trong PowerShell:

```powershell
& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_04\test_08_aggregation_outside_window\check_aggregation_outside_window.py
if ($LASTEXITCODE -ne 0) { throw "TC08 failed" }
```

Script gọi AlertManager thật, kiểm tra status, ID và trạng thái nhóm sau mỗi lượt. Sau đó script mở lại SQLite tạm ở chế độ chỉ đọc để xác nhận các nhóm đã lưu và ghi kết quả JSON. DB tạm được dọn sau lần chạy.

## Kết quả

**PASS TC08.** Script trả mã thoát `0`. Detection ở giây 60 và 121 tạo ID mới. SQLite lưu đúng ba nhóm, mỗi nhóm có hai lượt.

| Nhóm | First seen | Last seen | Count |
|---|---:|---:|---:|
| A | 1700000000.0 | 1700000059.5 | 2 |
| B | 1700000060.0 | 1700000119.5 | 2 |
| C | 1700000121.0 | 1700000180.5 | 2 |

Bộ đếm ghi nhận `created = 3`, `aggregated = 3`, tổng nhận 6 detection. JSON kết quả đọc lại thành công.

## Tệp

- `check_aggregation_outside_window.py`: tạo fixture, chạy AlertManager và đối chiếu SQLite.
- `result_outside_window.json`: trạng thái từng lượt, bộ đếm và ba nhóm đã lưu.
- `console.txt`: kết quả từng mốc và kết luận PASS/FAIL, lưu UTF-8.
