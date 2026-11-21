# Test 10 - Repository Query

## Mục tiêu

Kiểm tra TC10 Bài tập 4: SQLite lọc Alert theo khoảng thời gian và kết hợp đúng severity, SID, IP nguồn, IP đích và `run_id`. Các bộ lọc dùng phép AND. Khoảng thời gian tính theo `first_seen` và có dạng `[from, to)`.

## Dữ liệu

Script tạo chín nhóm Alert mô phỏng trực tiếp và ghi vào SQLite theo thứ tự timestamp giảm dần. Mốc đầu là `1700000000.0`. Các trường chuẩn là severity HIGH, SID `104101`, nguồn `192.0.2.10`, đích `198.51.100.20` và run `fixture-tc10-a`.

| Nhãn nhóm | Offset của `first_seen` (giây) | Điểm khác với nhóm chuẩn |
|---|---:|---|
| `before_range` | -1 | `last_seen` ở giây 2 để kiểm tra lọc theo `first_seen` |
| `at_start` | 0 | Nằm đúng biên trái |
| `inside` | 10 | Nằm trong kỳ |
| `other_severity` | 20 | LOW |
| `other_sid` | 25 | SID `104102` |
| `other_source` | 30 | IP nguồn `192.0.2.11` |
| `other_destination` | 35 | IP đích `198.51.100.21` |
| `other_run` | 40 | Run `fixture-tc10-b` |
| `at_end` | 60 | Nằm đúng biên phải |

## Thực hiện

Chạy từ thư mục gốc project trong PowerShell:

```powershell
& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_04\test_10_repository_query\check_repository_query.py
if ($LASTEXITCODE -ne 0) { throw "TC10 failed" }
```

Script dùng repository thật để ghi fixture, mở lại DB tạm ở chế độ chỉ đọc và đối chiếu danh sách Alert theo ID và thứ tự. Kỳ chính dùng offset `[0, 60)`, kỳ kế tiếp dùng `[60, 120)`. Các truy vấn kỳ đảo chiều và hai mốc bằng nhau phải báo `ValueError`. DB tạm được dọn sau khi kiểm tra.

## Kết quả

**PASS TC10.** Script trả mã thoát `0`. Sáu truy vấn hợp lệ trả đúng tập kết quả và hai khoảng không hợp lệ đều có lý do rõ ràng.

| Truy vấn | Số Alert | Kết quả kiểm tra |
|---|---:|---|
| Không lọc | 9 | Đúng thứ tự tăng dần theo `first_seen` |
| Chỉ lọc thời gian | 7 | Giữ nhóm biên trái, bỏ nhóm biên phải và nhóm bắt đầu trước kỳ |
| Kỳ chính và đầy đủ bộ lọc | 2 | `at_start`, `inside` |
| Kỳ chính và các bộ lọc, bỏ `run_id` | 3 | Thêm `other_run` |
| Kỳ kế tiếp và đầy đủ bộ lọc | 1 | `at_end` |
| SID không tồn tại | 0 | Danh sách rỗng |

JSON kết quả đọc lại thành công và giữ đầy đủ tiêu chí, danh sách kỳ vọng, Alert trả về và chẩn đoán.

## Tệp

- `check_repository_query.py`: tạo fixture, ghi SQLite và kiểm tra truy vấn.
- `result_queries.json`: bộ lọc, kết quả, Alert đọc được hoặc lỗi theo từng ca.
- `console.txt`: kết quả từng truy vấn và kết luận PASS/FAIL, lưu UTF-8.
