# Test 07 - Aggregation Within Window

## Mục tiêu

Kiểm tra TC07 Bài tập 4: các detection cùng khóa trong cửa sổ gom giữ chung một `alert_id`. Nhóm giữ `first_seen` ban đầu, cập nhật `last_seen` và tăng `count` sau mỗi lượt.

## Dữ liệu

Script tạo bốn Detection Event TCP/HTTP mô phỏng trong bộ nhớ. Cả bốn dùng SID `104071`, IP nguồn `192.0.2.10`, IP đích `198.51.100.20` và port đích `80`. Cấu hình mặc định bật gom nhóm trong 60 giây, tính từ timestamp đầu tiên `1700000000.0`.

| Detection | Giây kể từ mốc đầu | Port nguồn | Flow ID | Status mong đợi | Count mong đợi |
|---:|---:|---:|---|---|---:|
| 1 | 0 | 12345 | `flow-original` | `created` | 1 |
| 2 | 0 | 12345 | `flow-original` | `aggregated` | 2 |
| 3 | 15 | 23456 | `flow-later` | `aggregated` | 3 |
| 4 | 59.5 | 34567 | `flow-near-boundary` | `aggregated` | 4 |

Detection 2 giống detection đầu để kiểm tra event lặp tại cùng timestamp. Detection 3–4 đổi port nguồn và `flow_id`. Hai trường này nằm ngoài khóa gom, nên Alert vẫn giữ thông tin đại diện của detection đầu.

## Thực hiện

Chạy từ thư mục gốc project trong PowerShell:

```powershell
& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_04\test_07_aggregation_within_window\check_aggregation_within_window.py
if ($LASTEXITCODE -ne 0) { throw "TC07 failed" }
```

Script gọi AlertManager thật, so status, ID, metadata và thời gian ở từng bước với kỳ vọng. Sau lượt cuối, script mở lại SQLite tạm ở chế độ chỉ đọc để đối chiếu nhóm đã lưu rồi xuất kết quả JSON. DB tạm được dọn sau lần chạy.

## Kết quả

**PASS TC07.** Script trả mã thoát `0`. Trong bốn event, một event tạo nhóm và ba event được gom vào cùng nhóm. SQLite lưu đúng một Alert với `count = 4`, `first_seen = 1700000000.0` và `last_seen = 1700000059.5`.

`alert_id` giữ nguyên qua bốn lượt. Port nguồn và flow ID đại diện vẫn là `12345` và `flow-original`. JSON kết quả đọc lại khớp dữ liệu đã kiểm tra.

## Tệp

- `check_aggregation_within_window.py`: tạo detection, chạy AlertManager và đối chiếu SQLite.
- `result_aggregation.json`: trạng thái Alert sau từng lượt, bộ đếm và nhóm cuối đọc từ SQLite.
- `console.txt`: status, count từng lượt và kết luận PASS/FAIL, lưu UTF-8.
