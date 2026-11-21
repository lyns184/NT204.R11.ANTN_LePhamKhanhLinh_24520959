# Test 03 - Invalid Detection Event

## Mục tiêu

Kiểm tra TC03 Bài tập 4: Detection Event thiếu trường hoặc có giá trị sai bị từ chối với lý do rõ ràng. Detection hợp lệ sau các lỗi vẫn được xử lý và các event lỗi không làm tăng số lượt trong SQLite.

## Dữ liệu

Script tạo 11 Detection Event mô phỏng trong bộ nhớ, dùng cùng bản mẫu TCP/HTTP từ `192.0.2.10:12345` đến `198.51.100.20:80` với SID `104030`. Test dùng cấu hình mặc định với cửa sổ gom nhóm 60 giây.

| Thứ tự | Dữ liệu | Kết quả mong đợi |
|---|---|---|
| 1 | Detection hợp lệ tại `1700000000.0` | `created` |
| 2–6 | Bỏ lần lượt `timestamp`, `sid`, `msg`, `src_ip`, `dst_ip` | `rejected`, lý do chỉ rõ trường thiếu |
| 7–10 | Timestamp dạng chuỗi, SID kiểu boolean, IP nguồn ngoài phạm vi, port đích `65536` | `rejected`, lý do chỉ rõ trường lỗi |
| 11 | Detection hợp lệ cùng SID và endpoint tại `1700000001.0` | `aggregated` vào nhóm đầu |

## Thực hiện

Chạy từ thư mục gốc project trong PowerShell:

```powershell
& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_04\test_03_invalid_detection\check_invalid_detection.py
if ($LASTEXITCODE -ne 0) { throw "TC03 failed" }
```

Script gọi `AlertManager.process()` thật và kiểm tra status, nội dung chẩn đoán, bộ đếm và dữ liệu đầu vào. Sau đó script mở lại SQLite ở chế độ chỉ đọc để đối chiếu nhóm đã lưu. SQLite tạm được dọn sau lần chạy, còn kết quả đọc từ DB được lưu ở JSON.

## Kết quả

**PASS TC03.** Script trả mã thoát `0`. Cả 9 event lỗi đều trả `rejected` với lý do phù hợp. Event cuối trả `aggregated` và giữ cùng `alert_id` với event đầu.

| Chỉ số thực tế | Giá trị |
|---|---:|
| Detection nhận vào | 11 |
| Từ chối do dữ liệu lỗi | 9 |
| Nhóm mới / lượt gom vào nhóm | 1 / 1 |
| Lọc theo severity/SID / lỗi SQLite | 0 / 0 |
| Nhóm trong SQLite / tổng lượt | 1 / 2 |

Nhóm lưu có `first_seen = 1700000000.0` và `last_seen = 1700000001.0`. Kết quả JSON đọc lại khớp số liệu đã đối chiếu trong lần chạy.

## Tệp

- `check_invalid_detection.py`: tạo fixture, chạy AlertManager và đọc lại SQLite.
- `result_invalid_detection.json`: status/reason từng ca, bộ đếm và nhóm đọc từ SQLite.
- `console.txt`: chẩn đoán từng ca lỗi và kết luận PASS/FAIL, lưu UTF-8.
