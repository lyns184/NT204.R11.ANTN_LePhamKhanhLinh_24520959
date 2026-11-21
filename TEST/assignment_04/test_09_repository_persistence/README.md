# Test 09 - Repository Persistence

## Mục tiêu

Kiểm tra TC09 Bài tập 4: Alert lưu vào SQLite phải đọc lại được đầy đủ sau khi kết nối ghi đã đóng. Kiểm tra cả trường có giá trị, trường `null` và metadata của nhóm đã gom.

## Dữ liệu

`input_alerts.json` chứa hai Alert mô phỏng tại tầng repository. UUID và `run_id` được đặt cố định để so từng trường sau khi mở lại DB. Timestamp là Unix time.

| SID | Run ID | Severity | First seen | Last seen | Count | Metadata |
|---:|---|---|---:|---:|---:|---|
| 104091 | `fixture-tc09-a` | HIGH | 1700000000.25 | 1700000042.75 | 4 | Có port, TCP/HTTP, flow ID, classtype, priority và rev |
| 104092 | `fixture-tc09-b` | LOW | 1700000060.5 | 1700000060.5 | 1 | Các trường metadata nêu trên bằng `null` |

Cả hai record có message tiếng Việt và IP nguồn/đích được khai báo riêng trong fixture. Repository phải giữ đủ 19 trường trên mỗi Alert sau khi xuất, gồm `timestamp` lấy từ `first_seen`.

## Thực hiện

Chạy từ thư mục gốc project trong PowerShell:

```powershell
& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_04\test_09_repository_persistence\check_repository_persistence.py
if ($LASTEXITCODE -ne 0) { throw "TC09 failed" }
```

Script tạo DB SQLite tạm và ghi hai Alert theo thứ tự SID `104092`, `104091`. Repository đóng kết nối sau mỗi lần ghi. Một repository mới mở cùng DB ở chế độ chỉ đọc và so toàn bộ khóa, kiểu và giá trị với fixture. Script đối chiếu cả nội dung DB trước và sau lần đọc. DB tạm được dọn sau khi kiểm tra.

## Kết quả

**PASS TC09.** Script trả mã thoát `0`. SQLite đọc lại đúng hai Alert theo thứ tự `first_seen` tăng dần. Cả **19 trường trên mỗi Alert** khớp fixture, gồm hai ID, hai run ID, Unicode, giá trị `null`, timestamp phần lẻ và `count`. Nội dung DB giữ nguyên sau truy vấn chỉ đọc, file đầu vào giữ nguyên và JSON kết quả đọc lại thành công.

## Tệp

- `input_alerts.json`: hai Alert mô phỏng và dữ liệu kỳ vọng sau khi nạp lại.
- `check_repository_persistence.py`: ghi, mở lại, kiểm tra SQLite và xuất kết quả.
- `result_repository.json`: hai Alert đọc lại từ DB.
- `console.txt`: kết quả từng lần ghi/đọc và kết luận PASS/FAIL, lưu UTF-8.
