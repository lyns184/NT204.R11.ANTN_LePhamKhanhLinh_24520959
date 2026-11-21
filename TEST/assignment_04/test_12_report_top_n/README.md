# Test 12 - Report Top-N

## Mục tiêu

Kiểm tra TC12 Bài tập 4: báo cáo xếp hạng Top-N theo SID, classtype, IP nguồn và IP đích bằng số nhóm Alert. Khi đồng hạng, SID được xếp theo số tăng dần, classtype và IP theo thứ tự chuỗi tăng dần.

## Dữ liệu

Script ghi bảy nhóm Alert mô phỏng vào SQLite. Timestamp bắt đầu từ `1700000001.0` và tăng một giây mỗi nhóm. Cả bảy thuộc khoảng `[1700000000, 1700000060)`.

| Nhóm | SID | Classtype | IP nguồn | IP đích | Count |
|---:|---:|---|---|---|---:|
| 1 | 104121 | lab-http | 192.0.2.1 | 198.51.100.3 | 1 |
| 2 | 104123 | `null` | 192.0.2.1 | 198.51.100.2 | 25 |
| 3 | 104123 | `null` | 192.0.2.3 | 198.51.100.1 | 1 |
| 4 | 104122 | lab-dns | 192.0.2.3 | 198.51.100.1 | 1 |
| 5 | 104122 | lab-dns | 192.0.2.2 | 198.51.100.2 | 1 |
| 6 | 104121 | lab-http | 192.0.2.1 | 198.51.100.2 | 1 |
| 7 | 104121 | lab-http | 192.0.2.2 | 198.51.100.3 | 1 |

Riêng nhóm 2 có 25 lượt, khiến thứ hạng SID thay đổi nếu cộng theo lượt. Kỳ vọng là SID `104121` đứng đầu với ba nhóm. Classtype `null` được báo cáo dưới nhãn `UNKNOWN`.

## Thực hiện

Chạy từ thư mục gốc project trong PowerShell:

```powershell
& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_04\test_12_report_top_n\check_report_top_n.py
if ($LASTEXITCODE -ne 0) { throw "TC12 failed" }
```

Script mở lại SQLite tạm ở chế độ chỉ đọc và gọi `generate_report()` hai lần với `top_n = 2` và `top_n = 10`. Cả bốn bảng xếp hạng được đối chiếu theo giá trị, số nhóm, thứ tự và số dòng. Script kiểm tra thêm phân bố SID và classtype đầy đủ vẫn có ba giá trị khi Top-N giới hạn hai dòng.

## Kết quả

**PASS TC12.** Script trả mã thoát `0`. Báo cáo có **7 nhóm, 31 lượt**. Các bảng Top-2 đạt kết quả sau:

| Bảng | Hạng 1 | Hạng 2 |
|---|---|---|
| SID | 104121 (3 nhóm) | 104122 (2 nhóm) |
| Classtype | lab-http (3 nhóm) | UNKNOWN (2 nhóm) |
| IP nguồn | 192.0.2.1 (3 nhóm) | 192.0.2.2 (2 nhóm) |
| IP đích | 198.51.100.2 (3 nhóm) | 198.51.100.1 (2 nhóm) |

Với Top-10, mỗi bảng trả đủ ba giá trị có trong dữ liệu. Cả hai báo cáo được đọc lại thành công từ JSON.

## Tệp

- `check_report_top_n.py`: tạo dữ liệu SQLite, chạy báo cáo và đối chiếu các bảng xếp hạng.
- `result_top_n.json`: hai báo cáo thực tế cho Top-2 và Top-10.
- `console.txt`: kết quả từng bảng và kết luận PASS/FAIL, lưu UTF-8.
