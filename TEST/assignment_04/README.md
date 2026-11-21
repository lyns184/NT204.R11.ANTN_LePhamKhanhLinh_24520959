# Assignment 04 - Alert & Report cho hệ thống IDS

## Mục tiêu

Kiểm tra quá trình chuyển Detection Event thành Alert, lọc theo cấu hình, gom nhóm theo thời gian, lưu và truy vấn SQLite, rồi tổng hợp và xuất báo cáo.

## Danh sách testcase

| Testcase | Nội dung kiểm tra |
|---|---|
| [TC01 - Alert Object](test_01_alert_object/README.md) | Chuẩn hóa Detection Event thành Alert đủ trường và sinh UUIDv4 riêng cho mỗi lần chuyển đổi. |
| [TC02 - Priority to Severity](test_02_priority_severity/README.md) | Ánh xạ theo cấu hình và dùng severity mặc định khi priority thiếu, `null` hoặc ngoài mapping. |
| [TC03 - Invalid Detection Event](test_03_invalid_detection/README.md) | Từ chối event thiếu trường hoặc sai giá trị, ghi lý do và tiếp tục xử lý event hợp lệ. |
| [TC04 - Severity Filter](test_04_severity_filter/README.md) | Loại alert dưới ngưỡng và chấp nhận alert bằng hoặc trên ngưỡng. |
| [TC05 - SID Suppression](test_05_sid_suppression/README.md) | Loại SID theo cấu hình trước khi lưu và gom nhóm, kể cả alert có severity cao. |
| [TC06 - Distinct Alert Groups](test_06_distinct_alert_groups/README.md) | Tạo nhóm riêng khi SID, IP nguồn, IP đích, transport hoặc application protocol khác nhau. |
| [TC07 - Aggregation Within Window](test_07_aggregation_within_window/README.md) | Gom detection cùng khóa trong cửa sổ, giữ ID và cập nhật đúng `first_seen`, `last_seen`, `count`. |
| [TC08 - Aggregation Outside Window](test_08_aggregation_outside_window/README.md) | Tạo nhóm mới tại hoặc sau biên phải của cửa sổ tính từ `first_seen`. |
| [TC09 - Repository Persistence](test_09_repository_persistence/README.md) | Mở lại SQLite và đối chiếu đủ trường, giá trị `null`, Unicode, timestamp và số lượt. |
| [TC10 - Repository Query](test_10_repository_query/README.md) | Kết hợp bộ lọc thời gian, severity, SID, IP nguồn/đích và `run_id`. |
| [TC11 - Report Severity Statistics](test_11_report_severity_statistics/README.md) | Kiểm tra tổng số nhóm, tổng lượt và phân bố severity, gồm kỳ rỗng. |
| [TC12 - Report Top-N](test_12_report_top_n/README.md) | Xếp hạng SID, classtype, IP nguồn và IP đích, gồm đồng hạng và giới hạn Top-N. |
| [TC13 - Report Protocol and Time Statistics](test_13_report_protocol_time/README.md) | Đếm nhóm theo giao thức và giờ UTC, gồm nhóm kéo dài qua hai giờ và mốc sát biên. |
| [TC14 - Report Output](test_14_report_output/README.md) | Chạy CLI và đối chiếu báo cáo text, JSON và SQLite cho kỳ có dữ liệu và kỳ rỗng. |

Cả 14 testcase bắt buộc đều đã chạy và có kết quả PASS. Mỗi thư mục ghi nguồn dữ liệu, kỳ vọng và cách chạy trong `README.md`, kèm script `check_*.py`, log `console.txt` và kết quả đọc lại. Các ca dùng SQLite tạo DB tạm và lưu kết quả truy vấn hoặc báo cáo trong hồ sơ test.

## Cách tái hiện

Chạy từ thư mục gốc bằng Python trong virtual environment đã cài `requirements.txt`. Ví dụ chạy TC14 trong PowerShell:

```powershell
& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_04\test_14_report_output\check_report_output.py
if ($LASTEXITCODE -ne 0) { throw "TC14 failed" }
```

Script ghi lại kết quả và log trong thư mục testcase. Mã thoát `0` là PASS, mã khác `0` là lỗi. Các ID sinh tự động có thể thay đổi giữa những lần chạy.
