# Test 01 - Alert Object

## Mục tiêu

Kiểm tra TC01 Bài tập 4: Detection Event hợp lệ được chuyển thành Alert đủ trường, đúng kiểu và giá trị. Mỗi lần chuyển đổi sinh một `alert_id` riêng, kể cả khi sử dụng lại cùng một detection.

## Dữ liệu

`input_detections.jsonl` chứa hai Detection Event mô phỏng theo schema Bài 3. Fixture viết riêng cho testcase, không lấy từ PCAP hay lưu lượng thật. Thời gian là Unix timestamp cố định. Cấu hình Alert dùng mặc định.

| Dòng | SID / rev | Timestamp | Nguồn → đích | Protocol / application | Priority / severity mong đợi |
|---|---|---|---|---|---|
| 1 | 104001 / 2 | 1700000000.25 | 192.0.2.10:12345 → 198.51.100.20:80 | TCP / HTTP | 2 / HIGH |
| 2 | 104002 / 1 | 1700000001.0 | 192.0.2.11:53000 → 198.51.100.21:53 | UDP / UNKNOWN | null / LOW |

Dòng 1 có message tiếng Việt, `classtype = test-traffic` và `flow_id = test-flow-01`. Dòng 2 có `classtype` và `flow_id` bằng `null`. Application `UNKNOWN` của detection được chuẩn hóa thành `null` trong Alert.

## Thực hiện

Chạy từ thư mục gốc project trong PowerShell:

```powershell
& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_04\test_01_alert_object\check_alert_object.py
if ($LASTEXITCODE -ne 0) { throw "TC01 failed" }
```

Script gọi `convert_detection()` thật ba lần. Dòng TCP được truyền một lần dạng dictionary từ JSONL và một lần dạng `DetectionEvent`; dòng UDP được truyền dạng dictionary. Mỗi Alert được so với kỳ vọng khai báo riêng về schema, kiểu và giá trị. Sau đó script đọc lại JSONL đã ghi và kiểm tra các đối tượng đầu vào cùng file fixture vẫn giữ nguyên.

## Kết quả

**PASS TC01.** Script trả mã thoát `0`. Hai Alert TCP có cùng thông tin detection và severity `HIGH`. Alert UDP có severity `LOW`, giữ đúng endpoint UDP và có application, flow ID, classtype bằng `null`.

Cả ba Alert có `count = 1`, `first_seen = last_seen = timestamp` và `run_id = null` tại bước chuyển đổi trước khi lưu. Ba `alert_id` đều là UUIDv4 và khác nhau. UUID sẽ thay đổi khi chạy lại. JSONL đọc lại đủ ba dòng và giữ đúng message tiếng Việt.

## Tệp

- `input_detections.jsonl`: hai detection mô phỏng.
- `check_alert_object.py`: script chuyển đổi và đối chiếu tự động.
- `result_alerts.jsonl`: ba Alert sinh ra trong lần chạy chính thức, theo thứ tự TCP dictionary, TCP object và UDP dictionary.
- `console.txt`: kết quả kiểm tra từng Alert và kết luận PASS/FAIL, lưu UTF-8.
