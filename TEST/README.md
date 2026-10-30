# Kiểm thử hệ thống IDS

Thư mục này lưu dữ liệu và kết quả kiểm thử của từng bài tập.

## Danh sách bài tập

| Thư mục | Nội dung | Hồ sơ hiện có |
|---|---|---|
| [assignment_01](assignment_01/README.md) | Packet Capture & Parser | Live capture và 12 nhóm test offline |
| [assignment_02](assignment_02/README.md) | Decoder, Preprocessor, Flow/Connection Tracker | T01–T14 |
| [assignment_03](assignment_03/README.md) | Core Engine & Snort Rule Matching | T01–T14 |

Mỗi test case được lưu trong một thư mục riêng, bao gồm:

- Dữ liệu đầu vào.
- Kết quả đầu ra.
- Kết quả chạy trên terminal.
- README mô tả nguồn dữ liệu, mục tiêu và kết quả kiểm thử.

README từng test dùng các mục **Mục tiêu, Dữ liệu, Thực hiện, Kết quả, Tệp**. PCAP Scapy tự tạo, event/context mô phỏng trực tiếp và live capture được phân biệt rõ trong phần Dữ liệu.

## Cách tái hiện

Chạy lệnh trong README từng test tại root project với virtual environment đã cài `requirements.txt`. Ví dụ T14 Bài 3:

```powershell
& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_03\test_14_detection_schema\check_detection_schema.py
if ($LASTEXITCODE -ne 0) { throw "T14 failed" }
```

Runner ghi lại result/console của testcase; assertion thất bại trả mã thoát khác 0. Bài 1–2 có các test tái hiện bằng CLI hoặc script theo README tương ứng.

