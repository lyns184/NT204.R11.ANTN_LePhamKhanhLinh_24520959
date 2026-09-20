# Test 11 - Unknown/Unsupported Protocol

## Mục tiêu

Kiểm tra chương trình xử lý an toàn packet thuộc giao thức chưa được hỗ trợ mà không bị dừng hoặc phát sinh lỗi ngoài dự kiến.

## Dữ liệu

- File: `input.pcap`
- Nguồn: https://www.chrissanders.org/captures/arp_resolution.pcap
- Protocol trong PCAP: ARP
ARP hiện không thuộc phạm vi các giao thức mà chương trình phân tích, vì vậy được dùng để kiểm tra trường hợp unknown/unsupported protocol.

## Thực hiện

```powershell
python -X utf8 main.py `
  --pcap TEST\assignment_01\test_11_unknown_protocol\input.pcap `
  --output TEST\assignment_01\test_11_unknown_protocol\result.jsonl |
  Tee-Object -FilePath TEST\assignment_01\test_11_unknown_protocol\console.txt
```

## Kết quả

- Chương trình đọc được toàn bộ packet mà không bị crash.
- `network.protocol`: `UNKNOWN`
- `transport.protocol`: `UNKNOWN`
- `application.protocol`: `UNKNOWN`
- Không có `parse_errors`.

## Tệp

- `input.pcap`: dữ liệu kiểm thử công khai.
- `result.jsonl`: kết quả chuẩn hóa.
- `console.txt`: output khi chạy chương trình.