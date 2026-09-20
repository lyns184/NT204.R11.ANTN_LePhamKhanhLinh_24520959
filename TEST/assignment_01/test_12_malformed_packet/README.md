# Test 12 - Malformed Packet

## Mục tiêu

Kiểm tra chương trình xử lý an toàn packet có dữ liệu malformed mà không bị crash, đồng thời vẫn tạo được event theo cấu trúc chuẩn hóa.

## Dữ liệu

- File: `input.pcap`
- Nguồn: https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/zlip-1.pcap
- Protocol: DNS

File `zlip-1.pcap` chứa DNS exploit sử dụng cơ chế nén tên miền tự tham chiếu, có thể gây vòng lặp khi giải nén tên miền. Wireshark cung cấp file này để kiểm tra khả năng xử lý dữ liệu mạng bất thường.

## Thực hiện

```powershell
python -X utf8 main.py `
  --pcap TEST\assignment_01\test_12_malformed_packet\input.pcap `
  --output TEST\assignment_01\test_12_malformed_packet\result.jsonl |
  Tee-Object -FilePath TEST\assignment_01\test_12_malformed_packet\console.txt
```

## Kết quả

Chương trình xử lý thành công `1` packet mà không bị crash.

Packet được phân tích theo cấu trúc:

- Network: `IPv4`
- Transport: `UDP`
- Application: `DNS`
- Message type: `query`
- Domain: chuỗi rỗng
- Query type number: `49159`
- Query class: `16400`
- `parse_errors`: `[]`

Các trường DNS có giá trị bất thường cho thấy packet có dữ liệu không hợp lệ hoặc không được giải mã theo dạng DNS thông thường. Tuy nhiên, chương trình vẫn tạo được event chuẩn hóa và không phát sinh exception.

## Tệp

- `input.pcap`: dữ liệu kiểm thử công khai.
- `result.jsonl`: kết quả chuẩn hóa.
- `console.txt`: output khi chạy chương trình.