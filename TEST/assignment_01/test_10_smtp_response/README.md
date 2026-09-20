# Test 10 - SMTP Response

## Mục tiêu

Kiểm tra chương trình nhận diện và phân tích được các phản hồi từ SMTP server.

## Dữ liệu kiểm thử

- Tệp: `input.pcap`
- Nguồn: https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/smtp.pcap

## Thực hiện

```powershell
python -X utf8 main.py `
  --pcap TEST\assignment_01\test_10_smtp_response\input.pcap `
  --output TEST\assignment_01\test_10_smtp_response\result.jsonl |
  Tee-Object -FilePath TEST\assignment_01\test_10_smtp_response\console.txt
```


## Kết quả

Chương trình xử lý thành công `60` packet và nhận diện được `10` SMTP response.

Các SMTP status code được nhận diện:

* `220`: SMTP service ready.
* `250`: Request completed successfully.
* `334`: Authentication challenge.
* `235`: Authentication succeeded.
* `354`: Start mail input.
* `221`: Closing connection.

Các trường `parse_errors` đều rỗng.

## Tệp

* `input.pcap`: dữ liệu PCAP công khai.
* `result.jsonl`: kết quả chuẩn hóa.
* `console.txt`: output khi chạy chương trình.
