# Test 09 - SMTP Command

## Mục tiêu

Kiểm tra chương trình nhận diện và phân tích được SMTP command và SMTP response.

## Dữ liệu

- File: `input.pcap`
- Nguồn: https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/smtp.pcap
- Protocol: SMTP
- Tổng số packet: `60`



## Thực hiện

```powershell
python -X utf8 main.py `
  --pcap TEST\assignment_01\test_09_smtp_command\input.pcap `
  --output TEST\assignment_01\test_09_smtp_command\result.jsonl |
  Tee-Object -FilePath TEST\assignment_01\test_09_smtp_command\console.txt
```

## Kết quả

Chương trình xử lý thành công `60` packet.

Các SMTP command được nhận diện:

- `EHLO GP`
- `AUTH LOGIN`
- `MAIL FROM:<gurpartap@patriots.in>`
- `RCPT TO:<raj_deol2002in@yahoo.co.in>`
- `DATA`
- `QUIT`

Các SMTP response được nhận diện:

- `220` - SMTP service ready
- `250` - OK / accepted
- `334` - Authentication challenge
- `235` - Authentication succeeded
- `354` - Start mail input
- `221` - Closing connection

Một số TCP packet chứa dữ liệu email lớn được nhận diện là `UNKNOWN` vì payload được chia thành nhiều TCP segment và chương trình hiện tại chưa thực hiện TCP stream reassembly.

Không có `parse_errors`.



## Tệp

- `input.pcap`: dữ liệu kiểm thử.
- `result.jsonl`: kết quả chuẩn hóa.
- `console.txt`: output khi chạy chương trình.