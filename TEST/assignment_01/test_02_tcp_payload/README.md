# Test 02 - TCP Packet with Payload

## Mục tiêu

Kiểm tra chương trình phân tích được TCP packet có payload.

## Dữ liệu

- File: `input.pcap`
- Nguồn: Wireshark Sample Captures
- Protocol: TCP/HTTP

## Thực hiện

```powershell
python main.py --pcap TEST\assignment_01\test_02_tcp_payload\input.pcap --output TEST\assignment_01\test_02_tcp_payload\result.jsonl
```

## Kết quả

- Số packet: `12`
- Có TCP packet chứa payload.
- Không có `parse_errors`.

## Tệp

- `input.pcap`: dữ liệu kiểm thử
- `result.jsonl`: kết quả chuẩn hóa
- `console.txt`: output khi chạy chương trình