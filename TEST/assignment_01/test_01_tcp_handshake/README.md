# Test 01 - TCP Three-way Handshake

## Mục tiêu

Kiểm tra chương trình nhận diện đúng TCP three-way handshake:

- SYN
- SYN-ACK
- ACK

## Dữ liệu

- File: `input.pcap`
- Nguồn: https://www.chrissanders.org/captures/tcp_handshake.pcap

## Thực hiện

```powershell
python main.py --pcap TEST\assignment_01\test_01_tcp_handshake\input.pcap --output TEST\assignment_01\test_01_tcp_handshake\result.jsonl
```

## Kết quả

- Số packet: `3`
- TCP flags: `S`, `SA`, `A`
- `parse_errors`: không có

## Tệp

- `input.pcap`: dữ liệu kiểm thử
- `result.jsonl`: kết quả chuẩn hóa
- `console.txt`: output khi chạy chương trình