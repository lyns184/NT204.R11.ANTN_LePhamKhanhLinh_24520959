# Test 03 - UDP Packet

## Mục tiêu

Kiểm tra chương trình phân tích đúng IPv4/UDP packet.

## Dữ liệu

- File: `input.pcap`
- Nguồn: https://www.chrissanders.org/captures/udp_dnsrequest.pcap
- Protocol: UDP/DNS

## Thực hiện

```powershell
python -X utf8 main.py --pcap TEST\assignment_01\test_03_udp_packet\input.pcap --output TEST\assignment_01\test_03_udp_packet\result.jsonl
```

##  Kết quả
- Số packet: 1
- UDP packet: 1
- Source port: 1060
- Destination port: 53
- UDP length: 39 bytes.
- Payload length: 31 bytes.
- Nhận diện DNS query cho wireshark.org, type A.
- `parse_errors`: không có

## Tệp
`input.pcap`: dữ liệu kiểm thử
`result.jsonl`: kết quả chuẩn hóa
`console.txt`: output khi chạy chương trình