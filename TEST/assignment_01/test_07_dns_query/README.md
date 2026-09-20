# Test 07 - DNS Query

## Mục tiêu

Kiểm tra chương trình nhận diện và phân tích đúng DNS query, bao gồm domain và query type.

## Dữ liệu

- File: `input.pcap`

- Nguồn: https://www.chrissanders.org/captures/dns_query_response.pcap

- Protocol: DNS/UDP

- Tổng số packet: `2`

- DNS query: `1`

## Thực hiện

```powershell
python -X utf8 main.py --pcap TEST\assignment_01\test_07_dns_query\input.pcap --output TEST\assignment_01\test_07_dns_query\result.jsonl
```

## Kết quả

- DNS query được nhận diện.

- Transaction ID: `6159`

- Domain: `wireshark.org`

- Query type: `A`

- Query type number: `1`

- Question count: `1`

- UDP: `1060 -> 53`

- `parse_errors`: không có


## Tệp

- `input.pcap`: dữ liệu kiểm thử

- `result.jsonl`: kết quả chuẩn hóa

- `console.txt`: output khi chạy chương trình
