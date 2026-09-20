# Test 08 - DNS Response

## Mục tiêu

Kiểm tra chương trình nhận diện và phân tích đúng DNS response, bao gồm answer record, domain, query type, TTL và địa chỉ IP trả về.

## Dữ liệu

- File: `input.pcap`

- Nguồn: https://www.chrissanders.org/captures/dns_query_response.pcap

- Protocol: DNS/UDP

- Tổng số packet: `2`

- DNS response: `1`

## Thực hiện

```powershell
python -X utf8 main.py --pcap TEST\assignment_01\test_08_dns_response\input.pcap --output TEST\assignment_01\test_08_dns_response\result.jsonl
```

## Kết quả

- DNS response được nhận diện.

- Transaction ID: `6159`

- Response code: `0`

- Answer count: `1`

- Answer name: `wireshark.org`

- Answer type: `A`

- Answer type number: `1`

- TTL: `14400`

- Data: `128.121.50.122`

- UDP: `53 -> 1060`

- `parse_errors`: không có


## Tệp

- `input.pcap`: dữ liệu kiểm thử

- `result.jsonl`: kết quả chuẩn hóa

- `console.txt`: output khi chạy chương trình

- `README.md`: mô tả test case