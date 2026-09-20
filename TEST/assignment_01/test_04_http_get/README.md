# Test 04 - HTTP GET Request

## Mục tiêu

Kiểm tra chương trình nhận diện và phân tích đúng HTTP GET request.

## Dữ liệu

- File: `input.pcap`
- Nguồn: https://www.chrissanders.org/captures/http_google.pcap
- Protocol: HTTP/TCP

## Thực hiện

```powershell
python -X utf8 main.py --pcap TEST\assignment_01\test_04_http_get\input.pcap --output TEST\assignment_01\test_04_http_get\result.jsonl
```

## Kết quả

- Số packet: 12
- HTTP GET request được nhận diện.
- Method: `GET`
- Path: `/`
- Version: `HTTP/1.1`
- Host: `www.google.com`
- TCP: `1606 -> 80`
- Payload length: 627 bytes.
- `parse_errors`: không có

## Tệp

- `input.pcap`: dữ liệu kiểm thử
- `result.jsonl`: kết quả chuẩn hóa
- `console.txt`: output khi chạy chương trình