# Test 05 - HTTP POST Request

## Mục tiêu

Kiểm tra chương trình nhận diện và phân tích đúng HTTP POST request có body.

## Dữ liệu

- File: `input.pcap`
- Nguồn: https://www.chrissanders.org/captures/http_post.pcap
- Protocol: HTTP/TCP

## Thực hiện

```powershell
python -X utf8 main.py --pcap TEST\assignment_01\test_05_http_post\input.pcap --output TEST\assignment_01\test_05_http_post\result.jsonl
```

## Kết quả

- Số packet: 21
- HTTP POST request được nhận diện.
- Method: `POST`
- Path: `/wp-comments-post.php`
- Version: `HTTP/1.1`
- Host: `www.chrissanders.org`
- Content-Type: `application/x-www-form-urlencoded`
- Content-Length: `179` bytes.
- POST body được phân tích với độ dài `179` bytes.
- TCP: `1989 -> 80`
- `parse_errors`: không có

## Tệp

- `input.pcap`: dữ liệu kiểm thử
- `result.jsonl`: kết quả chuẩn hóa
- `console.txt`: output khi chạy chương trình