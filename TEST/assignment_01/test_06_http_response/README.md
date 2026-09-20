# Test 06 - HTTP Response có Status và Headers

## Mục tiêu

Kiểm tra chương trình nhận diện và phân tích đúng HTTP response, bao gồm status code và response headers.

## Dữ liệu

- File: `input.pcap`

- Nguồn: https://www.chrissanders.org/captures/http_post.pcap

- Protocol: HTTP/TCP

- Tổng số packet: `21`

- HTTP response packet: `2`

## Thực hiện

```powershell

python -X utf8 main.py --pcap TEST\assignment_01\test_06_http_response\input.pcap --output TEST\assignment_01\test_06_http_response\result.jsonl

```

## Kết quả

- Số packet: `21`

- Có `2` HTTP response được nhận diện.

- Response 1:
    - Version: `HTTP/1.1`
    - Status code: `302`
    - Reason: `Found`
    - Có response headers.
    - Có header `Location`.

- Response 2:
    - Version: `HTTP/1.1`
    - Status code: `200`
    - Reason: `OK`
    - Có response headers.
    - Có header `Content-Type`.

- `parse_errors`: không có


## Tệp

- `input.pcap`: dữ liệu kiểm thử

- `result.jsonl`: kết quả chuẩn hóa

- `console.txt`: output khi chạy chương trình