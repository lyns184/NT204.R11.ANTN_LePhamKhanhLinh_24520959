# Assignment 01 - Packet Capture & Parser

## Mục tiêu

Kiểm thử module thu thập và phân tích packet của hệ thống IDS.

## Chức năng cần kiểm thử

- Đọc packet từ file PCAP.
- Bắt packet trực tiếp từ network interface.
- Phân tích IPv4.
- Phân tích TCP và UDP.
- Phân tích HTTP/1.x, DNS và SMTP.
- Xử lý protocol không hỗ trợ.
- Xử lý packet malformed mà không làm chương trình dừng.
- Xuất kết quả theo định dạng JSON Lines.

## Danh sách test case

1. TCP three-way handshake.
2. TCP packet có payload.
3. UDP packet.
4. HTTP GET request.
5. HTTP POST request có body.
6. HTTP response có status và header.
7. DNS query.
8. DNS response.
9. SMTP command.
10. SMTP response.
11. Unsupported protocol.
12. Malformed packet.
