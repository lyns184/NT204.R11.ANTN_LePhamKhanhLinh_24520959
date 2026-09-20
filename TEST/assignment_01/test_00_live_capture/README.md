# Test 00 - Live Capture

## Mục tiêu

Kiểm tra chương trình có thể bắt packet trực tiếp từ network interface và đưa packet vào parsing pipeline để tạo normalized IDS event.

## Dữ liệu

- Nguồn: Live network capture
- Interface: `Wi-Fi`
- Số packet cần bắt: `5`

## Thực hiện

```powershell
python -X utf8 main.py `
  --interface "Wi-Fi" `
  --count 5 `
  --output TEST\assignment_01\test_00_live_capture\result.jsonl |
  Tee-Object -FilePath TEST\assignment_01\test_00_live_capture\console.txt
```

## Kết quả

Chương trình bắt và xử lý thành công `5` packet.

Các packet thu được gồm:

- Packet 1: TCP `SYN`, source port `64426`, destination port `443`.
- Packet 2: packet không được giải mã ở network và transport layer, được giữ ở trạng thái `UNKNOWN`.
- Packet 3: TCP `SYN-ACK`.
- Packet 4: TCP `ACK`.
- Packet 5: TCP `PSH-ACK` với payload `517` bytes.

Tất cả packet có:

- `capture_source`: `interface:Wi-Fi`
- `parse_errors`: `[]`




## Tệp

- `result.jsonl`: kết quả chuẩn hóa từ live capture.
- `console.txt`: output khi chạy chương trình.
- `README.md`: mô tả test case.