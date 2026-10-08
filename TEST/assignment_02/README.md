# Assignment 02 - Decoder, Preprocessor & Flow/Connection Tracker

## Mục tiêu

Kiểm thử các module giải mã, tiền xử lý dữ liệu và theo dõi flow/kết nối của hệ thống IDS theo mục 6 Bài tập 2.

## Chức năng cần kiểm thử

- Giải mã HTTP URL/percent-encoding và giữ nguyên URI gốc.
- Giải mã HTML entity trong text HTTP.
- Giải mã SMTP MIME Base64 và Quoted-Printable.
- Xử lý payload không phải UTF-8 hợp lệ mà không làm chương trình dừng.
- Chuẩn hóa header, protocol và domain về cách biểu diễn nhất quán.
- Xử lý field không bắt buộc bị thiếu bằng `null` hoặc `[]` phù hợp.
- Nhận diện TCP handshake và theo dõi trạng thái kết nối.
- Gộp packet hai chiều vào cùng flow và xác định direction.
- Xử lý đóng kết nối TCP bằng FIN/ACK hoặc RST.
- Theo dõi UDP query/response và phân biệt các flow đồng thời.
- Loại flow hết idle timeout khỏi bảng flow đang hoạt động.
- Thống kê packet, byte, TCP flags và duration của flow.
- Xử lý event invalid/unsupported mà không làm chương trình dừng, ghi status/reason phù hợp.

## Danh sách test case

1. **T01 - HTTP URL decode:** URI chứa percent-encoding được decode đúng; raw URI còn nguyên.
2. **T02 - HTML entity:** Giải mã `&lt;...&gt;` trong text HTTP đúng, không crash.
3. **T03 - SMTP Base64/QP:** Giải mã MIME body đúng và ghi `decode_status` phù hợp.
4. **T04 - Invalid bytes:** Payload không phải UTF-8 hợp lệ được đánh dấu lỗi/partial; chương trình tiếp tục.
5. **T05 - Normalization:** Header, protocol và domain khác kiểu chữ hoặc format được chuẩn hóa nhất quán.
6. **T06 - Missing field:** Event thiếu field không bắt buộc được xử lý `null`/`[]` nhất quán, không exception.
7. **T07 - TCP handshake:** SYN → SYN/ACK → ACK tạo một flow có trạng thái `ESTABLISHED`.
8. **T08 - Bidirectional flow:** Packet A→B và B→A có 5-tuple đảo chiều dùng cùng `flow_id`, đúng direction.
9. **T09 - TCP close:** FIN/ACK hoặc RST chuyển flow sang `CLOSED`/`RESET` phù hợp.
10. **T10 - UDP query/response:** DNS UDP hai chiều thuộc một flow, packet/byte count đúng.
11. **T11 - Concurrent flows:** Ít nhất hai flow có endpoint/port khác nhau không bị gộp nhầm.
12. **T12 - Idle timeout:** Flow không có packet mới quá timeout hết hạn và bị loại khỏi bảng flow đang hoạt động.
13. **T13 - Statistics:** Nhiều packet hai chiều có packet/byte/flag counters và duration đúng.
14. **T14 - Malformed event:** Event invalid/unsupported không làm chương trình crash; status/reason phù hợp.
