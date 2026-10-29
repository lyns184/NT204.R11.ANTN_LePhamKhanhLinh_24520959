# Assignment 03 - Core Engine & Snort Rule Matching

## Mục tiêu

Lưu dữ liệu, cách tái hiện và kết quả kiểm thử Core Engine theo Bài tập 3.

## Danh sách test case

1. [T01 - Rule Loading](test_01_rule_loading/README.md): bỏ comment/dòng trống, nạp đúng rule hợp lệ.
2. [T02 - Invalid Rules](test_02_invalid_rules/README.md): ghi diagnostic cho rule lỗi, tiếp tục chạy rule hợp lệ trước/sau.
3. [T03 - Unsupported Rules](test_03_unsupported_rules/README.md): báo keyword ngoài phạm vi, loại toàn bộ rule và tiếp tục chạy rule hợp lệ.
4. [T04 - Header Parsing](test_04_header_parsing/README.md): parse any/IPv4/CIDR, port/range và direction thành Rule Object đúng.
5. [T05 - Direction Matching](test_05_direction_matching/README.md): match đúng chiều `->`/`<>`, đảo đầy đủ IP/port và giữ orientation trong detection.
6. [T06 - Rule Indexing](test_06_rule_indexing/README.md): chọn candidate theo protocol/port, giữ thứ tự, dedup và xử lý port thiếu.
7. [T07 - Header Short-Circuit](test_07_header_short_circuit/README.md): dừng rule có header không khớp trước khi gọi Content Matcher.
8. [T08 - Flow Matching](test_08_flow_matching/README.md): kiểm tra to_server/to_client, established/not_established theo snapshot từng packet và giữ unknown cho midstream.
9. [T09 - Content / Nocase](test_09_content_nocase/README.md): phân biệt hoa/thường theo nocase, dùng raw payload và giữ đúng bytes/vị trí match.
10. [T10 - Offset / Depth](test_10_offset_depth/README.md): giới hạn vùng tìm theo offset/depth, kiểm tra vừa khít/vượt biên và payload ngắn.
11. [T11 - Distance / Within](test_11_distance_within/README.md): vùng tìm tương đối giữa hai content, biên distance/within và thử lại content đầu khi cần.

T12–T14 chưa thực hiện. README trong từng test có lệnh chạy từ thư mục gốc project và giải thích kết quả.
