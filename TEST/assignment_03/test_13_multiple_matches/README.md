# Test 13 - Multiple Matches

## Mục tiêu

Kiểm tra T13 Bài tập 3: một packet khớp nhiều rule phải tạo đủ detection cho các SID tương ứng. Engine tiếp tục duyệt sau MATCH hoặc NO_MATCH, không tạo detection trùng theo số lần content xuất hiện và không loại các lần match của packet sau trong cùng flow.

## Dữ liệu

`input.rules` gồm bốn rule hợp lệ, cùng header TCP `any any -> any 80`, revision 1:

| Rule / SID | Message | Điều kiện |
|---|---|---|
| R1 / 101301 | Admin marker | `content:"admin";` |
| R2 / 101302 | Root marker | `content:"root";` |
| R3 / 101303 | Login marker | `content:"login";` |
| R4 / 101304 | Nonempty payload | `dsize:>0;` |

R2 nằm giữa R1/R3 và không match packet nào, giúp kiểm tra Engine không dừng khi gặp NO_MATCH. Không có flow/flags condition hoặc content modifier; header cả bốn rule đều khớp năm packet.

`input.pcap` gồm năm packet Scapy tự tạo, không capture từ mạng thật:

- Ethernet/IPv4/TCP; MAC `02:00:00:00:00:01` → `02:00:00:00:00:02`.
- Cùng 5-tuple `10.0.0.1:12345` → `10.0.0.2:80`, TCP; timestamp `1700000000`–`1700000004`.
- Flags PA, ack 2001; sequence lần lượt 1001, 1018, 1023, 1029, 1029, tăng theo số byte payload đã gửi. P4 rỗng nên không tăng sequence.
- IP/TCP headers mỗi loại 20 byte; không có handshake hoặc HTTP header. Payload là raw TCP bytes trong bảng.

| Packet | Payload | Payload / IPv4 byte | SID phải MATCH | Số detection |
|---|---|---|---|---|
| 1 | `admin admin login` | 17 / 57 | 101301, 101303, 101304 | 3 |
| 2 | `admin` | 5 / 45 | 101301, 101304 | 2 |
| 3 | `public` | 6 / 46 | 101304 | 1 |
| 4 | Rỗng | 0 / 40 | Không có | 0 |
| 5 | `admin admin login` | 17 / 57 | 101301, 101303, 101304 | 3 |

P1/P5 chứa hai lần admin tại `[0,5)` và `[6,11)`, nhưng SID101301 chỉ tạo một detection cho mỗi packet, evidence dùng lần match đầu `[0,5)`. Login nằm tại `[12,17)`. P5 có payload giống P1 và cùng flow nhưng khác packet ID/timestamp/sequence, phải tạo đủ ba detection mới. P4 vẫn có event dù không rule nào match.

## Thực hiện

Chạy tại thư mục gốc project trong PowerShell:

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding

& .\.venv\Scripts\python.exe -X utf8 TEST\assignment_03\test_13_multiple_matches\check_multiple_matches.py
if ($LASTEXITCODE -ne 0) { throw "T13 failed" }
```

Script dùng Loader thật, kiểm tra rule order/conditions và đọc PCAP để đối chiếu payload/header/sequence/timestamp. Sau đó chạy `main.py` thật, đọc lại event/detection JSONL và xác nhận năm event cùng flow ID.

Phần API tạo context từ normalized event CLI và raw TCP payload PCAP đã xác minh đầy đủ độ dài. Một EvaluationEngine thật được tạo một lần, dùng xuyên suốt năm context. Mỗi lần evaluate phải trả đủ bốn rule_results theo thứ tự và đúng matched_results; script kiểm tra counters cộng dồn sau từng packet và snapshot cũ không đổi sau lần evaluate tiếp theo. Expected SID/byte range/counters được khai báo độc lập với output Engine.

Script đối chiếu đúng chín cặp packet/SID, không trùng, evidence riêng cho admin/login/dsize và metadata đúng rule/event. Input/context/raw bytes không được sửa; JSONL được đọc lại. Assertion thất bại trả mã thoát 1 và ghi FAIL vào console.



## Kết quả

**PASS T13.** CLI và script trả mã thoát `0`: năm event cùng flow, 20 kết quả Engine (9 MATCH/11 NO_MATCH), đúng chín detection theo bảng Dữ liệu.

Trong `result.jsonl`, năm event đều valid/process/tracked và cùng flow ID; parse/decode errors rỗng. Application protocol UNKNOWN và decode_status not_processed vì đây là raw TCP payload. P4 vẫn được ghi đầy đủ dù không tạo detection.

Trong `result_matches.jsonl`, mỗi packet có bốn dòng theo thứ tự SID101301–101304, kèm engine_matched_sids và engine_metrics của lần evaluate đó. R2 luôn NO_MATCH nhưng không ngăn R3/R4 được đánh giá. Mọi NO_MATCH có reason từ content stage, riêng R4/P4 từ dsize stage; matched_info null, không có ERROR hoặc NOT_EVALUABLE.

Counters của cùng một Engine được kiểm tra sau từng packet:

| Packet đã xử lý | events_evaluated | candidate_rules | matches cộng dồn | SID match của packet |
|---|---|---|---|---|
| 1 | 1 | 4 | 3 | 101301, 101303, 101304 |
| 2 | 2 | 8 | 5 | 101301, 101304 |
| 3 | 3 | 12 | 6 | 101304 |
| 4 | 4 | 16 | 6 | Không có |
| 5 | 5 | 20 | 9 | 101301, 101303, 101304 |

Snapshot của các lần evaluate trước giữ nguyên sau khi Engine xử lý packet sau. Skip/evaluation error/not-evaluable đều bằng 0.

Trong `result_detections.jsonl`, mỗi cặp packet ID/SID xuất hiện đúng một lần, theo thứ tự packet rồi thứ tự rule trong file:

- SID101301 có evidence admin `[0,5)`, pattern_hex/matched_hex `61646d696e`; hai lần admin trong P1/P5 không tạo thêm detection cho cùng SID.
- SID101303 có evidence login `[12,17)`, pattern_hex/matched_hex `6c6f67696e`.
- SID101304 có dsize expression `>0`, actual lần lượt 17/5/6/17 trên P1/P2/P3/P5; contents rỗng.
- Không có detection cho SID101302 hoặc P4. P5 vẫn có đủ ba detection mới, cùng flow ID với P1 nhưng packet ID/timestamp tương ứng P5.

Header orientation direct; flow/flags evidence null vì rule không có điều kiện này. Content rule có dsize evidence null; rule dsize không mang content evidence. Message/revision đúng rule, IP/port/timestamp/flow ID khớp event cùng lần chạy. CLI báo events_evaluated `5`, candidate_rules `20`, matches/detections_written `9`, khớp Engine API. Input/context/raw bytes không đổi và JSONL đọc lại được.

## Tệp

- `input.rules`: bốn rule content/dsize, gồm rule NO_MATCH xen giữa.
- `input.pcap`: năm packet tự tạo cùng flow, gồm payload lặp và rỗng.
- `check_multiple_matches.py`: kiểm tra fixture, CLI, Engine và detection.
- `result.jsonl`: năm IDS event của CLI.
- `result_matches.jsonl`: 20 kết quả từ EvaluationEngine, kèm matched_sids và counters từng event.
- `result_detections.jsonl`: chín detection của CLI khi kiểm tra thành công.
- `console.txt`: output CLI và kết quả kiểm tra PASS/FAIL, UTF-8.
- `README.md`: dữ liệu, cách chạy và giải thích kết quả.
