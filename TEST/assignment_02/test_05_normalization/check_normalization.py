"""Reproduce T05: PCAP pipeline plus direct Preprocessor checks."""

import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FOLDER = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from ids.core.event import IDSEvent
from ids.preprocessor.processor import preprocess_event


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def original_data(event):
    return deepcopy({key: getattr(event, key) for key in (
        "network", "transport", "application", "raw_payload", "decoded",
        "decode_status", "decode_errors", "parse_errors",
    )})


def check_pipeline(log):
    relative = FOLDER.relative_to(ROOT)
    temporary = ROOT / "output/t05_normalization"
    temporary.mkdir(parents=True, exist_ok=True)
    run = subprocess.run([
        sys.executable, "-X", "utf8", "main.py",
        "--pcap", str(relative / "input.pcap"),
        "--output", str(relative / "result.jsonl"),
        "--flow-output", str(temporary.relative_to(ROOT) / "flows.jsonl"),
    ], cwd=ROOT, capture_output=True, encoding="utf-8")
    log.append(run.stdout + run.stderr)
    require(run.returncode == 0, f"CLI exit code: {run.returncode}")
    events = [json.loads(line) for line in
              (FOLDER / "result.jsonl").read_text(encoding="utf-8").splitlines()]
    require([e["packet_id"] for e in events] == list(range(1, 8)), "Expected 7 events")
    for event in events:
        require(event["parse_errors"] == [] and event["decode_errors"] == [], "Unexpected error")
        require(event["preprocess_status"] == "valid", "Expected valid preprocessing")
        require(event["processing_action"] == "process", "Expected process action")
        require(event["flow_tracking_status"] == "tracked", "Expected tracked packet")
    http = []
    for event in events[3:5]:
        fields = event["normalized"]["application"]["fields"]
        require(event["application"]["protocol"] == "HTTP", "Expected HTTP")
        require(fields["headers"] == {"host": "Example.COM", "x-token": "AbC"}, "HTTP headers")
        require(fields["path"] == "/Search?q=hello%20world", "Raw path changed")
        require(event["decoded"]["http"]["uri"]["value"] == "/Search?q=hello world", "Decoded URI")
        http.append(fields)
    require(http[0] == http[1], "Equivalent HTTP inputs differ")
    dns = []
    require(events[5]["application"]["fields"]["questions"][0]["domain"] == "example.com", "DNS raw 1")
    require(events[6]["application"]["fields"]["questions"][0]["domain"] == "Example.COM", "DNS raw 2")
    for event in events[5:7]:
        require(event["application"]["protocol"] == "DNS", "Expected DNS")
        question = event["normalized"]["application"]["fields"]["questions"][0]
        require(question["domain"] == "example.com" and question["query_type"] == "A", "DNS normalization")
        dns.append(event["normalized"]["application"]["fields"])
    require(dns[0] == dns[1], "Equivalent DNS inputs differ")
    log.append("PASS PCAP: 7 events; HTTP headers and DNS domains consistent; raw path preserved.\n")


def check_direct(log):
    http_outputs, dns_outputs = [], []
    variants = [
        ("IPv4", "TCP", "HTTP", "host", "DNS", "example.com", "A"),
        ("ipv4", "tcp", "http", "HOST", "dns", "EXAMPLE.COM.", "a"),
        (" IPV4 ", " Tcp ", " Http ", " Host ", " Dns ", " Example.COM. ", " A "),
    ]
    for number, (network, transport, application, header, dns_protocol, domain, query_type) in enumerate(variants, 1):
        for kind in ("HTTP", "DNS"):
            fields = ({"message_type": " Request ", "method": "GET",
                       "path": "/Search?q=hello%20world", "headers": {header: "Example.COM", "X-Token": " AbC "},
                       "body": "MiXeD", "body_length": 5} if kind == "HTTP" else
                      {"questions": [{"domain": domain, "query_type": query_type}], "answers": []})
            event = IDSEvent(
                packet_id=number, timestamp=100.0, capture_source="test:T05:direct",
                network={"protocol": network, "src_ip": " 10.0.0.1 ", "dst_ip": "10.0.0.2"},
                transport={"protocol": transport if kind == "HTTP" else " udp ",
                           "src_port": 12345, "dst_port": 80 if kind == "HTTP" else 53},
                application={"protocol": application if kind == "HTTP" else dns_protocol, "fields": fields},
                raw_payload=b"original bytes",
            )
            before = original_data(event)
            preprocess_event(event)
            require(original_data(event) == before, "Original Parser/Decoder data mutated")
            require(event.preprocess_status == "valid" and event.processing_action == "process", "Direct status")
            normalized = event.normalized
            require(normalized["network"]["protocol"] == "IPv4", "Network protocol")
            require(normalized["network"]["src_ip"] == "10.0.0.1", "IP whitespace")
            require(normalized["transport"]["protocol"] == ("TCP" if kind == "HTTP" else "UDP"), "Transport protocol")
            require(normalized["application"]["protocol"] == kind, "Application protocol")
            result = normalized["application"]["fields"]
            if kind == "HTTP":
                require(result["headers"] == {"host": "Example.COM", "x-token": " AbC "}, "Header names/values")
                require(result["message_type"] == "request", "Message type")
                require(result["path"] == fields["path"] and result["body"] == "MiXeD" and result["method"] == "GET", "HTTP content changed")
                http_outputs.append(normalized)
            else:
                require(len(result["questions"]) == 1, "Direct DNS question count")
                question = result["questions"][0]
                require(question["domain"] == "example.com" and question["query_type"] == "A", "Direct DNS domain/type")
                dns_outputs.append(normalized)
            log.append(json.dumps({"case": f"direct_{kind}_{number}", "input": before["application"],
                                   "normalized": normalized, "original_preserved": True, "result": "PASS"}, ensure_ascii=False) + "\n")
    require(all(x == http_outputs[0] for x in http_outputs), "HTTP variants are inconsistent")
    require(all(x == dns_outputs[0] for x in dns_outputs), "DNS variants are inconsistent")
    log.append("PASS direct: 3 HTTP + 3 DNS variants; protocol/header/domain normalization; original data preserved.\n")


def main():
    log = []
    code = 0
    try:
        check_pipeline(log)
        check_direct(log)
        log.append("PASS T05: PCAP pipeline and direct Preprocessor checks passed.\n")
    except Exception as error:
        log.append(f"FAIL T05: {type(error).__name__}: {error}\n")
        code = 1
    (FOLDER / "console.txt").write_text("".join(log), encoding="utf-8")
    print("".join(log[-2:]), end="")
    return code


if __name__ == "__main__":
    sys.exit(main())
