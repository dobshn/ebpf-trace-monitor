#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
표준 입력(stdin)으로 들어오는 JSON Lines 형식의 로그를 읽어,
프로세스의 부모-자식 관계를 기반으로 OpenTelemetry Trace를 생성하고
OTLP Exporter를 통해 OpenTelemetry Collector로 전송합니다.
"""

import sys
import json

from opentelemetry import trace, context
from opentelemetry.sdk.trace import TracerProvider, Span
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.resources import Resource
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

# --- OpenTelemetry 설정 ---
resource = Resource(attributes={
    "service.name": "ebpf-trace-agent-py"
})
provider = TracerProvider(resource=resource)
trace.set_tracer_provider(provider)
otlp_exporter = OTLPSpanExporter(endpoint="localhost:4317", insecure=True)
span_processor = BatchSpanProcessor(otlp_exporter)
provider.add_span_processor(span_processor)
tracer = trace.get_tracer("ebpf.sensor.processor", "1.0.0")

# --- 핵심 로직 ---
def main():
    active_spans = {}
    print("[Agent] Python agent started. Waiting for JSON logs from stdin...", file=sys.stderr)

    for line in sys.stdin:
        # 시작 안내 메시지는 건너뜁니다.
        if "[ebpf-trace-monitor]" in line:
            continue

        try:
            log_data = json.loads(line)
        except json.JSONDecodeError:
            print(f"[Agent] Error: Failed to decode JSON from line: {line.strip()}", file=sys.stderr)
            continue

        log_type = log_data.get("type")
        pid = log_data.get("pid")
        
        if not log_type or not pid:
            continue
        
        # C Sensor가 보낸 Unix Epoch 타임스탬프를 그대로 사용합니다.
        corrected_timestamp = int(log_data.get("timestamp"))

        if log_type == "exec":
            ppid = log_data.get("ppid")
            comm = log_data.get("comm", "unknown")
            
            parent_span = active_spans.get(ppid)
            parent_context = trace.set_span_in_context(parent_span) if parent_span else None

            span = tracer.start_span(
                name=comm,
                context=parent_context,
                start_time=corrected_timestamp
            )
            
            span.set_attribute("event.type", log_type)
            span.set_attribute("process.pid", pid)
            span.set_attribute("process.ppid", ppid)
            span.set_attribute("process.executable.path", log_data.get("filename", ""))

            active_spans[pid] = span

        else:
            current_span = active_spans.get(pid)
            if current_span:
                event_time = corrected_timestamp

                if log_type == "exit":
                    current_span.set_attribute("process.exit_code", log_data.get("exit_code"))
                    current_span.set_attribute("process.duration_ms", log_data.get("duration_ms"))
                    current_span.end(end_time=event_time)
                    if pid in active_spans:
                        del active_spans[pid]
                
                elif log_type == "open":
                    current_span.add_event(
                        name="file_open",
                        attributes={"filename": log_data.get("filename", "")},
                        timestamp=event_time
                    )
                elif log_type == "conn":
                    current_span.add_event(
                        name="network_connect",
                        attributes={
                            "net.peer.ip": log_data.get("daddr", ""),
                            "net.peer.port": log_data.get("dport", 0),
                            "net.host.ip": log_data.get("saddr", "")
                        },
                        timestamp=event_time
                    )
                elif log_type == "cmd":
                     current_span.add_event(
                        name="shell_command",
                        attributes={"process.command_line": log_data.get("cmd", "")},
                        timestamp=event_time
                    )

    print("[Agent] Input stream finished. Shutting down.", file=sys.stderr)
    for pid, span in list(active_spans.items()):
        if span.is_recording():
            span.set_attribute("process.terminated", False)
            span.end()
            
    span_processor.force_flush()
    span_processor.shutdown()


if __name__ == "__main__":
    main()

