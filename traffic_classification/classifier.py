from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ClassificationResult:
    predicted_label: str
    rationale: str


def classify_flow(flow: dict[str, Any]) -> ClassificationResult:
    protocol = str(flow.get("protocol", "")).upper()
    dst_port = int(flow.get("dst_port", 0) or 0)
    src_port = int(flow.get("src_port", 0) or 0)
    avg_packet_size = float(flow.get("avg_packet_size", 0.0) or 0.0)
    bytes_per_second = float(flow.get("bytes_per_second", 0.0) or 0.0)
    total_bytes = int(flow.get("total_bytes", 0) or 0)
    duration = float(flow.get("duration_seconds", 0.0) or 0.0)
    packet_count = int(flow.get("packet_count", 0) or 0)
    small_packet_ratio = float(flow.get("small_packet_ratio", 0.0) or 0.0)
    mean_inter_arrival = float(flow.get("mean_inter_arrival", 0.0) or 0.0)

    if protocol == "ICMP":
        return ClassificationResult("ping", "ICMP flow — diagnostic or connectivity-test traffic")

    # Service-port rules are evaluated first because these ports are unique to
    # the generated assignment traffic and should take precedence over generic
    # size/rate heuristics.
    if protocol == "TCP" and {src_port, dst_port} & {8000, 80, 8080}:
        return ClassificationResult("web", "TCP flow targets a web service port")

    if protocol == "UDP" and (
        avg_packet_size >= 700 or bytes_per_second >= 500_000 or total_bytes >= 2_000_000
    ):
        return ClassificationResult("streaming", "High-rate UDP flow with large payload volume")

    if protocol == "TCP" and duration >= 4.0 and total_bytes >= 1_000_000 and avg_packet_size >= 700:
        return ClassificationResult("bulk_transfer", "Long-lived TCP flow carrying large byte volume")

    if protocol == "TCP" and packet_count >= 4 and avg_packet_size <= 220 and small_packet_ratio >= 0.6:
        return ClassificationResult("chat", "Small-packet interactive TCP pattern")

    if protocol == "TCP" and mean_inter_arrival >= 0.2 and avg_packet_size <= 250:
        return ClassificationResult("chat", "Bursty low-volume TCP flow with gaps between packets")

    return ClassificationResult("unknown", "Flow did not match any assignment heuristic")


def infer_ground_truth(flow: dict[str, Any]) -> str:
    ports = {int(flow.get("src_port", 0) or 0), int(flow.get("dst_port", 0) or 0)}
    protocol = str(flow.get("protocol", "")).upper()

    if protocol == "ICMP":
        return "ping"
    if ports & {8000, 80, 8080}:
        return "web"
    if protocol == "UDP" and 5001 in ports:
        return "streaming"
    if protocol == "TCP" and 5002 in ports:
        return "bulk_transfer"
    if protocol == "TCP" and 6000 in ports:
        return "chat"
    return "unknown"
