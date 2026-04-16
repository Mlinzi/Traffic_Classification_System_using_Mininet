from __future__ import annotations

import csv
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from statistics import mean


TIMESTAMP_FMT = "%Y-%m-%d %H:%M:%S.%f"
PACKET_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+"
    r"(?P<src_ip>\d+\.\d+\.\d+\.\d+)\.(?P<src_port>\d+)\s+>\s+"
    r"(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\.(?P<dst_port>\d+):\s+"
    r"(?P<rest>.+?)\s+length\s+(?P<length>\d+)$"
)
# ICMP lines have no port numbers: "IP 10.0.0.1 > 10.0.0.2: ICMP echo request, ..."
ICMP_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+"
    r"(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s+>\s+"
    r"(?P<dst_ip>\d+\.\d+\.\d+\.\d+):\s+ICMP\b.+\blength\s+(?P<length>\d+)$"
)


@dataclass
class FlowAccumulator:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    timestamps: list[datetime] = field(default_factory=list)
    lengths: list[int] = field(default_factory=list)

    def add_packet(self, timestamp: datetime, length: int) -> None:
        self.timestamps.append(timestamp)
        self.lengths.append(length)

    def to_record(self) -> dict[str, object]:
        packet_count = len(self.lengths)
        total_bytes = sum(self.lengths)
        first_seen = min(self.timestamps)
        last_seen = max(self.timestamps)
        duration = max((last_seen - first_seen).total_seconds(), 0.0)
        avg_packet_size = total_bytes / packet_count if packet_count else 0.0
        inter_arrivals = [
            (self.timestamps[idx] - self.timestamps[idx - 1]).total_seconds()
            for idx in range(1, len(self.timestamps))
        ]
        mean_inter_arrival = mean(inter_arrivals) if inter_arrivals else 0.0
        packets_per_second = packet_count / duration if duration > 0 else float(packet_count)
        bytes_per_second = total_bytes / duration if duration > 0 else float(total_bytes)
        small_packet_ratio = (
            sum(1 for length in self.lengths if length <= 200) / packet_count if packet_count else 0.0
        )

        return {
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "packet_count": packet_count,
            "total_bytes": total_bytes,
            "avg_packet_size": round(avg_packet_size, 3),
            "duration_seconds": round(duration, 6),
            "packets_per_second": round(packets_per_second, 3),
            "bytes_per_second": round(bytes_per_second, 3),
            "mean_inter_arrival": round(mean_inter_arrival, 6),
            "small_packet_ratio": round(small_packet_ratio, 3),
            "first_seen": first_seen.isoformat(),
            "last_seen": last_seen.isoformat(),
        }


def _flow_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str) -> tuple[str, str, int, str, int]:
    forward = (src_ip, src_port, dst_ip, dst_port)
    reverse = (dst_ip, dst_port, src_ip, src_port)
    if forward <= reverse:
        left_ip, left_port, right_ip, right_port = forward
    else:
        left_ip, left_port, right_ip, right_port = reverse
    return protocol, left_ip, left_port, right_ip, right_port


def _icmp_flow_key(src_ip: str, dst_ip: str) -> tuple[str, str, int, str, int]:
    """Return a canonical bidirectional key for ICMP flows (no ports)."""
    if src_ip <= dst_ip:
        return "ICMP", src_ip, 0, dst_ip, 0
    return "ICMP", dst_ip, 0, src_ip, 0


def parse_tcpdump_text(lines: list[str]) -> list[dict[str, object]]:
    flows: dict[tuple[str, str, int, str, int], FlowAccumulator] = {}

    for raw_line in lines:
        line = raw_line.strip()
        if not line or " IP6 " in line:
            continue

        match = PACKET_RE.match(line)
        if match:
            rest = match.group("rest")
            protocol = "UDP" if "UDP" in rest else "TCP"
            timestamp = datetime.strptime(match.group("timestamp"), TIMESTAMP_FMT)
            src_ip = match.group("src_ip")
            src_port = int(match.group("src_port"))
            dst_ip = match.group("dst_ip")
            dst_port = int(match.group("dst_port"))
            length = int(match.group("length"))
            key = _flow_key(src_ip, src_port, dst_ip, dst_port, protocol)
            if key not in flows:
                flows[key] = FlowAccumulator(
                    src_ip=key[1], src_port=key[2], dst_ip=key[3], dst_port=key[4], protocol=key[0]
                )
            flows[key].add_packet(timestamp, length)
            continue

        icmp_match = ICMP_RE.match(line)
        if icmp_match:
            timestamp = datetime.strptime(icmp_match.group("timestamp"), TIMESTAMP_FMT)
            src_ip = icmp_match.group("src_ip")
            dst_ip = icmp_match.group("dst_ip")
            length = int(icmp_match.group("length"))
            key = _icmp_flow_key(src_ip, dst_ip)
            if key not in flows:
                flows[key] = FlowAccumulator(
                    src_ip=key[1], src_port=key[2], dst_ip=key[3], dst_port=key[4], protocol=key[0]
                )
            flows[key].add_packet(timestamp, length)

    return [record.to_record() for record in flows.values()]


def extract_flows_from_pcap(pcap_path: Path) -> list[dict[str, object]]:
    command = ["tcpdump", "-tttt", "-nn", "-r", str(pcap_path)]
    result = subprocess.run(command, check=True, text=True, capture_output=True)
    lines = result.stdout.splitlines()
    return parse_tcpdump_text(lines)


def write_csv(rows: list[dict[str, object]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        output_path.write_text("", encoding="utf-8")
        return

    # Dict insertion order is stable in Python 3.7+, so the first row defines
    # a consistent column layout for the generated CSV file.
    fieldnames = list(rows[0].keys())
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
