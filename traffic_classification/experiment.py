from __future__ import annotations

import argparse
import json
import os
import signal
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSBridge
from mininet.topo import Topo

from traffic_classification.classifier import classify_flow, infer_ground_truth
from traffic_classification.feature_extractor import extract_flows_from_pcap, write_csv


class CliTheme:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    CYAN = "\033[36m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    BLUE = "\033[34m"


def style(text: str, *codes: str) -> str:
    return "".join(codes) + text + CliTheme.RESET


def print_banner() -> None:
    line = style("=" * 68, CliTheme.CYAN, CliTheme.BOLD)
    print(line)
    print(style("  Traffic Classification System", CliTheme.BOLD, CliTheme.CYAN))
    print(style("  Mininet · tcpdump · rule-based flow classifier", CliTheme.DIM))
    print(style("  Protocols: TCP  UDP  ICMP", CliTheme.DIM))
    print(line)


def print_stage(title: str, detail: str | None = None) -> None:
    print(style(f"\n[{title}]", CliTheme.BOLD, CliTheme.BLUE))
    if detail:
        print(style(f"  {detail}", CliTheme.DIM))


def print_ok(message: str) -> None:
    print(style(f"  [ok] {message}", CliTheme.GREEN))


def print_info(message: str) -> None:
    print(style(f"  [..] {message}", CliTheme.CYAN))


def print_warn(message: str) -> None:
    print(style(f"  [!] {message}", CliTheme.YELLOW))


def _accuracy_bar(accuracy: float, width: int = 20) -> str:
    """Return a coloured ASCII progress bar for *accuracy* (0.0–1.0)."""
    filled = round(accuracy * width)
    bar = "█" * filled + "░" * (width - filled)
    pct = f"{accuracy * 100:.1f}%"
    if accuracy >= 0.8:
        color = CliTheme.GREEN
    elif accuracy >= 0.6:
        color = CliTheme.YELLOW
    else:
        color = CliTheme.RED
    return style(bar, color) + style(f"  {pct}", CliTheme.BOLD, color)


def print_summary(
    summary: dict[str, object],
    results_csv: Path,
    summary_json: Path,
    pcap_kept: bool,
    args: argparse.Namespace,
) -> None:
    line = style("=" * 68, CliTheme.CYAN, CliTheme.BOLD)
    print(f"\n{line}")
    print(style("  Run Summary", CliTheme.BOLD, CliTheme.CYAN))
    print(line)

    print(f"  {'Topology':<22}: {args.topology}  ({args.hosts} hosts)")
    print(f"  {'Total flows':<22}: {summary['total_flows']}")
    print(f"  {'Known ground-truth':<22}: {summary['known_ground_truth_flows']}")
    print(f"  {'Classified':<22}: {summary['classified_flows']}")

    accuracy = float(summary["accuracy"])
    print(f"  {'Accuracy':<22}: {_accuracy_bar(accuracy)}")

    # Protocol breakdown
    proto_breakdown = dict(summary.get("protocol_breakdown", {}))
    total_flows = int(summary["total_flows"]) or 1
    if proto_breakdown:
        print(f"\n  {'Protocol breakdown':<22}:")
        proto_colors = {"TCP": CliTheme.BLUE, "UDP": CliTheme.YELLOW, "ICMP": CliTheme.CYAN}
        for proto in ("TCP", "UDP", "ICMP"):
            if proto in proto_breakdown:
                count = proto_breakdown[proto]
                pct = count / total_flows * 100
                color = proto_colors.get(proto, CliTheme.RESET)
                noun = "flow" if count == 1 else "flows"
                print(f"    {style(f'{proto:<8}', color, CliTheme.BOLD)}  {count:>4} {noun}  ({pct:.1f}%)")

    # Class breakdown
    breakdown = dict(summary.get("class_breakdown", {}))
    if breakdown:
        print(f"\n  {'Class breakdown':<22}:")
        label_colors = {
            "web": CliTheme.BLUE,
            "streaming": CliTheme.YELLOW,
            "bulk_transfer": CliTheme.CYAN,
            "chat": CliTheme.GREEN,
            "ping": CliTheme.CYAN,
            "unknown": CliTheme.DIM,
        }
        for label in ("web", "streaming", "bulk_transfer", "chat", "ping", "unknown"):
            if label in breakdown:
                count = breakdown[label]
                pct = count / total_flows * 100
                color = label_colors.get(label, CliTheme.RESET)
                noun = "flow" if count == 1 else "flows"
                print(f"    {style(f'{label:<14}', color, CliTheme.BOLD)}  {count:>4} {noun}  ({pct:.1f}%)")

    print(f"\n{line}")
    print(f"  Results CSV  : {results_csv}")
    print(f"  Summary JSON : {summary_json}")
    print(f"  PCAP kept    : {'yes' if pcap_kept else style('no (use --keep-pcap to retain)', CliTheme.DIM)}")
    print(line)


def build_run_output_dir(base_output_dir: str) -> Path:
    timestamp = datetime.now().strftime("run_%Y-%m-%d_%H-%M-%S")
    return Path(base_output_dir).resolve() / timestamp


def _prompt(label: str, default_hint: str, constraint_hint: str = "") -> str:
    """
    Styled prompt: bold-cyan label, dim constraint in parens, dim default in brackets.

      Label (constraint) [default]: _
    """
    parts = "  " + style(label, CliTheme.BOLD, CliTheme.CYAN)
    if constraint_hint:
        parts += style(f" ({constraint_hint})", CliTheme.DIM)
    parts += style(f" [{default_hint}]", CliTheme.DIM) + ": "
    return parts


def prompt_text(label: str, default: str) -> str:
    raw = input(_prompt(label, default)).strip()
    return raw or default


def prompt_yes_no(label: str, default: bool) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        raw = input(_prompt(label, hint)).strip().lower()
        if not raw:
            return default
        if raw in {"y", "yes"}:
            return True
        if raw in {"n", "no"}:
            return False
        print_warn("Please enter yes or no.")


def prompt_int(label: str, default: int, minimum: int | None = None, maximum: int | None = None) -> int:
    constraint = f"{minimum}–{maximum}" if minimum is not None and maximum is not None else ""
    while True:
        raw = input(_prompt(label, str(default), constraint)).strip()
        if not raw:
            value = default
        else:
            try:
                value = int(raw)
            except ValueError:
                print_warn("Please enter a valid integer.")
                continue

        if minimum is not None and value < minimum:
            print_warn(f"Value must be at least {minimum}.")
            continue
        if maximum is not None and value > maximum:
            print_warn(f"Value must be at most {maximum}.")
            continue
        return value


def prompt_choice(label: str, options: list[str], default: str) -> str:
    constraint = "/".join(options)
    while True:
        raw = input(_prompt(label, default, constraint)).strip().lower()
        if not raw:
            return default
        if raw in options:
            return raw
        print_warn(f"Please choose one of: {constraint}")


class TrafficClassificationTopo(Topo):
    def build(self, topology_type: str = "star", host_count: int = 4) -> None:
        hosts = [self.addHost(f"h{index}") for index in range(1, host_count + 1)]

        if topology_type == "linear":
            switches = [self.addSwitch(f"s{index}") for index in range(1, host_count + 1)]
            for index, host in enumerate(hosts):
                self.addLink(host, switches[index])
            for index in range(len(switches) - 1):
                self.addLink(switches[index], switches[index + 1])
            return

        switch = self.addSwitch("s1")
        for host in hosts:
            self.addLink(host, switch)


def ensure_root() -> None:
    if os.geteuid() != 0:
        raise SystemExit("This project must be run with sudo/root privileges.")


def require_command(name: str) -> None:
    if shutil.which(name) is None:
        raise SystemExit(f"Required command not found: {name}")


def run_host_cmd(host, command: str, background: bool = False) -> str:
    if background:
        return host.cmd(f"{command} >/tmp/{host.name}_bg.log 2>&1 & echo $!")
    return host.cmd(command)


def stop_background_pid(host, pid_text: str) -> None:
    pid = pid_text.strip().splitlines()[-1].strip() if pid_text.strip() else ""
    if pid.isdigit():
        host.cmd(f"kill -TERM {pid}")


def start_services(net: Mininet) -> dict[str, str]:
    h2, h3, h4 = net.get("h2", "h3", "h4")
    pids: dict[str, str] = {}

    pids["web"] = run_host_cmd(h2, "python3 -m http.server 8000", background=True)
    pids["udp_stream"] = run_host_cmd(h3, "iperf -s -u -p 5001", background=True)
    pids["tcp_bulk"] = run_host_cmd(h3, "iperf -s -p 5002", background=True)
    pids["chat"] = run_host_cmd(h4, "sh -c 'while true; do nc -l -p 6000 > /dev/null; done'", background=True)
    time.sleep(2)
    return pids


def stop_services(net: Mininet, pids: dict[str, str]) -> None:
    host_map = {
        "web": net.get("h2"),
        "udp_stream": net.get("h3"),
        "tcp_bulk": net.get("h3"),
        "chat": net.get("h4"),
    }
    for name, pid in pids.items():
        stop_background_pid(host_map[name], pid)


def start_capture(interface: str, capture_path: Path) -> subprocess.Popen[str]:
    capture_path.parent.mkdir(parents=True, exist_ok=True)
    return subprocess.Popen(
        ["tcpdump", "-i", interface, "-n", "-U", "-w", str(capture_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        start_new_session=True,
    )


def stop_capture(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return

    try:
        os.killpg(process.pid, signal.SIGINT)
        process.wait(timeout=5)
    except (ProcessLookupError, PermissionError):
        return
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=5)
        except (ProcessLookupError, PermissionError):
            return
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def generate_icmp_traffic(h1, target_ips: list[str], ping_count: int) -> None:
    for ip in target_ips:
        h1.cmd(f"ping -c {ping_count} -i 0.2 {ip}")


def generate_web_traffic(h1, web_requests: int) -> None:
    for _ in range(web_requests):
        h1.cmd(
            "python3 -c \"import urllib.request; "
            "urllib.request.urlopen('http://10.0.0.2:8000/', timeout=5).read()\""
        )
        time.sleep(0.4)


def generate_streaming_traffic(h1, stream_duration: int, stream_bandwidth_mbps: int) -> None:
    h1.cmd(f"iperf -u -c 10.0.0.3 -p 5001 -t {stream_duration} -b {stream_bandwidth_mbps}M")


def generate_bulk_traffic(h1, bulk_duration: int) -> None:
    h1.cmd(f"iperf -c 10.0.0.3 -p 5002 -t {bulk_duration}")


def generate_chat_traffic(h1, chat_messages: int) -> None:
    for idx in range(1, chat_messages + 1):
        h1.cmd(f"printf 'message-{idx}\\n' | nc -w 1 10.0.0.4 6000")
        time.sleep(0.35)


def run_traffic_scenario(net: Mininet, args: argparse.Namespace) -> None:
    h1 = net.get("h1")
    h2, h3, h4 = net.get("h2", "h3", "h4")
    generate_icmp_traffic(h1, [h2.IP(), h3.IP(), h4.IP()], args.ping_count)
    generate_web_traffic(h1, args.web_requests)
    generate_streaming_traffic(h1, args.stream_duration, args.stream_bandwidth_mbps)
    generate_bulk_traffic(h1, args.bulk_duration)
    generate_chat_traffic(h1, args.chat_messages)


def verify_connectivity(net: Mininet) -> None:
    h1, h2, h3, h4 = net.get("h1", "h2", "h3", "h4")
    for target_ip in (h2.IP(), h3.IP(), h4.IP()):
        output = h1.cmd(f"ping -c 1 -W 1 {target_ip}")
        if ", 0% packet loss" not in output:
            raise SystemExit(
                f"Connectivity check failed from h1 to {target_ip}. "
                "Mininet hosts are not forwarding traffic correctly."
            )


def evaluate_flows(flows: list[dict[str, object]]) -> tuple[list[dict[str, object]], dict[str, object]]:
    results: list[dict[str, object]] = []
    correct = 0
    known_flows = 0

    for flow in flows:
        predicted = classify_flow(flow)
        actual = infer_ground_truth(flow)
        is_correct = predicted.predicted_label == actual
        if actual != "unknown":
            known_flows += 1
            correct += int(is_correct)
        results.append(
            {
                **flow,
                "ground_truth": actual,
                "predicted_label": predicted.predicted_label,
                "correct": is_correct,
                "rationale": predicted.rationale,
            }
        )

    summary = {
        "total_flows": len(results),
        "known_ground_truth_flows": known_flows,
        "classified_flows": sum(1 for item in results if item["predicted_label"] != "unknown"),
        "accuracy": round(correct / known_flows, 3) if known_flows else 0.0,
        "class_breakdown": {},
    }

    breakdown: dict[str, int] = {}
    for item in results:
        label = str(item["predicted_label"])
        breakdown[label] = breakdown.get(label, 0) + 1
    summary["class_breakdown"] = breakdown

    proto_counts: dict[str, int] = {}
    for item in results:
        proto = str(item["protocol"])
        proto_counts[proto] = proto_counts.get(proto, 0) + 1
    summary["protocol_breakdown"] = proto_counts

    return results, summary


def write_summary(summary: dict[str, object], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Traffic Classification System using Mininet")
    parser.add_argument("--output-dir", default="outputs", help="Directory for generated artifacts")
    parser.add_argument("--capture-name", default="traffic_capture.pcap", help="Name of the packet capture file")
    parser.add_argument("--keep-pcap", action="store_true", help="Keep the raw packet capture after analysis")
    parser.add_argument("--topology", default="star", choices=("star", "linear"), help="Virtual topology type")
    parser.add_argument("--hosts", type=int, default=4, help="Number of hosts in the virtual topology")
    parser.add_argument("--web-requests", type=int, default=5, help="Number of HTTP requests to generate")
    parser.add_argument("--stream-duration", type=int, default=6, help="UDP streaming duration in seconds")
    parser.add_argument("--stream-bandwidth-mbps", type=int, default=8, help="UDP streaming bandwidth in Mbps")
    parser.add_argument("--bulk-duration", type=int, default=6, help="TCP bulk transfer duration in seconds")
    parser.add_argument("--chat-messages", type=int, default=9, help="Number of chat-style messages to generate")
    parser.add_argument("--ping-count", type=int, default=5, help="Number of ICMP echo requests per destination host")
    return parser.parse_args(argv)


def prompt_run_configuration(args: argparse.Namespace) -> argparse.Namespace:
    print_stage("Run Configuration", "Choose output settings for this execution")
    args.output_dir = prompt_text("Output directory", args.output_dir)
    args.capture_name = prompt_text("Capture file name", args.capture_name)
    args.keep_pcap = prompt_yes_no("Keep raw packet capture after analysis?", args.keep_pcap)
    print_ok("Run configuration captured")
    return args


def prompt_network_configuration(args: argparse.Namespace) -> argparse.Namespace:
    print_stage("Network Configuration", "Choose the Mininet topology and traffic settings")
    args.topology = prompt_choice("Topology type", ["star", "linear"], args.topology)
    args.hosts = prompt_int("Number of hosts", args.hosts, minimum=4, maximum=8)
    args.web_requests = prompt_int("HTTP request count", args.web_requests, minimum=1, maximum=20)
    args.stream_duration = prompt_int("UDP streaming duration (seconds)", args.stream_duration, minimum=1, maximum=30)
    args.stream_bandwidth_mbps = prompt_int(
        "UDP streaming bandwidth (Mbps)",
        args.stream_bandwidth_mbps,
        minimum=1,
        maximum=100,
    )
    args.bulk_duration = prompt_int("TCP bulk duration (seconds)", args.bulk_duration, minimum=1, maximum=30)
    args.chat_messages = prompt_int("Chat message count", args.chat_messages, minimum=1, maximum=30)
    args.ping_count = prompt_int("ICMP ping count per host", args.ping_count, minimum=1, maximum=20)
    print_ok("Network configuration captured")
    return args


def validate_capture(capture_path: Path) -> None:
    if not capture_path.exists():
        raise SystemExit(
            f"Packet capture was not created at {capture_path}. "
            "Verify that tcpdump started successfully and rerun the experiment."
        )
    if capture_path.stat().st_size == 0:
        raise SystemExit(
            f"Packet capture exists but is empty: {capture_path}. "
            "The traffic generation or tcpdump capture likely failed."
        )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    ensure_root()
    print_banner()
    args = prompt_run_configuration(args)
    args = prompt_network_configuration(args)
    print_stage("Environment Check", "Validating runtime requirements")
    for command in ("mn", "tcpdump", "iperf", "nc", "python3"):
        require_command(command)
        print_ok(f"Found command: {command}")

    setLogLevel("warning")

    output_dir = build_run_output_dir(args.output_dir)
    capture_path = output_dir / "captures" / args.capture_name
    flows_csv = output_dir / "flows.csv"
    results_csv = output_dir / "classification_results.csv"
    summary_json = output_dir / "summary.json"

    output_dir.mkdir(parents=True, exist_ok=True)

    net = Mininet(
        topo=TrafficClassificationTopo(topology_type=args.topology, host_count=args.hosts),
        switch=OVSBridge,
        controller=None,
        autoSetMacs=True,
    )
    capture_process: subprocess.Popen[str] | None = None
    service_pids: dict[str, str] = {}

    try:
        print_stage("Topology Setup", f"Starting Mininet {args.topology} topology with {args.hosts} hosts")
        net.start()
        print_ok("Mininet started")
        print_stage("Connectivity Test", "Checking host-to-host reachability from h1")
        verify_connectivity(net)
        print_ok("All destination hosts reachable from h1")
        print_stage("Service Launch", "Starting web, streaming, bulk-transfer, and chat receivers")
        service_pids = start_services(net)
        print_ok("Traffic receiver services started")
        print_stage("Packet Capture", f"Capturing packets on s1-eth1 into {capture_path.name}")
        capture_process = start_capture("s1-eth1", capture_path)
        print_ok("Packet capture started")
        time.sleep(2)
        print_stage("Traffic Generation", "Generating web, UDP streaming, TCP bulk, and chat traffic")
        print_info(f"ICMP ping: {args.ping_count} requests to each of h2, h3, h4")
        print_info(f"Web requests: {args.web_requests}")
        print_info(f"UDP streaming: {args.stream_duration} seconds at {args.stream_bandwidth_mbps} Mbps")
        print_info(f"TCP bulk transfer: {args.bulk_duration} seconds")
        print_info(f"Chat messages: {args.chat_messages} short connections")
        run_traffic_scenario(net, args)
        print_ok("Traffic generation completed")
        time.sleep(2)
    finally:
        print_stage("Cleanup", "Stopping capture, services, and Mininet")
        if capture_process is not None:
            stop_capture(capture_process)
            time.sleep(1)
            print_ok("Packet capture stopped")
        if service_pids:
            stop_services(net, service_pids)
            print_ok("Background services stopped")
        net.stop()
        print_ok("Mininet stopped")

    print_stage("Feature Extraction", "Parsing captured packets into bidirectional flows")
    validate_capture(capture_path)
    flows = extract_flows_from_pcap(capture_path)
    print_ok(f"Extracted {len(flows)} flows")
    print_stage("Classification", "Applying rule-based traffic labels")
    results, summary = evaluate_flows(flows)
    write_csv(flows, flows_csv)
    write_csv(results, results_csv)
    write_summary(summary, summary_json)
    print_ok("CSV and JSON outputs written")

    if not args.keep_pcap:
        capture_path.unlink()
        print_warn("Raw packet capture removed because --keep-pcap was not used")

    print_summary(summary, results_csv, summary_json, args.keep_pcap, args)
    return 0
