from __future__ import annotations

import unittest

from traffic_classification.classifier import classify_flow, infer_ground_truth
from traffic_classification.feature_extractor import parse_tcpdump_text, _icmp_flow_key
from traffic_classification.experiment import evaluate_flows


class ClassifierTests(unittest.TestCase):
    def test_web_flow_is_classified(self) -> None:
        flow = {
            "protocol": "TCP",
            "src_port": 45000,
            "dst_port": 8000,
            "avg_packet_size": 320.0,
            "bytes_per_second": 8000.0,
            "total_bytes": 3200,
            "duration_seconds": 1.1,
            "packet_count": 10,
            "small_packet_ratio": 0.2,
            "mean_inter_arrival": 0.08,
        }
        self.assertEqual(classify_flow(flow).predicted_label, "web")
        self.assertEqual(infer_ground_truth(flow), "web")

    def test_streaming_flow_is_classified(self) -> None:
        flow = {
            "protocol": "UDP",
            "src_port": 53000,
            "dst_port": 5001,
            "avg_packet_size": 1200.0,
            "bytes_per_second": 900000.0,
            "total_bytes": 3_000_000,
            "duration_seconds": 6.0,
            "packet_count": 2500,
            "small_packet_ratio": 0.0,
            "mean_inter_arrival": 0.002,
        }
        self.assertEqual(classify_flow(flow).predicted_label, "streaming")

    def test_bulk_transfer_flow_is_classified(self) -> None:
        flow = {
            "protocol": "TCP",
            "src_port": 52000,
            "dst_port": 5002,
            "avg_packet_size": 1300.0,
            "bytes_per_second": 400000.0,
            "total_bytes": 2_400_000,
            "duration_seconds": 6.0,
            "packet_count": 1900,
            "small_packet_ratio": 0.05,
            "mean_inter_arrival": 0.003,
        }
        self.assertEqual(classify_flow(flow).predicted_label, "bulk_transfer")

    def test_chat_flow_is_classified(self) -> None:
        flow = {
            "protocol": "TCP",
            "src_port": 51510,
            "dst_port": 6000,
            "avg_packet_size": 60.0,
            "bytes_per_second": 300.0,
            "total_bytes": 540,
            "duration_seconds": 2.2,
            "packet_count": 9,
            "small_packet_ratio": 1.0,
            "mean_inter_arrival": 0.31,
        }
        self.assertEqual(classify_flow(flow).predicted_label, "chat")


    def test_icmp_flow_is_classified_as_ping(self) -> None:
        flow = {
            "protocol": "ICMP",
            "src_port": 0,
            "dst_port": 0,
            "avg_packet_size": 84.0,
            "bytes_per_second": 420.0,
            "total_bytes": 420,
            "duration_seconds": 1.0,
            "packet_count": 5,
            "small_packet_ratio": 0.0,
            "mean_inter_arrival": 0.2,
        }
        self.assertEqual(classify_flow(flow).predicted_label, "ping")
        self.assertEqual(infer_ground_truth(flow), "ping")


class FeatureExtractorTests(unittest.TestCase):
    def test_parse_tcpdump_text_groups_bidirectional_packets(self) -> None:
        lines = [
            "2026-04-06 18:00:00.000000 IP 10.0.0.1.50000 > 10.0.0.2.8000: Flags [S], seq 1, win 64240, length 0",
            "2026-04-06 18:00:00.050000 IP 10.0.0.2.8000 > 10.0.0.1.50000: Flags [S.], seq 2, ack 2, win 65160, length 0",
            "2026-04-06 18:00:00.150000 IP 10.0.0.1.50000 > 10.0.0.2.8000: Flags [P.], seq 2:200, ack 3, win 64240, length 198",
            "2026-04-06 18:00:00.300000 IP 10.0.0.2.8000 > 10.0.0.1.50000: Flags [P.], seq 3:503, ack 200, win 65160, length 500",
        ]
        flows = parse_tcpdump_text(lines)
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0]["packet_count"], 4)
        self.assertEqual(flows[0]["protocol"], "TCP")
        # The canonical flow key preserves the lexicographically smaller
        # endpoint pair as the left side for bidirectional grouping.
        self.assertEqual({flows[0]["src_port"], flows[0]["dst_port"]}, {50000, 8000})

    def test_parse_tcpdump_text_detects_icmp_packets(self) -> None:
        lines = [
            "2026-04-06 18:00:00.000000 IP 10.0.0.1 > 10.0.0.2: ICMP echo request, id 1, seq 1, length 64",
            "2026-04-06 18:00:00.010000 IP 10.0.0.2 > 10.0.0.1: ICMP echo reply, id 1, seq 1, length 64",
            "2026-04-06 18:00:00.200000 IP 10.0.0.1 > 10.0.0.2: ICMP echo request, id 1, seq 2, length 64",
            "2026-04-06 18:00:00.210000 IP 10.0.0.2 > 10.0.0.1: ICMP echo reply, id 1, seq 2, length 64",
        ]
        flows = parse_tcpdump_text(lines)
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0]["protocol"], "ICMP")
        self.assertEqual(flows[0]["packet_count"], 4)
        self.assertEqual(flows[0]["src_port"], 0)
        self.assertEqual(flows[0]["dst_port"], 0)

    def test_icmp_flow_key_is_canonical(self) -> None:
        key_ab = _icmp_flow_key("10.0.0.1", "10.0.0.2")
        key_ba = _icmp_flow_key("10.0.0.2", "10.0.0.1")
        self.assertEqual(key_ab, key_ba)
        self.assertEqual(key_ab[0], "ICMP")

    def test_evaluate_flows_excludes_unknown_ground_truth_from_accuracy(self) -> None:
        flows = [
            {
                "protocol": "TCP",
                "src_port": 45000,
                "dst_port": 8000,
                "avg_packet_size": 320.0,
                "bytes_per_second": 8000.0,
                "total_bytes": 3200,
                "duration_seconds": 1.1,
                "packet_count": 10,
                "small_packet_ratio": 0.2,
                "mean_inter_arrival": 0.08,
            },
            {
                "protocol": "TCP",
                "src_port": 41000,
                "dst_port": 41001,
                "avg_packet_size": 500.0,
                "bytes_per_second": 4000.0,
                "total_bytes": 1000,
                "duration_seconds": 1.0,
                "packet_count": 2,
                "small_packet_ratio": 0.0,
                "mean_inter_arrival": 0.5,
            },
        ]
        _, summary = evaluate_flows(flows)
        self.assertEqual(summary["known_ground_truth_flows"], 1)
        self.assertEqual(summary["accuracy"], 1.0)


if __name__ == "__main__":
    unittest.main()
