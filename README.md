# Traffic Classification System

This project builds a small Mininet network, generates multiple traffic types, captures packets, extracts simple flow features, and classifies the observed traffic into categories.

## Objective

The assignment demonstrates a lightweight traffic classification pipeline using:

- `Mininet` for virtual network emulation
- `tcpdump` for packet capture
- `iperf`, Python HTTP server, and `nc` for traffic generation
- Python standard library for flow feature extraction and rule-based classification

## Traffic Classes

The project generates and classifies these traffic categories:

- `web`
- `streaming`
- `bulk_transfer`
- `chat`
- `ping` (ICMP)

## Project Structure

```text
.
├── README.md
├── requirements.txt
├── main.py
├── traffic_classification
│   ├── __init__.py
│   ├── classifier.py
│   ├── experiment.py
│   └── feature_extractor.py
└── tests
    └── test_classifier.py
```

## Network Topology

The topology is a single-switch star network:

- `h1`: traffic generator and packet capture host
- `h2`: web server (also ICMP ping target)
- `h3`: bulk and streaming server (also ICMP ping target)
- `h4`: chat server (also ICMP ping target)
- `s1`: Open vSwitch switch

## Workflow

1. Start Mininet and create the virtual topology.
2. Launch services on destination hosts.
3. Capture traffic on `h1-eth0` using `tcpdump`.
4. Generate:
   - ICMP echo requests (`ping`) to h2, h3, h4
   - HTTP requests to `h2`
   - UDP streaming-like traffic using `iperf`
   - TCP bulk transfer using `iperf`
   - Small repeated chat-like messages using `nc`
5. Save packets as a `.pcap` file.
6. Parse the capture into bidirectional flows.
7. Extract simple flow features.
8. Apply a rule-based classifier.
9. Save results as CSV and JSON summaries.

## Requirements

System tools expected on Ubuntu:

- `python3`
- `mn`
- `tcpdump`
- `iperf`
- `nc`

Python dependencies:

- No third-party Python packages are required.

## How to Run

Use `sudo` because Mininet and packet capture need elevated privileges:

```bash
sudo python3 main.py
```

Optional arguments:

```bash
sudo python3 main.py --output-dir outputs
sudo python3 main.py --capture-name custom_capture.pcap
sudo python3 main.py --keep-pcap
sudo python3 main.py --ping-count 10
```

## Output Files

After execution, the project writes:

- `outputs/captures/<capture>.pcap`
- `outputs/flows.csv`
- `outputs/classification_results.csv`
- `outputs/summary.json`

## Example Features

For each flow, the extractor computes:

- source and destination IPs
- source and destination ports
- transport protocol
- packet count
- total bytes
- average packet size
- duration
- packets per second
- bytes per second
- mean inter-arrival time
- ratio of small packets

## Classification Logic

The classifier is rule-based and covers all three transport-layer protocols:

- `ping`: any ICMP flow — identified purely by protocol type
- `web`: TCP traffic to port `8000`, `80`, or `8080`
- `streaming`: high-rate UDP with large average packet size or high byte volume
- `bulk_transfer`: long-lived high-volume TCP transfer with large packets
- `chat`: small, bursty packets over short repeated TCP connections

The summary output includes both a **protocol breakdown** (TCP / UDP / ICMP flow counts) and a **class breakdown** (application-level label counts), satisfying the requirements to identify protocols and analyse traffic distribution.

This is intentionally simple and interpretable for a Computer Networks mini-project.

## Portability Notes

- The chat listener uses a loop around OpenBSD `nc` listen mode because Ubuntu's default `nc` does not reliably support the same persistent listen flags as other variants.
- Accuracy is computed only over flows with known ground-truth labels so unmatched background or malformed flows do not inflate the result.

## Test

Run the unit tests with:

```bash
python3 -m unittest discover -s tests -v
```

## Notes

- If a previous Mininet session was not cleaned up, run `sudo mn -c`.
- The classifier is rule-based, not machine-learning-based, to keep the pipeline transparent and easy to explain in a viva or report.
- The generated traffic is synthetic but realistic enough to illustrate differences among traffic classes.
