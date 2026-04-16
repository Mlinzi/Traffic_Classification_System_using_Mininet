# Traffic Classification System

## Title Page

**Project Title:** Traffic Classification System  
**Subject Code:** `[Enter Subject Code]`  
**Subject Name:** `[Enter Subject Name]`  
**Student Name:** `[Enter Your Name]`  
**SRN:** `[Enter Your SRN]`  
**Institution:** `[Enter College / Department Name]`  
**Submission Date:** `[Enter Date]`

---

## Table of Contents

1. Problem Statement
2. SDN Architecture
3. Mininet Topology Design
4. Controller Implementation
5. Flow Rule Management
6. Functionality Implementation
7. Performance Evaluation
8. Python Script
9. Screenshot of Demo
10. GitHub Repository Link
11. Conclusion

---

## 1. Problem Statement

Modern networks carry different forms of traffic such as web browsing, file transfer, streaming, and chat communication. Network administrators need a way to observe this traffic, group it into flows, and classify it into useful categories for analysis and management.

The objective of this mini project is to build a small SDN-style experimental environment using Mininet, generate different categories of traffic, capture packets, extract simple flow-based features, and classify each flow into a meaningful traffic class.

The project focuses on the following goals:

- create a virtual network using Mininet
- generate multiple traffic types in the same environment
- capture packets using `tcpdump`
- convert packet traces into flow-level features
- classify traffic into `web`, `streaming`, `bulk_transfer`, and `chat`
- save experiment results for later comparison

---

## 2. SDN Architecture

The project follows a simple SDN-oriented architecture using software-based networking components instead of physical devices.

### Architectural Components

- **Application Layer:** Python scripts used to automate topology setup, traffic generation, packet capture, feature extraction, and classification.
- **Control / Switching Layer:** Open vSwitch bridge instances created by Mininet. These provide programmable software switching behavior inside the emulated network.
- **Data Plane:** Virtual hosts and links created by Mininet. These hosts generate and receive the traffic used in the experiment.

### Working Principle

1. Mininet creates the virtual hosts, switches, and links.
2. Virtual hosts run different applications such as HTTP server, `iperf`, and `nc`.
3. Packets are forwarded through the Open vSwitch software switch.
4. Packets are captured from the emulated topology using `tcpdump`.
5. The Python analysis pipeline extracts flow features and classifies the traffic.

This architecture allows the project to demonstrate SDN concepts in a lightweight and reproducible way on a single Ubuntu machine.

---

## 3. Mininet Topology Design

The project uses a configurable Mininet topology. During execution, the user can choose:

- topology type: `star` or `linear`
- number of hosts: from 4 to 8

### Default Host Roles

The first four hosts are assigned fixed roles so the traffic generation remains predictable:

- `h1`: client / traffic generator
- `h2`: web server
- `h3`: streaming and bulk-transfer server
- `h4`: chat server

Additional hosts, when selected, remain passive and simply participate as extra devices in the experiment.

### Star Topology

In star topology mode:

- one central switch connects all hosts
- all traffic passes through the main switch
- this mode is simple and easy to visualize

### Linear Topology

In linear topology mode:

- hosts are attached across a line of switches
- traffic may travel through multiple switches before reaching the destination
- this gives a slightly more distributed SDN setup while keeping the project manageable

### Topology Design Rationale

The topology was kept intentionally small and configurable so that:

- experiments run quickly on a local system
- the traffic remains easy to explain during a demonstration
- the same classification pipeline can be reused across different virtual layouts

---

## 4. Controller Implementation

This project uses **Open vSwitch in bridge mode through Mininet's `OVSBridge` integration** rather than implementing a separate external controller such as Ryu or POX.

### Why This Design Was Chosen

- the main focus of the project is traffic classification, not controller app development
- `OVSBridge` provides reliable forwarding inside the Mininet environment
- it keeps the implementation simple, lightweight, and suitable for a mini project

### Practical Interpretation

Although the project does not include a standalone custom SDN controller process, it still demonstrates the SDN idea of using software-defined virtual switches and a programmable emulated network. The Open vSwitch layer acts as the software switching component that enables end-to-end traffic experiments.

If the project is extended in the future, a custom controller can be added to:

- install explicit flow rules
- monitor ports dynamically
- reroute or prioritize traffic

---

## 5. Flow Rule Management

The project does not manually install custom OpenFlow rules from a separate controller. Instead, forwarding is handled by the Open vSwitch bridge behavior inside Mininet.

Flow handling in the current project occurs at two levels:

### Network Forwarding Level

- hosts generate traffic toward known destination services
- Open vSwitch forwards the packets through the emulated topology
- packet capture is performed on the Mininet switch side to observe the transmitted flows

### Traffic Classification Level

After packet capture, the Python logic groups packets into bidirectional flows using:

- source IP
- destination IP
- source port
- destination port
- transport protocol

Then the classifier applies rule-based logic:

- `web`: TCP traffic to port `8000`, `80`, or `8080`
- `streaming`: high-rate UDP flow with large payload volume
- `bulk_transfer`: long-duration TCP transfer with high byte count
- `chat`: repeated small TCP exchanges

This rule management approach is transparent and easy to justify in a mini-project report.

---

## 6. Functionality Implementation

The project is divided into clear modules.

### a. Experiment Orchestration

File: `traffic_classification/experiment.py`

This module:

- creates the Mininet topology
- prompts the user for runtime settings
- launches server-side applications
- starts packet capture
- generates traffic
- stops the experiment cleanly
- writes the final outputs

### b. Traffic Generation

The project generates four categories of traffic:

- **Web traffic:** Python HTTP requests from `h1` to `h2`
- **Streaming traffic:** UDP `iperf` traffic from `h1` to `h3`
- **Bulk transfer traffic:** TCP `iperf` traffic from `h1` to `h3`
- **Chat traffic:** repeated small `nc` messages from `h1` to `h4`

### c. Packet Capture

Packets are captured using `tcpdump` on the switch-side Mininet interface.  
The captured packets are stored as a `.pcap` file for later processing.

### d. Feature Extraction

File: `traffic_classification/feature_extractor.py`

This module converts captured packets into flows and extracts features such as:

- packet count
- total bytes
- average packet size
- duration
- packets per second
- bytes per second
- mean inter-arrival time
- ratio of small packets

### e. Classification

File: `traffic_classification/classifier.py`

This module applies rule-based heuristics to assign one of the supported traffic labels to each flow.

---

## 7. Performance Evaluation

The performance of the project was evaluated by running the end-to-end Mininet experiment and checking whether the extracted flows were correctly classified.

### Sample Successful Run

From a recent execution:

- Total flows extracted: `16`
- Known ground-truth flows: `16`
- Classified flows: `16`
- Accuracy: `1.0`

### Class Breakdown Observed

- `web`: `5`
- `streaming`: `1`
- `bulk_transfer`: `1`
- `chat`: `9`

### Evaluation Comments

- the project successfully distinguishes among the four traffic categories
- the extracted features are sufficient for a small rule-based classifier
- the pipeline is deterministic and easy to reproduce
- the timestamped output folders allow multiple runs to be preserved for comparison

This level of evaluation is appropriate for a mini project and demonstrates both functionality and correctness.

---

## 8. Python Script

The main source files used in the project are:

- `main.py`  
  Entry point for the project.

- `traffic_classification/experiment.py`  
  Handles Mininet setup, runtime prompts, service launch, packet capture, traffic generation, and cleanup.

- `traffic_classification/feature_extractor.py`  
  Parses the `.pcap` and extracts flow-level features.

- `traffic_classification/classifier.py`  
  Applies rule-based classification to the extracted flows.

- `tests/test_classifier.py`  
  Contains basic unit tests for the classifier and feature extractor logic.

> You can attach source-code screenshots here if your professor wants script snapshots in addition to the repository.

**[Insert Python Script Screenshot / Snippet Here]**

---

## 9. Screenshot of Demo

Attach screenshots of the working demo in this section.

Recommended screenshots:

- startup CLI configuration prompt
- Mininet experiment running
- final summary output
- generated output folder contents
- packet capture or classification result CSV

**[Insert Demo Screenshot 1 Here]**

**[Insert Demo Screenshot 2 Here]**

**[Insert Demo Screenshot 3 Here]**

---

## 10. GitHub Repository Link

Repository URL:

`https://github.com/Mlinzi/Traffic_Classification_System_using_Mininet`

> Replace this line with the final public/private repository URL after the push is complete, if needed.

---

## 11. Conclusion

The Traffic Classification System project successfully demonstrates how an SDN-style virtual network can be built using Mininet and Open vSwitch, and how multiple traffic types can be generated, captured, analyzed, and classified using Python.

The project achieves the mini-project objectives by:

- creating a configurable Mininet topology
- generating realistic synthetic traffic
- capturing packets and extracting useful flow features
- classifying traffic into meaningful categories
- preserving experiment outputs for later analysis

The implementation is simple, readable, and suitable for academic demonstration. It can also be extended in the future with:

- a custom SDN controller
- ML-based traffic classification
- advanced topology options
- live dashboards or visualization

Overall, the project provides a practical and understandable SDN mini-project that connects networking concepts with hands-on experimentation.
