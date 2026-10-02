# Network Traffic Triage Tool

A browser-based cybersecurity tool for analysing Wireshark CSV exports and identifying unusual network traffic patterns.

> Educational project: Alerts indicate activity worth investigating and do not prove malicious behaviour.

## About the Project

The Network Traffic Triage Tool helps cybersecurity students understand how a SOC analyst or network defender can investigate unusual network behaviour.

The tool allows users to:

1. Capture network traffic using Wireshark.
2. Export the packet list as a CSV file.
3. Upload the CSV into the application.
4. Analyse the traffic locally inside the browser.
5. Identify unusual traffic patterns.
6. Review explainable security alerts.
7. Investigate the source and destination hosts.

## Privacy

All analysis happens locally inside the user's browser.

- Packet data is not uploaded to a server.
- No external AI APIs are used.
- No analytics or tracking.
- No cookies.
- No remote database.
- No cloud processing.
- No external API calls.
- No packet data is stored remotely.

Your packet capture data is analysed locally in your browser and is not uploaded anywhere.

## Features

### Network Traffic Dashboard

The dashboard provides:

- Total packets
- Unique source hosts
- Unique destination hosts
- Most active source host
- Most contacted destination host
- Most common protocol
- Average packet length
- Top source hosts
- Top destination hosts
- Protocol distribution
- Detection alerts

### Wireshark CSV Support

Version 1 supports Wireshark packet-list CSV exports.

Common supported fields include:

- No.
- Time
- Source
- Destination
- Protocol
- Length
- Info

The parser can tolerate reasonable variations in column names such as:

- Source
- Source IP
- src
- ip.src

Similar handling is used for destination, protocol, length and information fields.

## Detection Rules

The tool uses an explainable rule-based detection engine.

It does not use machine learning and does not automatically classify unusual activity as malicious.

### 1. High Packet Volume

Detects when one source generates more packets than the configured threshold.

Default threshold:

50 packets

Possible explanations include:

- File transfers
- Software updates
- Backups
- Network scanning
- Automated scripts
- Misconfiguration
- Malicious activity

The alert means the activity deserves investigation.

### 2. Possible Host Scanning

Detects when one source communicates with an unusually large number of unique destination IP addresses.

Default threshold:

10 unique destinations

This pattern may be consistent with host discovery or network scanning, but legitimate network-management tools can produce similar behaviour.

### 3. Possible Port Scanning

If the CSV contains enough information in the Info field, the tool can attempt to identify one source contacting many different destination ports.

Default threshold:

10 unique destination ports

This behaviour can occur during legitimate service discovery as well as network scanning.

### 4. High ICMP Activity

Detects sources generating high numbers of ICMP packets.

Default threshold:

30 ICMP packets

Possible explanations include:

- Troubleshooting
- Network monitoring
- Ping sweeps
- Network discovery
- Other legitimate network activity

### 5. High DNS Activity

Detects sources generating unusually high numbers of DNS packets.

Default threshold:

30 DNS packets

Possible explanations include:

- Normal browsing
- Software updates
- Automated applications
- Misconfigured systems
- Automated DNS lookups

### 6. Repeated Source-to-Destination Communication

Detects when one source repeatedly communicates with the same destination.

Default threshold:

40 packets

The alert displays:

- Source
- Destination
- Packet count
- Most common protocol

Repeated communication may represent normal application behaviour or unusual automated activity.

## Configurable Thresholds

Users can configure the detection thresholds.

| Detection | Default Threshold |
|---|---:|
| Packets per source | 50 |
| Unique destinations | 10 |
| Unique ports | 10 |
| ICMP packets | 30 |
| DNS packets | 30 |
| Repeated source-to-destination packets | 40 |

These are educational defaults and are not universal security thresholds.

A busy server may legitimately generate thousands of packets, while similar activity from another endpoint may deserve investigation.

## Alert Severity

Alerts use the following severity levels:

- Informational
- Low
- Medium
- High

Severity represents investigative priority, not certainty that an attack occurred.

## Investigation Score

The application may provide an explainable investigation score.

Example:

- High packet volume: +20
- Large number of destinations: +15
- High ICMP activity: +15

The score shows exactly what contributed to the investigation priority.

It does not represent a percentage probability of malicious activity.

## How to Think Like an Analyst

The basic investigation workflow is:

1. Observe unusual behaviour.
2. Identify the source and destination.
3. Determine which protocol is involved.
4. Establish whether the activity is expected.
5. Look for supporting indicators.
6. Correlate with other security telemetry.
7. Decide whether further investigation is required.

An anomaly is a starting point for investigation, not proof of compromise.

## Technology Stack

- HTML5
- CSS3
- Vanilla JavaScript
- Wireshark CSV
- Browser File API

No backend is required.

The project does not use:

- React
- Next.js
- Node.js backend
- Python backend
- Databases
- Cloud services
- External AI APIs
- API keys
- Unnecessary frameworks

## Project Structure

```text
NETWORK-TOOL/
│
├── index.html
├── styles.css
├── script.js
├── README.md
│
└── samples/
    ├── normal-traffic.csv
    ├── high-volume-traffic.csv
    └── mixed-soc-lab.csv
