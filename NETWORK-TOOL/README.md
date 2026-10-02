# Network Traffic Triage Tool (NT3)

> **Educational Network Traffic Analysis & SOC Triage Dashboard**  
> Built for cybersecurity enthusiasts, students, and aspiring SOC analysts to learn traffic triage principles without complex installations or cloud APIs.

![Privacy Guarantee](https://img.shields.io/badge/Privacy-100%25%20Local%20Browser-success)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Mac%20%7C%20Linux-blue)
![Stack](https://img.shields.io/badge/Stack-HTML5%20%7C%20CSS3%20%7C%20Vanilla%20JS-orange)

---

## 📌 Project Purpose

The **Network Traffic Triage Tool** bridges the gap between raw Wireshark packet captures and real-world Security Operations Center (SOC) investigation workflows. 

When beginning cybersecurity, packet captures can feel overwhelming due to thousands of raw lines. This tool allows users to export Wireshark packet lists as simple `.csv` files, parse them locally in their browser, and inspect an explainable triage dashboard that highlights traffic anomalies **without claiming that unusual traffic automatically equals an attack.**

### 🚨 Core Educational Philosophy
> **"An anomaly is a starting point for investigation, not proof of compromise. Detection tells an analyst where to look. Investigation determines what actually happened."**

---

## 🔒 Privacy & Local Processing Design

Privacy is a non-negotiable requirement of this project:
- **100% In-Browser Execution:** Packet captures are parsed and analyzed entirely inside your local web browser memory.
- **Zero Server Uploads:** Your network data is never sent to a cloud server, AI provider, external API, or third-party platform.
- **Zero Tracking:** No telemetry, cookies, analytics, advertisements, or background data collection.

You can safely run this tool on confidential enterprise or lab network captures completely offline.

---

## 🚀 How to Run Locally on Windows

**No installation required!** No Node.js, Python, or npm packages are needed.

1. Download or clone this repository to your local computer:
   ```text
   NETWORK-TOOL/
   ├── index.html
   ├── styles.css
   ├── script.js
   ├── README.md
   └── samples/
       ├── normal-traffic.csv
       ├── high-volume-traffic.csv
       └── mixed-soc-lab.csv
   ```
2. Double-click **`index.html`** in your Windows File Explorer.
3. The application will launch instantly in your default web browser (Google Chrome, Microsoft Edge, Firefox, Brave, etc.).

---

## 📥 How to Export Wireshark Packets as CSV

1. Open **Wireshark** on your computer.
2. Select your network adapter and capture traffic during your lab or exercise.
3. Stop the capture when finished.
4. Click **File → Export Packet Dissections → As CSV...**
5. Save the `.csv` file to your computer.
6. Drag and drop the exported `.csv` into the upload zone of the triage tool.

---

## 🔍 Supported Wireshark CSV Fields

Wireshark CSV exports may vary depending on user preferences and versions. The built-in parser automatically detects variations in column headers:

| Field | Supported Column Variations in CSV |
| :--- | :--- |
| **Source Address** | `Source`, `Source IP`, `src`, `ip.src`, `src ip` |
| **Destination Address** | `Destination`, `Destination IP`, `dst`, `ip.dst`, `dst ip` |
| **Protocol** | `Protocol`, `proto`, `trans protocol` |
| **Packet Length** | `Length`, `len`, `pkt length`, `bytes` |
| **Info / Summary** | `Info`, `summary`, `details`, `description` |
| **Frame / Packet No.** | `No.`, `No`, `number`, `frame.number`, `idx` |
| **Time** | `Time`, `timestamp`, `frame.time_relative` |

If optional columns are missing, the tool safely adapts analysis without crashing.

---

## 🛡️ Explainable Detection Rules & Default Thresholds

This tool relies on a **100% explainable, rule-based detection engine** (no hidden black-box machine learning).

| Rule Name | Severity | Default Threshold | Trigger Condition & Explanation |
| :--- | :--- | :--- | :--- |
| **Rule 1: High Packet Volume** | High / Medium | `> 50 packets` | Triggers when one Source IP generates more than 50 packets. May indicate large file transfers, OS updates, backups, or automated scripts. |
| **Rule 2: Possible Host Scanning** | Medium | `> 10 unique dest IPs` | Triggers when a host communicates with over 10 unique destinations. Consistent with host discovery or network management tools. |
| **Rule 3: Possible Port Scanning** | Medium | `> 10 unique ports` | Triggers when a host probes over 10 distinct ports on a single destination system (extracted from Info column). |
| **Rule 4: High ICMP Activity** | Low | `> 30 ICMP packets` | Triggers on high ICMP echo request volume. Associated with ping sweeps, path monitoring, or diagnostic tools. |
| **Rule 5: High DNS Activity** | Low | `> 30 DNS queries` | Triggers on high DNS query volume. Caused by active browsing, app updates, or automated lookups. |
| **Rule 6: Repeated Pair Comms** | Low | `> 40 packets` | Triggers when a specific Source-to-Destination host pair exchanges over 40 packets. Represents dominant traffic flows. |
| **Rule 7: TCP SYN Heavy Activity** | Medium | `> 20 TCP SYN packets` | Triggers when repeated TCP SYN connection requests are observed. Indicates rapid connection attempts or unfulfilled handshakes. |

---

## ⚙️ Why Thresholds Are Not Universal

All rule thresholds in the settings tab are **educational defaults**, not static security rules. 

> **Environmental Context:** A busy enterprise web server legitimately processes thousands of packets per minute, whereas the same packet volume originating from an idle printer or IoT thermostat warrants immediate investigation. SOC analysts must tune thresholds according to the environment's baseline.

---

## 📊 Transparent Investigation Scoring

Instead of creating fake mathematical probabilities like *"97% Malicious"*, NT3 calculates a **Transparent Investigation Score** (0 to 100):

- **0:** Normal Baseline Activity
- **1 – 25:** Low Activity Baseline
- **26 – 55:** Moderate Activity (Worth Reviewing)
- **56 – 100:** Elevated Activity (Requires Priority Triage)

Users can see the exact breakdown of which rules contributed points to the score.

---

## 🎥 Video Demonstration Scenarios (For Recruiters / YouTube)

Use the built-in **Interactive Demo Test Buttons** to easily demonstrate the tool:

1. **Test 1 — Baseline Traffic (`Load Normal Sample`):**
   - *Result:* Loads 20 baseline packets. Displays **Score: 0 (Normal Baseline Activity)** with zero high-severity alerts.
2. **Test 2 — High Volume Traffic (`Load High-Volume Sample`):**
   - *Result:* Host `192.168.1.25` generates 58 packets. Triggers **Rule 1: HIGH PACKET VOLUME HOST**.
3. **Test 3 — Multi-Indicator Lab (`Load Mixed SOC Lab`):**
   - *Result:* Host `192.168.1.50` contacts 18 hosts across 20+ ports. Triggers **Host Scanning, Port Scanning, SYN Heavy, ICMP, and DNS alerts**, elevating the Investigation Score to **70 (Elevated Activity)**.
4. **Key Talking Point for Demonstrations:**
   - *"Notice how the tool does not call any host an attacker. It tells the analyst where to focus their time and outlines benign explanations versus next investigative steps."*

---

## 🚧 Limitations

To maintain simplicity and client-side compatibility, Version 1 has documented limitations:
1. **CSV vs PCAP:** CSV exports contain text summaries, not full raw packet hex/payload bytes.
2. **Encrypted Payloads:** HTTPS/TLS payload content cannot be inspected from packet list CSVs.
3. **Port Extraction:** Port detection relies on Wireshark's exported `Info` string formatting.
4. **NAT Attribution:** Network Address Translation (NAT) can cause multiple internal hosts to appear as a single public IP.

---

## 🔮 Future Improvements (Version 2+ Roadmap)

- Direct `.pcap` and `.pcapng` binary parsing via WebAssembly (WASM).
- Sliding time-window detection rules (e.g. packets per second bursts).
- Interactive SVG network topology connection graphs.
- Local GeoIP lookup for public IP destination triage.
- Exportable PDF / Markdown SOC Triage Reports.

---

## 📜 License & Educational Use

This tool is created for educational and training purposes. Always ensure you have authorization before capturing or analyzing network traffic on any network.
