\# Network Intrusion Detection System (IDS) Simulation



A safe, offline, defensive \*\*Network Intrusion Detection System (IDS) and Security Operations Center (SOC) simulation\*\* built with Python, Flask, SQLite and Scikit-learn.



The project generates synthetic network-flow telemetry and demonstrates how an IDS can detect suspicious behavior, assign risk scores, generate alerts and support SOC-style investigation.



> \*\*Safety:\*\* This project uses only synthetic/local traffic records. It does not scan, probe, exploit, disrupt, or send malicious traffic to public or third-party systems.



\---



\## Project Overview



This project simulates an end-to-end IDS workflow:



\*\*Synthetic Traffic → Feature Engineering → Detection → Anomaly Analysis → Risk Scoring → Alert Storage → SOC Investigation → Incident Report\*\*



The goal is to demonstrate practical defensive cybersecurity concepts in a safe local environment.



\---



\## Key Features



\- Synthetic network-flow traffic generator

\- CSV traffic upload and analysis

\- Source IP and destination analysis

\- Protocol and port analysis

\- Signature/rule-based detection

\- Statistical anomaly detection

\- Optional Isolation Forest ML detection

\- Risk scoring from 0–100

\- Severity classification:

&#x20; - INFO

&#x20; - LOW

&#x20; - MEDIUM

&#x20; - HIGH

&#x20; - CRITICAL

\- Detection classification:

&#x20; - NORMAL

&#x20; - SUSPICIOUS

&#x20; - POTENTIAL INTRUSION

\- SQLite event and alert storage

\- SOC-style alert queue

\- Alert severity filtering

\- Alert investigation workflow

\- OPEN / INVESTIGATING / CLOSED lifecycle

\- Attack and detection analytics

\- HTML incident report generation

\- Automated tests



\---



\## Technology Stack



| Technology | Purpose |

|---|---|

| Python | Core application and detection logic |

| Flask | SOC web dashboard |

| SQLite | Local alert/event storage |

| Pandas | Network-flow data processing |

| NumPy | Statistical feature calculations |

| Scikit-learn | Isolation Forest anomaly detection |

| HTML/CSS | SOC dashboard interface |

| Pytest | Automated testing |

| Git/GitHub | Version control and project hosting |



\---



\## System Architecture



```text

┌──────────────────────────┐

│ Synthetic Traffic       │

│ Generator / CSV Upload  │

└────────────┬─────────────┘

&#x20;            │

&#x20;            ▼

┌──────────────────────────┐

│ Feature Engineering      │

│ Bytes / Packets / Ports  │

│ Duration / PPS           │

└────────────┬─────────────┘

&#x20;            │

&#x20;            ▼

┌──────────────────────────┐

│ Detection Engine         │

│                          │

│ • Signature Rules       │

│ • Statistical Anomaly   │

│ • Isolation Forest ML   │

└────────────┬─────────────┘

&#x20;            │

&#x20;            ▼

┌──────────────────────────┐

│ Risk \& Severity Engine   │

│ Risk Score: 0–100       │

│ INFO → CRITICAL         │

└────────────┬─────────────┘

&#x20;            │

&#x20;            ▼

┌──────────────────────────┐

│ SQLite Alert Storage     │

└────────────┬─────────────┘

&#x20;            │

&#x20;            ▼

┌──────────────────────────┐

│ Flask SOC Dashboard      │

│                          │

│ • Dashboard             │

│ • Alerts                │

│ • Analytics             │

│ • Investigation         │

│ • Incident Report       │

└──────────────────────────┘

