# PacketWatch
## Real-Time ML-Powered Network Intrusion Detection System

Silent Sentinel is a real-time, machine learning-based Network Intrusion Detection System (IDS) designed for resource-constrained network environments. It operates as an inline middlebox, inspecting traffic flows and blocking threats autonomously — without relying on signature databases or cloud connectivity.

---

## Overview

Traditional IDS solutions depend on known-attack signatures, leaving networks vulnerable to novel or evolving threats. Silent Sentinel addresses this by combining unsupervised anomaly detection with supervised attack classification in a two-layer ML pipeline, deployed on a physical middlebox between the attacker and the protected network.

The system was designed and evaluated in the context of a Primary Health Centre (PHC) network, where data sensitivity and reliable uptime are critical.

---

## Key Features

### Two-Layer ML Detection Pipeline
- **Layer 1 — Isolation Forest** (unsupervised): Detects any anomalous traffic pattern and produces a continuous anomaly score (0–100)
- **Layer 2 — Random Forest** (supervised): Classifies confirmed anomalies into specific attack types
- Layer 2 is only invoked when Layer 1 signals an anomaly, reducing false positives and computation overhead

### Attack Coverage
Trained on the CICIDS2017 dataset across seven attack classes:

| Attack Type | Description |
|-------------|-------------|
| DDoS | Distributed volumetric flooding |
| DoS | Single-source denial of service |
| PortScan | Network reconnaissance |
| BruteForce | Credential stuffing attacks |
| WebAttack | SQL injection, XSS, etc. |
| Infiltration | Covert exfiltration attempts |
| Botnet | C2 communication patterns |

### Static Rules Engine
Fast-path pre-ML detection for four high-confidence attack patterns:
- SYN / Half-Open Scan
- DoS / DDoS Asymmetric Flood
- Port / Stealth Scan
- ICMP Flood

Static rules trigger blocking immediately, without invoking the ML pipeline.

### Proportional IP Blocking
- iptables-based blocking via a dedicated `IDS_BLOCK` chain
- Block duration scales with anomaly score: 2 min (low) → 5 min (medium) → 10 min (high)
- Permanent blocking for repeat offenders (score ≥ 70)
- Protected IPs (gateway, server) are never blocked

### Privacy-by-Design
- Packet capture limited to `snaplen=128` bytes — headers only, no payload inspection
- No user data is stored or transmitted externally

### Live Web Dashboard
- Flask backend with `alerts.json` storage
- Real-time alert feed, blocked IP sidebar, attack type charts
- Session-authenticated login page
- Remote unblock capability via dashboard UI

---

## System Architecture

```
Attacker Laptop
      ↓ WiFi
┌─────────────────────────────────┐
│     IDS Laptop (Ubuntu)         │
│  ┌─────────────────────────┐    │
│  │   Static Rules Engine   │    │
│  └────────────┬────────────┘    │
│               ↓                 │
│  ┌─────────────────────────┐    │
│  │  Layer 1: Isolation     │    │
│  │  Forest (anomaly score) │    │
│  └────────────┬────────────┘    │
│               ↓ (if anomaly)    │
│  ┌─────────────────────────┐    │
│  │  Layer 2: Random Forest │    │
│  │  (attack classification)│    │
│  └────────────┬────────────┘    │
│               ↓                 │
│  ┌─────────────────────────┐    │
│  │  Blocker (iptables)     │    │
│  └────────────┬────────────┘    │
└───────────────┼─────────────────┘
                ↓ Ethernet
     Server Laptop (Windows)
     Flask Dashboard (port 5000)
```

---

## Performance

| Metric | Value |
|--------|-------|
| Layer 2 Weighted Accuracy | ~100% (held-out test set) |
| Layer 2 Attack Classes | 7 |
| Features Used | 10 |
| Anomaly Score Range | 0–100 (continuous) |
| Packet Capture Snaplen | 128 bytes |

---

## Technology Stack

| Component | Technology |
|-----------|------------|
| IDS Host OS | Ubuntu (inline middlebox) |
| Packet Capture | pcapy-ng, dpkt |
| ML Framework | scikit-learn (sklearn 1.8.0) |
| Layer 1 Model | Isolation Forest |
| Layer 2 Model | Random Forest |
| IP Blocking | iptables (`IDS_BLOCK` chain) |
| Dashboard Backend | Flask (Python) |
| Dashboard Frontend | HTML / CSS / JavaScript / Chart.js |
| Model Serialization | joblib |
| Dataset | CICIDS2017 |

---

## Project Structure

```
/
├── feature_extractor.py   # pcapy + dpkt packet capture, flow feature computation
├── ids.py                 # Main detection loop, ML inference, alert posting
├── static_rules.py        # Fast-path rule-based detection
├── blocker.py             # iptables blocking / unblocking logic
├── server.py              # Flask dashboard backend
├── templates/
│   └── dashboard.html     # Web dashboard frontend
├── alerts.json            # Live alert storage (last 100 alerts)
├── ML_1.pkl               # Trained Isolation Forest model
└── ML_2_layer.pkl         # Trained Random Forest model
```

---

## Selected Features

```python
selected_columns = [
    'Flow Duration', 'Flow IAT Mean', 'Flow IAT Std',
    'Packet Length Variance', 'Packet Length Max',
    'Init Fwd Win Bytes', 'Init Bwd Win Bytes',
    'Fwd Packets/s', 'Bwd Packet Length Mean', 'Packet Length Min'
]
```

Features were selected through a two-phase process: initial importance ranking followed by class separability analysis to resolve overlap between PortScan, BruteForce, and Botnet classes.

---

## Dataset

**CICIDS2017** — Canadian Institute for Cybersecurity Intrusion Detection dataset  
- Sampled to 17,600 flows per class for balanced training  
- Benign traffic used exclusively for Layer 1 (unsupervised) training  
- All seven attack classes used for Layer 2 (supervised) training  

---

## Notes

- scikit-learn version must match between training and deployment environments — model `.pkl` files are version-sensitive
- The IDS laptop uses the `FORWARD` iptables chain (not `INPUT`), as it operates as a router/middlebox
- Running `ids.py` with `sudo` requires dependencies installed in the root Python environment
