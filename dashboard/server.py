"""
server.py — Sentinel IDS Laptop Server
Receives alerts from Raspberry Pi over Ethernet, stores them in alerts.json,
and serves the monitoring dashboard.
Run:  python server.py
"""
import json
import os
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

# ── Config ────────────────────────────────────────────────────────────────────
ALERTS_FILE  = "alerts.json"
MAX_ALERTS   = 100
PORT         = 5000
HOST         = "0.0.0.0"

# ── App setup ─────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder=".")
CORS(app)

# ── Command queue (in memory) ─────────────────────────────────────────────────
command_queue = []  # list of {"action": "unblock", "ip": "x.x.x.x"}
# ── Helpers ───────────────────────────────────────────────────────────────────
def load_alerts() -> list:
    if not os.path.exists(ALERTS_FILE):
        return []
    try:
        with open(ALERTS_FILE, "r") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []

def save_alerts(alerts: list) -> None:
    with open(ALERTS_FILE, "w") as f:
        json.dump(alerts, f, indent=2)

def normalise_alert(raw: dict) -> dict:
    label = raw.get("label", "UNKNOWN").strip()
    label_map = {
        "ANOMALY":     "DDoS",
        "DDOS":        "DDoS",
        "DOS":         "DoS",
        "PORTSCAN":    "PortScan",
        "PORT_SCAN":   "PortScan",
        "BRUTEFORCE":  "BruteForce",
        "BRUTE_FORCE": "BruteForce",
        "BENIGN":      "Benign",
        "NORMAL":      "Benign",
    }
    attack_type = label_map.get(label.upper(), label)
    
    return {
    "timestamp":     raw.get("timestamp", datetime.now().isoformat()),
    "src_ip":        raw.get("src_ip", "—"),
    "dst_ip":        raw.get("dst_ip", "—"),
    "attack_type":   attack_type,
    "anomaly_score": raw.get("anomaly_score", None),  # ← keep this
    "received_at":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "protocol":      raw.get("protocol"),
    "label":         label,
    "block_status":  raw.get("block_status", "none"),
    }

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/", methods=["GET"])
def index():
    return send_from_directory(".", "dashboard.html")

@app.route("/<path:filename>", methods=["GET"])
def static_files(filename):
    return send_from_directory(".", filename)

@app.route("/alert", methods=["POST"])
def receive_alert():
    raw = request.get_json(silent=True)
    if not raw:
        return jsonify({"error": "Invalid or missing JSON body"}), 400

    alert = normalise_alert(raw)

    alerts = load_alerts()
    alerts.append(alert)
    if len(alerts) > MAX_ALERTS:
        alerts = alerts[-MAX_ALERTS:]
    save_alerts(alerts)

    print(
        f"[{alert['received_at']}]  ALERT"
        f"  |  {alert['attack_type']:12s}"
        f"  |  {alert['src_ip']} → {alert['dst_ip']}"
        f"  |  score={alert['anomaly_score']}"
        f"  |  block={alert['block_status']}"
    )
    return jsonify({"status": "ok", "alert": alert}), 201

@app.route("/alerts", methods=["GET"])
def get_alerts():
    return jsonify(load_alerts())

# ── Command queue routes ───────────────────────────────────────────────────────
@app.route("/unblock", methods=["POST"])
def queue_unblock():
    """Dashboard calls this to request an IP unblock."""
    data = request.get_json(silent=True)
    ip = data.get("ip") if data else None

    if not ip:
        return jsonify({"error": "No IP provided"}), 400

    # check if already queued
    if any(c["ip"] == ip and c["action"] == "unblock" for c in command_queue):
        return jsonify({"status": "already_queued", "ip": ip}), 200

    command_queue.append({"action": "unblock", "ip": ip})
    print(f"[server] Unblock queued for {ip}")
    return jsonify({"status": "queued", "ip": ip}), 200

@app.route("/commands", methods=["GET"])
def get_commands():
    """Pi polls this every 2s to get pending commands."""
    pending = command_queue.copy()
    command_queue.clear()   # clear after Pi picks them up
    return jsonify({"commands": pending}), 200
@app.route("/confirm", methods=["POST"])


def confirm_command():
    data = request.get_json(silent=True)
    ip     = data.get("ip")
    status = data.get("status")
    action = data.get("action")
    print(f"[server] Confirmed: {action} {ip} → {status}")

    if action == "unblock" and status == "done":
        alerts = load_alerts()
        for alert in alerts:
            if alert.get("src_ip") == ip:
                alert["block_status"] = "unblocked"
        save_alerts(alerts)

    return jsonify({"status": "ok"}), 200
# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if not os.path.exists(ALERTS_FILE):
        save_alerts([])
    app.run(host=HOST, port=PORT, debug=False)