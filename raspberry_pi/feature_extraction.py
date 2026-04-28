import numpy as np
import dpkt
import pcapy
import threading
import time
from collections import defaultdict


INTERFACE = "enp4s0f1"
PACKET_THRESHOLD = 10       # compute features every N packets per flow
SNAPLEN          = 128      # bytes captured per packet (headers only)
PROMISC          = True
TIMEOUT_MS       = 100
BPF_FILTER       = "tcp or udp or icmp"

flows           = {}        
completed_flows = []        
lock            = threading.Lock()


# ─── Packet handler ───────────────────────────────────────────────────────────
def process_packet(hdr, buf):
    
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except Exception:
        return

    if not isinstance(eth.data, dpkt.ip.IP):
        return

    ip       = eth.data
    protocol = ip.p                     # 6=TCP, 17=UDP, 1=ICMP
    src_ip   = dpkt.socket.inet_ntoa(ip.src)
    dst_ip   = dpkt.socket.inet_ntoa(ip.dst)

    # Use original wire length, NOT len(buf), for accurate byte counts
    length    = hdr.getlen()
    timestamp = time.time()

    # ── TCP flags & window size ───────────────────────────────────────────────
    syn = ack = rst = 0
    tcp_window = 0

    if isinstance(ip.data, dpkt.tcp.TCP):
        tcp   = ip.data
        flags = tcp.flags
        syn   = 1 if (flags & dpkt.tcp.TH_SYN) else 0
        ack   = 1 if (flags & dpkt.tcp.TH_ACK) else 0
        rst   = 1 if (flags & dpkt.tcp.TH_RST) else 0
        tcp_window = tcp.win                # TCP receive window (bytes)

    packet_info = {
        "timestamp":  timestamp,
        "length":     length,
        "syn":        syn,
        "ack":        ack,
        "rst":        rst,
        "tcp_window": tcp_window,
        "src_ip":     src_ip,   # kept per-packet to determine Fwd/Bwd
    }

    flow_key = (src_ip, dst_ip, protocol)

    with lock:
        if flow_key not in flows:
            flows[flow_key] = []

        flows[flow_key].append(packet_info)

        if len(flows[flow_key]) >= PACKET_THRESHOLD:
            flow_packets = flows.pop(flow_key)
            features, meta = compute_features(flow_packets, flow_key)
            completed_flows.append((meta, features))


# ─── Feature computation ──────────────────────────────────────────────────────
def compute_features(packets, flow_key):
    """
    Extracts the 10 features the ML model was trained on:

        Flow Duration, Flow IAT Mean, Flow IAT Std,
        Packet Length Variance, Packet Length Max,
        Init Fwd Win Bytes, Init Bwd Win Bytes,
        Fwd Packets/s, Bwd Packet Length Mean, Packet Length Min

    Direction convention (matches CICIDS2017):
        Fwd = packets whose src_ip matches the FIRST packet's src_ip
        Bwd = all other packets
    """
    src_ip, dst_ip, protocol = flow_key

    # Fwd direction = same src_ip as the first packet seen in this flow
    fwd_src = packets[0]["src_ip"]

    lengths    = [p["length"]    for p in packets]
    timestamps = [p["timestamp"] for p in packets]

    fwd_packets = [p for p in packets if p["src_ip"] == fwd_src]
    bwd_packets = [p for p in packets if p["src_ip"] != fwd_src]

    # ── Flow Duration ─────────────────────────────────────────────────────────
    flow_duration = timestamps[-1] - timestamps[0]
    if flow_duration == 0:
        flow_duration = 1e-6

    # ── Flow IAT Mean / Std ───────────────────────────────────────────────────
    iats = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps) - 1)]
    flow_iat_mean = float(np.mean(iats)) if iats else 0.0
    flow_iat_std  = float(np.std(iats))  if iats else 0.0

    # ── Packet Length stats ───────────────────────────────────────────────────
    pkt_len_variance = float(np.var(lengths))
    pkt_len_max      = float(max(lengths))
    pkt_len_min      = float(min(lengths))

    # ── Init Fwd / Bwd Win Bytes ─────────────────────────────────────────────
    # TCP window size of the very first packet in each direction
    init_fwd_win = float(fwd_packets[0]["tcp_window"]) if fwd_packets else 0.0
    init_bwd_win = float(bwd_packets[0]["tcp_window"]) if bwd_packets else 0.0

    # ── Fwd Packets/s ─────────────────────────────────────────────────────────
    fwd_packets_per_s = len(fwd_packets) / flow_duration

    # ── Bwd Packet Length Mean ────────────────────────────────────────────────
    bwd_lengths = [p["length"] for p in bwd_packets]
    bwd_pkt_len_mean = float(np.mean(bwd_lengths)) if bwd_lengths else 0.0

    # ── Assemble feature vector (order must match model training) ─────────────
    features = np.array([
        flow_duration,        # Flow Duration
        flow_iat_mean,        # Flow IAT Mean
        flow_iat_std,         # Flow IAT Std
        pkt_len_variance,     # Packet Length Variance
        pkt_len_max,          # Packet Length Max
        init_fwd_win,         # Init Fwd Win Bytes
        init_bwd_win,         # Init Bwd Win Bytes
        fwd_packets_per_s,    # Fwd Packets/s
        bwd_pkt_len_mean,     # Bwd Packet Length Mean
        pkt_len_min,          # Packet Length Min
    ], dtype=np.float32)

    meta = {
        "src_ip":   src_ip,
        "dst_ip":   dst_ip,
        "protocol": protocol,
    }

    return features, meta


# ─── Public API ───────────────────────────────────────────────────────────────
def extract_features():
    """Drain and return all completed flows since last call."""
    with lock:
        ready = completed_flows[:]
        completed_flows.clear()
    return ready


# ─── Capture loop ─────────────────────────────────────────────────────────────
def _capture_loop():
    cap = pcapy.open_live(INTERFACE, SNAPLEN, PROMISC, TIMEOUT_MS)
    cap.setfilter(BPF_FILTER)
    while True:
        cap.dispatch(1, process_packet)

def start_sniffing():
    t = threading.Thread(target=_capture_loop, daemon=True)
    t.start()
    return t
