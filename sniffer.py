import time
import threading
from collections import deque, defaultdict
from scapy.all import sniff, IP, TCP


lock = threading.Lock()


captured_packets = deque(maxlen=50)


stats = {
    "total": 0,
    "syn": 0,
    "syn_ack": 0,
    "ack": 0,
    "fin": 0,
    "rst": 0,
    "data": 0
}


connection_flow = deque(maxlen=10)


anomalies_history = deque(maxlen=20)


syn_timestamps = deque(maxlen=100)
rst_timestamps = deque(maxlen=100)
port_scan_tracker = defaultdict(set)
last_scan_reset = time.time()


sniffing_active = False


def parse_tcp_flags(tcp_layer):
    """Parses TCP flag bits and returns human-readable flag names."""
    flags = []
    f = tcp_layer.flags

    if f.S:
        flags.append("SYN")
    if f.A:
        flags.append("ACK")
    if f.F:
        flags.append("FIN")
    if f.R:
        flags.append("RST")
    if f.P:
        flags.append("PSH")
    if f.U:
        flags.append("URG")

    return " | ".join(flags) if flags else "NONE"


def determine_flow_stage(f_str):
    """Categorises the TCP packet into a flow stage."""

    if "SYN" in f_str and "ACK" in f_str:
        return "SYN-ACK"
    elif "SYN" in f_str:
        return "SYN"
    elif "FIN" in f_str:
        return "FIN"
    elif "RST" in f_str:
        return "RST"
    elif "ACK" in f_str:
        return "ACK/DATA"

    return "OTHER"


def run_anomaly_rules(src_ip, dst_port, f_str, current_time):
    """
    Applies rule-based detection logic:
    Detect -> Diagnose -> Show Severity -> Explain -> Recommend
    """

    detected_anomalies = []

    
    if "SYN" in f_str and "ACK" not in f_str:
        syn_timestamps.append(current_time)

    if "RST" in f_str:
        rst_timestamps.append(current_time)

    
    while syn_timestamps and current_time - syn_timestamps[0] > 5:
        syn_timestamps.popleft()

    while rst_timestamps and current_time - rst_timestamps[0] > 5:
        rst_timestamps.popleft()

   
    if len(syn_timestamps) > 15:
        detected_anomalies.append({
            "timestamp": time.strftime("%H:%M:%S"),
            "alert": "Possible SYN Flood Attack",
            "severity": "CRITICAL",
            "reason": f"High rate of SYN packets detected ({len(syn_timestamps)} in 5 seconds).",
            "recommendation": "Check source IP connection limits and consider enabling SYN cookies on firewall."
        })

   
    if len(rst_timestamps) > 10:
        detected_anomalies.append({
            "timestamp": time.strftime("%H:%M:%S"),
            "alert": "Excessive Connection Resets (RST)",
            "severity": "WARNING",
            "reason": f"Rapid connection resets detected ({len(rst_timestamps)} RST packets in 5s).",
            "recommendation": "Inspect server error logs and verify if target ports are open or filtered."
        })

   
    if f_str == "NONE":
        detected_anomalies.append({
            "timestamp": time.strftime("%H:%M:%S"),
            "alert": "NULL Flag Packet Detected",
            "severity": "WARNING",
            "reason": "Packet received with no TCP flags set (Null Scan technique).",
            "recommendation": "Block anomalous scanner IP and verify network firewall rules."
        })

    elif "FIN" in f_str and "PSH" in f_str and "URG" in f_str:
        detected_anomalies.append({
            "timestamp": time.strftime("%H:%M:%S"),
            "alert": "Xmas Scan Packet Detected",
            "severity": "CRITICAL",
            "reason": "Packet received with FIN, PSH, and URG flags set simultaneously.",
            "recommendation": "Configure IDS/IPS to drop stealth scan packets."
        })

   
    global last_scan_reset

    if current_time - last_scan_reset > 10:
        port_scan_tracker.clear()
        last_scan_reset = current_time

    port_scan_tracker[src_ip].add(dst_port)

    if len(port_scan_tracker[src_ip]) > 12:
        detected_anomalies.append({
            "timestamp": time.strftime("%H:%M:%S"),
            "alert": "Possible Port Scan Detected",
            "severity": "WARNING",
            "reason": f"Source IP {src_ip} probed {len(port_scan_tracker[src_ip])} distinct ports.",
            "recommendation": "Investigate source IP activity and temporarily restrict port probing."
        })

    return detected_anomalies


def calculate_health_score(anomalies):
    """Calculates TCP Health Score from 0 to 100."""

    score = 100

    for anomaly in anomalies:
        if anomaly["severity"] == "CRITICAL":
            score -= 25

        elif anomaly["severity"] == "WARNING":
            score -= 10

    return max(0, score)


def process_packet(packet):
    """Callback triggered whenever Scapy captures a TCP packet."""

    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return

    ip_layer = packet[IP]
    tcp_layer = packet[TCP]
    now = time.time()

    flags_str = parse_tcp_flags(tcp_layer)
    packet_len = len(packet)
    flow_stage = determine_flow_stage(flags_str)

    pkt_data = {
        "timestamp": time.strftime("%H:%M:%S"),
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
        "src_port": tcp_layer.sport,
        "dst_port": tcp_layer.dport,
        "flags": flags_str,
        "size": packet_len,
        "stage": flow_stage
    }

    with lock:

        captured_packets.appendleft(pkt_data)

        stats["total"] += 1

        
        if "SYN" in flags_str and "ACK" in flags_str:
            stats["syn_ack"] += 1

        elif "SYN" in flags_str:
            stats["syn"] += 1

        elif "FIN" in flags_str:
            stats["fin"] += 1

        elif "RST" in flags_str:
            stats["rst"] += 1

        elif "ACK" in flags_str:
            stats["ack"] += 1

        
        if len(tcp_layer.payload) > 0:
            stats["data"] += 1

        
        connection_flow.appendleft({
            "stage": flow_stage,
            "src": f"{ip_layer.src}:{tcp_layer.sport}",
            "dst": f"{ip_layer.dst}:{tcp_layer.dport}",
            "time": pkt_data["timestamp"]
        })

        
        anomalies = run_anomaly_rules(
            ip_layer.src,
            tcp_layer.dport,
            flags_str,
            now
        )

        for anomaly in anomalies:

           
            if (
                not anomalies_history
                or anomalies_history[0]["alert"] != anomaly["alert"]
            ):
                anomalies_history.appendleft(anomaly)


def start_sniffer():
    """Starts background packet capture using Scapy."""

    global sniffing_active

    if sniffing_active:
        return

    sniffing_active = True

    def sniff_thread():

        sniff(
            filter="tcp",
            prn=process_packet,
            store=False
        )

    t = threading.Thread(
        target=sniff_thread,
        daemon=True
    )

    t.start()


def get_dashboard_data():
    """Retrieves current snapshot for the Flask Web API."""

    with lock:

        recent_anomalies = list(anomalies_history)

        health_score = calculate_health_score(
            recent_anomalies[:5]
        )

        if health_score < 50:
            overall_status = "CRITICAL"

        elif health_score < 80:
            overall_status = "WARNING"

        else:
            overall_status = "NORMAL"

        return {
            "packets": list(captured_packets),
            "stats": dict(stats),
            "flow": list(connection_flow),
            "anomalies": recent_anomalies,
            "health_score": health_score,
            "status": overall_status
        }
