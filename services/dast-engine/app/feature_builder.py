from urllib.parse import urlparse
import time


def build_ml_features_from_zap_messages(messages: list, target_url: str) -> dict:
    parsed_target = urlparse(target_url)
    target_port = parsed_target.port or 80

    # fallback si aucun message
    if not messages:
        return {
            "Destination Port": float(target_port),
            "Protocol": 6.0,
            "Flow Duration": 1.0,
            "Total Fwd Packets": 0.0,
            "Total Backward Packets": 0.0,
            "Total Length of Fwd Packets": 0.0,
            "Total Length of Bwd Packets": 0.0,
            "Flow Bytes/s": 0.0,
            "Flow Packets/s": 0.0,
            "Average Packet Size": 0.0,
        }

    request_sizes = []
    response_sizes = []
    timestamps = []

    get_count = 0
    post_count = 0

    for msg in messages:
        request_header = msg.get("requestHeader", "") or ""
        request_body = msg.get("requestBody", "") or ""
        response_header = msg.get("responseHeader", "") or ""
        response_body = msg.get("responseBody", "") or ""

        request_size = len(request_header) + len(request_body)
        response_size = len(response_header) + len(response_body)

        request_sizes.append(request_size)
        response_sizes.append(response_size)

        first_line = request_header.splitlines()[0] if request_header else ""
        if first_line.startswith("GET "):
            get_count += 1
        elif first_line.startswith("POST "):
            post_count += 1

        ts = msg.get("timeSentMillis")
        if ts:
            try:
                timestamps.append(int(ts))
            except:
                pass

    # 🔥 CORRECTION 1 : durée réelle
    if len(timestamps) >= 2:
        flow_duration = (max(timestamps) - min(timestamps)) / 1000.0
    else:
        # fallback si ZAP ne donne pas timestamps
        flow_duration = max(len(messages) * 0.01, 1.0)

    # 🔥 CORRECTION 2 : clamp durée
    flow_duration = max(flow_duration, 0.5)

    total_fwd_packets = float(len(request_sizes))
    total_bwd_packets = float(len(response_sizes))

    total_fwd_bytes = float(sum(request_sizes))
    total_bwd_bytes = float(sum(response_sizes))
    total_bytes = total_fwd_bytes + total_bwd_bytes

    total_packets = total_fwd_packets + total_bwd_packets

    # 🔥 CORRECTION 3 : éviter explosion
    flow_bytes_per_sec = total_bytes / flow_duration
    flow_packets_per_sec = total_packets / flow_duration

    # 🔥 CORRECTION 4 : clamp valeurs extrêmes
    flow_bytes_per_sec = min(flow_bytes_per_sec, 1e7)
    flow_packets_per_sec = min(flow_packets_per_sec, 1e5)

    all_packet_sizes = request_sizes + response_sizes

    packet_length_mean = (
        sum(all_packet_sizes) / len(all_packet_sizes) if all_packet_sizes else 0.0
    )

    packet_length_max = max(all_packet_sizes) if all_packet_sizes else 0.0
    packet_length_min = min(all_packet_sizes) if all_packet_sizes else 0.0

    avg_fwd_segment_size = (
        total_fwd_bytes / total_fwd_packets if total_fwd_packets > 0 else 0.0
    )

    avg_bwd_segment_size = (
        total_bwd_bytes / total_bwd_packets if total_bwd_packets > 0 else 0.0
    )

    down_up_ratio = (
        total_bwd_packets / total_fwd_packets if total_fwd_packets > 0 else 0.0
    )

    return {
        "Destination Port": float(target_port),
        "Protocol": 6.0,

        "Flow Duration": float(flow_duration),

        "Total Fwd Packets": total_fwd_packets,
        "Total Backward Packets": total_bwd_packets,

        "Total Length of Fwd Packets": total_fwd_bytes,
        "Total Length of Bwd Packets": total_bwd_bytes,

        "Flow Bytes/s": float(flow_bytes_per_sec),
        "Flow Packets/s": float(flow_packets_per_sec),

        "Packet Length Mean": float(packet_length_mean),
        "Max Packet Length": float(packet_length_max),
        "Min Packet Length": float(packet_length_min),
        "Average Packet Size": float(packet_length_mean),

        "Avg Fwd Segment Size": float(avg_fwd_segment_size),
        "Avg Bwd Segment Size": float(avg_bwd_segment_size),

        "Subflow Fwd Packets": total_fwd_packets,
        "Subflow Fwd Bytes": total_fwd_bytes,
        "Subflow Bwd Packets": total_bwd_packets,
        "Subflow Bwd Bytes": total_bwd_bytes,

        "Down/Up Ratio": float(down_up_ratio),

        # approximation flags
        "PSH Flag Count": float(post_count),
        "ACK Flag Count": float(total_packets),
        "SYN Flag Count": 0.0,
        "RST Flag Count": 0.0,
        "FIN Flag Count": 0.0,
        "URG Flag Count": 0.0,
    }