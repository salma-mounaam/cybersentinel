import time
from collections import defaultdict


class FlowStore:
    def __init__(self):
        self.flows = {}

    def update(self, packet_info: dict):
        key = (
            packet_info["src_ip"],
            packet_info["dst_ip"],
            packet_info["src_port"],
            packet_info["dst_port"],
            packet_info["protocol"],
        )

        now = time.time()

        if key not in self.flows:
            self.flows[key] = {
                "start_time": now,
                "last_time": now,
                "packet_count": 0,
                "byte_count": 0,
                "src_ip": packet_info["src_ip"],
                "dst_ip": packet_info["dst_ip"],
                "src_port": packet_info["src_port"],
                "dst_port": packet_info["dst_port"],
                "protocol": packet_info["protocol"],
            }

        flow = self.flows[key]
        flow["packet_count"] += 1
        flow["byte_count"] += packet_info["length"]
        flow["last_time"] = now

    def export_features(self):
        results = []

        for _, flow in self.flows.items():
            duration = max(flow["last_time"] - flow["start_time"], 0.001)
            avg_packet_size = flow["byte_count"] / max(flow["packet_count"], 1)

            results.append({
                "src_ip": flow["src_ip"],
                "dst_ip": flow["dst_ip"],
                "src_port": flow["src_port"],
                "dst_port": flow["dst_port"],
                "protocol": flow["protocol"],
                "packet_count": flow["packet_count"],
                "byte_count": flow["byte_count"],
                "duration": round(duration, 4),
                "avg_packet_size": round(avg_packet_size, 2),
            })

        return results

    def clear(self):
        self.flows = {}