from scapy.all import sniff, IP, TCP, UDP
from app.features import FlowStore

flow_store = FlowStore()


def process_packet(packet):
    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = packet[IP].proto
    length = len(packet)

    src_port = 0
    dst_port = 0

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    packet_info = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "length": length,
    }

    flow_store.update(packet_info)


def start_sniffing(interface="eth0", timeout=30):
    sniff(iface=interface, prn=process_packet, store=False, timeout=timeout)
    return flow_store.export_features()