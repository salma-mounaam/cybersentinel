from urllib.parse import urlparse
from zapv2 import ZAPv2
import time

ZAP_PROXY = "http://zap:8090"


def _build_zap_client():
    return ZAPv2(proxies={"http": ZAP_PROXY, "https": ZAP_PROXY})


def run_zap_scan(target_url: str):
    zap = _build_zap_client()

    print(f"[ZAP] Target: {target_url}")

    # Accès initial
    zap.urlopen(target_url)
    time.sleep(2)

    # Spider
    print("[ZAP] Spider...")
    spider_scan_id = zap.spider.scan(target_url)

    while int(zap.spider.status(spider_scan_id)) < 100:
        print(f"[ZAP] Spider progress: {zap.spider.status(spider_scan_id)}%")
        time.sleep(2)

    # Active scan
    print("[ZAP] Active scan...")
    ascan_scan_id = zap.ascan.scan(target_url)

    while int(zap.ascan.status(ascan_scan_id)) < 100:
        print(f"[ZAP] Scan progress: {zap.ascan.status(ascan_scan_id)}%")
        time.sleep(5)

    alerts = zap.core.alerts(baseurl=target_url)
    return alerts


def get_zap_messages_for_target(target_url: str, count: int = 5000):
    """
    Récupère les messages HTTP de ZAP liés à la cible scannée.
    """
    zap = _build_zap_client()
    target_host = urlparse(target_url).hostname

    collected = []
    start = 0
    page_size = 500

    while start < count:
        batch = zap.core.messages(start=start, count=page_size)

        if not batch:
            break

        for msg in batch:
            request_header = msg.get("requestHeader", "") or ""
            first_line = request_header.splitlines()[0] if request_header else ""
            parts = first_line.split(" ")

            if len(parts) < 2:
                continue

            full_url = parts[1]
            parsed = urlparse(full_url)

            if parsed.hostname == target_host:
                collected.append(msg)

        if len(batch) < page_size:
            break

        start += page_size

    return collected