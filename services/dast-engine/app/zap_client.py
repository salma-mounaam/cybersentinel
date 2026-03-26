from zapv2 import ZAPv2
import time


ZAP_PROXY = "http://zap:8090"


def run_zap_scan(target_url: str):
    zap = ZAPv2(proxies={'http': ZAP_PROXY, 'https': ZAP_PROXY})

    print(f"[ZAP] Target: {target_url}")

    # accès initial
    zap.urlopen(target_url)
    time.sleep(2)

    # spider
    print("[ZAP] Spider...")
    scan_id = zap.spider.scan(target_url)

    while int(zap.spider.status(scan_id)) < 100:
        print(f"[ZAP] Spider progress: {zap.spider.status(scan_id)}%")
        time.sleep(2)

    # active scan
    print("[ZAP] Active scan...")
    scan_id = zap.ascan.scan(target_url)

    while int(zap.ascan.status(scan_id)) < 100:
        print(f"[ZAP] Scan progress: {zap.ascan.status(scan_id)}%")
        time.sleep(5)

    alerts = zap.core.alerts(baseurl=target_url)

    return alerts