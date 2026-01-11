import os
import sys
import time
from typing import Dict, Any, Optional, List, Tuple
from urllib.parse import urlparse

from scapy import all as scapy
from opensearchpy import OpenSearch
from opensearchpy.helpers import bulk
from prometheus_client import Counter, start_http_server


# Prometheus metrics (REQUIRED NAMES + LABELS)
PCAP_PACKETS_TOTAL = Counter(
    "pcap_packets_total",
    "Total number of packets processed",
    ["protocol"],  # tcp|udp|icmp|other
)

PCAP_BYTES_TOTAL = Counter(
    "pcap_bytes_total",
    "Total bytes processed (sum of packet_length)",
    ["protocol"],  # tcp|udp|icmp|other
)

PCAP_ELASTIC_WRITE_TOTAL = Counter(
    "pcap_elastic_write_total",
    "Total writes to Elasticsearch/OpenSearch",
    ["status"],  # success|fail
)


def extract_packet_fields(packet) -> Dict[str, Any]:
    timestamp = float(packet.time)
    packet_length = len(packet)

    src_ip = dst_ip = None
    src_port = dst_port = None
    l4_protocol = "other"

    if scapy.IP in packet:
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst

    if scapy.TCP in packet:
        l4_protocol = "tcp"
        src_port = int(packet[scapy.TCP].sport)
        dst_port = int(packet[scapy.TCP].dport)
    elif scapy.UDP in packet:
        l4_protocol = "udp"
        src_port = int(packet[scapy.UDP].sport)
        dst_port = int(packet[scapy.UDP].dport)
    elif scapy.ICMP in packet:
        l4_protocol = "icmp"

    return {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "l4_protocol": l4_protocol,
        "packet_length": packet_length,
    }


def build_os_client() -> OpenSearch:
    url = os.getenv("ELASTIC_URL", "http://localhost:9200")
    username = os.getenv("ELASTIC_USERNAME")
    password = os.getenv("ELASTIC_PASSWORD")

    parsed = urlparse(url)
    host = parsed.hostname or "localhost"
    port = parsed.port or 9200
    use_ssl = (parsed.scheme == "https")

    client_kwargs = dict(
        hosts=[{"host": host, "port": port}],
        use_ssl=use_ssl,
        verify_certs=False,  # ok for exercise; in prod should be True + CA certs
        ssl_show_warn=False,
        timeout=30,
    )

    if username and password:
        client_kwargs["http_auth"] = (username, password)

    return OpenSearch(**client_kwargs)


def bulk_write_with_retry(
    client: OpenSearch,
    index_name: str,
    docs: List[Dict[str, Any]],
    retries: int = 3,
    delay_sec: float = 0.5,
) -> Tuple[int, int]:
    """
    Writes docs using OpenSearch/Elasticsearch Bulk API.
    Returns (success_count, fail_count).
    """
    if not docs:
        return 0, 0

    last_err: Optional[Exception] = None

    for attempt in range(1, retries + 1):
        try:
            actions = (
                {
                    "_op_type": "index",
                    "_index": index_name,
                    "_source": doc,
                }
                for doc in docs
            )

            # stats_only=True -> returns (successes, errors_count)
            success_count, error_count = bulk(
                client,
                actions,
                stats_only=True,
                raise_on_error=False,
                raise_on_exception=False,
                request_timeout=30,
            )

            return int(success_count), int(error_count)

        except Exception as e:
            last_err = e
            print(f"[ERROR] bulk write failed (attempt {attempt}/{retries}): {e}")
            time.sleep(delay_sec * attempt)  # small backoff

    print(f"[ERROR] bulk write failed after {retries} retries. last error: {last_err}")
    return 0, len(docs)


def main():
    # 1) Metrics endpoint (required env + default)
    metrics_port = int(os.getenv("METRICS_PORT", "9100"))
    start_http_server(metrics_port)
    print(f"Prometheus metrics exposed at http://localhost:{metrics_port}/metrics")

    # 2) CLI arg for pcap file (required)
    if len(sys.argv) < 2:
        print("Usage: python app.py <pcap_file>")
        sys.exit(1)

    pcap_path = sys.argv[1]
    if not os.path.exists(pcap_path):
        print(f"[ERROR] PCAP file not found: {pcap_path}")
        sys.exit(1)

    # 3) Index via env (required) or default allowed by spec
    index_name = os.getenv("ELASTIC_INDEX", "pcap-packets")

    # 4) Read PCAP
    packets = scapy.rdpcap(pcap_path)
    print(f"Loaded {len(packets)} packets from {pcap_path}")

    # 5) Connect to Elasticsearch/OpenSearch
    client = build_os_client()
    try:
        info = client.info()
        version = info.get("version", {}).get("number", "")
        dist = info.get("version", {}).get("distribution", "opensearch")
        print(f"Connected to {dist} {version}")
    except Exception as e:
        print(f"[ERROR] Connection error: {e}")
        sys.exit(2)

    # Optional helper: reset index between runs
    reset_index = os.getenv("RESET_INDEX", "false").lower() == "true"
    if reset_index:
        try:
            client.indices.delete(index=index_name)
            print(f"Deleted index {index_name} (RESET_INDEX=true)")
        except Exception:
            # index may not exist
            pass

    # Bulk size (optional)
    bulk_size = int(os.getenv("BULK_SIZE", "500"))

    success = 0
    fail = 0
    batch: List[Dict[str, Any]] = []

    def flush_batch():
        nonlocal success, fail, batch
        ok_count, fail_count = bulk_write_with_retry(client, index_name, batch)
        success += ok_count
        fail += fail_count

        if ok_count:
            PCAP_ELASTIC_WRITE_TOTAL.labels(status="success").inc(ok_count)
        if fail_count:
            PCAP_ELASTIC_WRITE_TOTAL.labels(status="fail").inc(fail_count)

        batch = []

    # 6) Process each packet + update required metrics + bulk write
    for i, packet in enumerate(packets, start=1):
        doc = extract_packet_fields(packet)
        protocol = doc["l4_protocol"]

        # Required metrics:
        PCAP_PACKETS_TOTAL.labels(protocol=protocol).inc()
        PCAP_BYTES_TOTAL.labels(protocol=protocol).inc(doc["packet_length"])

        batch.append(doc)

        if len(batch) >= bulk_size:
            flush_batch()

        if i % 1000 == 0:
            print(f"Progress {i}/{len(packets)} (success={success}, fail={fail})")

    # Flush remaining docs
    if batch:
        flush_batch()

    print(f"Done. success={success}, fail={fail}")

    # Keep process alive so /metrics can be checked easily
    input("Press Enter to exit... (keeps /metrics alive)\n")


if __name__ == "__main__":
    main()
