# PCAP Analysis → OpenSearch + Prometheus Metrics

This project processes a PCAP file, extracts network packet metadata, stores each packet as a document in OpenSearch (Elasticsearch-compatible), and exposes Prometheus metrics for observability.

The exercise demonstrates:
- Basic understanding of networking (L3/L4)
- Clean and readable Python code
- Bulk ingestion to OpenSearch
- Observability using Prometheus metrics

---

## Architecture Overview

- **Input**: PCAP file (CLI argument)
- **Processing**: Python + Scapy
- **Storage**: OpenSearch (Docker, single-node)
- **Metrics**: Prometheus-compatible `/metrics` endpoint

Flow:
PCAP → Python (Scapy) → Bulk API → OpenSearch ->Prometheus Metrics (/metrics)
---

## Extracted Fields per Packet

Each packet is stored as a single document with the following fields:

- `timestamp`
- `src_ip`
- `dst_ip`
- `src_port`
- `dst_port`
- `l4_protocol` (tcp / udp / icmp / other)
- `packet_length`

Packets without IP or TCP/UDP layers are still ingested with the available fields.

---

## Prometheus Metrics

The application exposes the following metrics on `/metrics`:

- `pcap_packets_total{protocol}`
- `pcap_bytes_total{protocol}`
- `pcap_elastic_write_total{status}`

These metrics allow monitoring:
- Traffic volume per protocol
- Total bytes processed
- Success / failure of writes to OpenSearch

---

## Requirements

- Python 3.10+
- Docker + Docker Compose

---

## Setup & Run

### 1. Start OpenSearch (Docker)

```bash
docker compose up -d
```
### 2. Verify OpenSearch is running:
```bash
curl http://localhost:9200
```
### 3. Install Python dependencies
```bash
python -m pip install -r requirements.txt
```
### 4. Configure environment variables (PowerShell)
```bash
$env:ELASTIC_URL="http://localhost:9200"
$env:ELASTIC_INDEX="pcap-packets"
$env:METRICS_PORT="9100"
$env:BULK_SIZE="500"
$env:RESET_INDEX="true"
```
### 5. Run the application
```bash
python app.py sample.pcap
```
### 6. Verify that documents were written to OpenSearch:
```bash
curl "http://localhost:9200/pcap-packets/_count?pretty"
```
### 7. Retrieve a sample document from the index:
```bash
curl "http://localhost:9200/pcap-packets/_search?size=1&pretty"
```
### 8.Verify Prometheus metrics:
```bash
(iwr "http://localhost:9100/metrics").Content | Select-String "pcap_"
```
## Design Notes

- **Bulk ingestion** is used to significantly improve write performance and reduce load on OpenSearch compared to indexing each document individually.
- **Retry logic** is implemented for bulk write operations to handle transient failures and improve reliability.
- **Configuration via environment variables** allows flexible deployment across different environments without code changes.
- **TLS certificate verification** is disabled to simplify local execution and demonstration scope; in a production environment, certificate verification should be enabled.

---

## Possible Improvements

- Define **explicit index mappings** (e.g. `timestamp` as `date`, IP fields as `ip`) to improve query performance and data consistency.
- Implement **de-duplication** using deterministic document IDs to avoid duplicate documents on repeated runs.
- Replace `print` statements with **structured logging** (e.g. using Python’s `logging` module).
- Package and run the application itself inside **Docker** for fully containerized deployment.
- Add a **Prometheus server configuration** to scrape and visualize metrics over time.

---

## Author

Nitzan Cohen Sason
