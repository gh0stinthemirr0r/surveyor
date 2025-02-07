# Surveyor

**Surveyor** is a Python-based network scanning and diagnostics tool that uses Nmap for host discovery and port scanning, simulates traffic generation for connection quality measurements, and displays the results on a modern, scrollable dashboard built with Pygame. It also generates detailed reports in both PDF and CSV formats and exposes Prometheus metrics for monitoring.

## Features

- **Interactive Scanning**  
  Prompts the user to enter an IP or CIDR range to scan. If no input is provided, it falls back to scanning default RFC1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).

- **Host Discovery & Port Enumeration**  
  Uses Nmap (via the `python-nmap` library) to perform ping scans and port scans on specified candidate ports (e.g., 22, 80, 443, 3389, 8080, 8443).

- **Traffic Generation**  
  Simulates sending 120 traffic packets per discovered host to measure connection quality (average latency).

- **Prometheus Metrics**  
  Exposes key metrics such as total traffic packets generated, number of enumerated hosts, and packet latencies using the `prometheus_client` library.

- **Dashboard Visualization**  
  Features a sleek, modern, scrollable dashboard using Pygame that displays each scanned range along with host IPs, open ports, and average latency.

- **Reporting**  
  Automatically generates detailed PDF and CSV reports of the scan results.

- **Graceful Shutdown**  
  Listens for shutdown signals (e.g., CTRL‑C) to exit cleanly.

## Prerequisites

- **Python 3.6+**  
- **Nmap** must be installed on your system. You can download it from [nmap.org](https://nmap.org/).  
- Required Python packages:
  - `python-nmap`
  - `prometheus_client`
  - `reportlab`
  - `pygame`

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/yourusername/surveyor.git
   cd surveyor
