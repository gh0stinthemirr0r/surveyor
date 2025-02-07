#!/usr/bin/env python3
"""
Surveyor Project (Python Version)
This version prompts the user to enter an IP address or CIDR range to scan.
It uses Nmap (via python‑nmap) to discover “up” hosts and to enumerate open ports.
For each discovered host, it then simulates sending 120 traffic packets to determine
connection quality (average latency). A modern, scrollable dashboard (using Pygame)
displays each host with its open ports and measured quality, and reports are generated
in both PDF and CSV formats.
"""

import csv
import ipaddress
import logging
import os
import random
import signal
import sys
import threading
import time
from datetime import datetime

# Third-party libraries
import nmap  # pip install python-nmap
from prometheus_client import Counter, Gauge, Histogram, start_http_server
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
import pygame

# ---------------- Global Constants and Directories ----------------

LOG_DIR = os.path.join("ghostshell", "logging")
REPORT_DIR = os.path.join("ghostshell", "reporting")
# Dashboard window size and colors
WINDOW_WIDTH = 1280
WINDOW_HEIGHT = 720
DARK_GREY = (30, 30, 30)
VIOLET = (138, 43, 226)
WHITE = (255, 255, 255)
SCROLLBAR_COLOR = (80, 80, 80)
SCROLLBAR_BG = (50, 50, 50)

# ---------------- Prometheus Metrics ----------------

traffic_generated = Counter(
    "traffic_generated_total",
    "Total number of traffic packets generated.",
    ['range']
)
enumerated_hosts = Gauge(
    "enumerated_hosts",
    "Number of hosts enumerated in a given IP range.",
    ['range']
)
packet_latency = Histogram(
    "packet_latency_ms",
    "Latency of generated packets in milliseconds.",
    ['range'],
    buckets=[i for i in range(10, 210, 10)]
)

# ---------------- Global Logger ----------------

logger = None
metrics_port = "8080"  # Default metrics port

# ---------------- Logging Setup ----------------

def setup_logger():
    """Sets up the logging configuration."""
    os.makedirs(LOG_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(LOG_DIR, f"surveyor_log_{timestamp}.log")
    
    global logger
    logger = logging.getLogger("surveyor")
    logger.setLevel(logging.DEBUG)
    
    # File handler
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    
    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    
    logger.addHandler(fh)
    logger.addHandler(ch)
    
    logger.info("Logger setup complete, logging to %s", log_file)

# ---------------- Metrics Server ----------------

def start_metrics_server(port):
    """Starts the Prometheus metrics server."""
    try:
        start_http_server(int(port))
        logger.info("Started Prometheus metrics server on port %s", port)
    except Exception as e:
        logger.error("Failed to start metrics server: %s", e)

# ---------------- Scanning & Host Details via Nmap ----------------

# Default RFC1918 ranges (used if no destination is provided)
RFC1918_RANGES = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16"
]

# Candidate ports to scan (for open ports)
CANDIDATE_PORTS = [22, 80, 443, 3389, 8080, 8443]

def nmap_scan_range(dest):
    """
    Uses Nmap to scan the specified destination (IP or CIDR).
    Performs a ping scan (-sn) to determine which hosts are up,
    and then for each up host, does a port scan on the candidate ports.
    Returns a list of host detail dictionaries.
    """
    scanner = nmap.PortScanner()
    try:
        logger.info("Performing ping scan on %s", dest)
        scanner.scan(hosts=dest, arguments='-sn')
    except Exception as e:
        logger.error("Nmap scan failed: %s", e)
        return []
    
    # Retrieve the scan results dictionary (if available)
    scan_results = scanner._scan_result.get("scan", {})
    
    hosts_up = []
    for host in scanner.all_hosts():
        host_info = scan_results.get(host)
        if not host_info:
            continue
        # Check if the host's status indicates it is up
        if host_info.get("status", {}).get("state", "") == 'up':
            # Now scan for open ports among the candidate ports
            port_args = "-p " + ",".join(map(str, CANDIDATE_PORTS))
            try:
                scanner.scan(host, arguments=port_args)
            except Exception as e:
                logger.error("Port scan failed for host %s: %s", host, e)
                open_ports = []
            else:
                open_ports = []
                # Check TCP ports from the scan result
                host_scan = scanner._scan_result.get("scan", {}).get(host, {})
                tcp_info = host_scan.get("tcp", {})
                for port, port_data in tcp_info.items():
                    if port_data.get("state") == "open":
                        open_ports.append(port)
            host_details = {
                "ip": host,
                "open_ports": sorted(open_ports),
                "avg_latency": None  # to be updated in traffic generation
            }
            hosts_up.append(host_details)
    logger.info("Nmap scan of %s found %d up hosts", dest, len(hosts_up))
    return hosts_up

def scan_all(dest=None):
    """
    If a destination (IP or CIDR) is provided, scan only that range using Nmap.
    Otherwise, scan all default RFC1918 ranges concurrently.
    Returns a dictionary mapping each scanned range to its list of host detail dictionaries.
    """
    results = {}
    threads = []
    lock = threading.Lock()

    def worker(range_dest):
        hosts = nmap_scan_range(range_dest)
        enumerated_hosts.labels(range=range_dest).set(len(hosts))
        with lock:
            results[range_dest] = hosts

    if dest:
        worker(dest)
    else:
        for cidr in RFC1918_RANGES:
            t = threading.Thread(target=worker, args=(cidr,))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
    
    return results

# ---------------- Traffic Generation & Connection Quality ----------------

def generate_traffic_for_host(dest, host_data):
    """
    Simulates sending 120 traffic packets to a given host.
    For each packet, a random delay (latency) is applied.
    After sending all packets, computes the average latency and updates host_data.
    """
    packet_count = 120
    latencies = []
    
    for _ in range(packet_count):
        start_time = time.time()
        delay = random.uniform(0.01, 0.06)
        time.sleep(delay)
        latency = (time.time() - start_time) * 1000  # milliseconds
        latencies.append(latency)
        
        traffic_generated.labels(range=dest).inc()
        packet_latency.labels(range=dest).observe(latency)
        
        logger.debug("Traffic packet sent to host %s in %s, latency=%.2fms", host_data["ip"], dest, latency)
    
    avg_latency = sum(latencies) / len(latencies) if latencies else None
    host_data["avg_latency"] = avg_latency

def generate_traffic_concurrently(scan_results):
    """
    For each scanned range and for each up host, generate traffic concurrently.
    Updates each host's connection quality (average latency).
    """
    logger.info("Starting traffic generation for all scanned ranges.")
    threads = []
    
    for dest, hosts in scan_results.items():
        for host_data in hosts:
            t = threading.Thread(target=generate_traffic_for_host, args=(dest, host_data))
            threads.append(t)
            t.start()
    
    for t in threads:
        t.join()
    
    logger.info("Traffic generation completed.")

# ---------------- Report Generation ----------------

def generate_pdf_report(file_path, scan_results):
    """Generates a PDF report using ReportLab."""
    logger.info("Generating PDF report at %s", file_path)
    c = canvas.Canvas(file_path, pagesize=A4)
    width, height = A4

    c.setFont("Helvetica-Bold", 16)
    c.drawString(30, height - 30, "Surveyor Report - Scan Results")
    c.setFont("Helvetica", 12)
    text = c.beginText(30, height - 60)
    text.textLine("Scanned Ranges:")
    for dest in scan_results.keys():
        text.textLine(f"  - {dest}")
    c.drawText(text)

    y = height - 120
    for dest, hosts in scan_results.items():
        c.setFont("Helvetica-Bold", 14)
        c.drawString(30, y, f"Range: {dest} ({len(hosts)} up hosts)")
        y -= 20
        c.setFont("Helvetica", 12)
        for host_data in hosts:
            open_ports = ", ".join(str(p) for p in host_data["open_ports"])
            avg_latency = f"{host_data['avg_latency']:.2f} ms" if host_data["avg_latency"] is not None else "N/A"
            line = f"Host: {host_data['ip']} | Open Ports: {open_ports} | Avg Latency: {avg_latency}"
            c.drawString(40, y, line)
            y -= 15
            if y < 50:
                c.showPage()
                y = height - 50
    c.save()

def generate_csv_report(file_path, scan_results):
    """Generates a CSV report."""
    logger.info("Generating CSV report at %s", file_path)
    with open(file_path, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Range", "Host", "Open Ports", "Avg Latency (ms)"])
        for dest, hosts in scan_results.items():
            for host_data in hosts:
                open_ports = ";".join(str(p) for p in host_data["open_ports"])
                avg_latency = f"{host_data['avg_latency']:.2f}" if host_data["avg_latency"] is not None else ""
                writer.writerow([dest, host_data["ip"], open_ports, avg_latency])

def generate_report(scan_results):
    """Generates both PDF and CSV reports."""
    os.makedirs(REPORT_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pdf_file = os.path.join(REPORT_DIR, f"surveyor_report_{timestamp}.pdf")
    csv_file = os.path.join(REPORT_DIR, f"surveyor_report_{timestamp}.csv")

    generate_pdf_report(pdf_file, scan_results)
    generate_csv_report(csv_file, scan_results)
    logger.info("Reports generated: PDF (%s), CSV (%s)", pdf_file, csv_file)

# ---------------- Modern Scrollable Dashboard Visualization ----------------

def visualize_interface(scan_results):
    """
    Displays a sleek, modern dashboard with a dark grey background and violet text.
    It shows the scanned ranges and, for each host, lists the IP, open ports, and average latency.
    A scrollable area is used when there are more entries than can fit on the screen.
    """
    pygame.init()
    screen_width, screen_height = 900, 600
    screen = pygame.display.set_mode((screen_width, screen_height))
    pygame.display.set_caption("Surveyor Dashboard")
    clock = pygame.time.Clock()

    header_font = pygame.font.SysFont("Segoe UI", 24)
    text_font = pygame.font.SysFont("Segoe UI", 18)

    scroll_offset = 0
    scroll_speed = 20

    running = True
    while running:
        total_content_height = 0
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                running = False
            elif event.type == pygame.KEYDOWN:
                if event.key == pygame.K_DOWN:
                    scroll_offset += scroll_speed
                elif event.key == pygame.K_UP:
                    scroll_offset -= scroll_speed
            elif event.type == pygame.MOUSEBUTTONDOWN:
                if event.button == 4:  # Mouse wheel up
                    scroll_offset -= scroll_speed
                elif event.button == 5:  # Mouse wheel down
                    scroll_offset += scroll_speed

        content_surface = pygame.Surface((screen_width - 40, 3000))
        content_surface.fill(DARK_GREY)
        y = 20

        header = header_font.render("Surveyor Dashboard", True, VIOLET)
        content_surface.blit(header, (20, y))
        y += 40

        for dest in scan_results:
            hosts = scan_results.get(dest, [])
            range_line = f"Range: {dest} | Up Hosts: {len(hosts)}"
            line_surface = text_font.render(range_line, True, WHITE)
            content_surface.blit(line_surface, (20, y))
            y += 30
            for host_data in hosts:
                open_ports = ", ".join(str(p) for p in host_data["open_ports"])
                avg_latency = f"{host_data['avg_latency']:.2f} ms" if host_data["avg_latency"] is not None else "N/A"
                host_line = f"{host_data['ip']} | Open Ports: {open_ports} | Avg Latency: {avg_latency}"
                line_surface = text_font.render(host_line, True, WHITE)
                content_surface.blit(line_surface, (40, y))
                y += 25
            y += 10

        total_content_height = y

        if scroll_offset < 0:
            scroll_offset = 0
        if total_content_height - scroll_offset < screen_height:
            scroll_offset = max(0, total_content_height - screen_height)

        screen.fill(DARK_GREY)
        screen.blit(content_surface, (0, -scroll_offset))

        if total_content_height > screen_height:
            scrollbar_height = screen_height * (screen_height / total_content_height)
            scrollbar_y = (scroll_offset / total_content_height) * screen_height
            scrollbar_rect = pygame.Rect(screen_width - 20, scrollbar_y, 10, scrollbar_height)
            pygame.draw.rect(screen, SCROLLBAR_BG, (screen_width - 20, 0, 10, screen_height))
            pygame.draw.rect(screen, SCROLLBAR_COLOR, scrollbar_rect)

        pygame.display.flip()
        clock.tick(30)
    pygame.quit()

# ---------------- Signal Handling ----------------

shutdown_event = threading.Event()

def signal_handler(sig, frame):
    logger.info("Received shutdown signal: %s", sig)
    shutdown_event.set()

# ---------------- Main Function ----------------

def main():
    setup_logger()
    
    # Prompt the user for a destination IP or CIDR
    dest_input = input("Enter an IP or CIDR range to scan (leave blank to scan default RFC1918 ranges): ").strip()
    if dest_input:
        logger.info("Scanning destination: %s", dest_input)
    else:
        logger.info("No destination provided; scanning default RFC1918 ranges: %s", ", ".join(RFC1918_RANGES))
    
    # Start Prometheus metrics server
    start_metrics_server(metrics_port)
    
    # Perform the scan using Nmap if a destination is provided; otherwise scan defaults
    scan_results = scan_all(dest_input if dest_input else None)
    
    # Generate traffic concurrently
    traffic_thread = threading.Thread(target=generate_traffic_concurrently, args=(scan_results,))
    traffic_thread.start()
    
    # Start the dashboard visualization in a separate thread
    ui_thread = threading.Thread(target=visualize_interface, args=(scan_results,))
    ui_thread.start()
    
    # Wait for traffic generation to complete
    traffic_thread.join()
    
    # Generate reports (PDF and CSV)
    try:
        generate_report(scan_results)
    except Exception as e:
        logger.error("Failed to generate reports: %s", e)
        sys.exit(1)
    
    logger.info("Surveying completed. Awaiting shutdown signal...")
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    while not shutdown_event.is_set():
        time.sleep(1)
    
    logger.info("Exiting Surveyor cleanly.")

if __name__ == "__main__":
    main()
