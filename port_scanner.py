#!/usr/bin/env python3
"""
Advanced Port Scanner - improved, robust single-file scanner with multi-target & safe export.

Usage examples:
  python port_scanner.py -t 127.0.0.1 -p 20-1024 -w 100
  python port_scanner.py -t 127.0.0.1,scanme.nmap.org --output reports/scan.txt
  python port_scanner.py --targets targets.txt --output reports/scan.txt
  python port_scanner.py               # will prompt for a single target
"""

from __future__ import annotations
import argparse
import socket
import sys
import time
import json
import csv
import signal
import os
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Any

# -----------------------
# ANSI color codes
# -----------------------
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# -----------------------
# Common service mapping
# -----------------------
COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS", 138: "NetBIOS",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 162: "SNMP-TRAP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog", 587: "SMTP",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB", 9200: "Elasticsearch"
}

# -----------------------
# Globals for signal handling
# -----------------------
_EXECUTOR: Optional[ThreadPoolExecutor] = None
_RESULTS: List[Dict[str, Any]] = []
_INTERRUPTED = False

def handle_sigint(signum, frame):
    """Gracefully handle Ctrl+C: stop executor and print partial results."""
    global _EXECUTOR, _RESULTS, _INTERRUPTED
    _INTERRUPTED = True
    print(f"\n{Colors.YELLOW}⚠️  Scan interrupted by user — stopping...{Colors.ENDC}")
    try:
        if _EXECUTOR is not None:
            # cancel_futures available on Python 3.9+
            _EXECUTOR.shutdown(wait=False, cancel_futures=True)
    except Exception:
        try:
            _EXECUTOR.shutdown(wait=False)
        except Exception:
            pass

    if _RESULTS:
        print(f"{Colors.CYAN}📝 Partial results ({len(_RESULTS)} items):{Colors.ENDC}")
        for item in sorted(_RESULTS, key=lambda x: (x.get('host',''), x['port'])):
            host = item.get('host','<unknown>')
            print(f"  {host} - Port {item['port']}: {item['status'].upper():<8} {item.get('service','')}")
    else:
        print("No results collected yet.")
    sys.exit(1)

signal.signal(signal.SIGINT, handle_sigint)

# -----------------------
# Utility functions
# -----------------------
def parse_port_range(port_str: str) -> List[int]:
    """Parse port range like '1-100,443,8080' into a sorted unique list of ints."""
    ports = set()
    for part in port_str.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            start_s, end_s = part.split('-', 1)
            start, end = int(start_s), int(end_s)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p <= 65535)

def sanitize_for_filename(s: str) -> str:
    """Make a safe filename fragment from a host string."""
    s = s.strip()
    s = re.sub(r'[^A-Za-z0-9._-]', '_', s)
    return s or "target"

def load_config(file_path: str) -> Dict[str, Any]:
    if not os.path.isfile(file_path):
        print(f"Config file not found: {file_path}")
        sys.exit(1)
    _, ext = os.path.splitext(file_path.lower())
    try:
        with open(file_path, 'r') as f:
            if ext in ('.yaml', '.yml'):
                if not yaml:
                    print("PyYAML not installed. Cannot read YAML config.")
                    sys.exit(1)
                return yaml.safe_load(f)
            elif ext == '.json':
                return json.load(f)
            else:
                print(f"Unsupported config file extension: {ext}")
                sys.exit(1)
    except Exception as e:
        print(f"Error reading config file: {e}")
        sys.exit(1)

# -----------------------
# PortScanner class
# -----------------------
class PortScanner:
    def __init__(self, target: str, timeout: float = 1.0, max_workers: int = 100, quiet: bool = False):
        self.target = target
        self.timeout = timeout
        self.max_workers = max_workers
        self.quiet = quiet

        self.open_ports: List[Dict[str, Any]] = []
        self.closed_ports: List[int] = []
        self.filtered_ports: List[int] = []
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None

    def print_banner(self):
        banner = f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════════════════╗
║              {Colors.BOLD}⚡ ADVANCED PORT SCANNER v2.0 ⚡{Colors.ENDC}{Colors.CYAN}                 ║
║          {Colors.GREEN}Fast • Robust • Friendly CLI{Colors.ENDC}{Colors.CYAN}                        ║
╚═══════════════════════════════════════════════════════════════╝{Colors.ENDC}
"""
        print(banner)

    def resolve_target(self) -> str:
        try:
            ip = socket.gethostbyname(self.target)
            if not self.quiet:
                print(f"{Colors.GREEN}✓{Colors.ENDC} Target resolved: {Colors.BOLD}{self.target}{Colors.ENDC} → {Colors.CYAN}{ip}{Colors.ENDC}")
            return ip
        except socket.gaierror:
            print(f"{Colors.RED}✗ Error:{Colors.ENDC} Could not resolve hostname: {self.target}")
            # Don't exit here in multi-target mode; raise to caller to handle
            raise

    @staticmethod
    def get_service_name(port: int) -> str:
        return COMMON_PORTS.get(port, "")

    def _scan_one_port(self, ip: str, port: int) -> Dict[str, Any]:
        """Scan a single port and return dict: {'port', 'status', 'service'}"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                res = sock.connect_ex((ip, port))
                if res == 0:
                    return {'port': port, 'status': 'open', 'service': self.get_service_name(port)}
                else:
                    return {'port': port, 'status': 'closed', 'service': ''}
        except socket.timeout:
            return {'port': port, 'status': 'filtered', 'service': ''}
        except Exception:
            return {'port': port, 'status': 'closed', 'service': ''}

    def scan_ports(self, ip: str, ports: List[int], show_progress: bool = True) -> List[Dict[str, Any]]:
        """
        Perform threaded scan for this target.
        Returns list of result dicts with keys: port, status, service
        """
        global _EXECUTOR, _RESULTS

        total = len(ports)
        if not self.quiet:
            print(f"\n{Colors.YELLOW}⚡ Scanning {total} ports on {ip} with {self.max_workers} threads...{Colors.ENDC}\n")
            print(f"{Colors.BLUE}{'PORT':<8} {'STATUS':<10} {'SERVICE':<20}{Colors.ENDC}")
            print("─" * 50)

        self.start_time = time.time()
        scanned = 0
        results: List[Dict[str, Any]] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            _EXECUTOR = executor
            future_to_port = {executor.submit(self._scan_one_port, ip, port): port for port in ports}

            try:
                for future in as_completed(future_to_port):
                    if _INTERRUPTED:
                        break
                    res = future.result()
                    scanned += 1
                    # attach host for global results printing
                    res_with_host = {'host': self.target, **res}
                    results.append(res_with_host)
                    _RESULTS.append(res_with_host)

                    port = res['port']
                    status = res['status']
                    service = res.get('service', '')

                    if status == 'open':
                        self.open_ports.append({'port': port, 'service': service})
                        if not self.quiet:
                            print(f"{Colors.GREEN}{port:<8} {'OPEN':<10} {service:<20}{Colors.ENDC}")
                    elif status == 'filtered':
                        self.filtered_ports.append(port)
                        if not self.quiet:
                            print(f"{Colors.CYAN}{port:<8} {'FILTERED':<10} {service:<20}{Colors.ENDC}")
                    else:
                        self.closed_ports.append(port)
                        # avoid printing every closed port unless verbose

                    if show_progress and (scanned % 100 == 0 or scanned == total):
                        progress = (scanned / total) * 100
                        if not self.quiet:
                            print(f"{Colors.CYAN}Progress: {scanned}/{total} ({progress:.1f}%) {Colors.ENDC}", end='\r')
            except KeyboardInterrupt:
                try:
                    executor.shutdown(wait=False, cancel_futures=True)
                except Exception:
                    pass
                raise
            finally:
                _EXECUTOR = None

        self.end_time = time.time()
        if show_progress and not self.quiet:
            print(" " * 60, end='\r')
        return results

    def print_summary(self):
        if not self.start_time or not self.end_time:
            print("No scan data available.")
            return
        duration = max(0.0001, self.end_time - self.start_time)
        total = len(self.open_ports) + len(self.closed_ports) + len(self.filtered_ports)

        print("\n" + "═" * 50)
        print(f"{Colors.BOLD}{Colors.CYAN}📊 SCAN SUMMARY for {self.target}{Colors.ENDC}")
        print("═" * 50)
        print(f"Target:          {Colors.BOLD}{self.target}{Colors.ENDC}")
        print(f"Duration:        {Colors.YELLOW}{duration:.2f} seconds{Colors.ENDC}")
        print(f"Ports Scanned:   {total}")
        print(f"Open Ports:      {Colors.GREEN}{len(self.open_ports)}{Colors.ENDC}")
        print(f"Filtered Ports:  {Colors.CYAN}{len(self.filtered_ports)}{Colors.ENDC}")
        print(f"Closed Ports:    {Colors.RED}{len(self.closed_ports)}{Colors.ENDC}")
        speed = total / duration
        print(f"Scan Speed:      {Colors.CYAN}{speed:.0f} ports/sec{Colors.ENDC}")
        print("═" * 50 + "\n")

        if self.open_ports:
            print(f"{Colors.GREEN}Open ports:{Colors.ENDC}")
            for item in sorted(self.open_ports, key=lambda x: x['port']):
                print(f"  - {item['port']}: {item.get('service','')}")
            print()

    def export_results(self, fmt: str, filename: str):
        """Export results for this scanner to filename; create parent dirs automatically."""
        try:
            # ensure parent directory exists
            dirpath = os.path.dirname(filename) or '.'
            os.makedirs(dirpath, exist_ok=True)

            if fmt == 'json':
                data = {
                    'target': self.target,
                    'scan_time': datetime.now().isoformat(),
                    'duration': (self.end_time - self.start_time) if self.end_time and self.start_time else None,
                    'open_ports': self.open_ports,
                    'filtered_ports': sorted(self.filtered_ports),
                    'closed_ports': sorted(self.closed_ports),
                    'total_scanned': len(self.open_ports) + len(self.closed_ports) + len(self.filtered_ports)
                }
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2)
            elif fmt == 'csv':
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Port', 'Service', 'Status'])
                    for item in self.open_ports:
                        writer.writerow([item['port'], item.get('service',''), 'OPEN'])
                    for p in sorted(self.filtered_ports):
                        writer.writerow([p, '', 'FILTERED'])
                    for p in sorted(self.closed_ports):
                        writer.writerow([p, '', 'CLOSED'])
            elif fmt == 'txt':
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"Port Scan Results for {self.target}\n")
                    f.write(f"Scan Date: {datetime.now()}\n")
                    f.write(f"Duration: {self.end_time - self.start_time:.2f} seconds\n\n")
                    f.write("OPEN PORTS:\n")
                    f.write("-" * 40 + "\n")
                    for item in self.open_ports:
                        f.write(f"Port {item['port']}: {item.get('service','')}\n")
                    f.write("\nFILTERED PORTS (timeouts):\n")
                    f.write("-" * 40 + "\n")
                    for p in sorted(self.filtered_ports):
                        f.write(f"Port {p}\n")
                    f.write("\nCLOSED PORTS:\n")
                    f.write("-" * 40 + "\n")
                    for p in sorted(self.closed_ports):
                        f.write(f"Port {p}\n")
            else:
                print("Unsupported export format.")
                return
            print(f"{Colors.GREEN}✓{Colors.ENDC} Results exported to: {Colors.BOLD}{filename}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.RED}✗ Export failed:{Colors.ENDC} {e}")

# -----------------------
# CLI and main
# -----------------------
def main():
    # re-register SIGINT in main thread
    signal.signal(signal.SIGINT, handle_sigint)

    parser = argparse.ArgumentParser(
        description='Advanced Port Scanner - Fast, robust scanning with export options',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('-t', '--target', required=False, help='Target IP or hostname (comma-separated supported)')
    parser.add_argument('--targets', help='Path to file with targets (one per line)')
    parser.add_argument('-p', '--ports', default='1-1024', help='Port range (default: 1-1024) e.g. 22,80,1-1024')
    parser.add_argument('--full', action='store_true', help='Scan all 65535 ports')
    parser.add_argument('--top', type=int, metavar='N', help='Scan top N common ports (from built-in list)')
    parser.add_argument('-w', '--workers', type=int, default=100, help='Number of worker threads')
    parser.add_argument('-T', '--timeout', type=float, default=1.0, help='Connection timeout (sec)')
    parser.add_argument('-o', '--output', help='Export results to file or directory (e.g. reports/scan.txt or reports/)')
    parser.add_argument('-f', '--format', choices=['json','csv','txt'], default='json', help='Output format when using --output (default: json)')
    parser.add_argument('--no-banner', action='store_true', help='Hide banner')
    parser.add_argument('--quiet', action='store_true', help='Minimal output')
    args = parser.parse_args()

    # Build list of targets
    targets: List[str] = []

    if args.targets:
        # read file
        try:
            with open(args.targets, 'r', encoding='utf-8') as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        targets.append(line)
        except Exception as e:
            print(f"{Colors.RED}✗ Failed to read targets file:{Colors.ENDC} {e}")
            sys.exit(1)
    elif args.target:
        # comma separated or single
        if ',' in args.target:
            targets = [x.strip() for x in args.target.split(',') if x.strip()]
        else:
            targets = [args.target.strip()]
    else:
        # interactive fallback for single target
        try:
            t = input("Enter target to scan (IP or hostname): ").strip()
            if not t:
                print("No target provided. Exiting.")
                sys.exit(1)
            targets = [t]
        except (KeyboardInterrupt, EOFError):
            print("\nNo target provided. Exiting.")
            sys.exit(1)

    # Determine ports to scan
    if args.full:
        ports = list(range(1, 65536))
    elif args.top:
        top_list = sorted(COMMON_PORTS.keys())[:args.top]
        if not top_list:
            print("No common ports configured for requested top value.")
            sys.exit(1)
        ports = top_list
    elif config.get("ports") and not args.ports:
        try:
            ports = parse_port_range(str(config.get("ports")))
        except Exception:
            ports = list(range(1, 1025))
    else:
        try:
            ports = parse_port_range(args.ports)
        except Exception as e:
            print(f"{Colors.RED}✗ Error parsing ports:{Colors.ENDC} {e}")
            sys.exit(1)

    # Output handling:
    # If args.output is provided and multiple targets, we'll create per-host files.
    output_path = args.output
    multi_mode = len(targets) > 1

    # If user provided a directory (endswith slash or is an existing dir), use it as folder
    if output_path:
        # normalize separators
        output_path = os.path.normpath(output_path)
        if output_path.endswith(os.sep):
            output_dir = output_path
            output_file_template = None
        elif os.path.isdir(output_path):
            output_dir = output_path
            output_file_template = None
        else:
            # it's a file path - split ext
            output_dir = os.path.dirname(output_path) or '.'
            base = os.path.basename(output_path)
            name, ext = os.path.splitext(base)
            output_file_template = (name, ext or '.json')  # ext includes dot if present
    else:
        output_dir = None
        output_file_template = None

    # If multi targets & output is a single file name, we'll create per-host files by inserting host name
    # e.g. reports/scan.txt -> reports/scan_<host>.txt
    try:
        # Resolve each target and scan sequentially (port scanning uses threads per host)
        for idx, target in enumerate(targets, start=1):
            print(f"\n{Colors.HEADER}=== [{idx}/{len(targets)}] Scanning target: {target} ==={Colors.ENDC}\n")
            scanner = PortScanner(target, timeout=args.timeout, max_workers=args.workers, quiet=args.quiet)
            try:
                ip = scanner.resolve_target()
            except Exception:
                # resolution failed for this host; continue to next
                continue

            scanner.scan_ports(ip, ports, show_progress=not args.quiet)

            if not args.quiet:
                scanner.print_summary()

            # handle export if requested
            if output_path:
                if multi_mode:
                    # produce per-host filename
                    if output_file_template is None:
                        # user supplied a directory: create it and write <host>.ext
                        dirpath = output_dir
                        os.makedirs(dirpath, exist_ok=True)
                        # default filename uses host + timestamp for uniqueness
                        ext = args.format if args.format else 'json'
                        filename = os.path.join(dirpath, f"{sanitize_for_filename(target)}{'.' + ext}")
                    else:
                        # user provided a file path: insert host into filename before extension
                        name, ext = output_file_template
                        ext = ext if ext.startswith('.') else ('.' + ext)
                        filename = os.path.join(output_dir, f"{name}_{sanitize_for_filename(target)}{ext}")
                else:
                    # single target: honor exactly what user asked
                    if os.path.isdir(output_path) or (output_path.endswith(os.sep)):
                        dirpath = output_dir
                        os.makedirs(dirpath, exist_ok=True)
                        ext = args.format if args.format else 'json'
                        filename = os.path.join(dirpath, f"{sanitize_for_filename(target)}{'.' + ext}")
                    else:
                        # user provided a file path; ensure parent exists
                        filename = output_path
                        parent = os.path.dirname(filename) or '.'
                        os.makedirs(parent, exist_ok=True)

                # write export
                scanner.export_results(args.format, filename)

    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}⚠ Scan interrupted by user{Colors.ENDC}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}✗ Error:{Colors.ENDC} {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
