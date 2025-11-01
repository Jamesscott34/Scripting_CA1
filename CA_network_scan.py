#!/usr/bin/env python3
"""
CA_network_scan.py - Network Scanner
Advanced network discovery and port scanning tool with vulnerability assessment

Features:
- Port Scanning: TCP and UDP port scanning with nmap integration
- Host Discovery: Ping sweep for network host identification
- Service Detection: Banner grabbing and version detection
- SSL/TLS Analysis: Certificate validation and security checks
- HTTP Security: Security headers analysis for web services
- Vulnerability Detection: Basic vulnerability identification
- Batch Scanning: Multiple targets from file input
- Scan Templates: Save and load scan configurations for reuse
- Progress Tracking: Real-time scan progress updates
- Multiple Output Formats: JSON and CSV export
- Exploit Discovery: Integration with searchsploit (Kali Linux)

Author: Security Analyst
Version: 1.0.0

Scan Flow:
1. Tries Python nmap library first (if available)
2. Falls back to system nmap command if library unavailable
3. Runs searchsploit on discovered services (when --use-searchsploit enabled)
4. Stores exploit details (title, path, EDB-ID) in port information
"""

import argparse
import json
import csv
import time
import socket

import subprocess
import sys
import os
import ssl
import requests
from datetime import datetime

# Optional imports
try:
    import nmap

    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    from scapy.all import ARP, Ether, srp

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import netaddr  # noqa: F401

    NETADDR_AVAILABLE = True
except ImportError:
    NETADDR_AVAILABLE = False


class NetworkScanner:
    """
    Comprehensive network scanner with multi-tool integration.

    Provides network discovery, port scanning, service detection, and vulnerability
    assessment through integration with Python socket libraries, nmap, and searchsploit.

    Features:
        - Intelligent tool fallback: Python nmap library -> system nmap -> manual scanning
        - Exploit discovery integration with searchsploit
        - Multiple scan types: TCP, UDP, service detection, SSL/TLS, HTTP security
        - Template-based configuration and batch scanning support
    """

    def __init__(self):
        """Initialize the network scanner."""
        self.results = {"scan_info": {}, "hosts": {}, "summary": {}}
        self.common_tcp_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
        self.common_udp_ports = [53, 67, 68, 161, 162]
        self.extended_tcp_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3307, 3389, 5432, 5900, 6379, 8080, 8443, 9000]
        self.scan_progress = {}
        self.ensure_output_directories()

    def ensure_output_directories(self):
        """Create output directories if they don't exist."""
        dirs = ["Network_Scans"]
        for dir_name in dirs:
            os.makedirs(dir_name, exist_ok=True)

    def format_timestamp(self, dt=None):
        """Format datetime in dd-mm-yy hh:mm format."""
        if dt is None:
            dt = datetime.now()
        return dt.strftime("%d-%m-%y %H:%M")

    def is_host_alive(self, host, timeout=1):
        """Check if host is alive using ping."""
        try:
            if sys.platform == "win32":
                result = subprocess.run(["ping", "-n", "1", "-w", str(timeout * 1000), host], capture_output=True, timeout=timeout + 1)
            else:
                result = subprocess.run(["ping", "-c", "1", "-W", str(timeout), host], capture_output=True, timeout=timeout + 1)
            return result.returncode == 0
        except Exception:
            return False

    def arp_discover(self, cidr):
        """Discover alive hosts on a local subnet via ARP using scapy.srp (best-effort)."""
        if not SCAPY_AVAILABLE or not NETADDR_AVAILABLE:
            return []
        try:
            # Limit scan size for safety
            from netaddr import IPNetwork
            network = IPNetwork(cidr)
            if network.size > 1024:
                return []
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=str(network))
            answered, _ = srp(pkt, timeout=2, verbose=0)
            hosts = []
            for _, recv in answered:
                ip = recv.psrc
                mac = recv.hwsrc
                hosts.append({"ip": ip, "mac": mac})
            return hosts
        except Exception:
            return []

    def scan_port(self, host, port, protocol="tcp", timeout=1):
        """Scan a single port."""
        try:
            if protocol.lower() == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                sock.close()
                return result == 0
            else:  # UDP
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)
                sock.connect((host, port))
                sock.close()
                return True
        except Exception:
            return False

    def get_service_banner(self, host, port, timeout=3):
        """Attempt to grab service banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))

            # Try to receive banner
            try:
                banner = sock.recv(1024).decode("utf-8", errors="ignore")
                sock.close()
                return banner.strip()
            except Exception:
                sock.close()
                return None
        except Exception:
            return None

    def check_ssl_certificate(self, host, port=443):
        """Check SSL/TLS certificate validity and security."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()

                    cert_info = {
                        "subject": dict(x[0] for x in cert["subject"]),
                        "issuer": dict(x[0] for x in cert["issuer"]),
                        "version": cert.get("version"),
                        "serialNumber": cert.get("serialNumber"),
                        "notBefore": cert.get("notBefore"),
                        "notAfter": cert.get("notAfter"),
                        "valid": True,
                    }

                    # Check expiration
                    import calendar

                    not_after = cert.get("notAfter")
                    if not_after:
                        time_tuple = time.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        expiration = calendar.timegm(time_tuple)
                        if expiration < time.time():
                            cert_info["valid"] = False
                            cert_info["expired"] = True

                    return cert_info
        except Exception as e:
            return {"error": str(e), "valid": False}

    def check_http_security_headers(self, url):
        """Check HTTP security headers."""
        try:
            response = requests.get(url, timeout=5, verify=False)
            headers = {
                "X-Frame-Options": response.headers.get("X-Frame-Options", "Missing"),
                "X-Content-Type-Options": response.headers.get("X-Content-Type-Options", "Missing"),
                "X-XSS-Protection": response.headers.get("X-XSS-Protection", "Missing"),
                "Strict-Transport-Security": response.headers.get("Strict-Transport-Security", "Missing"),
                "Content-Security-Policy": response.headers.get("Content-Security-Policy", "Missing"),
                "Server": response.headers.get("Server", "Unknown"),
                "status_code": response.status_code,
            }
            return headers
        except Exception as e:
            return {"error": str(e)}

    def detect_vulnerabilities(self, host, port, service):
        """Basic vulnerability detection."""
        vulnerabilities = []

        # SSH weak configurations
        if service == "ssh" and port == 22:
            vulnerabilities.append({"type": "info", "description": "SSH service detected - check for weak keys"})

        # FTP anonymous access
        if service == "ftp" and port == 21:
            vulnerabilities.append({"type": "warning", "description": "FTP service detected - check for anonymous access"})

        # Telnet insecure
        if service == "telnet":
            vulnerabilities.append({"type": "critical", "description": "Telnet service detected - unencrypted protocol"})

        # HTTP without HTTPS
        if service == "http" and not self.check_port(host, 443):
            vulnerabilities.append({"type": "warning", "description": "HTTP without HTTPS - unencrypted communication"})

        return vulnerabilities

    def check_port(self, host, port):
        """Quick check if port is open."""
        return self.scan_port(host, port)

    def is_nmap_installed(self):
        """Check if nmap command is installed on the system."""
        try:
            result = subprocess.run(["nmap", "--version"], capture_output=True, text=True)
            if result.returncode == 0:
                return True
            return False
        except FileNotFoundError:
            return False

    def run_nmap_scan(self, host, ports=None, scan_type="tcp"):
        """
        Run nmap scan - tries Python nmap library first, then falls back to system nmap.

        Args:
            host (str): Target host IP
            ports (list): List of ports to scan
            scan_type (str): Scan type (tcp/udp)

        Returns:
            dict: Nmap scan results
        """
        # Try Python nmap library first
        if NMAP_AVAILABLE:
            try:
                print(f"[INFO] Using Python nmap library for {host}")
                nm = nmap.PortScanner()
                port_str = ",".join(map(str, ports)) if ports else "1-1000"

                if scan_type.lower() == "udp":
                    nm.scan(host, port_str, arguments="-sU -T4")
                else:
                    nm.scan(host, port_str, arguments="-sV -T4")

                results = {"nmap": {"command_line": nm.command_line(), "scan_info": nm.scaninfo(), "hosts": {}, "method": "python_nmap"}}

                for hostname in nm.all_hosts():
                    host_info = {"state": nm[hostname].state(), "ports": {}, "services": []}

                    for protocol in nm[hostname].all_protocols():
                        ports_info = nm[hostname][protocol]
                        for port in ports_info.keys():
                            port_data = ports_info[port]
                            host_info["ports"][port] = {
                                "state": port_data["state"],
                                "name": port_data["name"],
                                "product": port_data.get("product", ""),
                                "version": port_data.get("version", ""),
                                "extrainfo": port_data.get("extrainfo", ""),
                            }

                            # Add to services list
                            if port_data["state"] == "open":
                                host_info["services"].append(
                                    {
                                        "port": int(port),
                                        "protocol": protocol,
                                        "service": port_data["name"],
                                        "product": port_data.get("product", ""),
                                        "version": port_data.get("version", ""),
                                    }
                                )

                    results["nmap"]["hosts"][hostname] = host_info

                return results
            except Exception as e:
                print(f"[WARNING] Python nmap library failed: {e}")
                print("[INFO] Falling back to system nmap command")
        else:
            print("[INFO] Python nmap library not available, using system nmap")

        # Fallback to system nmap command
        if not self.is_nmap_installed():
            print("[WARNING] nmap command not found. Install with: sudo apt install nmap (Kali/Debian)")
            return None

        try:
            # Build nmap command
            nmap_cmd = ["nmap"]

            # Add scan type
            if scan_type.lower() == "udp":
                nmap_cmd.extend(["-sU", "-T4"])
            else:
                nmap_cmd.extend(["-sV", "-T4"])

            # Add ports if specified
            port_str = ",".join(map(str, ports)) if ports else "1-1000"
            nmap_cmd.extend(["-p", port_str])

            # Add target
            nmap_cmd.append(host)

            print(f"[INFO] Running nmap: {' '.join(nmap_cmd)}")

            # Run nmap command
            result = subprocess.run(nmap_cmd, capture_output=True, text=True, timeout=300)

            if result.returncode == 0:
                # Parse nmap output
                nmap_output = result.stdout
                parsed_results = self.parse_nmap_output(nmap_output, host)
                parsed_results["nmap"]["method"] = "system_nmap"
                return parsed_results
            else:
                print(f"[ERROR] nmap scan failed: {result.stderr}")
                return None

        except subprocess.TimeoutExpired:
            print(f"[ERROR] nmap scan timed out for {host}")
            return None
        except Exception as e:
            print(f"[ERROR] nmap scan failed: {e}")
            return None

    def parse_nmap_output(self, output, host):
        """Parse nmap output text."""
        results = {"nmap": {"command_line": "nmap", "scan_info": {}, "hosts": {}}}

        host_info = {"state": "up", "ports": {}, "services": []}

        lines = output.split("\n")
        # Track last parsed port if needed in future

        for line in lines:
            line = line.strip()

            # Parse port information
            if "/tcp" in line or "/udp" in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_info = parts[0].split("/")
                    if len(port_info) == 2:
                        port_num = int(port_info[0])
                        _protocol = port_info[1]
                        state = parts[1] if len(parts) > 1 else "unknown"

                        port_data = {"state": state, "name": "unknown", "product": "", "version": "", "protocol": _protocol}

                        # Try to extract service info
                        if len(parts) >= 3:
                            port_data["name"] = parts[2]
                        if len(parts) >= 4:
                            port_data["product"] = parts[3]
                        if len(parts) >= 5:
                            port_data["version"] = parts[4]

                        if state == "open":
                            host_info["ports"][port_num] = port_data
                            host_info["services"].append(
                                {
                                    "port": port_num,
                                    "state": state,
                                    "service": port_data["name"],
                                    "product": port_data["product"],
                                    "version": port_data["version"],
                                }
                            )

        results["nmap"]["hosts"][host] = host_info
        return results

    def is_searchsploit_installed(self):
        """Check if searchsploit command is installed."""
        try:
            result = subprocess.run(["which", "searchsploit"], capture_output=True, text=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def run_searchsploit(self, service_name, version=None, port=None):
        """
        Run searchsploit to find exploits for a service.

        Args:
            service_name (str): Name of the service
            version (str): Version of the service (optional)
            port (int): Port number (optional)

        Returns:
            dict: Exploit results
        """
        # Check if searchsploit is available
        if not self.is_searchsploit_installed():
            print("[WARNING] searchsploit not found (only available on Kali Linux)")
            return {"exploits": [], "error": "searchsploit not installed"}

        try:
            # Build search terms
            search_terms = []
            if version:
                search_terms.append(f"{service_name} {version}")
            search_terms.append(service_name)

            exploits_found = []

            for search_term in search_terms:
                try:
                    print(f"[INFO] Searching searchsploit for: {search_term}")

                    result = subprocess.run(["searchsploit", "--json", search_term], capture_output=True, text=True, timeout=30)

                    if result.returncode == 0:
                        try:
                            exploit_data = json.loads(result.stdout)

                            if "RESULTS_EXPLOIT" in exploit_data:
                                for exploit in exploit_data["RESULTS_EXPLOIT"]:
                                    exploit_info = {
                                        "title": exploit.get("Title", "Unknown"),
                                        "edb_id": exploit.get("EDB-ID", "N/A"),
                                        "path": exploit.get("Path", "Unknown"),
                                        "date_published": exploit.get("Date_Published", "N/A"),
                                        "platform": exploit.get("Platform", "N/A"),
                                        "type": exploit.get("Type", "N/A"),
                                        "search_term": search_term,
                                        "service": service_name,
                                        "port": port,
                                    }
                                    exploits_found.append(exploit_info)
                        except (json.JSONDecodeError, ValueError):
                            continue
                except subprocess.TimeoutExpired:
                    print(f"[WARNING] Searchsploit timed out for: {search_term}")
                    continue
                except Exception as e:
                    print(f"[ERROR] Searchsploit failed for {search_term}: {e}")
                    continue

            return {"exploits": exploits_found, "total": len(exploits_found)}

        except Exception as e:
            print(f"[ERROR] Failed to run searchsploit: {e}")
            return {"exploits": [], "error": str(e)}

    def get_exploit_counts(self, service_name, product=None, version=None):
        """
        Get exploit details from searchsploit using three-tiered search strategy.

        Strategy:
            1. Count exploits for service name (summary only)
            2. Get full exploit details for product name
            3. Get full exploit details for product + version (most specific)

        Args:
            service_name (str): Name of the service (e.g., 'ftp', 'http')
            product (str, optional): Product name (e.g., 'vsftpd', 'Apache')
            version (str, optional): Product version (e.g., '2.3.4')

        Returns:
            dict: Contains service_exploits count, and full details for
                  product_exploits and version_specific_exploits
        """
        if not self.is_searchsploit_installed():
            return {"service_exploits": 0, "product_exploits": [], "version_specific_exploits": []}

        result_data = {"service_exploits": 0, "product_exploits": [], "version_specific_exploits": []}

        try:
            # Count 1: Option to count service name (get count only for summary)
            if service_name and service_name != "unknown":
                try:
                    result = subprocess.run(["searchsploit", "--json", service_name], capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        data = json.loads(result.stdout)
                        if "RESULTS_EXPLOIT" in data:
                            result_data["service_exploits"] = len(data["RESULTS_EXPLOIT"])
                except Exception:
                    pass

            # Search 2: Product name - get full details
            if product and product.strip():
                try:
                    result = subprocess.run(["searchsploit", "--json", product], capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        data = json.loads(result.stdout)
                        if "RESULTS_EXPLOIT" in data:
                            for exploit in data["RESULTS_EXPLOIT"]:
                                exploit_info = {
                                    "title": exploit.get("Title", "Unknown"),
                                    "edb_id": exploit.get("EDB-ID", "N/A"),
                                    "path": exploit.get("Path", "Unknown"),
                                    "date_published": exploit.get("Date_Published", "N/A"),
                                    "platform": exploit.get("Platform", "N/A"),
                                    "type": exploit.get("Type", "N/A"),
                                }
                                result_data["product_exploits"].append(exploit_info)
                except Exception:
                    pass

            # Search 3: Product + Version - get full details (most specific)
            if product and version and product.strip() and version.strip():
                search_term = f"{product} {version}"
                try:
                    result = subprocess.run(["searchsploit", "--json", search_term], capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        data = json.loads(result.stdout)
                        if "RESULTS_EXPLOIT" in data:
                            for exploit in data["RESULTS_EXPLOIT"]:
                                exploit_info = {
                                    "title": exploit.get("Title", "Unknown"),
                                    "edb_id": exploit.get("EDB-ID", "N/A"),
                                    "path": exploit.get("Path", "Unknown"),
                                    "date_published": exploit.get("Date_Published", "N/A"),
                                    "platform": exploit.get("Platform", "N/A"),
                                    "type": exploit.get("Type", "N/A"),
                                }
                                result_data["version_specific_exploits"].append(exploit_info)
                except Exception:
                    pass
        except Exception:
            pass

        return result_data

    def scan_targets_from_file(self, filename, ports, scan_type="tcp", service_detection=False):
        """Scan multiple targets from a file."""
        targets = []
        try:
            with open(filename, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
        except FileNotFoundError:
            print(f"[ERROR] File not found: {filename}")
            return None

        return self.scan_multiple_targets(targets, ports, scan_type, service_detection)

    def expand_cidr(self, cidr):
        """
        Expand CIDR notation to list of individual IP addresses.

        Args:
            cidr (str): CIDR notation (e.g., '192.168.1.0/24')

        Returns:
            list: List of IP addresses in the CIDR range
        """
        if not NETADDR_AVAILABLE:
            print("[ERROR] netaddr library not available. Install with: pip install netaddr")
            return []

        try:
            from netaddr import IPNetwork

            network = IPNetwork(cidr)
            # Exclude network and broadcast addresses for /24 and larger
            if network.size > 2:
                return [str(ip) for ip in network if ip != network.network and ip != network.broadcast]
            return [str(ip) for ip in network]
        except Exception as e:
            print(f"[ERROR] Failed to expand CIDR {cidr}: {e}")
            return []

    def scan_multiple_targets(self, targets, ports, scan_type="tcp", service_detection=False):
        """Scan multiple targets."""
        results = {"scan_info": {"scan_type": scan_type, "total_targets": len(targets), "start_time": self.format_timestamp()}, "hosts": {}, "summary": {}}

        print(f"[INFO] Scanning {len(targets)} targets...")

        for target in targets:
            print(f"[INFO] Scanning {target}...")
            target_results = self.comprehensive_scan(target, ports, scan_type, service_detection)
            if target_results["hosts"]:
                results["hosts"].update(target_results["hosts"])

        results["scan_info"]["end_time"] = self.format_timestamp()
        results["summary"] = self.generate_summary(results)

        return results

    def comprehensive_scan(
        self,
        target,
        ports=None,
        scan_type="tcp",
        service_detection=False,
        ssl_check=False,
        http_security=False,
        use_python_only=False,
        use_nmap=False,
        use_searchsploit=False,
    ):
        """
        Perform comprehensive network scan with multi-tool integration.

        Scan workflow:
            1. Attempts nmap scan (Python library -> system command) unless --use-python-only
            2. Falls back to manual Python socket scanning if nmap unavailable
            3. Runs searchsploit queries for discovered services (when enabled)
            4. Embeds exploit details directly into port information
            5. Performs SSL/TLS and HTTP security checks (when enabled)

        Args:
            target (str): Target IP address or hostname
            ports (list, optional): List of ports to scan. Defaults to common/extended ports
            scan_type (str): 'tcp' or 'udp'. Defaults to 'tcp'
            service_detection (bool): Enable service and version detection
            ssl_check (bool): Perform SSL/TLS certificate validation
            http_security (bool): Analyze HTTP security headers
            use_python_only (bool): Use only Python socket scanning (skip nmap)
            use_nmap (bool): Force use of nmap for scanning
            use_searchsploit (bool): Enable searchsploit for exploit discovery

        Returns:
            dict: Comprehensive scan results with hosts, ports, services, and exploits
        """
        if ports is None:
            ports = self.extended_tcp_ports if service_detection else self.common_tcp_ports

        results = {
            "scan_info": {"target": target, "scan_type": scan_type, "ports": ports, "start_time": self.format_timestamp()},
            "hosts": {},
            "summary": {},
        }

        # Try nmap first if not using Python-only mode
        # In auto mode, use all tools; otherwise respect user flags
        should_use_nmap = not use_python_only and (use_nmap or service_detection)

        if should_use_nmap:
            print(f"[INFO] Starting with nmap scan on {target}")
            nmap_results = self.run_nmap_scan(target, ports, scan_type)
            if nmap_results:
                results["scan_info"]["nmap_used"] = True
                if "nmap" in nmap_results and "hosts" in nmap_results["nmap"]:
                    for host, host_info in nmap_results["nmap"]["hosts"].items():
                        if host_info["state"] == "up":
                            results["hosts"][host] = {"alive": True, "ports": {}, "services": []}

                            for port, port_data in host_info["ports"].items():
                                if port_data["state"] == "open":
                                    port_info = {
                                        "port": int(port),
                                        "state": "open",
                                        "service": port_data["name"],
                                        "product": port_data.get("product", ""),
                                        "version": port_data.get("version", ""),
                                    }

                                    # Add exploit details if enabled
                                    if use_searchsploit:
                                        exploit_data = self.get_exploit_counts(port_data["name"], port_data.get("product", ""), port_data.get("version", ""))
                                        if exploit_data.get("product_exploits") or exploit_data.get("version_specific_exploits"):
                                            num_product = len(exploit_data.get("product_exploits", []))
                                            num_version = len(exploit_data.get("version_specific_exploits", []))
                                            print(
                                                f"[INFO] Found {num_product} product exploits and {num_version} version-specific exploits "
                                                f"for {port_data['name']} on port {port}"
                                            )
                                            port_info["exploits"] = exploit_data

                                    results["hosts"][host]["ports"][port] = port_info

                            # Add to services list
                            if "services" in host_info:
                                results["hosts"][host]["services"] = host_info["services"]

                            # Exploit counts are already added to each port above

                            results["scan_info"]["end_time"] = self.format_timestamp()
                            results["summary"] = self.generate_summary(results)
                            return results

        # Manual scanning if nmap not available or not used
        print(f"[INFO] Scanning {target}...")
        is_alive = self.is_host_alive(target)

        if is_alive:
            host_info = {"alive": True, "ports": {}, "services": []}

            # Port scanning
            print("[INFO] Scanning ports...")
            for port in ports:
                if self.scan_port(target, port, scan_type):
                    port_info = {"port": port, "state": "open", "service": self.identify_service(port), "product": "", "version": ""}

                    # Service detection
                    if service_detection:
                        banner = self.get_service_banner(target, port)
                        if banner:
                            port_info["banner"] = banner

                        # Try to extract product/version from banner
                        # This is a simple extraction - could be improved
                        if banner:
                            if "Apache" in banner:
                                port_info["product"] = "Apache"
                            elif "nginx" in banner.lower():
                                port_info["product"] = "nginx"

                    # Add exploit details if enabled
                    if use_searchsploit:
                        exploit_data = self.get_exploit_counts(port_info["service"], port_info.get("product", ""), port_info.get("version", ""))
                        if exploit_data.get("product_exploits") or exploit_data.get("version_specific_exploits"):
                            num_product = len(exploit_data.get("product_exploits", []))
                            num_version = len(exploit_data.get("version_specific_exploits", []))
                            print(
                                f"[INFO] Found {num_product} product exploits and {num_version} version-specific exploits "
                                f"for {port_info['service']} on port {port}"
                            )
                            port_info["exploits"] = exploit_data

                    host_info["ports"][port] = port_info
                    host_info["services"].append(port_info)

                    print(f"[FOUND] {target}:{port} - {port_info['service']}")

            results["hosts"][target] = host_info

            # Exploit counts are already added to each port above

            # SSL check
            if ssl_check and 443 in host_info["ports"]:
                print("[INFO] Checking SSL certificate...")
                cert_info = self.check_ssl_certificate(target, 443)
                if "ssl_cert" not in results["hosts"][target]:
                    results["hosts"][target]["ssl_cert"] = cert_info

            # HTTP security headers check
            if http_security:
                for port in [80, 443, 8080, 8443]:
                    if port in host_info["ports"]:
                        protocol = "https" if port in [443, 8443] else "http"
                        url = f"{protocol}://{target}:{port}"
                        print(f"[INFO] Checking HTTP security headers for {url}...")
                        headers = self.check_http_security_headers(url)
                        if "http_security" not in results["hosts"][target]:
                            results["hosts"][target]["http_security"] = {}
                        results["hosts"][target]["http_security"][port] = headers
        else:
            print(f"[WARNING] Host {target} appears to be down")

        results["scan_info"]["end_time"] = self.format_timestamp()
        results["summary"] = self.generate_summary(results)

        return results

    def identify_service(self, port):
        """Identify service by port number."""
        services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            3389: "RDP",
            3306: "MySQL",
            3307: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            8080: "HTTP-Alt",
        }
        return services.get(port, "unknown")

    def generate_summary(self, results):
        """
        Generate comprehensive scan summary statistics.

        Aggregates:
            - Host counts (total, alive)
            - Port and service counts
            - Exploit discovery statistics from all ports

        Returns:
            dict: Summary statistics including exploit counts
        """
        summary = {
            "total_hosts": len(results["hosts"]),
            "alive_hosts": sum(1 for h in results["hosts"].values() if h["alive"]),
            "total_services": 0,
            "total_ports": 0,
            "total_exploits": 0,
            "product_exploits": 0,
            "version_exploits": 0,
        }

        for host_info in results["hosts"].values():
            summary["total_ports"] += len(host_info["ports"])
            summary["total_services"] += len(host_info["services"])

            # Count exploits from ports
            for port_info in host_info["ports"].values():
                if "exploits" in port_info:
                    exploits = port_info["exploits"]
                    summary["product_exploits"] += len(exploits.get("product_exploits", []))
                    summary["version_exploits"] += len(exploits.get("version_specific_exploits", []))

        summary["total_exploits"] = summary["product_exploits"] + summary["version_exploits"]

        return summary

    def save_template(self, template_name, config):
        """Save scan configuration template."""
        # Create templates folder only when saving a template
        template_dir = "Network_Scans/templates"
        os.makedirs(template_dir, exist_ok=True)

        template_file = f"{template_dir}/{template_name}.json"
        with open(template_file, "w") as f:
            json.dump(config, f, indent=2)
        print(f"[INFO] Template saved: {template_file}")

    def load_template(self, template_name):
        """Load scan configuration template."""
        template_file = f"Network_Scans/templates/{template_name}.json"
        try:
            with open(template_file, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"[ERROR] Template not found: {template_file}")
            return None

    def save_results(self, results, output_file=None, format="both"):
        """Save scan results to file."""
        # Generate output filename if not provided
        timestamp = datetime.now().strftime("%d-%m")
        if output_file is None:
            if len(results["hosts"]) == 1:
                target = list(results["hosts"].keys())[0]
                safe_target = target.replace(".", "_").replace("/", "_")
                base_file = f"Network_Scans/Scan_{safe_target}_{timestamp}"
            else:
                base_file = f"Network_Scans/Scan_file_{timestamp}"
        else:
            # Remove extension if provided
            base_file = output_file.replace(".json", "").replace(".csv", "")

        if format == "json" or format == "both":
            json_file = f"{base_file}.json"
            with open(json_file, "w") as f:
                json.dump(results, f, indent=2)
            print(f"[INFO] Results saved: {json_file}")

        if format == "csv" or format == "both":
            csv_file = f"{base_file}.csv"
            with open(csv_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                # Comprehensive headers including exploits
                writer.writerow(
                    [
                        "Host",
                        "Alive",
                        "Port",
                        "Protocol",
                        "State",
                        "Service",
                        "Product",
                        "Version",
                        "Service Exploits Count",
                        "Product Exploits Count",
                        "Version Exploits Count",
                        "Product Exploit Titles",
                        "Version Exploit Titles",
                    ]
                )

                for host, host_info in results["hosts"].items():
                    host_alive = host_info.get("alive", False)

                    # If there are no ports, add a row with host info
                    if not host_info.get("ports"):
                        writer.writerow([host, host_alive, "", "", "", "", "", "", "", "", "", "", ""])
                        continue

                    for port, port_info in host_info["ports"].items():
                        # Extract exploit data
                        exploits = port_info.get("exploits", {})
                        service_exploits_count = exploits.get("service_exploits", 0) if exploits else 0
                        product_exploits = exploits.get("product_exploits", []) if exploits else []
                        version_exploits = exploits.get("version_specific_exploits", []) if exploits else []

                        # Format exploit titles
                        product_titles = "; ".join([e.get("title", "") for e in product_exploits]) if product_exploits else "None"
                        version_titles = "; ".join([e.get("title", "") for e in version_exploits]) if version_exploits else "None"

                        # Protocol - default to TCP if not specified
                        protocol = port_info.get("protocol", "tcp")

                        writer.writerow(
                            [
                                host,
                                host_alive,
                                port,
                                protocol,
                                port_info.get("state", "unknown"),
                                port_info.get("service", "unknown"),
                                port_info.get("product", ""),
                                port_info.get("version", ""),
                                service_exploits_count,
                                len(product_exploits),
                                len(version_exploits),
                                product_titles,
                                version_titles,
                            ]
                        )
            print(f"[INFO] CSV results saved: {csv_file}")

        return base_file


def parse_ports(port_string):
    """Parse port specification string."""
    ports = []

    if "-" in port_string:
        # Range
        start, end = map(int, port_string.split("-"))
        ports = list(range(start, end + 1))
    elif "," in port_string:
        # Comma-separated
        ports = [int(p.strip()) for p in port_string.split(",")]
    else:
        # Single port
        ports = [int(port_string)]

    return ports


def interactive_mode(scanner):
    """Interactive mode for the scanner."""
    print("\n" + "=" * 60)
    print("NETWORK SCANNER - INTERACTIVE MODE")
    print("=" * 60)

    # Target selection
    print("\nTarget Selection:")
    print("1. Single IP address or hostname")
    print("2. CIDR range (e.g., 192.168.1.0/24)")
    print("3. File with targets")

    choice = input("Choose option (1-3): ").strip()

    target = None
    if choice == "1":
        target = input("Enter IP address or hostname: ").strip()
    elif choice == "2":
        target = input("Enter CIDR range: ").strip()
    elif choice == "3":
        filename = input("Enter filename: ").strip()
        results = scanner.scan_targets_from_file(filename, scanner.extended_tcp_ports)
        if results:
            scanner.save_results(results, format="both")
        return

    # Port selection
    print("\nPort Selection:")
    print("1. Common ports (21,22,23,25,53,80,110,143,443,993,995)")
    print("2. Extended ports (includes DHCP, SNMP, LDAP, SMB, etc.)")
    print("3. Custom ports")

    port_choice = input("Choose option (1-3): ").strip()

    if port_choice == "1":
        ports = scanner.common_tcp_ports
    elif port_choice == "2":
        ports = scanner.extended_tcp_ports
    else:
        port_string = input("Enter ports (e.g., 1-1000 or 80,443,8080): ").strip()
        ports = parse_ports(port_string)

    # Scan options
    service_detection = input("Enable service detection? (y/n): ").strip().lower() == "y"
    ssl_check = input("Check SSL certificates? (y/n): ").strip().lower() == "y"
    http_security = input("Check HTTP security headers? (y/n): ").strip().lower() == "y"

    # Perform scan
    print(f"\n[INFO] Starting scan on {target}...")
    results = scanner.comprehensive_scan(target, ports, "tcp", service_detection, ssl_check, http_security)

    # Save results
    output = input("\nOutput file (press Enter for auto): ").strip()
    if not output:
        output = None

    format_choice = input("Output format (json/csv/both): ").strip().lower()
    if not format_choice:
        format_choice = "both"

    scanner.save_results(results, output, format_choice)

    # Print summary
    print("\n" + "=" * 60)
    print("SCAN SUMMARY")
    print("=" * 60)
    print(f"Target: {target}")
    print(f"Total hosts: {results['summary']['total_hosts']}")
    print(f"Alive hosts: {results['summary']['alive_hosts']}")
    print(f"Services found: {results['summary']['total_services']}")
    print(f"Ports open: {results['summary']['total_ports']}")
    print("=" * 60)


def auto_mode(scanner, target):
    """Auto mode - comprehensive automated scanning using all tools."""
    print(f"[INFO] Auto mode: Comprehensive scan on {target} with all tools enabled")

    ports = scanner.extended_tcp_ports

    # Check if target is CIDR notation
    if "/" in target:
        print(f"[INFO] Detected CIDR notation: {target}")
        # ARP discovery first (best-effort) to find alive hosts quickly
        alive = scanner.arp_discover(target)
        if alive:
            print(f"[INFO] ARP discovery found {len(alive)} hosts on {target}")
            for h in alive[:10]:
                print(f"  - {h['ip']} ({h.get('mac', '')})")
        expanded_targets = scanner.expand_cidr(target)
        if expanded_targets:
            print(f"[INFO] Expanded to {len(expanded_targets)} IP addresses")
            results = scanner.scan_multiple_targets(expanded_targets, ports, "tcp", True)
        else:
            print(f"[ERROR] Failed to expand CIDR: {target}")
            return
    else:
        results = scanner.comprehensive_scan(target, ports, "tcp", True, True, True, use_python_only=False, use_nmap=True, use_searchsploit=True)

    scanner.save_results(results, format="both")

    print("\n" + "=" * 60)
    print("AUTO SCAN SUMMARY")
    print("=" * 60)
    print(f"Target: {target}")
    print(f"Alive hosts: {results['summary']['alive_hosts']}")
    print(f"Services found: {results['summary']['total_services']}")
    print("=" * 60)


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Network Scanner - Advanced network discovery and port scanning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single target scanning
  python3 CA_network_scan.py --target 192.168.1.1
  python3 CA_network_scan.py --target 192.168.1.0/24 --ports 1-1000
  # File input scanning
  python3 CA_network_scan.py --file targets.txt --ports 80,443
  python3 CA_network_scan.py --file targets.txt --ports 1-1000 --protocols tcp,udp
  # Output options
  python3 CA_network_scan.py --target 192.168.1.1 --output custom_results.json
  python3 CA_network_scan.py --target 192.168.1.1 --format both
  # Interactive and auto modes
  python3 CA_network_scan.py --interactive
  python3 CA_network_scan.py --auto --target 192.168.1.1
  python3 CA_network_scan.py --auto --target 192.168.1.0/24
  # Advanced features
  python3 CA_network_scan.py --target 192.168.1.1 --service-detection
  python3 CA_network_scan.py --target 192.168.1.1 --ssl-check
  # Tool selection
  python3 CA_network_scan.py --target 192.168.1.1 --use-python-only
  python3 CA_network_scan.py --target 192.168.1.1 --use-nmap --use-searchsploit
  python3 CA_network_scan.py --target 192.168.1.1 --auto  # Uses all tools
        """,
    )

    parser.add_argument("--target", help="Target IP address or CIDR range")
    parser.add_argument("--file", help="File containing target IPs")
    parser.add_argument("--ports", help="Ports to scan (e.g., 1-1000, 80,443,8080)")
    parser.add_argument("--output", help="Output file path")
    parser.add_argument("--format", choices=["json", "csv", "both"], default="both", help="Output format")
    parser.add_argument("--protocols", help="Protocols to scan (tcp,udp)", default="tcp")
    parser.add_argument("--service-detection", action="store_true", help="Enable service detection")
    parser.add_argument("--ssl-check", action="store_true", help="Check SSL/TLS certificates")
    parser.add_argument("--http-security", action="store_true", help="Check HTTP security headers")
    parser.add_argument("--interactive", action="store_true", help="Run in interactive mode")
    parser.add_argument("--auto", action="store_true", help="Auto mode: uses all tools (nmap, searchsploit, etc.)")
    parser.add_argument("--use-python-only", action="store_true", help="Use only Python socket scanning (no nmap)")
    parser.add_argument("--use-nmap", action="store_true", help="Force use of nmap (Python library or system)")
    parser.add_argument("--use-searchsploit", action="store_true", help="Enable searchsploit for exploit discovery")
    parser.add_argument("--save-template", help="Save scan configuration as template")
    parser.add_argument("--load-template", help="Load scan configuration template")
    parser.add_argument("--template-name", help="Template name for save/load operations")
    parser.add_argument("--test", action="store_true", help="Test mode: default to local CA lab host/ports")

    args = parser.parse_args()

    # Initialize scanner
    scanner = NetworkScanner()

    # Interactive mode
    if args.interactive:
        interactive_mode(scanner)
        return

    # Test helper: if --test and no target passed, default to local lab
    if args.test and not args.target:
        args.target = "127.0.0.1"

    # Auto mode
    if args.auto:
        target_for_auto = args.target or "127.0.0.1"
        auto_mode(scanner, target_for_auto)
        return

    # Validate arguments
    if not args.target and not args.file:
        print("[ERROR] Either --target or --file must be specified")
        print("[INFO] Use --interactive for guided setup")
        print("[INFO] Use --auto with --target for automated scanning")
        sys.exit(1)

    # Parse ports
    ports = None
    if args.ports:
        ports = parse_ports(args.ports)
    elif args.service_detection:
        ports = scanner.extended_tcp_ports
    else:
        ports = scanner.common_tcp_ports

    # Load template if specified
    config = None
    if args.load_template:
        config = scanner.load_template(args.load_template)
        if config:
            print(f"[INFO] Loaded template: {args.load_template}")

    # Check if target is CIDR notation and expand if needed
    if args.target and "/" in args.target:
        print(f"[INFO] Detected CIDR notation: {args.target}")
        expanded_targets = scanner.expand_cidr(args.target)
        if expanded_targets:
            print(f"[INFO] Expanded to {len(expanded_targets)} IP addresses")
            # Convert to file-like scanning for multiple targets
            results = scanner.scan_multiple_targets(expanded_targets, ports, args.protocols, args.service_detection)
        else:
            print(f"[ERROR] Failed to expand CIDR: {args.target}")
            sys.exit(1)
    # Perform scan
    elif args.file:
        results = scanner.scan_targets_from_file(args.file, ports, args.protocols, args.service_detection)
    else:
        # Determine tool usage based on flags
        # In auto mode, use all tools; otherwise respect individual flags
        use_python_only = args.use_python_only and not args.auto
        use_nmap = args.auto or args.use_nmap or args.service_detection
        use_searchsploit = args.auto or args.use_searchsploit

        results = scanner.comprehensive_scan(
            args.target,
            ports,
            args.protocols,
            args.service_detection,
            args.ssl_check,
            args.http_security,
            use_python_only=use_python_only,
            use_nmap=use_nmap,
            use_searchsploit=use_searchsploit,
        )
    if results:
        # Save results
        scanner.save_results(results, args.output, args.format)

        # Save template if requested
        if args.save_template:
            config = {
                "ports": ports,
                "protocols": args.protocols,
                "service_detection": args.service_detection,
                "ssl_check": args.ssl_check,
                "http_security": args.http_security,
            }
            scanner.save_template(args.save_template, config)

        # Print summary
        print("\n" + "=" * 60)
        print("SCAN RESULTS")
        print("=" * 60)
        print(f"Total hosts: {results['summary']['total_hosts']}")
        print(f"Alive hosts: {results['summary']['alive_hosts']}")
        print(f"Services found: {results['summary']['total_services']}")
        print(f"Ports open: {results['summary']['total_ports']}")
        if use_searchsploit and results["summary"].get("total_exploits", 0) > 0:
            print("\nExploit Discovery:")
            print(f"  Product exploits found: {results['summary'].get('product_exploits', 0)}")
            print(f"  Version-specific exploits found: {results['summary'].get('version_exploits', 0)}")
            print(f"  Total exploits: {results['summary'].get('total_exploits', 0)}")
        print("=" * 60)
    else:
        print("[ERROR] Scan failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
