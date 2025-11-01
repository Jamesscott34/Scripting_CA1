## Auto and Test Mode

Both scanners support a zero‑config test mode aimed at the local CA lab.

- Web vulnerability scanner (defaults to http://localhost:8080):

```
python CA_web_vuln.py --auto --test
# Or target explicitly
python CA_web_vuln.py --auto --target http://127.0.0.1:8080
```

- Network scanner (defaults to 127.0.0.1 and includes MySQL 3307 in extended ports):

```
python CA_network_scan.py --auto --test
# Or target explicitly
python CA_network_scan.py --auto --target 127.0.0.1
```

Notes

- `--auto` runs full scans end-to-end.
- `--test` forces sensible local-lab defaults when target is not provided.
- Network scanner includes 3307 (host-mapped MySQL) and identifies it as MySQL.

## Optional: Fake Open Ports for Testing

You can simulate additional open ports with simple TCP banner listeners (run in separate PowerShell windows):

```
# FTP-like on 2121
python -c "import socket as s, threading as t, time;h='';p=2121;ban=b'220 ProFTPD 1.3.5a\r\n';\
def srv():\
 import socket as s2;ss=s2.socket();ss.setsockopt(1,2,1);ss.bind((h,p));ss.listen(5);\
 while True: c,_=ss.accept(); c.sendall(ban); c.close()\
t.Thread(target=srv,daemon=True).start(); time.sleep(10**9)"

# SSH-like on 2222
python -c "import socket as s, threading as t, time;h='';p=2222;ban=b'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3\r\n';\
def srv():\
 import socket as s2;ss=s2.socket();ss.setsockopt(1,2,1);ss.bind((h,p));ss.listen(5);\
 while True: c,_=ss.accept(); c.sendall(ban); c.close()\
t.Thread(target=srv,daemon=True).start(); time.sleep(10**9)"

# MySQL-like extra port on 3308
python -c "import socket as s, threading as t, time;h='';p=3308;ban=b'5.7.30-log\r\n';\
def srv():\
 import socket as s2;ss=s2.socket();ss.setsockopt(1,2,1);ss.bind((h,p));ss.listen(5);\
 while True: c,_=ss.accept(); c.sendall(ban); c.close()\
t.Thread(target=srv,daemon=True).start(); time.sleep(10**9)"
```

Re-scan with:

```
python CA_network_scan.py --target 127.0.0.1 --ports 21,22,80,8080,2121,2222,3307,3308 --service-detection --use-nmap --http-security
```

## Local Subnet Discovery (netaddr + scapy.srp)

When a CIDR target is used in network auto mode, a best‑effort ARP sweep runs first to quickly find alive hosts (requires local network and appropriate permissions):

```
python CA_network_scan.py --auto --target 192.168.1.0/24
```

## Environment Overrides (Optional)

You can set environment variables to hotfix defaults without changing code:

PowerShell

```
$env:CA_LAB_HOST = "127.0.0.1"
$env:CA_LAB_URL  = "http://localhost:8080"
```

Then run:

```
python CA_network_scan.py --auto
python CA_web_vuln.py --auto
```

# CA Assignment - Secure Programming and Scripting 

**Author:** SBA2400 James Scott
**Course:** Secure Programming and Scripting
**Assignment:** CA1 - Security Assessment Tools

## Overview

This repository contains three comprehensive security assessment tools developed for the CA assignment:

1. **CA_web_vuln.py** - Web Vulnerability Scanner (40%)
2. **CA_network_scan.py** - Network Scanner (40%)
3. **CA_error_manager.sh** - System Error Manager (20%)

## 🚀 Quick Start

### Prerequisites

```bash
# Install Python dependencies
pip install -r CA_requirements.txt

# Ensure required system tools are available
sudo apt-get install nmap arp-scan curl wget
```

### Basic Usage

```bash
# Web Vulnerability Scanner
python3 CA_web_vuln.py --target 192.168.1.100
python3 CA_web_vuln.py --url http://example.com --scan-type sql,xss

# Network Scanner
python3 CA_network_scan.py --target 192.168.1.1
python3 CA_network_scan.py --file targets.txt --ports 80,443

# Error Manager
./CA_error_manager.sh logs.txt
```

## 📁 Directory Structure

```
Scripting_CA1/
├── CA_web_vuln.py              # Web vulnerability scanner
├── CA_network_scan.py          # Network scanner
├── CA_error_manager.sh         # Error manager script
├── CA_error_consumer.py        # Error analysis consumer
├── CA_requirements.txt         # Python dependencies
├── Web_Scans/                  # Web scan results
│   └── Vuln_target_DD-MM.json
├── Network_Scans/              # Network scan results
│   ├── Scan_ip_DD-MM.json
│   ├── Scan_file_DD-MM.json
│   ├── Scan_batch_DD-MM.json
│   ├── batch_results/
│   ├── exploit_scans/
│   ├── exploits/
│   └── individual_ips/
├── error_reports/              # Error analysis results
│   ├── archives/
│   ├── csv/
│   ├── json/
│   └── text/
└── test_targets.txt            # Sample targets file
```

## 🔍 CA_web_vuln.py - Web Vulnerability Scanner

### Features

- **SQL Injection Testing**: Error-based, blind, time-based, union-based
- **XSS Detection**: Reflected, DOM-based, stored, encoding bypass
- **Additional Tests**: CSRF, file upload, authentication bypass
- **Security Analysis**: Headers, SSL/TLS, HTTP methods, information disclosure
- **Enhanced Banner Grabbing**: Server detection, technology identification
- **Progress Indicators**: Real-time scan progress with percentages
- **Multiple Output Formats**: JSON and CSV export
- **Encryption Support**: Sensitive data protection using cryptography

### Usage Examples

```bash
# Basic scanning
python3 CA_web_vuln.py --target 192.168.1.100
python3 CA_web_vuln.py --url http://example.com

# Specific scan types
python3 CA_web_vuln.py --target http://192.168.1.100 --scan-type sql,xss
python3 CA_web_vuln.py --url https://example.com --scan-type sql,xss,headers

# Output options
python3 CA_web_vuln.py --target 192.168.1.100 --output custom_results.json
python3 CA_web_vuln.py --target 192.168.1.100 --format both

# Interactive and auto modes
python3 CA_web_vuln.py --interactive
python3 CA_web_vuln.py --auto

# Encryption
python3 CA_web_vuln.py --target 192.168.1.100 --encrypt --password mypass
```

### Test Websites

For testing purposes, you can use these vulnerable websites:

- http://testphp.vulnweb.com/
- http://demo.testfire.net/
- http://www.hackthissite.org/

### Scan Types

- `sql` - SQL injection testing
- `xss` - Cross-site scripting detection
- `directory` - Directory enumeration
- `headers` - Security headers analysis
- `ssl` - SSL/TLS configuration analysis
- `csrf` - CSRF vulnerability testing
- `file_upload` - File upload vulnerability detection
- `auth_bypass` - Authentication bypass testing
- `http_methods` - HTTP methods security testing
- `info_disclosure` - Information disclosure checks

### Output Files

- **Format**: `Vuln_{target_name}_{DD-MM}.json`
- **Location**: `Web_Scans/` directory
- **Example**: `Vuln_192.168.1.100_12-10.json`

## 🌐 CA_network_scan.py - Network Scanner

### Features

- **Port Scanning**: TCP and UDP port scanning
- **Host Discovery**: Ping sweep, ARP scanning
- **Service Detection**: Banner grabbing, version detection
- **SSL/TLS Analysis**: Certificate validation and security checks
- **HTTP Security**: Security headers analysis
- **Vulnerability Detection**: Basic vulnerability identification
- **Batch Scanning**: Multiple targets from file
- **Scan Templates**: Save and load scan configurations
- **Progress Tracking**: Real-time scan progress
- **Multiple Output Formats**: JSON and CSV export

### Usage Examples

```bash
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
python3 CA_network_scan.py --auto

# Advanced features
python3 CA_network_scan.py --target 192.168.1.1 --service-detection
python3 CA_network_scan.py --target 192.168.1.1 --ssl-check
```

### Port Ranges

- **Common Ports**: 21,22,23,25,53,80,110,143,443,993,995
- **Extended Ports**: DHCP, SNMP, LDAP, SMB, NFS, MySQL, PostgreSQL
- **Custom Ranges**: `1-1000`, `80,443,8080`, `22-25`

### Output Files

- **Single Target**: `Scan_{target_ip}_{DD-MM}.json`
- **File Input**: `Scan_file_{DD-MM}.json`
- **Batch Scan**: `Scan_batch_{DD-MM}.json`
- **Location**: `Network_Scans/` directory
- **Example**: `Scan_192.168.1.1_12-10.json`

## 🔧 CA_error_manager.sh - System Error Manager

### Features

- **Comprehensive Log Analysis**: All `/var/log` files
- **Error Pattern Detection**: Malformed and invalid entries
- **Service Identification**: 20+ service types
- **Automated Reporting**: JSON, CSV, and text formats
- **SSH Integration**: Remote log analysis
- **Python Consumer**: Advanced analysis with CA_error_consumer.py
- **Interactive Mode**: Guided error analysis
- **Auto Mode**: Automated comprehensive analysis

### Usage Examples

```bash
# Basic error analysis
./CA_error_manager.sh logs.txt

# Interactive mode
./CA_error_manager.sh --interactive

# Auto mode
./CA_error_manager.sh --auto

# SSH integration
./CA_error_manager.sh logs.txt --ssh user@server

# Python consumer integration
./CA_error_manager.sh logs.txt --consumer
```

### Supported Log Types

- **System Logs**: `/var/log/syslog`, `/var/log/kern.log`
- **Authentication**: `/var/log/auth.log`, `/var/log/secure`
- **Boot Logs**: `/var/log/boot.log`, `/var/log/dmesg`
- **Package Management**: `/var/log/dpkg.log`, `/var/log/apt/`
- **Web Servers**: `/var/log/apache2/`, `/var/log/nginx/`
- **Database Logs**: `/var/log/mysql/`, `/var/log/postgresql/`
- **All `/var/log` files**: Comprehensive system-wide analysis

### Service Identification

The error manager identifies and analyzes errors from:

- SSH Daemon, Apache, Nginx
- MySQL, PostgreSQL, SQLite
- Kernel, Systemd, Docker
- Fail2ban, Cron, Network services
- And 10+ additional service types

### Output Files

- **JSON Reports**: `error_reports/json/`
- **CSV Reports**: `error_reports/csv/`
- **Text Summaries**: `error_reports/text/`
- **Archives**: `error_reports/archives/`

## 📊 CA_error_consumer.py - Error Analysis Consumer

### Features

- **Statistical Analysis**: Error frequency and patterns
- **Service Classification**: Automatic service identification
- **Alert Generation**: Critical error detection
- **Recommendations**: Automated remediation suggestions
- **Interactive Mode**: Guided analysis workflow
- **Auto Mode**: Comprehensive automated analysis

### Usage Examples

```bash
# Basic analysis
python3 CA_error_consumer.py logs.txt

# Interactive mode
python3 CA_error_consumer.py --interactive

# Auto mode
python3 CA_error_consumer.py --auto

# Specific analysis
python3 CA_error_consumer.py logs.txt --service ssh
python3 CA_error_consumer.py logs.txt --severity critical
```

## 🛠️ Installation and Setup

### 1. Clone Repository

```bash
git clone <repository-url>
cd Scripting_CA1
```

### 2. Install Dependencies

```bash
# Python dependencies
pip install -r CA_requirements.txt

# System dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install nmap arp-scan curl wget netcat-openbsd

# Make scripts executable
chmod +x CA_error_manager.sh
```

### 3. Verify Installation

```bash
# Test web scanner
python3 CA_web_vuln.py --help

# Test network scanner
python3 CA_network_scan.py --help

# Test error manager
./CA_error_manager.sh --help
```

## 📋 Requirements

### Python Dependencies

```
requests>=2.25.1
beautifulsoup4>=4.9.3
cryptography>=3.4.8
python-nmap>=0.7.1
netaddr>=0.8.0
tabulate>=0.9.0
tqdm>=4.62.0
```

### System Dependencies

- **nmap**: Network scanning
- **arp-scan**: ARP scanning
- **curl**: HTTP requests
- **wget**: File downloads
- **netcat**: Network connectivity testing

### Permissions

- **Network Scanning**: May require sudo for raw socket access
- **Log Analysis**: Read access to `/var/log` files
- **File Creation**: Write access to current directory

## 🔒 Security Considerations

### Legal and Ethical Use

- **Only scan systems you own or have explicit permission to test**
- **Use vulnerable test sites for learning purposes**
- **Respect rate limits and don't overload target systems**
- **Follow responsible disclosure practices**

### Data Protection

- **Encryption**: Sensitive data is encrypted using cryptography
- **Local Storage**: All results stored locally
- **No Data Transmission**: No data sent to external servers
- **Secure Defaults**: Conservative scanning parameters

## 🐛 Troubleshooting

### Common Issues

#### Network Scanner Issues

```bash
# Permission denied for raw sockets
sudo python3 CA_network_scan.py --target 192.168.1.1

# Nmap not found
sudo apt-get install nmap

# ARP scan failed
sudo apt-get install arp-scan
```

#### Web Scanner Issues

```bash
# SSL certificate errors
python3 CA_web_vuln.py --target https://example.com --verify-ssl false

# Timeout issues
python3 CA_web_vuln.py --target http://slow-site.com --timeout 30
```

#### Error Manager Issues

```bash
# Permission denied for log files
sudo ./CA_error_manager.sh /var/log/syslog

# Python consumer not found
python3 CA_error_consumer.py logs.txt
```

### Debug Mode

```bash
# Enable verbose output
python3 CA_web_vuln.py --target 192.168.1.100 --verbose
python3 CA_network_scan.py --target 192.168.1.1 --debug
./CA_error_manager.sh logs.txt --verbose
```

## 📈 Performance Optimization

### Network Scanner

- **Concurrent Scanning**: Uses ThreadPoolExecutor for faster scans
- **Port Range Optimization**: Focus on common ports first
- **Service Detection**: Parallel service identification
- **Memory Management**: Efficient data structures

### Web Scanner

- **Session Reuse**: Maintains HTTP sessions for efficiency
- **Concurrent Requests**: Parallel vulnerability testing
- **Smart Timeouts**: Adaptive timeout management
- **Progress Tracking**: Real-time progress indicators

### Error Manager

- **Streaming Processing**: Processes large log files efficiently
- **Pattern Caching**: Caches compiled regex patterns
- **Memory Optimization**: Minimal memory footprint
- **Parallel Analysis**: Concurrent log file processing

## 🔄 Integration Examples

### Chaining Tools

```bash
# Network scan → Web scan → Error analysis
python3 CA_network_scan.py --target 192.168.1.0/24 --ports 80,443
python3 CA_web_vuln.py --target 192.168.1.100 --scan-type all
./CA_error_manager.sh /var/log/syslog --consumer
```

### SSH Integration

```bash
# Remote network scanning
ssh user@server "python3 CA_network_scan.py --target 192.168.1.1"

# Remote error analysis
./CA_error_manager.sh logs.txt --ssh user@server
```

### Automation Scripts

```bash
#!/bin/bash
# Automated security assessment
python3 CA_network_scan.py --target $1 --auto
python3 CA_web_vuln.py --target $1 --auto
./CA_error_manager.sh /var/log/syslog --auto
```

### Future Enhancements

- **GUI Interface**: Graphical user interface
- **Database Integration**: Results storage and analysis
- **API Support**: RESTful API for tool integration
- **Cloud Integration**: Cloud-based scanning capabilities
- **Advanced Reporting**: Enhanced reporting and visualization
- **Machine Learning**: AI-powered vulnerability detection

## 👥 Contributing

This is a course assignment project. For questions or issues, please contact the author or course instructor.
