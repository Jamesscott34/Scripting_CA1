# CA Assignment - Secure Programming and Scripting

**Author:** SBA2400 James Scott
**Course:** Secure Programming and Scripting
**Assignment:** CA1 - Security Assessment Tools

## ⚡ Quick Setup

Get started in 3 simple steps:

### Step 1: Install Dependencies

**Windows (WSL/Git Bash):**

```bash
# Python dependencies
pip install -r CA_requirements.txt

# System tools (if using WSL/Linux)
sudo apt-get update
sudo apt-get install nmap arp-scan curl wget jq grep bash
```

**Linux/Mac:**

```bash
pip install -r CA_requirements.txt
sudo apt-get install nmap arp-scan curl wget jq grep  # Linux
# or
brew install nmap curl wget jq grep  # Mac
```

### Step 2: Make Scripts Executable (Linux/Mac/WSL)

```bash
chmod +x CA_error_manager.sh
```

### Step 3: Run Your First Scan

```bash
# Web Vulnerability Scanner
python3 CA_web_vuln.py --auto --test

# Network Scanner
python3 CA_network_scan.py --auto --test

# Error Manager (process log files)
wsl bash CA_error_manager.sh logs.txt  # Windows
# or
./CA_error_manager.sh logs.txt  # Linux/Mac/WSL
```

### Quick Test

Verify everything works:

```bash
# Test web scanner
python3 CA_web_vuln.py --target http://localhost:8080

# Test network scanner
python3 CA_network_scan.py --target 127.0.0.1

# Test error manager
wsl bash CA_error_manager.sh logs.txt
```

**That's it!** You're ready to start scanning. For detailed usage, see the sections below.

---

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

## Overview

This repository contains three comprehensive security assessment tools developed for the CA assignment:

1. **CA_web_vuln.py** - Web Vulnerability Scanner
2. **CA_network_scan.py** - Network Scanner
3. **CA_error_manager.sh** - System Error Manager

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
│   ├── archives/               # Archived old reports
│   ├── comparisons/            # Report comparison JSON files
│   ├── csv/                    # CSV reports
│   ├── json/                   # Main JSON reports
│   │   └── advanced/           # Advanced analysis JSON reports
│   └── text/                   # Alert summaries and comparison summaries
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
- **Security Threat Detection**: SQL injection, XSS, CSRF, command injection, path traversal, and more
- **Authentication Security**: Failed login attempts, password policy violations, account lockouts
- **Advanced Security Patterns**: Certificate issues, session hijacking, DoS attacks, RCE, XXE, SSRF, IDOR
- **Service Identification**: 20+ service types (handled by Python consumer)
- **Automated Reporting**: JSON, CSV, and text formats
- **SSH Integration**: Remote log processing with automatic result transfer
- **Report Comparison**: Compare current and previous reports to identify persistent issues
- **Auto-Archiving**: Automatically archives old reports when new scan of same file is processed
- **Python Consumer Integration**: Advanced analysis with CA_error_consumer.py
- **Interactive Mode**: Guided error analysis
- **Auto Mode**: Automated comprehensive analysis

### Usage Examples

```bash
# Basic error analysis
./CA_error_manager.sh logs.txt

# Process multiple log files
./CA_error_manager.sh logcat.txt logs.txt

# Interactive mode
./CA_error_manager.sh --interactive

# Auto mode
./CA_error_manager.sh --auto

# SSH integration (downloads log, processes locally, sends results back)
./CA_error_manager.sh --ssh user@server:/var/log/syslog

# Custom output directory
./CA_error_manager.sh logs.txt --output /custom/path

# Force JSON output
./CA_error_manager.sh logs.txt --json

# Specify log format
./CA_error_manager.sh logs.txt --format auth
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

#### Main Reports (JSON/CSV)

- **Main JSON Report**: `error_reports/json/filename_dd-mm-yy_hhmm.json`
  - Contains raw error data grouped by severity (LOW, MEDIUM, HIGH, CRITICAL)
  - Includes line numbers, content, and category (security/performance/connectivity/error)
- **CSV Report**: `error_reports/csv/filename_dd-mm-yy_hhmm.csv`
  - Same data as JSON in CSV format for easy spreadsheet analysis

#### Advanced Analysis

- **Advanced JSON Report**: `error_reports/json/advanced/advanced_analysis_filename_dd-mm-yy_hhmm.json`
  - Generated by Python consumer
  - Contains statistical analysis, pattern recognition, alerts, and recommendations
- **Alert Summary**: `error_reports/text/alert_summary_filename_dd-mm.txt`
  - Human-readable summary of critical alerts and warnings

#### Report Comparison

- **Comparison JSON**: `error_reports/comparisons/comparison_filename_dd-mm-yy_hhmm.json`
  - Detailed comparison analysis between old and new reports
- **Comparison Summary**: `error_reports/text/comparison_summary_filename_dd-mm.txt`
  - Human-readable summary of report comparison (persistent, new, resolved errors)

#### Archives

- **Archived Reports**: `error_reports/archives/dd-mm-yy_filename_dd-mm-yy_hhmm.json`
  - Old reports automatically moved here when a new scan processes the same file
  - Format: `dd-mm-yy_filename_dd-mm-yy_hhmm.json`

### Report Comparison Feature

When processing a log file that was previously analyzed, the script:

1. Archives the old report (JSON, CSV, advanced JSON if exists)
2. Processes the new log file
3. Compares the new report with the archived report
4. Generates comparison analysis showing:
   - Persistent errors (appeared in both reports)
   - New errors (only in current report)
   - Resolved errors (only in previous report)
   - Severity trends and pattern changes

### Filename Format Details

All reports use the `dd-mm-yy_hhmm` date format:

- `dd-mm-yy`: Day-month-year (e.g., 02-11-25 for November 2, 2025)
- `hhmm`: Hour and minute (24-hour format, e.g., 1545 for 3:45 PM)

**Examples:**

- Main JSON: `logs_02-11-25_1545.json`
- Advanced JSON: `advanced_analysis_logs_02-11-25_1545.json`
- CSV: `logs_02-11-25_1545.csv`
- Alert Summary: `alert_summary_logs_02-11.txt`
- Comparison JSON: `comparison_logs_02-11-25_1545.json`
- Comparison Summary: `comparison_summary_logs_02-11.txt`
- Archived: `02-11-25_logs_02-11-25_1545.json`

### Workflow

```
1. Bash Script (CA_error_manager.sh)
   ├── Reads log files
   ├── Extracts errors (grep patterns)
   ├── Basic severity classification
   ├── Basic category tagging
   └── Generates JSON/CSV with raw data

2. Python Consumer (CA_error_consumer.py) - Automatic
   ├── Loads JSON report
   ├── Statistical analysis
   ├── Pattern recognition (uses bash categories)
   ├── Service identification
   ├── Alert generation
   └── Recommendations

3. Report Comparison (if archived report exists)
   ├── Python Consumer compares reports
   ├── Identifies persistent/new/resolved errors
   └── Generates comparison JSON and TXT

4. Archiving (if same file scanned again)
   └── Moves old reports to archives folder
```

## 📊 CA_error_consumer.py - Error Analysis Consumer

### Features

- **Statistical Analysis**: Error frequency, distributions, and percentages (moved from bash)
- **Pattern Recognition**: Detailed sub-pattern analysis (leverages bash categorization, adds insights)
- **Service Identification**: Automatic service identification from content (SSH, Apache, MySQL, etc.)
- **Alert Generation**: Threshold-based critical error detection
- **Recommendations**: Automated remediation suggestions based on analysis
- **Report Comparison**: Compare two JSON reports to identify trends and persistent issues
- **Interactive Mode**: Guided analysis workflow
- **Auto Mode**: Comprehensive automated analysis

### Division of Labor

**Bash Script (`CA_error_manager.sh`)** handles:

- File I/O and log extraction (grep operations)
- Basic severity classification
- Initial category tagging (security/performance/connectivity)
- Raw JSON/CSV generation
- File management and archiving

**Python Consumer (`CA_error_consumer.py`)** handles:

- Statistical calculations (distributions, percentages)
- Advanced pattern analysis and sub-patterns
- Service identification from content
- Alert generation and recommendations
- Report comparison and trend analysis

### Usage Examples

```bash
# Basic analysis (analyzes JSON report from bash script)
python3 CA_error_consumer.py error_report.json

# Save advanced analysis to JSON
python3 CA_error_consumer.py error_report.json --output advanced_analysis.json

# Generate alerts only (to stdout)
python3 CA_error_consumer.py error_report.json --alerts-only

# Compare two reports
python3 CA_error_consumer.py new_report.json --compare old_report.json

# Compare and save comparison JSON
python3 CA_error_consumer.py new_report.json --compare old_report.json --compare-output comparison.json

# Filter by severity
python3 CA_error_consumer.py error_report.json --severity-filter HIGH,CRITICAL

# Interactive mode
python3 CA_error_consumer.py --interactive

# Auto mode
python3 CA_error_consumer.py --auto
```

## 🛠️ Installation and Setup

### 1. Clone Repository

```bash
git clone https://github.com/Jamesscott34/Scripting_CA1.git
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


# SSH connection fails
# Ensure SSH key authentication is configured:
ssh-copy-id -i ~/.ssh/id_rsa_error_manager.pub user@server

# Comparison feature not working
# Ensure CA_error_consumer.py is in the same directory as CA_error_manager.sh
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

- **Streaming Processing**: Processes large log files efficiently with grep
- **Pattern Caching**: Caches compiled regex patterns
- **Memory Optimization**: Minimal memory footprint
- **Parallel Analysis**: Concurrent log file processing
- **Automatic Archiving**: Moves old reports to archives when processing same file again
- **Efficient Division**: Bash handles data extraction, Python handles analysis (no duplication)

## 🔄 Integration Examples

### SSH Integration

```bash
# Remote error analysis (downloads log, processes locally, sends results back)
./CA_error_manager.sh --ssh user@server:/var/log/syslog

# The script will:
# 1. Set up SSH key authentication (if not already configured)
# 2. Download the log file from remote server
# 3. Process it locally
# 4. Generate JSON/CSV reports and advanced analysis
# 5. Send results back to remote server at ~/checked_reports/
```

### Automation Scripts

```bash
#!/bin/bash
# Automated security assessment
python3 CA_network_scan.py --target $1 --auto
python3 CA_web_vuln.py --target $1 --auto
./CA_error_manager.sh /var/log/syslog --auto

# The error manager automatically:
# 1. Processes the log file
# 2. Generates JSON/CSV reports
# 3. Chains with Python consumer for advanced analysis
# 4. Compares with previous reports if available
# 5. Archives old reports
```
