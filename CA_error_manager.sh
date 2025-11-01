#!/bin/bash

# Enable safe mode for security
set -euo pipefail

################################################################################
# CA Error Manager Script
# Author: SBA2400 James Scott
# Description: Basic log analysis and error detection tool for CA Assignment
# 
# This script provides automated error detection, malformed entry analysis,
# and structured reporting for system logs. It supports both manual file
# processing and automated system monitoring workflows.
#
# Requirements Met:
# • Produce an automated output file that captures and handles error entries found in logs.txt
# • Accept a logs.txt input and detect malformed or invalid entry patterns
# • Chain SSH transfer and Python consumer with concrete examples
# • Include clear documentation and comments within the script
#
# Usage Examples:
#   ./CA_error_manager.sh logs.txt                    # Process specific file
#   ./CA_error_manager.sh --ssh user@host:/path/log   # Remote log processing
#   ./CA_error_manager.sh --interactive               # Interactive mode
#   ./CA_error_manager.sh                             # Auto-launches interactive mode
################################################################################

# Global configuration variables
readonly SCRIPT_NAME="CA_error_manager.sh"
readonly SCRIPT_VERSION="1.0.0"
readonly OUTPUT_DIRECTORY="error_reports"
readonly TEMPORARY_DIRECTORY="/tmp/ca_error_processing"
readonly MAXIMUM_LOG_SIZE_MB=100

# Color codes for terminal output
readonly COLOR_RED='\033[0;31m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_PURPLE='\033[0;35m'
readonly COLOR_CYAN='\033[0;36m'
readonly COLOR_WHITE='\033[1;37m'
readonly COLOR_RESET='\033[0m'

# Error severity levels
readonly SEVERITY_CRITICAL="CRITICAL"
readonly SEVERITY_HIGH="HIGH"
readonly SEVERITY_MEDIUM="MEDIUM"
readonly SEVERITY_LOW="LOW"
readonly SEVERITY_INFO="INFO"

################################################################################
# Function: display_usage_information
# Description: Shows comprehensive help information for script usage
# Parameters: None
# Returns: None (exits script)
################################################################################
display_usage_information() {
    cat << EOF
${COLOR_CYAN}CA Error Manager Script v${SCRIPT_VERSION}${COLOR_RESET}

${COLOR_WHITE}DESCRIPTION:${COLOR_RESET}
    Basic log analysis tool for system error detection and reporting.
    Processes log files to identify errors, malformed entries, and security issues.

${COLOR_WHITE}REQUIREMENTS MET:${COLOR_RESET}
    • Automated output file capturing error entries from logs.txt
    • Malformed entry pattern detection
    • SSH transfer and Python consumer chaining
    • Clear documentation and comments

${COLOR_WHITE}USAGE:${COLOR_RESET}
    $SCRIPT_NAME [OPTIONS] [LOG_FILE_PATH]

${COLOR_WHITE}OPTIONS:${COLOR_RESET}
    -h, --help              Display this help information
    -v, --version           Show script version information
    -s, --ssh HOST:PATH     Process remote log file via SSH
    -o, --output DIR        Specify custom output directory (default: $OUTPUT_DIRECTORY)
    -f, --format FORMAT     Specify log format (syslog, auth, kern, apache, nginx, custom)
    -j, --json              Force JSON output format
    --verbose               Enable verbose output mode
    --quiet                 Suppress non-essential output
    --interactive           Run in interactive mode

${COLOR_WHITE}EXAMPLES:${COLOR_RESET}
    # Process local log file
    $SCRIPT_NAME logs.txt

    # Process remote log via SSH
    $SCRIPT_NAME --ssh user@server:/var/log/syslog

    # Custom output with JSON format
    $SCRIPT_NAME --output /tmp/reports --json logs.txt

    # Interactive mode
    $SCRIPT_NAME --interactive

${COLOR_WHITE}SUPPORTED LOG TYPES:${COLOR_RESET}
    • System logs: /var/log/syslog, /var/log/messages, /var/log/system.log
    • Authentication: /var/log/auth.log, /var/log/secure, /var/log/wtmp, /var/log/lastlog
    • Kernel: /var/log/kern.log, /var/log/dmesg, /var/log/boot.log
    • Web servers: /var/log/apache2/, /var/log/nginx/, /var/log/httpd/
    • Database: /var/log/mysql/, /var/log/postgresql/, /var/log/mongodb/
    • Mail services: /var/log/mail.log, /var/log/postfix/, /var/log/dovecot/
    • DNS services: /var/log/bind/, /var/log/named/
    • DHCP services: /var/log/dhcpd.log, /var/log/isc-dhcp-server/
    • VPN services: /var/log/openvpn/, /var/log/strongswan/
    • Firewall: /var/log/ufw.log, /var/log/iptables.log, /var/log/firewalld/
    • Package management: /var/log/apt/, /var/log/yum.log, /var/log/dpkg.log
    • Cron jobs: /var/log/cron, /var/log/cron.log
    • System services: /var/log/systemd/, /var/log/journal/
    • Hardware: /var/log/hardware.log, /var/log/hp/
    • Network: /var/log/network.log, /var/log/wireless/
    • Security: /var/log/audit/, /var/log/faillog, /var/log/tallylog
    • Application: Custom application logs in /var/log/
    • Container logs: /var/log/containers/, /var/log/pods/
    • Cloud services: /var/log/cloud-init/, /var/log/amazon/, /var/log/azure/
    • Monitoring: /var/log/prometheus/, /var/log/grafana/, /var/log/elasticsearch/
    • Message brokers: /var/log/rabbitmq/, /var/log/kafka/, /var/log/redis/
    • CI/CD: /var/log/jenkins/, /var/log/gitlab/, /var/log/buildbot/
    • Version control: /var/log/git/, /var/log/svn/
    • Backup services: /var/log/backup/, /var/log/rsync/
    • Print services: /var/log/cups/, /var/log/samba/
    • Virtualization: /var/log/libvirt/, /var/log/vmware/, /var/log/xen/
    • All other /var/log/ files and subdirectories

${COLOR_WHITE}OUTPUT FORMATS:${COLOR_RESET}
    • JSON: Structured data for programmatic processing
    • Text: Human-readable summary reports
    • CSV: Tabular data for spreadsheet analysis

${COLOR_WHITE}SSH AND PYTHON CONSUMER CHAINING:${COLOR_RESET}
    The script demonstrates how to chain SSH transfers with Python consumer processing:
    
    1. SSH Transfer: Downloads log file from remote server
    2. Local Processing: Analyzes the log file locally
    3. Python Consumer: Runs advanced analysis using CA_error_consumer.py
    4. Result Integration: Combines results from both processes
    
    Example chain:
    ./CA_error_manager.sh --ssh admin@server:/var/log/syslog
    → Downloads syslog via SSH
    → Processes locally with Bash script
    → Chains to Python consumer for advanced analysis
    → Exports combined results

EOF
    exit 0
}

################################################################################
# Function: log_message_with_timestamp
# Description: Logs messages with timestamp and severity level
# Parameters: $1 - Message text, $2 - Severity level (optional)
# Returns: None
################################################################################
log_message_with_timestamp() {
    local message_content="$1"
    local severity_level="${2:-INFO}"
    local current_timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local color_code=""
    
    # Assign color based on severity
    case "$severity_level" in
        "CRITICAL") color_code="$COLOR_RED" ;;
        "HIGH") color_code="$COLOR_RED" ;;
        "MEDIUM") color_code="$COLOR_YELLOW" ;;
        "LOW") color_code="$COLOR_CYAN" ;;
        "INFO") color_code="$COLOR_GREEN" ;;
        *) color_code="$COLOR_WHITE" ;;
    esac
    
    echo -e "${color_code}[$current_timestamp] [$severity_level] $message_content${COLOR_RESET}" >&2
}

################################################################################
# Function: validate_file_existence_and_permissions
# Description: Checks if file exists and is readable
# Parameters: $1 - File path to validate
# Returns: 0 if valid, 1 if invalid
################################################################################
validate_file_existence_and_permissions() {
    local file_path="$1"
    
    if [[ ! -f "$file_path" ]]; then
        log_message_with_timestamp "File does not exist: $file_path" "$SEVERITY_CRITICAL"
        return 1
    fi
    
    if [[ ! -r "$file_path" ]]; then
        log_message_with_timestamp "File is not readable: $file_path" "$SEVERITY_HIGH"
        return 1
    fi
    
    # Check file size to prevent memory issues
    local file_size_mb=$(du -m "$file_path" | cut -f1)
    if [[ $file_size_mb -gt $MAXIMUM_LOG_SIZE_MB ]]; then
        log_message_with_timestamp "File size ($file_size_mb MB) exceeds maximum ($MAXIMUM_LOG_SIZE_MB MB)" "$SEVERITY_MEDIUM"
        log_message_with_timestamp "Consider using tail or head to process file in chunks" "$SEVERITY_INFO"
    fi
    
    return 0
}

################################################################################
# Function: create_output_directory_structure
# Description: Creates necessary directories for output files
# Parameters: $1 - Base output directory path
# Returns: None
################################################################################
create_output_directory_structure() {
    local base_directory="$1"
    
    if [[ ! -d "$base_directory" ]]; then
        mkdir -p "$base_directory" || {
            log_message_with_timestamp "Failed to create output directory: $base_directory" "$SEVERITY_CRITICAL"
            exit 1
        }
        chmod 755 "$base_directory"
    fi
    
    # Create subdirectories for different output types with proper permissions
    mkdir -p "$base_directory"/{json,text,csv,archives} 2>/dev/null
    
    # Ensure the directories exist and are writable with secure permissions
    for subdir in json text csv archives; do
        if [[ ! -d "$base_directory/$subdir" ]]; then
            mkdir -p "$base_directory/$subdir" || {
                log_message_with_timestamp "Failed to create subdirectory: $base_directory/$subdir" "$SEVERITY_CRITICAL"
                exit 1
            }
        fi
        chmod 755 "$base_directory/$subdir"
    done
    
    log_message_with_timestamp "Output directory structure created with secure permissions: $base_directory" "$SEVERITY_INFO"
}

################################################################################
# Function: detect_log_format_automatically
# Description: Automatically detects log file format based on content analysis
# Parameters: $1 - File path to analyze
# Returns: Detected format string
################################################################################
detect_log_format_automatically() {
    local file_path="$1"
    local sample_lines=$(head -n 50 "$file_path" 2>/dev/null)
    
    # Syslog format detection
    if echo "$sample_lines" | grep -qE "^[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"; then
        echo "syslog"
        return 0
    fi
    
    # Apache access log detection
    if echo "$sample_lines" | grep -qE '^\d+\.\d+\.\d+\.\d+\s+.*\[.*\]\s+".*"\s+\d+\s+\d+'; then
        echo "apache_access"
        return 0
    fi
    
    # Apache error log detection
    if echo "$sample_lines" | grep -qE '^\[.*\]\s+\[.*\]\s+\[.*\]'; then
        echo "apache_error"
        return 0
    fi
    
    # Nginx log detection
    if echo "$sample_lines" | grep -qE '^\d+\.\d+\.\d+\.\d+\s+.*\s+\[.*\]\s+".*"\s+\d+\s+\d+'; then
        echo "nginx"
        return 0
    fi
    
    # MySQL error log detection
    if echo "$sample_lines" | grep -qE '^\d{6}\s+\d{1,2}:\d{2}:\d{2}'; then
        echo "mysql"
        return 0
    fi
    
    # Authentication log detection
    if echo "$sample_lines" | grep -qE "(sshd|sudo|su|login|authentication)"; then
        echo "auth"
        return 0
    fi
    
    # Default to custom format
    echo "custom"
}

################################################################################
# Function: extract_error_patterns_from_log
# Description: Extracts error patterns based on detected log format
# Parameters: $1 - File path, $2 - Log format type
# Returns: None (writes to global variables)
################################################################################
extract_error_patterns_from_log() {
    local file_path="$1"
    local log_format="$2"
    local error_patterns_file="$TEMPORARY_DIRECTORY/error_patterns.txt"
    local malformed_entries_file="$TEMPORARY_DIRECTORY/malformed_entries.txt"
    local security_issues_file="$TEMPORARY_DIRECTORY/security_issues.txt"
    local performance_issues_file="$TEMPORARY_DIRECTORY/performance_issues.txt"
    local connectivity_issues_file="$TEMPORARY_DIRECTORY/connectivity_issues.txt"
    
    # Initialize temporary files
    > "$error_patterns_file"
    > "$malformed_entries_file"
    > "$security_issues_file"
    > "$performance_issues_file"
    > "$connectivity_issues_file"
    
    log_message_with_timestamp "Extracting comprehensive error patterns for format: $log_format" "$SEVERITY_INFO"
    
    # Universal error patterns (applies to all log formats)
    local universal_error_patterns=(
        "error|Error|ERROR|failed|Failed|FAILED|critical|Critical|CRITICAL|warning|Warning|WARNING"
        "exception|Exception|EXCEPTION|fatal|Fatal|FATAL|panic|Panic|PANIC"
        "timeout|Timeout|TIMEOUT|expired|Expired|EXPIRED|abort|Abort|ABORT"
        "denied|Denied|DENIED|refused|Refused|REFUSED|rejected|Rejected|REJECTED"
        "invalid|Invalid|INVALID|corrupt|Corrupt|CORRUPT|damaged|Damaged|DAMAGED"
        "missing|Missing|MISSING|not found|Not Found|NOT FOUND|unavailable|Unavailable|UNAVAILABLE"
        "insufficient|Insufficient|INSUFFICIENT|out of|Out Of|OUT OF|exceeded|Exceeded|EXCEEDED"
        "mismatch|Mismatch|MISMATCH|conflict|Conflict|CONFLICT|collision|Collision|COLLISION"
        "overflow|Overflow|OVERFLOW|underflow|Underflow|UNDERFLOW|leak|Leak|LEAK"
        "hang|Hang|HANG|stuck|Stuck|STUCK|frozen|Frozen|FROZEN|deadlock|Deadlock|DEADLOCK"
    )
    
    # Security-specific patterns
    local security_patterns=(
        "authentication failure|Authentication Failure|AUTHENTICATION FAILURE"
        "permission denied|Permission Denied|PERMISSION DENIED|access denied|Access Denied|ACCESS DENIED"
        "invalid user|Invalid User|INVALID USER|failed password|Failed Password|FAILED PASSWORD"
        "connection refused|Connection Refused|CONNECTION REFUSED|login failed|Login Failed|LOGIN FAILED"
        "intrusion|Intrusion|INTRUSION|attack|Attack|ATTACK|exploit|Exploit|EXPLOIT"
        "malware|Malware|MALWARE|virus|Virus|VIRUS|trojan|Trojan|TROJAN"
        "firewall|Firewall|FIREWALL|blocked|Blocked|BLOCKED|filtered|Filtered|FILTERED"
        "suspicious|Suspicious|SUSPICIOUS|anomaly|Anomaly|ANOMALY|breach|Breach|BREACH"
        "unauthorized|Unauthorized|UNAUTHORIZED|forbidden|Forbidden|FORBIDDEN"
        "brute force|Brute Force|BRUTE FORCE|dictionary|Dictionary|DICTIONARY"
    )
    
    # Performance-specific patterns
    local performance_patterns=(
        "slow|Slow|SLOW|performance|Performance|PERFORMANCE|latency|Latency|LATENCY"
        "high cpu|High CPU|HIGH CPU|cpu usage|CPU Usage|CPU USAGE"
        "high memory|High Memory|HIGH MEMORY|memory usage|Memory Usage|MEMORY USAGE"
        "disk full|Disk Full|DISK FULL|disk space|Disk Space|DISK SPACE"
        "load average|Load Average|LOAD AVERAGE|system load|System Load|SYSTEM LOAD"
        "queue|Queue|QUEUE|backlog|Backlog|BACKLOG|bottleneck|Bottleneck|BOTTLENECK"
        "throttle|Throttle|THROTTLE|rate limit|Rate Limit|RATE LIMIT"
        "resource|Resource|RESOURCE|capacity|Capacity|CAPACITY|utilization|Utilization|UTILIZATION"
    )
    
    # Connectivity-specific patterns
    local connectivity_patterns=(
        "network|Network|NETWORK|connection|Connection|CONNECTION|connect|Connect|CONNECT"
        "timeout|Timeout|TIMEOUT|unreachable|Unreachable|UNREACHABLE|unavailable|Unavailable|UNAVAILABLE"
        "dns|DNS|resolution|Resolution|RESOLUTION|resolve|Resolve|RESOLVE"
        "socket|Socket|SOCKET|port|Port|PORT|bind|Bind|BIND|listen|Listen|LISTEN"
        "proxy|Proxy|PROXY|gateway|Gateway|GATEWAY|router|Router|ROUTER"
        "packet|Packet|PACKET|drop|Drop|DROP|loss|Loss|LOSS"
        "bandwidth|Bandwidth|BANDWIDTH|throughput|Throughput|THROUGHPUT"
    )
    
    # Combine all patterns for comprehensive error detection
    local combined_error_pattern=$(IFS='|'; echo "${universal_error_patterns[*]}")
    local combined_security_pattern=$(IFS='|'; echo "${security_patterns[*]}")
    local combined_performance_pattern=$(IFS='|'; echo "${performance_patterns[*]}")
    local combined_connectivity_pattern=$(IFS='|'; echo "${connectivity_patterns[*]}")
    
    case "$log_format" in
        "syslog")
            # Comprehensive syslog error patterns
            grep -E "($combined_error_pattern)" "$file_path" > "$error_patterns_file" 2>/dev/null || true
            grep -E "($combined_security_pattern)" "$file_path" > "$security_issues_file" 2>/dev/null || true
            grep -E "($combined_performance_pattern)" "$file_path" > "$performance_issues_file" 2>/dev/null || true
            grep -E "($combined_connectivity_pattern)" "$file_path" > "$connectivity_issues_file" 2>/dev/null || true
            
            # Malformed syslog entries (missing timestamp, invalid format, corrupted data)
            grep -vE "^[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}" "$file_path" | head -n 100 > "$malformed_entries_file" 2>/dev/null || true
            ;;
        "auth")
            # Comprehensive authentication error patterns
            grep -E "($combined_error_pattern|$combined_security_pattern)" "$file_path" > "$error_patterns_file" 2>/dev/null || true
            grep -E "(authentication|Authentication|AUTHENTICATION|login|Login|LOGIN|password|Password|PASSWORD)" "$file_path" > "$security_issues_file" 2>/dev/null || true
            
            # Malformed auth entries
            grep -vE "^[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}.*(sshd|sudo|su|login|pam|auth)" "$file_path" | head -n 100 > "$malformed_entries_file" 2>/dev/null || true
            ;;
        "apache_error")
            # Comprehensive Apache error patterns
            grep -E "($combined_error_pattern)" "$file_path" > "$error_patterns_file" 2>/dev/null || true
            grep -E "(emerg|alert|crit|error|warn|notice|info|debug)" "$file_path" >> "$error_patterns_file" 2>/dev/null || true
            grep -E "($combined_security_pattern)" "$file_path" > "$security_issues_file" 2>/dev/null || true
            grep -E "($combined_performance_pattern)" "$file_path" > "$performance_issues_file" 2>/dev/null || true
            
            # Malformed Apache error entries
            grep -vE "^\[.*\]\s+\[.*\]\s+\[.*\]" "$file_path" | head -n 100 > "$malformed_entries_file" 2>/dev/null || true
            ;;
        "nginx")
            # Comprehensive Nginx error patterns
            grep -E "($combined_error_pattern)" "$file_path" > "$error_patterns_file" 2>/dev/null || true
            grep -E "(emerg|alert|crit|error|warn|notice|info|debug)" "$file_path" >> "$error_patterns_file" 2>/dev/null || true
            grep -E "($combined_security_pattern)" "$file_path" > "$security_issues_file" 2>/dev/null || true
            grep -E "($combined_performance_pattern)" "$file_path" > "$performance_issues_file" 2>/dev/null || true
            
            # Malformed Nginx entries
            grep -vE '^\d+\.\d+\.\d+\.\d+\s+.*\s+\[.*\]\s+".*"' "$file_path" | head -n 100 > "$malformed_entries_file" 2>/dev/null || true
            ;;
        "mysql")
            # Comprehensive MySQL error patterns
            grep -E "($combined_error_pattern)" "$file_path" > "$error_patterns_file" 2>/dev/null || true
            grep -E "(error|Error|ERROR|warning|Warning|WARNING|failed|Failed|FAILED)" "$file_path" >> "$error_patterns_file" 2>/dev/null || true
            grep -E "(deadlock|Deadlock|DEADLOCK|lock|Lock|LOCK|transaction|Transaction|TRANSACTION)" "$file_path" >> "$error_patterns_file" 2>/dev/null || true
            
            # Malformed MySQL entries
            grep -vE '^\d{6}\s+\d{1,2}:\d{2}:\d{2}' "$file_path" | head -n 100 > "$malformed_entries_file" 2>/dev/null || true
            ;;
        "kernel")
            # Comprehensive kernel error patterns
            grep -E "($combined_error_pattern)" "$file_path" > "$error_patterns_file" 2>/dev/null || true
            grep -E "(panic|Panic|PANIC|oops|Oops|OOPS|segfault|Segfault|SEGFAULT)" "$file_path" >> "$error_patterns_file" 2>/dev/null || true
            grep -E "(hardware|Hardware|HARDWARE|driver|Driver|DRIVER|firmware|Firmware|FIRMWARE)" "$file_path" >> "$error_patterns_file" 2>/dev/null || true
            
            # Malformed kernel entries
            grep -vE "^[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}.*kernel" "$file_path" | head -n 100 > "$malformed_entries_file" 2>/dev/null || true
            ;;
        "systemd")
            # Comprehensive systemd error patterns
            grep -E "($combined_error_pattern)" "$file_path" > "$error_patterns_file" 2>/dev/null || true
            grep -E "(failed|Failed|FAILED|timeout|Timeout|TIMEOUT|dependency|Dependency|DEPENDENCY)" "$file_path" >> "$error_patterns_file" 2>/dev/null || true
            grep -E "(service|Service|SERVICE|unit|Unit|UNIT|daemon|Daemon|DAEMON)" "$file_path" >> "$error_patterns_file" 2>/dev/null || true
            
            # Malformed systemd entries
            grep -vE "^[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}.*systemd" "$file_path" | head -n 100 > "$malformed_entries_file" 2>/dev/null || true
            ;;
        *)
            # Generic comprehensive error patterns for custom formats
            grep -E "($combined_error_pattern)" "$file_path" > "$error_patterns_file" 2>/dev/null || true
            grep -E "($combined_security_pattern)" "$file_path" > "$security_issues_file" 2>/dev/null || true
            grep -E "($combined_performance_pattern)" "$file_path" > "$performance_issues_file" 2>/dev/null || true
            grep -E "($combined_connectivity_pattern)" "$file_path" > "$connectivity_issues_file" 2>/dev/null || true
            
            # Generic malformed entry detection (lines that don't match common patterns)
            grep -vE "(^[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|^\d+\.\d+\.\d+\.\d+|^\[.*\]|^\d{6}\s+\d{1,2}:\d{2}:\d{2}|^[0-9]{4}-[0-9]{2}-[0-9]{2})" "$file_path" | head -n 100 > "$malformed_entries_file" 2>/dev/null || true
            ;;
    esac
    
    # Count results from all files
    error_count=$(wc -l < "$error_patterns_file" 2>/dev/null | tr -d ' \n\r' || echo "0")
    malformed_count=$(wc -l < "$malformed_entries_file" 2>/dev/null | tr -d ' \n\r' || echo "0")
    security_count=$(wc -l < "$security_issues_file" 2>/dev/null | tr -d ' \n\r' || echo "0")
    performance_count=$(wc -l < "$performance_issues_file" 2>/dev/null | tr -d ' \n\r' || echo "0")
    connectivity_count=$(wc -l < "$connectivity_issues_file" 2>/dev/null | tr -d ' \n\r' || echo "0")
    
    log_message_with_timestamp "Found $error_count error entries, $malformed_count malformed entries" "$SEVERITY_INFO"
    log_message_with_timestamp "Security issues: $security_count, Performance issues: $performance_count, Connectivity issues: $connectivity_count" "$SEVERITY_INFO"
}

################################################################################
# Function: generate_csv_error_report
# Description: Generates CSV report from error analysis
# Parameters: $1 - Output file path, $2 - Source log file path, $3 - Log format
# Returns: None
################################################################################
generate_csv_error_report() {
    local output_file="$1"
    local source_file="$2"
    local log_format="$3"
    local error_patterns_file="$TEMPORARY_DIRECTORY/error_patterns.txt"
    local malformed_entries_file="$TEMPORARY_DIRECTORY/malformed_entries.txt"
    
    log_message_with_timestamp "Generating CSV error report: $output_file" "$SEVERITY_INFO"
    
    # Create CSV header
    cat > "$output_file" << EOF
Line_Number,Severity,Category,Content,Timestamp,Source_File,Log_Format
EOF
    
    # Add error entries to CSV
    local line_number=0
    while IFS= read -r line; do
        ((line_number++))
        local severity=$(classify_error_severity "$line")
        local category="error"
        
        # Escape CSV special characters
        local escaped_line=$(echo "$line" | sed 's/"/""/g' | tr -d '\n\r')
        
        # Add timestamp if available
        local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
        
        cat >> "$output_file" << EOF
$line_number,"$severity","$category","$escaped_line","$timestamp","$source_file","$log_format"
EOF
    done < "$error_patterns_file" 2>/dev/null || true
    
    # Add malformed entries to CSV
    while IFS= read -r line; do
        ((line_number++))
        local issue_type=$(classify_malformed_entry "$line" "$log_format")
        local escaped_line=$(echo "$line" | sed 's/"/""/g' | tr -d '\n\r')
        local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
        
        cat >> "$output_file" << EOF
$line_number,"MALFORMED","$issue_type","$escaped_line","$timestamp","$source_file","$log_format"
EOF
    done < "$malformed_entries_file" 2>/dev/null || true
    
    # Set proper permissions
    chmod 644 "$output_file"
    
    if [[ -f "$output_file" ]]; then
        log_message_with_timestamp "CSV report generated: $output_file" "$SEVERITY_INFO"
    else
        log_message_with_timestamp "Failed to generate CSV report: $output_file" "$SEVERITY_HIGH"
        return 1
    fi
}

################################################################################
# Description: Generates structured JSON report from error analysis
# Parameters: $1 - Output file path, $2 - Source log file path, $3 - Log format
# Returns: None
################################################################################
generate_json_error_report() {
    local output_file="$1"
    local source_file="$2"
    local log_format="$3"
    local error_patterns_file="$TEMPORARY_DIRECTORY/error_patterns.txt"
    local malformed_entries_file="$TEMPORARY_DIRECTORY/malformed_entries.txt"
    
    local current_timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local file_size=$(stat -f%z "$source_file" 2>/dev/null || stat -c%s "$source_file" 2>/dev/null || echo "0")
    local error_count=$(wc -l < "$error_patterns_file" 2>/dev/null || echo "0")
    local malformed_count=$(wc -l < "$malformed_entries_file" 2>/dev/null || echo "0")
    
    # Count additional issue categories
    local security_count=$(wc -l < "$TEMPORARY_DIRECTORY/security_issues.txt" 2>/dev/null | tr -d ' \n\r' || echo "0")
    local performance_count=$(wc -l < "$TEMPORARY_DIRECTORY/performance_issues.txt" 2>/dev/null | tr -d ' \n\r' || echo "0")
    local connectivity_count=$(wc -l < "$TEMPORARY_DIRECTORY/connectivity_issues.txt" 2>/dev/null | tr -d ' \n\r' || echo "0")
    
    # Calculate severity distribution counts
    local critical_count=$(grep -c -i "critical\|fatal\|emergency\|panic" "$error_patterns_file" 2>/dev/null || echo "0")
    critical_count=$(echo "$critical_count" | tr -d '\n\r' | sed 's/[^0-9]//g')
    critical_count=${critical_count:-0}
    critical_count=$((critical_count + 0))  # Force numeric conversion
    
    local high_count=$(grep -c -i "error\|failed\|denied\|timeout\|abort" "$error_patterns_file" 2>/dev/null || echo "0")
    high_count=$(echo "$high_count" | tr -d '\n\r' | sed 's/[^0-9]//g')
    high_count=${high_count:-0}
    high_count=$((high_count + 0))  # Force numeric conversion
    
    local medium_count=$(grep -c -i "warning\|retry\|slow\|performance" "$error_patterns_file" 2>/dev/null || echo "0")
    medium_count=$(echo "$medium_count" | tr -d '\n\r' | sed 's/[^0-9]//g')
    medium_count=${medium_count:-0}
    medium_count=$((medium_count + 0))  # Force numeric conversion
    
    local low_count=$(grep -c -i "notice\|info\|debug" "$error_patterns_file" 2>/dev/null || echo "0")
    low_count=$(echo "$low_count" | tr -d '\n\r' | sed 's/[^0-9]//g')
    low_count=${low_count:-0}
    low_count=$((low_count + 0))  # Force numeric conversion
    
    # Create JSON report structure
    cat > "$output_file" << EOF
{
  "error_analysis_report": {
    "metadata": {
      "script_name": "$SCRIPT_NAME",
      "script_version": "$SCRIPT_VERSION",
      "analysis_timestamp": "$current_timestamp",
      "source_file": "$source_file",
      "source_file_size_bytes": $file_size,
      "detected_log_format": "$log_format",
      "analysis_duration_seconds": "$SECONDS"
    },
    "summary_statistics": {
      "total_error_entries": $error_count,
      "total_malformed_entries": $malformed_count,
      "security_issues": $security_count,
      "performance_issues": $performance_count,
      "connectivity_issues": $connectivity_count,
      "error_severity_distribution": {
        "critical": $critical_count,
        "high": $high_count,
        "medium": $medium_count,
        "low": $low_count
      },
      "issue_categories": {
        "security": {
          "count": $security_count,
          "types": ["authentication_failure", "permission_denied", "intrusion_attempt", "malware_detection", "firewall_block"]
        },
        "performance": {
          "count": $performance_count,
          "types": ["high_cpu", "memory_usage", "disk_space", "slow_response", "resource_exhaustion"]
        },
        "connectivity": {
          "count": $connectivity_count,
          "types": ["network_timeout", "dns_failure", "connection_refused", "packet_loss", "service_unavailable"]
        }
      }
    },
    "error_entries": [
EOF

    # Add error entries to JSON
    line_number=0
    while IFS= read -r line; do
        if [[ $line_number -gt 0 ]]; then
            echo "," >> "$output_file"
        fi
        # Escape JSON special characters and remove control characters
        escaped_line=$(echo "$line" | tr -d '\000-\037' | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\r/\\r/g; s/\n/\\n/g')
        cat >> "$output_file" << EOF
      {
        "line_number": $((line_number + 1)),
        "content": "$escaped_line",
        "severity": "$(classify_error_severity "$line")"
      }
EOF
        ((line_number++))
    done < "$error_patterns_file" 2>/dev/null || true
    
    cat >> "$output_file" << EOF
    ],
    "malformed_entries": [
EOF

    # Add malformed entries to JSON
    line_number=0
    while IFS= read -r line; do
        if [[ $line_number -gt 0 ]]; then
            echo "," >> "$output_file"
        fi
        # Escape JSON special characters and remove control characters
        escaped_line=$(echo "$line" | tr -d '\000-\037' | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\r/\\r/g; s/\n/\\n/g')
        cat >> "$output_file" << EOF
      {
        "line_number": $((line_number + 1)),
        "content": "$escaped_line",
        "issue_type": "$(classify_malformed_entry "$line" "$log_format")"
      }
EOF
        ((line_number++))
    done < "$malformed_entries_file" 2>/dev/null || true
    
    # Add security issues to JSON
    cat >> "$output_file" << EOF
    ],
    "security_issues": [
EOF

    line_number=0
    while IFS= read -r line; do
        if [[ $line_number -gt 0 ]]; then
            echo "," >> "$output_file"
        fi
        escaped_line=$(echo "$line" | tr -d '\000-\037' | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\r/\\r/g; s/\n/\\n/g')
        cat >> "$output_file" << EOF
      {
        "line_number": $((line_number + 1)),
        "content": "$escaped_line",
        "severity": "$(classify_error_severity "$line")",
        "category": "security"
      }
EOF
        ((line_number++))
    done < "$TEMPORARY_DIRECTORY/security_issues.txt" 2>/dev/null || true
    
    # Add performance issues to JSON
    cat >> "$output_file" << EOF
    ],
    "performance_issues": [
EOF

    line_number=0
    while IFS= read -r line; do
        if [[ $line_number -gt 0 ]]; then
            echo "," >> "$output_file"
        fi
        escaped_line=$(echo "$line" | tr -d '\000-\037' | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\r/\\r/g; s/\n/\\n/g')
        cat >> "$output_file" << EOF
      {
        "line_number": $((line_number + 1)),
        "content": "$escaped_line",
        "severity": "$(classify_error_severity "$line")",
        "category": "performance"
      }
EOF
        ((line_number++))
    done < "$TEMPORARY_DIRECTORY/performance_issues.txt" 2>/dev/null || true
    
    # Add connectivity issues to JSON
    cat >> "$output_file" << EOF
    ],
    "connectivity_issues": [
EOF

    line_number=0
    while IFS= read -r line; do
        if [[ $line_number -gt 0 ]]; then
            echo "," >> "$output_file"
        fi
        escaped_line=$(echo "$line" | tr -d '\000-\037' | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\r/\\r/g; s/\n/\\n/g')
        cat >> "$output_file" << EOF
      {
        "line_number": $((line_number + 1)),
        "content": "$escaped_line",
        "severity": "$(classify_error_severity "$line")",
        "category": "connectivity"
      }
EOF
        ((line_number++))
    done < "$TEMPORARY_DIRECTORY/connectivity_issues.txt" 2>/dev/null || true
    
    cat >> "$output_file" << EOF
    ],
    "recommendations": [
      $(generate_recommendations_json "$error_count" "$malformed_count" "$log_format" "$security_count" "$performance_count" "$connectivity_count")
    ]
  }
}
EOF

    if [[ -f "$output_file" ]]; then
        chmod 644 "$output_file"
        log_message_with_timestamp "JSON report generated: $output_file" "$SEVERITY_INFO"
    else
        log_message_with_timestamp "Failed to generate JSON report: $output_file" "$SEVERITY_HIGH"
        return 1
    fi
}

################################################################################
# Function: classify_error_severity
# Description: Classifies error severity based on content analysis
# Parameters: $1 - Error line content
# Returns: Severity level string
################################################################################
classify_error_severity() {
    local line_content="$1"
    local lower_line=$(echo "$line_content" | tr '[:upper:]' '[:lower:]')
    
    if echo "$lower_line" | grep -qE "(critical|fatal|emergency|panic|kernel panic)"; then
        echo "$SEVERITY_CRITICAL"
    elif echo "$lower_line" | grep -qE "(error|failed|denied|refused|timeout)"; then
        echo "$SEVERITY_HIGH"
    elif echo "$lower_line" | grep -qE "(warning|retry|attempt)"; then
        echo "$SEVERITY_MEDIUM"
    elif echo "$lower_line" | grep -qE "(notice|info|debug)"; then
        echo "$SEVERITY_LOW"
    else
        echo "$SEVERITY_INFO"
    fi
}

################################################################################
# Function: classify_malformed_entry
# Description: Classifies type of malformed entry issue
# Parameters: $1 - Entry content, $2 - Expected log format
# Returns: Issue type string
################################################################################
classify_malformed_entry() {
    local entry_content="$1"
    local expected_format="$2"
    
    case "$expected_format" in
        "syslog")
            if [[ ! "$entry_content" =~ ^[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2} ]]; then
                echo "missing_timestamp"
            else
                echo "invalid_format"
            fi
            ;;
        "auth")
            if [[ ! "$entry_content" =~ (sshd|sudo|su|login) ]]; then
                echo "missing_service_identifier"
            else
                echo "invalid_format"
            fi
            ;;
        *)
            echo "format_violation"
            ;;
    esac
}

################################################################################
# Function: generate_recommendations_json
# Description: Generates JSON array of recommendations based on analysis
# Parameters: $1 - Error count, $2 - Malformed count, $3 - Log format
# Returns: JSON array string
################################################################################
generate_recommendations_json() {
    local error_count="$1"
    local malformed_count="$2"
    local log_format="$3"
    local security_count="$4"
    local performance_count="$5"
    local connectivity_count="$6"
    local recommendations=""
    
    # General recommendations
    if [[ $error_count -gt 100 ]]; then
        recommendations+='      "High error volume detected - investigate system stability"'
    fi
    
    if [[ $malformed_count -gt 10 ]]; then
        if [[ -n "$recommendations" ]]; then
            recommendations+=','
        fi
        recommendations+='      "Malformed entries detected - check log rotation and application configuration"'
    fi
    
    # Security-specific recommendations
    if [[ $security_count -gt 5 ]]; then
        if [[ -n "$recommendations" ]]; then
            recommendations+=','
        fi
        recommendations+='      "🔐 SECURITY: Multiple security issues detected - review authentication, firewall rules, and access controls"'
    fi
    
    # Performance-specific recommendations
    if [[ $performance_count -gt 10 ]]; then
        if [[ -n "$recommendations" ]]; then
            recommendations+=','
        fi
        recommendations+='      "⚡ PERFORMANCE: Performance issues detected - monitor CPU, memory, disk usage and optimize system resources"'
    fi
    
    # Connectivity-specific recommendations
    if [[ $connectivity_count -gt 8 ]]; then
        if [[ -n "$recommendations" ]]; then
            recommendations+=','
        fi
        recommendations+='      "🌐 CONNECTIVITY: Network connectivity issues detected - check DNS resolution, firewall rules, and service availability"'
    fi
    
    # Service-specific recommendations based on log format
    case "$log_format" in
        "auth")
            if [[ $error_count -gt 50 ]]; then
                if [[ -n "$recommendations" ]]; then
                    recommendations+=','
                fi
                recommendations+='      "🔑 SSH: Review SSH configuration, key management, and failed login attempts"'
            fi
            ;;
        "apache_error"|"nginx")
            if [[ $error_count -gt 20 ]]; then
                if [[ -n "$recommendations" ]]; then
                    recommendations+=','
                fi
                recommendations+='      "🌐 WEB SERVER: Check web server configuration, SSL certificates, and application errors"'
            fi
            ;;
        "mysql"|"postgresql")
            if [[ $error_count -gt 10 ]]; then
                if [[ -n "$recommendations" ]]; then
                    recommendations+=','
                fi
                recommendations+='      "🗄️  DATABASE: Review database configuration, connection pooling, and query performance"'
            fi
            ;;
        "redis")
            if [[ $error_count -gt 5 ]]; then
                if [[ -n "$recommendations" ]]; then
                    recommendations+=','
                fi
                recommendations+='      "⚡ REDIS: Check Redis configuration, memory usage, and connection limits"'
            fi
            ;;
        "mongodb")
            if [[ $error_count -gt 5 ]]; then
                if [[ -n "$recommendations" ]]; then
                    recommendations+=','
                fi
                recommendations+='      "🍃 MONGODB: Review MongoDB configuration, replica set status, and disk space"'
            fi
            ;;
        "elasticsearch")
            if [[ $error_count -gt 5 ]]; then
                if [[ -n "$recommendations" ]]; then
                    recommendations+=','
                fi
                recommendations+='      "🔍 ELASTICSEARCH: Check cluster health, index status, and disk space"'
            fi
            ;;
        "rabbitmq"|"kafka")
            if [[ $error_count -gt 5 ]]; then
                if [[ -n "$recommendations" ]]; then
                    recommendations+=','
                fi
                recommendations+='      "📨 MESSAGE BROKER: Review queue status, consumer lag, and broker configuration"'
            fi
            ;;
        "jenkins")
            if [[ $error_count -gt 5 ]]; then
                if [[ -n "$recommendations" ]]; then
                    recommendations+=','
                fi
                recommendations+='      "🔧 JENKINS: Check build pipeline status, job failures, and resource usage"'
            fi
            ;;
        "gitlab")
            if [[ $error_count -gt 5 ]]; then
                if [[ -n "$recommendations" ]]; then
                    recommendations+=','
                fi
                recommendations+='      "📚 GITLAB: Review repository status, CI/CD pipelines, and backup procedures"'
            fi
            ;;
        "prometheus")
            if [[ $error_count -gt 5 ]]; then
                if [[ -n "$recommendations" ]]; then
                    recommendations+=','
                fi
                recommendations+='      "📊 PROMETHEUS: Check monitoring targets, alert rules, and storage retention"'
            fi
            ;;
        "grafana")
            if [[ $error_count -gt 5 ]]; then
                if [[ -n "$recommendations" ]]; then
                    recommendations+=','
                fi
                recommendations+='      "📈 GRAFANA: Review dashboard performance, data source connectivity, and user access"'
            fi
            ;;
        "vault")
            if [[ $error_count -gt 5 ]]; then
                if [[ -n "$recommendations" ]]; then
                    recommendations+=','
                fi
                recommendations+='      "🔐 VAULT: Check secret engine status, authentication methods, and audit logs"'
            fi
            ;;
        "docker")
            if [[ $error_count -gt 10 ]]; then
                if [[ -n "$recommendations" ]]; then
                    recommendations+=','
                fi
                recommendations+='      "🐳 DOCKER: Review container health, resource usage, and registry connectivity"'
            fi
            ;;
        "systemd")
            if [[ $error_count -gt 20 ]]; then
                if [[ -n "$recommendations" ]]; then
                    recommendations+=','
                fi
                recommendations+='      "⚙️  SYSTEMD: Check service status, dependencies, and system startup issues"'
            fi
            ;;
        "kernel")
            if [[ $error_count -gt 10 ]]; then
                if [[ -n "$recommendations" ]]; then
                    recommendations+=','
                fi
                recommendations+='      "🔧 KERNEL: Review hardware drivers, memory management, and system stability"'
            fi
            ;;
        "fail2ban")
            if [[ $error_count -gt 5 ]]; then
                if [[ -n "$recommendations" ]]; then
                    recommendations+=','
                fi
                recommendations+='      "🛡️  FAIL2BAN: Review firewall rules, ban thresholds, and security policies"'
            fi
            ;;
    esac
    
    if [[ -z "$recommendations" ]]; then
        recommendations='      "✅ SYSTEM STATUS: No immediate action required - system appears stable"'
    fi
    
    echo "$recommendations"
}

################################################################################
# Function: setup_ssh_keys
# Description: Sets up SSH keys with proper permissions for secure connections
# Parameters: None
# Returns: None
################################################################################
setup_ssh_keys() {
    local ssh_dir="$HOME/.ssh"
    local key_file="$ssh_dir/id_rsa_error_manager"
    
    log_message_with_timestamp "Setting up SSH keys for secure connections" "$SEVERITY_INFO"
    
    # Create .ssh directory with proper permissions
    if [[ ! -d "$ssh_dir" ]]; then
        mkdir -p "$ssh_dir"
        chmod 700 "$ssh_dir"
        log_message_with_timestamp "Created .ssh directory with secure permissions" "$SEVERITY_INFO"
    else
        # Ensure existing directory has correct permissions
        chmod 700 "$ssh_dir"
    fi
    
    # Generate SSH key if it doesn't exist
    # Use RSA key for compatibility with older SSH servers (OpenSSH 4.x)
    if [[ ! -f "$key_file" ]]; then
        log_message_with_timestamp "Generating new SSH key for error manager" "$SEVERITY_INFO"
        ssh-keygen -t rsa -b 2048 -f "$key_file" -N "" -C "error_manager_$(date +%Y%m%d)" >/dev/null 2>&1
        chmod 600 "$key_file"
        chmod 644 "${key_file}.pub"
        log_message_with_timestamp "SSH key generated: $key_file" "$SEVERITY_INFO"
    else
        # Ensure existing keys have correct permissions
        chmod 600 "$key_file"
        chmod 644 "${key_file}.pub" 2>/dev/null || true
        log_message_with_timestamp "Using existing SSH key: $key_file" "$SEVERITY_INFO"
    fi
    
    # Verify key permissions
    if [[ -f "$key_file" && -r "$key_file" ]]; then
        log_message_with_timestamp "SSH key setup completed successfully" "$SEVERITY_INFO"
        return 0
    else
        log_message_with_timestamp "SSH key setup failed" "$SEVERITY_CRITICAL"
        return 1
    fi
}

################################################################################
# Function: sanitize_ssh_connection
# Description: Validates and sanitizes SSH connection string
# Parameters: $1 - SSH connection string
# Returns: Sanitized connection string or exits on error
################################################################################
sanitize_ssh_connection() {
    local connection="$1"
    
    # Validate format: user@host:path
    if [[ ! "$connection" =~ ^[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+:.+ ]]; then
        log_message_with_timestamp "Invalid SSH connection format: $connection" "$SEVERITY_CRITICAL"
        log_message_with_timestamp "Expected format: user@host:/path/to/file" "$SEVERITY_HIGH"
        return 1
    fi
    
    # Extract and validate components
    local host_info=$(echo "$connection" | cut -d':' -f1)
    local username=$(echo "$host_info" | cut -d'@' -f1)
    local hostname=$(echo "$host_info" | cut -d'@' -f2)
    local remote_path=$(echo "$connection" | cut -d':' -f2-)
    
    # Validate username (alphanumeric, dots, dashes, underscores only)
    if [[ ! "$username" =~ ^[a-zA-Z0-9._-]+$ ]]; then
        log_message_with_timestamp "Invalid username in SSH connection: $username" "$SEVERITY_CRITICAL"
        return 1
    fi
    
    # Validate hostname (alphanumeric, dots, dashes only)
    if [[ ! "$hostname" =~ ^[a-zA-Z0-9.-]+$ ]]; then
        log_message_with_timestamp "Invalid hostname in SSH connection: $hostname" "$SEVERITY_CRITICAL"
        return 1
    fi
    
    # Validate remote path (basic path validation)
    if [[ ! "$remote_path" =~ ^/ ]]; then
        log_message_with_timestamp "Remote path must be absolute: $remote_path" "$SEVERITY_HIGH"
        return 1
    fi
    
    log_message_with_timestamp "SSH connection validated: $connection" "$SEVERITY_INFO"
    echo "$connection"
    return 0
}

################################################################################
# Function: save_local_copies
# Description: Saves local copies of parsed files with host-based naming
# Parameters: $1 - Remote host, $2 - Remote file path, $3 - JSON report path, $4 - CSV report path
# Returns: None
################################################################################
save_local_copies() {
    local remote_host="$1"
    local remote_file="$2"
    local json_report="$3"
    local csv_report="$4"

    local base_name
    base_name="$(basename "$remote_file" | sed 's/[^a-zA-Z0-9_.-]//g')"  # sanitize filename
    local prefix="${remote_host}_${base_name}"

    # Create directories with proper permissions
    mkdir -p ./error_reports/json ./error_reports/csv
    chmod 755 ./error_reports/json ./error_reports/csv

    # Copy JSON file
    if [[ -f "$json_report" ]]; then
        cp "$json_report" "./error_reports/json/${prefix}.json"
        chmod 644 "./error_reports/json/${prefix}.json"
        log_message_with_timestamp "Local JSON copy saved: ./error_reports/json/${prefix}.json" "$SEVERITY_INFO"
    fi
    
    # Copy CSV file if it exists
    if [[ -f "$csv_report" ]]; then
        cp "$csv_report" "./error_reports/csv/${prefix}.csv"
        chmod 644 "./error_reports/csv/${prefix}.csv"
        log_message_with_timestamp "Local CSV copy saved: ./error_reports/csv/${prefix}.csv" "$SEVERITY_INFO"
    fi

    echo "[INFO] Local copies saved as:"
    echo "       ./error_reports/json/${prefix}.json"
    if [[ -f "$csv_report" ]]; then
        echo "       ./error_reports/csv/${prefix}.csv"
    fi
}

################################################################################
# Function: setup_ssh_remote_processing
# Description: Sets up SSH connection and transfers log file for remote processing
# Parameters: $1 - SSH connection string (user@host:/path/to/log)
# Returns: Local path to transferred file
################################################################################
setup_ssh_remote_processing() {
    local ssh_connection="$1"
    
    # Sanitize SSH connection
    if ! ssh_connection=$(sanitize_ssh_connection "$ssh_connection"); then
        return 1
    fi
    
    local remote_file_path=$(echo "$ssh_connection" | cut -d':' -f2-)
    local local_temp_file="$TEMPORARY_DIRECTORY/remote_log_$(date +%s)_$$.log"  # Add PID for uniqueness
    
    log_message_with_timestamp "Setting up SSH connection for remote log processing" "$SEVERITY_INFO"
    log_message_with_timestamp "Remote file: $remote_file_path" "$SEVERITY_INFO"
    
    # Setup SSH keys first
    if ! setup_ssh_keys; then
        log_message_with_timestamp "Failed to setup SSH keys" "$SEVERITY_CRITICAL"
        return 1
    fi
    
    # Extract host and user information
    local host_info=$(echo "$ssh_connection" | cut -d':' -f1)
    local username=$(echo "$host_info" | cut -d'@' -f1)
    local hostname=$(echo "$host_info" | cut -d'@' -f2)
    local key_file="$HOME/.ssh/id_rsa_error_manager"
    local pub_key_file="${key_file}.pub"
    
    # Test SSH connectivity with timeout and proper error handling
    log_message_with_timestamp "Testing SSH connectivity to $host_info..." "$SEVERITY_INFO"
    
    # First try with key-based authentication (BatchMode)
    # Add compatibility options for older SSH servers (like OpenSSH 4.x)
    local ssh_test_output
    ssh_test_output=$(ssh -o ConnectTimeout=10 -o BatchMode=yes -o StrictHostKeyChecking=no -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa -i "$key_file" "$host_info" "echo 'SSH connection successful'" 2>&1)
    local ssh_test_exit=$?
    if [[ $ssh_test_exit -ne 0 ]]; then
        log_message_with_timestamp "SSH test failed (exit code: $ssh_test_exit). Error: $ssh_test_output" "$SEVERITY_MEDIUM"
        # If key-based auth fails, try to copy the key to remote host
        log_message_with_timestamp "SSH key authentication not configured. Attempting to copy SSH key to remote host..." "$SEVERITY_INFO"
        log_message_with_timestamp "You may be prompted for the password (this is a one-time setup)" "$SEVERITY_MEDIUM"
        
        # Try to copy the public key to the remote host using ssh-copy-id
        if command -v ssh-copy-id >/dev/null 2>&1; then
            if ssh-copy-id -i "$pub_key_file" -o StrictHostKeyChecking=no -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa "$host_info" 2>&1 | grep -v "WARNING:"; then
                log_message_with_timestamp "SSH key successfully copied to remote host" "$SEVERITY_INFO"
            else
                # If ssh-copy-id fails, try manual method
                log_message_with_timestamp "ssh-copy-id unavailable, trying manual key installation..." "$SEVERITY_MEDIUM"
                if [[ -f "$pub_key_file" ]]; then
                    local pub_key_content=$(cat "$pub_key_file")
                    if ssh -o StrictHostKeyChecking=no -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa "$host_info" "mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '$pub_key_content' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys" 2>/dev/null; then
                        log_message_with_timestamp "SSH key manually installed on remote host" "$SEVERITY_INFO"
                    else
                        log_message_with_timestamp "Failed to install SSH key on remote host" "$SEVERITY_CRITICAL"
                        log_message_with_timestamp "Please manually copy the key: ssh-copy-id -i $pub_key_file $host_info" "$SEVERITY_HIGH"
                        return 1
                    fi
                else
                    log_message_with_timestamp "SSH public key file not found: $pub_key_file" "$SEVERITY_CRITICAL"
                    return 1
                fi
            fi
        else
            # Manual method if ssh-copy-id is not available
            log_message_with_timestamp "ssh-copy-id not available, trying manual key installation..." "$SEVERITY_MEDIUM"
            if [[ -f "$pub_key_file" ]]; then
                local pub_key_content=$(cat "$pub_key_file")
                if ssh -o StrictHostKeyChecking=no -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa "$host_info" "mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '$pub_key_content' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys" 2>/dev/null; then
                    log_message_with_timestamp "SSH key manually installed on remote host" "$SEVERITY_INFO"
                else
                    log_message_with_timestamp "Failed to install SSH key on remote host" "$SEVERITY_CRITICAL"
                    log_message_with_timestamp "Please manually install the key or use password authentication" "$SEVERITY_HIGH"
                    return 1
                fi
            else
                log_message_with_timestamp "SSH public key file not found: $pub_key_file" "$SEVERITY_CRITICAL"
                return 1
            fi
        fi
        
        # Test again with key-based authentication
        log_message_with_timestamp "Testing SSH key authentication..." "$SEVERITY_INFO"
        local ssh_test_output_retry
        ssh_test_output_retry=$(ssh -o ConnectTimeout=10 -o BatchMode=yes -o StrictHostKeyChecking=no -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa -i "$key_file" "$host_info" "echo 'SSH connection successful'" 2>&1)
        local ssh_test_exit_retry=$?
        if [[ $ssh_test_exit_retry -ne 0 ]]; then
            log_message_with_timestamp "SSH key authentication still failed (exit code: $ssh_test_exit_retry)" "$SEVERITY_CRITICAL"
            log_message_with_timestamp "Error details: $ssh_test_output_retry" "$SEVERITY_MEDIUM"
            log_message_with_timestamp "Please verify:" "$SEVERITY_MEDIUM"
            log_message_with_timestamp "  1. Permissions: chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys" "$SEVERITY_MEDIUM"
            log_message_with_timestamp "  2. Key exists in ~/.ssh/authorized_keys on remote host" "$SEVERITY_MEDIUM"
            log_message_with_timestamp "  3. SSH server allows PubkeyAuthentication" "$SEVERITY_MEDIUM"
            log_message_with_timestamp "Test manually: ssh -i $key_file $host_info 'echo test'" "$SEVERITY_MEDIUM"
            return 1
        fi
    else
        log_message_with_timestamp "SSH key authentication already configured" "$SEVERITY_INFO"
    fi
    
    log_message_with_timestamp "SSH connection successful" "$SEVERITY_INFO"
    
    # Check if remote file exists and get its size with proper error handling
    # Add compatibility options for older SSH servers
    local remote_file_size
    if ! remote_file_size=$(ssh -i "$key_file" -o ConnectTimeout=10 -o BatchMode=yes -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa "$host_info" "stat -c%s '$remote_file_path' 2>/dev/null || echo '0'"); then
        log_message_with_timestamp "Failed to check remote file: $remote_file_path" "$SEVERITY_CRITICAL"
        return 1
    fi
    
    if [[ "$remote_file_size" == "0" ]]; then
        log_message_with_timestamp "Remote file does not exist or is empty: $remote_file_path" "$SEVERITY_CRITICAL"
        return 1
    fi
    
    log_message_with_timestamp "Remote file size: $remote_file_size bytes" "$SEVERITY_INFO"
    
    # Transfer log file using SCP with compression and proper error handling
    # Add compatibility options for older SSH servers
    log_message_with_timestamp "Transferring log file from remote host (with compression)..." "$SEVERITY_INFO"
    if scp -i "$key_file" -C -o ConnectTimeout=30 -o BatchMode=yes -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa "$ssh_connection" "$local_temp_file" 2>/dev/null; then
        local scp_exit_code=$?
        log_message_with_timestamp "Remote log file transferred successfully" "$SEVERITY_INFO"
        
        # Set secure permissions on temporary file
        chmod 600 "$local_temp_file"
        
        # Verify transfer integrity
        local local_file_size
        if ! local_file_size=$(stat -c%s "$local_temp_file" 2>/dev/null || stat -f%z "$local_temp_file" 2>/dev/null || echo "0"); then
            log_message_with_timestamp "Failed to get local file size" "$SEVERITY_MEDIUM"
        fi
        
        if [[ "$local_file_size" == "$remote_file_size" ]]; then
            log_message_with_timestamp "File transfer integrity verified" "$SEVERITY_INFO"
        else
            log_message_with_timestamp "File transfer integrity check failed (local: $local_file_size, remote: $remote_file_size)" "$SEVERITY_MEDIUM"
        fi
        
        echo "$local_temp_file"
        return 0
    else
        local scp_exit_code=$?
        log_message_with_timestamp "Failed to transfer remote log file (exit code: $scp_exit_code)" "$SEVERITY_CRITICAL"
        return 1
    fi
}

################################################################################
# Function: send_results_back_to_host
# Description: Sends processed results back to remote host
# Parameters: $1 - SSH connection string, $2 - Local result file path
# Returns: None
################################################################################
send_results_back_to_host() {
    local ssh_connection="$1"
    local local_result_file="$2"
    
    if [[ ! -f "$local_result_file" ]]; then
        log_message_with_timestamp "Result file not found: $local_result_file" "$SEVERITY_HIGH"
        return 1
    fi
    
    local host_info=$(echo "$ssh_connection" | cut -d':' -f1)
    local key_file="$HOME/.ssh/id_rsa_error_manager"
    local remote_dir="~/checked_reports"
    local remote_filename=$(basename "$local_result_file")
    local remote_path="${remote_dir}/${remote_filename}"
    
    log_message_with_timestamp "Sending results back to remote host..." "$SEVERITY_INFO"
    
    # Create remote directory if it doesn't exist
    # Add compatibility options for older SSH servers
    if ! ssh -i "$key_file" -o ConnectTimeout=10 -o BatchMode=yes -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa "$host_info" "mkdir -p $remote_dir"; then
        log_message_with_timestamp "Failed to create remote directory: $remote_dir" "$SEVERITY_HIGH"
        return 1
    fi
    
    # Send the file back to remote host
    # Add compatibility options for older SSH servers
    if scp -i "$key_file" -o ConnectTimeout=30 -o BatchMode=yes -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa "$local_result_file" "${host_info}:${remote_path}"; then
        log_message_with_timestamp "Results successfully sent to remote host: $remote_path" "$SEVERITY_INFO"
        
        # Set proper permissions on remote file
        ssh -i "$key_file" -o ConnectTimeout=10 -o BatchMode=yes -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa "$host_info" "chmod 644 $remote_path" 2>/dev/null || true
        
        return 0
    else
        local scp_exit_code=$?
        log_message_with_timestamp "Failed to send results to remote host (exit code: $scp_exit_code)" "$SEVERITY_HIGH"
        return 1
    fi
}

################################################################################
# Description: Chains processing with external Python consumer for advanced analysis
# Parameters: $1 - JSON report file path
# Returns: None
################################################################################
chain_python_consumer_processing() {
    local json_report_file="$1"
    local python_script_path="CA_error_consumer.py"
    local advanced_analysis_output="$OUTPUT_DIRECTORY/json/advanced_analysis_$(date +%m-%d_%H%M).json"
    
    log_message_with_timestamp "Setting up Python consumer for advanced analysis" "$SEVERITY_INFO"
    
    # Check if Python consumer script exists
    if [[ ! -f "$python_script_path" ]]; then
        log_message_with_timestamp "Python consumer script not found: $python_script_path" "$SEVERITY_HIGH"
        log_message_with_timestamp "Skipping advanced analysis - ensure CA_error_consumer.py is in the same directory" "$SEVERITY_MEDIUM"
        return 1
    fi
    
    # Check if Python3 is available
    if ! command -v python3 >/dev/null 2>&1; then
        log_message_with_timestamp "Python3 not available - skipping advanced analysis" "$SEVERITY_MEDIUM"
        return 1
    fi
    
    # Run Python consumer with comprehensive analysis and proper error handling
    log_message_with_timestamp "Executing Python consumer for advanced analysis..." "$SEVERITY_INFO"
    if python3 "$python_script_path" "$json_report_file" --output "$advanced_analysis_output"; then
        local python_exit_code=$?
        chmod 644 "$advanced_analysis_output"
        log_message_with_timestamp "Python consumer analysis completed successfully" "$SEVERITY_INFO"
        log_message_with_timestamp "Advanced analysis saved to: $advanced_analysis_output" "$SEVERITY_INFO"
        
        # Also run alerts-only check for quick summary
        local alerts_output="$OUTPUT_DIRECTORY/text/alerts_summary_$(date +%m-%d_%H%M).txt"
        if python3 "$python_script_path" "$json_report_file" --alerts-only > "$alerts_output" 2>&1; then
            chmod 644 "$alerts_output"
            log_message_with_timestamp "Alert summary saved to: $alerts_output" "$SEVERITY_INFO"
        else
            log_message_with_timestamp "Failed to generate alert summary" "$SEVERITY_MEDIUM"
        fi
        
        return 0
    else
        local python_exit_code=$?
        log_message_with_timestamp "Python consumer analysis failed (exit code: $python_exit_code)" "$SEVERITY_MEDIUM"
        return 1
    fi
}

################################################################################
# Function: run_auto_mode
# Description: Runs the script in automated mode with optimal settings
# Parameters: None
# Returns: None
################################################################################
run_auto_mode() {
    echo ""
    echo "======================================================================"
    echo "🤖 CA ERROR MANAGER - AUTOMATED MODE"
    echo "======================================================================"
    echo "Running automated error management with optimal settings..."
    
    # Auto-detect log file
    LOG_FILE_PATH=""
    
    # Function to find all readable log files in /var/log
    find_log_files() {
        local log_files=()
        
        # Check if /var/log exists and is readable
        if [[ -d "/var/log" && -r "/var/log" ]]; then
            echo "🔍 Scanning /var/log directory for log files..."
            
            # Find all readable files in /var/log and subdirectories
            while IFS= read -r -d '' file; do
                # Check if file is readable and has content
                if [[ -r "$file" && -s "$file" ]]; then
                    log_files+=("$file")
                fi
            done < <(find /var/log -type f -readable -size +0 -print0 2>/dev/null)
            
            # Sort by modification time (newest first)
            if [[ ${#log_files[@]} -gt 0 ]]; then
                IFS=$'\n' log_files=($(printf '%s\n' "${log_files[@]}" | xargs -I {} stat -c '%Y %n' {} 2>/dev/null | sort -nr | cut -d' ' -f2-))
            fi
        fi
        
        printf '%s\n' "${log_files[@]}"
    }
    
    # Get all available log files
    AVAILABLE_LOGS=($(find_log_files))
    
    if [[ ${#AVAILABLE_LOGS[@]} -gt 0 ]]; then
        echo "📋 Found ${#AVAILABLE_LOGS[@]} readable log files in /var/log"
        
        # Show first 10 log files found
        echo "🔍 Available log files (showing first 10):"
        for i in "${!AVAILABLE_LOGS[@]}"; do
            if [[ $i -lt 10 ]]; then
                file_size=$(stat -f%z "${AVAILABLE_LOGS[$i]}" 2>/dev/null || stat -c%s "${AVAILABLE_LOGS[$i]}" 2>/dev/null || echo "unknown")
                echo "  $((i+1)). ${AVAILABLE_LOGS[$i]} (${file_size} bytes)"
            fi
        done
        
        if [[ ${#AVAILABLE_LOGS[@]} -gt 10 ]]; then
            echo "  ... and $(( ${#AVAILABLE_LOGS[@]} - 10 )) more files"
        fi
        
        # Use the most recently modified log file
        LOG_FILE_PATH="${AVAILABLE_LOGS[0]}"
        echo "🎯 Auto-selected most recent log file: $LOG_FILE_PATH"
        
        # Offer to choose a different file
        echo ""
        echo "💡 Tip: You can specify a different log file with:"
        echo "   ./CA_error_manager.sh /path/to/specific/logfile"
        echo "   ./CA_error_manager.sh --interactive"
        
    else
        echo "⚠️  No readable log files found in /var/log"
        echo "💡 Tip: Run with sudo for system log access or use --interactive mode"
    fi
    
    # Create sample log if none found
    if [[ -z "$LOG_FILE_PATH" ]]; then
        echo "📝 No log files found. Creating sample log file..."
        LOG_FILE_PATH="sample_auto_logs.txt"
        cat > "$LOG_FILE_PATH" << 'EOF'
2024-01-01 10:00:00 ERROR: Database connection failed - Connection timeout after 30 seconds
2024-01-01 10:01:00 WARNING: High memory usage detected - 85% memory utilization
2024-01-01 10:02:00 CRITICAL: System disk full - Only 100MB free space remaining
2024-01-01 10:03:00 INFO: User login successful - User: admin, IP: 192.168.1.100
2024-01-01 10:04:00 ERROR: Network timeout - Failed to reach external API
2024-01-01 10:05:00 WARNING: SSL certificate expires soon - Expires in 7 days
2024-01-01 10:06:00 ERROR: Failed to connect to API - HTTP 500 Internal Server Error
2024-01-01 10:07:00 INFO: Backup completed successfully - 2.5GB backed up
2024-01-01 10:08:00 CRITICAL: Service unavailable - Web server down
2024-01-01 10:09:00 ERROR: Invalid input format - Malformed JSON received
2024-01-01 10:10:00 WARNING: CPU usage high - 90% CPU utilization
2024-01-01 10:11:00 ERROR: File system error - Disk I/O error on /dev/sda1
2024-01-01 10:12:00 INFO: Scheduled maintenance completed - System updated
2024-01-01 10:13:00 ERROR: Authentication failed - Invalid credentials
2024-01-01 10:14:00 WARNING: Network interface down - eth0 interface offline
EOF
        echo "✅ Sample log file created: $LOG_FILE_PATH"
    fi
    
    # Optimal settings for automated processing
    FORCE_JSON=true
    VERBOSE_MODE=true
    
    echo "📊 Processing Configuration:"
    echo "   Input file: $LOG_FILE_PATH"
    echo "   Output format: JSON"
    echo "   Analysis: Comprehensive"
    echo "   Python consumer: Enabled"
    
    echo ""
    echo "🚀 Starting automated error processing..."
    echo "======================================================================"
    
    # Process the log file
    process_log_file "$LOG_FILE_PATH"
    
    echo ""
    echo "======================================================================"
    echo "✅ AUTOMATED ERROR PROCESSING COMPLETED!"
    echo "======================================================================"
    echo "📁 Results available in: $OUTPUT_DIR"
    
    # Chain with Python consumer
    if command -v python3 >/dev/null 2>&1; then
        echo ""
        echo "🐍 Chaining with Python consumer for advanced analysis..."
        
        # Find the most recent JSON report
        if [[ -d "$OUTPUT_DIR/json" ]]; then
            JSON_FILES=($(ls -t "$OUTPUT_DIR/json"/*.json 2>/dev/null))
            if [[ ${#JSON_FILES[@]} -gt 0 ]]; then
                LATEST_JSON="${JSON_FILES[0]}"
                echo "📊 Analyzing: $LATEST_JSON"
                
                # Run Python consumer
                if [[ -f "CA_error_consumer.py" ]]; then
                    python3 CA_error_consumer.py "$LATEST_JSON" --output "ca_auto_analysis_$(date +%Y%m%d_%H%M%S).json"
                    echo "✅ Python consumer analysis completed"
                else
                    echo "⚠️  CA_error_consumer.py not found, skipping advanced analysis"
                fi
            fi
        fi
    else
        echo "⚠️  Python3 not available, skipping advanced analysis"
    fi
}

################################################################################
# Function: run_interactive_mode
# Description: Runs the script in interactive mode with guided setup
# Parameters: None
# Returns: None
################################################################################
run_interactive_mode() {
    echo ""
    echo "======================================================================"
    echo "📊 CA ERROR MANAGER - INTERACTIVE MODE"
    echo "======================================================================"
    echo "Welcome! This interactive mode will guide you through error management."
    echo "You can analyze log files, detect errors, and chain with Python consumers."
    
    # Operation mode selection with detailed guidance
    echo ""
    echo "======================================================================"
    echo "🔧 OPERATION MODE SELECTION"
    echo "======================================================================"
    echo "Choose how to process log files:"
    echo "1. Process specific log file (recommended)"
    echo "2. Process remote log file via SSH"
    echo "3. Process logs.txt (default file)"
    echo "4. Create and process sample log file"
    
    while true; do
        echo ""
        read -p "Choose operation mode (1-4): " mode_choice
        case $mode_choice in
            1)
                echo ""
                echo "📁 LOG FILE SELECTION:"
                echo "1. Enter path to log file manually"
                echo "2. Browse common system logs"
                echo "3. Browse current directory"
                
                while true; do
                    read -p "Choose option (1-3): " file_choice
                    case $file_choice in
                        1)
                            echo ""
                            echo "📝 Manual File Path:"
                            echo "Examples: /var/log/syslog, /path/to/custom.log, error.log"
                            read -p "Enter path to log file: " log_file
                            if [[ -f "$log_file" && -r "$log_file" ]]; then
                                file_size=$(stat -f%z "$log_file" 2>/dev/null || stat -c%s "$log_file" 2>/dev/null || echo "unknown")
                                echo "✅ File found: $log_file (${file_size} bytes)"
                                LOG_FILE_PATH="$log_file"
                                break
                            else
                                echo "❌ File not found or not readable."
                                echo "💡 Tip: Check file permissions or run with sudo for system logs"
                                retry=$(read -p "Try again? (y/n): " && echo "$REPLY")
                                if [[ "$retry" =~ ^[Yy]$ ]]; then
                                    continue
                                fi
                            fi
                            ;;
                        2)
                            echo ""
                            echo "📁 Common System Logs:"
                            echo "1. /var/log/syslog (system messages)"
                            echo "2. /var/log/auth.log (authentication)"
                            echo "3. /var/log/kern.log (kernel messages)"
                            echo "4. /var/log/boot.log (boot messages)"
                            echo "5. /var/log/nginx/error.log (nginx errors)"
                            echo "6. /var/log/apache2/error.log (apache errors)"
                            echo "7. /var/log/mysql/error.log (mysql errors)"
                            echo "8. logs.txt (sample log file)"
                            
                            read -p "Choose log file (1-8): " common_choice
                            case $common_choice in
                                1) LOG_FILE_PATH="/var/log/syslog" ;;
                                2) LOG_FILE_PATH="/var/log/auth.log" ;;
                                3) LOG_FILE_PATH="/var/log/kern.log" ;;
                                4) LOG_FILE_PATH="/var/log/boot.log" ;;
                                5) LOG_FILE_PATH="/var/log/nginx/error.log" ;;
                                6) LOG_FILE_PATH="/var/log/apache2/error.log" ;;
                                7) LOG_FILE_PATH="/var/log/mysql/error.log" ;;
                                8) LOG_FILE_PATH="logs.txt" ;;
                                *) echo "❌ Invalid choice" ; continue ;;
                            esac
                            
                            if [[ -f "$LOG_FILE_PATH" && -r "$LOG_FILE_PATH" ]]; then
                                file_size=$(stat -f%z "$LOG_FILE_PATH" 2>/dev/null || stat -c%s "$LOG_FILE_PATH" 2>/dev/null || echo "unknown")
                                echo "✅ File accessible: $LOG_FILE_PATH (${file_size} bytes)"
                                break
                            else
                                echo "❌ File not accessible. Please choose another option or run with sudo"
                                echo "💡 Tip: Some system logs require root privileges to read"
                            fi
                            ;;
                        3)
                            echo ""
                            echo "📁 Current Directory Files:"
                            echo "Available log files in current directory:"
                            ls -la *.log *.txt 2>/dev/null | head -10
                            if [[ $? -ne 0 ]]; then
                                echo "No log files found in current directory."
                                echo "💡 Tip: Create a sample log file or use option 4."
                            fi
                            read -p "Enter filename: " log_file
                            if [[ -f "$log_file" && -r "$log_file" ]]; then
                                file_size=$(stat -f%z "$log_file" 2>/dev/null || stat -c%s "$log_file" 2>/dev/null || echo "unknown")
                                echo "✅ File found: $log_file (${file_size} bytes)"
                                LOG_FILE_PATH="$log_file"
                                break
                            else
                                echo "❌ File not found or not readable."
                            fi
                            ;;
                        *)
                            echo "❌ Invalid choice. Please enter 1-3"
                            ;;
                    esac
                done
                break
                ;;
            2)
                echo ""
                echo "📡 SSH REMOTE PROCESSING:"
                echo "This will download and process log files from a remote server."
                echo "You need SSH access to the remote host."
                echo ""
                echo "📝 SSH Connection Details:"
                echo "Examples: admin@server.example.com, user@192.168.1.100"
                read -p "Username@Hostname: " host_info
                echo ""
                echo "📝 Remote Log Path:"
                echo "Examples: /var/log/syslog, /var/log/messages, /tmp/custom.log"
                read -p "Remote log path: " remote_path
                
                if [[ -n "$host_info" && -n "$remote_path" ]]; then
                    SSH_CONNECTION="$host_info:$remote_path"
                    echo ""
                    echo "✅ SSH connection configured: $SSH_CONNECTION"
                    echo "🔄 Will download and process log file from remote host"
                    echo "💡 Tip: Make sure you have SSH key authentication or password access"
                    break
                else
                    echo "❌ Please provide both hostname and log path"
                fi
                ;;
            3)
                LOG_FILE_PATH="logs.txt"
                if [[ -f "$LOG_FILE_PATH" ]]; then
                    file_size=$(stat -f%z "$LOG_FILE_PATH" 2>/dev/null || stat -c%s "$LOG_FILE_PATH" 2>/dev/null || echo "unknown")
                    echo ""
                    echo "✅ Using default logs.txt file (${file_size} bytes)"
                else
                    echo ""
                    echo "⚠️  logs.txt not found. Creating sample file..."
                    cat > "$LOG_FILE_PATH" << 'EOF'
2024-01-01 10:00:00 ERROR: Database connection failed
2024-01-01 10:01:00 WARNING: High memory usage detected
2024-01-01 10:02:00 CRITICAL: System disk full
2024-01-01 10:03:00 INFO: User login successful
2024-01-01 10:04:00 ERROR: Network timeout
2024-01-01 10:05:00 WARNING: SSL certificate expires soon
2024-01-01 10:06:00 ERROR: Failed to connect to API
2024-01-01 10:07:00 INFO: Backup completed successfully
2024-01-01 10:08:00 CRITICAL: Service unavailable
2024-01-01 10:09:00 ERROR: Invalid input format
EOF
                    if [[ -f "$LOG_FILE_PATH" ]]; then
                        file_size=$(stat -f%z "$LOG_FILE_PATH" 2>/dev/null || stat -c%s "$LOG_FILE_PATH" 2>/dev/null || echo "unknown")
                        echo "✅ Sample logs.txt created (${file_size} bytes)"
                    else
                        echo "❌ Failed to create sample file"
                    fi
                fi
                break
                ;;
            4)
                echo ""
                echo "📝 Sample Log File Creation:"
                echo "Creating a comprehensive sample log file for demonstration..."
                LOG_FILE_PATH="sample_comprehensive_logs.txt"
                cat > "$LOG_FILE_PATH" << 'EOF'
2024-01-01 10:00:00 ERROR: Database connection failed - Connection timeout after 30 seconds
2024-01-01 10:01:00 WARNING: High memory usage detected - 85% memory utilization
2024-01-01 10:02:00 CRITICAL: System disk full - Only 100MB free space remaining
2024-01-01 10:03:00 INFO: User login successful - User: admin, IP: 192.168.1.100
2024-01-01 10:04:00 ERROR: Network timeout - Failed to reach external API
2024-01-01 10:05:00 WARNING: SSL certificate expires soon - Expires in 7 days
2024-01-01 10:06:00 ERROR: Failed to connect to API - HTTP 500 Internal Server Error
2024-01-01 10:07:00 INFO: Backup completed successfully - 2.5GB backed up
2024-01-01 10:08:00 CRITICAL: Service unavailable - Web server down
2024-01-01 10:09:00 ERROR: Invalid input format - Malformed JSON received
2024-01-01 10:10:00 WARNING: CPU usage high - 90% CPU utilization
2024-01-01 10:11:00 ERROR: File system error - Disk I/O error on /dev/sda1
2024-01-01 10:12:00 INFO: Scheduled maintenance completed - System updated
2024-01-01 10:13:00 ERROR: Authentication failed - Invalid credentials
2024-01-01 10:14:00 WARNING: Network interface down - eth0 interface offline
EOF
                if [[ -f "$LOG_FILE_PATH" ]]; then
                    file_size=$(stat -f%z "$LOG_FILE_PATH" 2>/dev/null || stat -c%s "$LOG_FILE_PATH" 2>/dev/null || echo "unknown")
                    echo "✅ Comprehensive sample log file created: $LOG_FILE_PATH (${file_size} bytes)"
                    echo "   Contains various error types and severity levels"
                else
                    echo "❌ Failed to create sample file"
                fi
                break
                ;;
            *)
                echo "❌ Invalid choice. Please enter 1-4"
                ;;
        esac
    done
    
    # Output options with detailed guidance
    echo ""
    echo "======================================================================"
    echo "💾 OUTPUT OPTIONS"
    echo "======================================================================"
    echo "Choose output configuration:"
    echo "1. Auto-generated filename (recommended)"
    echo "2. Custom filename"
    echo "3. Multiple output formats"
    echo "4. Console output only"
    
    while true; do
        echo ""
        read -p "Choose option (1-4): " output_choice
        case $output_choice in
            1)
                echo "✅ Auto-generated filename selected"
                echo "   Format: error_analysis_YYYY-MM-DD_HHMM.json"
                break
                ;;
            2)
                echo ""
                echo "📝 Custom Filename:"
                echo "Examples: my_analysis.json, error_report_2024.json"
                read -p "Enter output filename: " custom_filename
                if [[ -n "$custom_filename" ]]; then
                    if [[ "$custom_filename" != *.json ]]; then
                        custom_filename="${custom_filename}.json"
                    fi
                    echo "✅ Custom filename: $custom_filename"
                    FORCE_JSON=true
                    break
                else
                    echo "❌ Filename cannot be empty."
                fi
                ;;
            3)
                echo "✅ Multiple output formats selected"
                echo "   Will create JSON, TXT, and CSV files"
                FORCE_JSON=true
                break
                ;;
            4)
                echo "✅ Console output only"
                echo "   Results will be displayed on screen"
                break
                ;;
            *)
                echo "❌ Invalid choice. Please enter 1-4"
                ;;
        esac
    done
    
    # Analysis options with detailed guidance
    echo ""
    echo "======================================================================"
    echo "🔍 ANALYSIS OPTIONS"
    echo "======================================================================"
    echo "Choose analysis depth:"
    echo "1. Basic analysis (errors and malformed entries)"
    echo "2. Detailed analysis (patterns and statistics)"
    echo "3. Advanced analysis (correlations and trends)"
    echo "4. Custom analysis options"
    
    while true; do
        echo ""
        read -p "Choose option (1-4): " analysis_choice
        case $analysis_choice in
            1)
                echo "✅ Basic analysis selected"
                echo "   Will detect errors and malformed entries"
                break
                ;;
            2)
                echo "✅ Detailed analysis selected"
                echo "   Will include patterns and statistics"
                VERBOSE_MODE=true
                break
                ;;
            3)
                echo "✅ Advanced analysis selected"
                echo "   Will include correlations and trends"
                VERBOSE_MODE=true
                break
                ;;
            4)
                echo ""
                echo "📝 Custom Analysis Options:"
                echo "1. Error pattern analysis only"
                echo "2. Malformed entry analysis only"
                echo "3. Statistical analysis only"
                echo "4. All analysis types"
                
                read -p "Choose custom option (1-4): " custom_analysis
                case $custom_analysis in
                    1) echo "✅ Error pattern analysis selected"; break ;;
                    2) echo "✅ Malformed entry analysis selected"; break ;;
                    3) echo "✅ Statistical analysis selected"; break ;;
                    4) echo "✅ All analysis types selected"; VERBOSE_MODE=true; break ;;
                    *) echo "❌ Invalid custom option." ;;
                esac
                ;;
            *)
                echo "❌ Invalid choice. Please enter 1-4"
                ;;
        esac
    done
    
    # Python consumer chaining options
    echo ""
    echo "======================================================================"
    echo "🐍 PYTHON CONSUMER CHAINING"
    echo "======================================================================"
    echo "Choose Python consumer options:"
    echo "1. No Python consumer (Bash only)"
    echo "2. Chain with CA_error_consumer.py (recommended)"
    echo "3. Chain with custom Python script"
    echo "4. Advanced chaining options"
    
    while true; do
        echo ""
        read -p "Choose option (1-4): " python_choice
        case $python_choice in
            1)
                echo "✅ Bash-only processing selected"
                echo "   Results will be processed by Bash script only"
                break
                ;;
            2)
                echo "✅ CA_error_consumer.py chaining selected"
                echo "   Results will be processed by Python consumer"
                echo "   This provides advanced analysis and reporting"
                break
                ;;
            3)
                echo ""
                echo "📝 Custom Python Script:"
                echo "Examples: custom_analyzer.py, /path/to/script.py"
                read -p "Enter Python script path: " python_script
                if [[ -f "$python_script" ]]; then
                    echo "✅ Custom Python script: $python_script"
                    break
                else
                    echo "❌ Python script not found."
                    retry=$(read -p "Try again? (y/n): " && echo "$REPLY")
                    if [[ "$retry" =~ ^[Yy]$ ]]; then
                        continue
                    fi
                fi
                ;;
            4)
                echo ""
                echo "📝 Advanced Chaining Options:"
                echo "1. Chain with remote Python consumer"
                echo "2. Chain with multiple consumers"
                echo "3. Chain with custom analysis pipeline"
                
                read -p "Choose advanced option (1-3): " advanced_choice
                case $advanced_choice in
                    1)
                        read -p "Enter remote Python consumer (user@host:script): " remote_script
                        if [[ -n "$remote_script" ]]; then
                            echo "✅ Remote Python consumer: $remote_script"
                            break
                        else
                            echo "❌ Remote script cannot be empty."
                        fi
                        ;;
                    2)
                        echo "✅ Multiple consumers chaining selected"
                        break
                        ;;
                    3)
                        echo "✅ Custom analysis pipeline selected"
                        break
                        ;;
                    *)
                        echo "❌ Invalid advanced option."
                        ;;
                esac
                ;;
            *)
                echo "❌ Invalid choice. Please enter 1-4"
                ;;
        esac
    done
    
    # Show comprehensive summary
    echo ""
    echo "======================================================================"
    echo "📊 COMPREHENSIVE SUMMARY"
    echo "======================================================================"
    echo "Input file: $LOG_FILE_PATH"
    echo "Output: ${custom_filename:-"Auto-generated"}"
    echo "Analysis: $analysis_choice"
    echo "Python consumer: $python_choice"
    echo "Verbose mode: $VERBOSE_MODE"
    echo "Force JSON: $FORCE_JSON"
    
    # Confirm execution
    echo ""
    echo "======================================================================"
    read -p "🚀 Start error management with these settings? (y/n): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        echo ""
        echo "🚀 Starting error management..."
        echo "======================================================================"
        
        # Process the log file
        if [[ -n "$LOG_FILE_PATH" ]]; then
            process_log_file "$LOG_FILE_PATH"
        else
            echo "❌ No log file specified"
            exit 1
        fi
    else
        echo "❌ Operation cancelled by user."
        echo "💡 Tip: Run the script again to restart with new settings."
    fi
}

################################################################################
# Function: process_log_file
# Description: Processes a log file and generates error reports
# Parameters: $1 - Log file path
# Returns: None
################################################################################
process_log_file() {
    local file_path="$1"
    
    log_message_with_timestamp "Processing log file: $file_path" "$SEVERITY_INFO"
    
    # Validate file
    if ! validate_file_existence_and_permissions "$file_path"; then
        log_message_with_timestamp "Skipping file due to validation failure: $file_path" "$SEVERITY_HIGH"
        return 1
    fi
    
    # Detect or use specified log format
    if [[ -z "$LOG_FORMAT" ]]; then
        LOG_FORMAT=$(detect_log_format_automatically "$file_path")
        log_message_with_timestamp "Auto-detected log format: $LOG_FORMAT" "$SEVERITY_INFO"
    else
        log_message_with_timestamp "Using specified log format: $LOG_FORMAT" "$SEVERITY_INFO"
    fi
    
    # Extract error patterns
    if ! extract_error_patterns_from_log "$file_path" "$LOG_FORMAT"; then
        log_message_with_timestamp "Error during pattern extraction for: $file_path" "$SEVERITY_HIGH"
        return 1
    fi
    
    # Generate output files
    current_date=$(date +"%m-%d")
    current_time=$(date +"%H%M")
    base_filename=$(basename "$file_path" .log)
    log_type=$(basename "$file_path" | cut -d'.' -f1)
    
    # Create output subdirectories
    mkdir -p "$OUTPUT_DIR/json"
    mkdir -p "$OUTPUT_DIR/csv"
    
    json_output_file="$OUTPUT_DIR/json/${log_type}_${current_date}_${current_time}.json"
    
    log_message_with_timestamp "Generating JSON report: $json_output_file" "$SEVERITY_INFO"
    
    # Generate JSON report
    generate_json_error_report "$json_output_file" "$file_path" "$LOG_FORMAT"
    
    # Verify JSON file was created
    if [[ -f "$json_output_file" ]]; then
        log_message_with_timestamp "JSON file confirmed created: $json_output_file" "$SEVERITY_INFO"
        
        # Also output JSON to stdout if redirecting (for backward compatibility)
        if [[ ! -t 1 ]]; then
            # stdout is redirected, also output JSON content
            cat "$json_output_file"
        fi
    else
        log_message_with_timestamp "WARNING: JSON file not found after generation: $json_output_file" "$SEVERITY_HIGH"
    fi
    
    # Generate CSV report if requested
    csv_output_file=""
    if [[ "$FORCE_JSON" == true ]] || [[ -n "${csv_report:-}" ]]; then
        csv_output_file="$OUTPUT_DIR/csv/${log_type}_${current_date}_${current_time}.csv"
        generate_csv_error_report "$csv_output_file" "$file_path" "$LOG_FORMAT"
    fi
    
    # Save local copies with host-based naming if this was remote processing
    if [[ "${REMOTE_PROCESSING_MODE:-false}" == true ]] && [[ -n "${SSH_CONNECTION:-}" ]]; then
        remote_host=$(echo "$SSH_CONNECTION" | cut -d':' -f1 | cut -d'@' -f2)
        remote_file=$(echo "$SSH_CONNECTION" | cut -d':' -f2-)
        save_local_copies "$remote_host" "$remote_file" "$json_output_file" "$csv_output_file"
    fi
    
    # Chain Python consumer for advanced analysis
    if command -v python3 >/dev/null 2>&1; then
        chain_python_consumer_processing "$json_output_file"
        
        # Send results back to remote host if this was remote processing
        if [[ "${REMOTE_PROCESSING_MODE:-false}" == true ]] && [[ -n "${SSH_CONNECTION:-}" ]]; then
            # Find the most recent advanced analysis file
            advanced_analysis_file="$OUTPUT_DIR/json/advanced_analysis_$(date +%m-%d_%H%M).json"
            if [[ -f "$advanced_analysis_file" ]]; then
                send_results_back_to_host "$SSH_CONNECTION" "$advanced_analysis_file"
            else
                # Fallback to original JSON report
                send_results_back_to_host "$SSH_CONNECTION" "$json_output_file"
            fi
        fi
    else
        log_message_with_timestamp "Python3 not available - skipping advanced analysis" "$SEVERITY_MEDIUM"
        
        # Send original JSON report back to remote host if this was remote processing
        if [[ "${REMOTE_PROCESSING_MODE:-false}" == true ]] && [[ -n "${SSH_CONNECTION:-}" ]]; then
            send_results_back_to_host "$SSH_CONNECTION" "$json_output_file"
        fi
    fi
    
    log_message_with_timestamp "Log processing completed successfully" "$SEVERITY_INFO"
    log_message_with_timestamp "Output files available in: $OUTPUT_DIR" "$SEVERITY_INFO"
}

################################################################################
# Function: cleanup_temporary_files
# Description: Cleans up temporary files and directories
# Parameters: None
# Returns: None
################################################################################
cleanup_temporary_files() {
    if [[ -d "$TEMPORARY_DIRECTORY" ]]; then
        # Securely remove all files in temporary directory
        find "$TEMPORARY_DIRECTORY" -type f -exec shred -f -z -n 3 {} \; 2>/dev/null || true
        rm -rf "$TEMPORARY_DIRECTORY"
        log_message_with_timestamp "Temporary files securely cleaned up" "$SEVERITY_INFO"
    fi
    
    # Clean up any remaining temporary files with predictable names
    local temp_files=($(find /tmp -name "remote_log_*" -user "$(whoami)" 2>/dev/null || true))
    for temp_file in "${temp_files[@]}"; do
        if [[ -f "$temp_file" ]]; then
            shred -f -z -n 3 "$temp_file" 2>/dev/null || true
            rm -f "$temp_file"
        fi
    done
}

################################################################################
# Function: create_secure_temporary_directory
# Description: Creates secure temporary directory with proper permissions
# Parameters: None
# Returns: None
################################################################################
create_secure_temporary_directory() {
    # Create temporary directory with secure permissions
    if [[ ! -d "$TEMPORARY_DIRECTORY" ]]; then
        mkdir -p "$TEMPORARY_DIRECTORY"
        chmod 700 "$TEMPORARY_DIRECTORY"
        log_message_with_timestamp "Created secure temporary directory: $TEMPORARY_DIRECTORY" "$SEVERITY_INFO"
    else
        # Ensure existing directory has correct permissions
        chmod 700 "$TEMPORARY_DIRECTORY"
    fi
    
    # Verify directory permissions
    local dir_perms=$(stat -c "%a" "$TEMPORARY_DIRECTORY" 2>/dev/null || stat -f "%A" "$TEMPORARY_DIRECTORY" 2>/dev/null || echo "unknown")
    if [[ "$dir_perms" == "700" ]]; then
        log_message_with_timestamp "Temporary directory permissions verified: $dir_perms" "$SEVERITY_INFO"
    else
        log_message_with_timestamp "Warning: Temporary directory permissions may be insecure: $dir_perms" "$SEVERITY_MEDIUM"
    fi
}

################################################################################
# Description: Initializes script environment and validates dependencies
# Parameters: None
# Returns: None
################################################################################
initialize_script_environment() {
    # Create secure temporary directory
    create_secure_temporary_directory
    
    # Check for required commands
    local required_commands=("grep" "wc" "head" "tail" "stat" "date" "ssh" "scp")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log_message_with_timestamp "Required command not found: $cmd" "$SEVERITY_CRITICAL"
            exit 1
        fi
    done
    
    # Check for optional commands
    local optional_commands=("python3")
    for cmd in "${optional_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log_message_with_timestamp "Optional command not available: $cmd (some features may be limited)" "$SEVERITY_MEDIUM"
        fi
    done
    
    log_message_with_timestamp "Script environment initialized successfully" "$SEVERITY_INFO"
}

################################################################################
# MAIN SCRIPT EXECUTION
################################################################################

# Initialize script environment
initialize_script_environment

# Set up signal handlers for cleanup
trap cleanup_temporary_files EXIT
trap 'log_message_with_timestamp "Script interrupted by user" "$SEVERITY_MEDIUM"; exit 1' INT TERM

# Parse command line arguments
SSH_CONNECTION=""
OUTPUT_DIR="$OUTPUT_DIRECTORY"
FORCE_JSON=false
VERBOSE_MODE=false
QUIET_MODE=false
LOG_FORMAT=""
INTERACTIVE_MODE=false
AUTO_MODE=false
LOG_FILES=()  # Array to store multiple log files

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            display_usage_information
            ;;
        -v|--version)
            echo "$SCRIPT_NAME version $SCRIPT_VERSION"
            exit 0
            ;;
        -s|--ssh)
            SSH_CONNECTION="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -f|--format)
            LOG_FORMAT="$2"
            shift 2
            ;;
        -j|--json)
            FORCE_JSON=true
            shift
            ;;
        --verbose)
            VERBOSE_MODE=true
            shift
            ;;
        --quiet)
            QUIET_MODE=true
            shift
            ;;
        --interactive)
            INTERACTIVE_MODE=true
            shift
            ;;
        --auto|-a)
            AUTO_MODE=true
            shift
            ;;
        -*)
            log_message_with_timestamp "Unknown option: $1" "$SEVERITY_HIGH"
            display_usage_information
            ;;
        *)
            # Collect log file paths - handle wildcards and multiple files
            if [[ -f "$1" ]]; then
                LOG_FILES+=("$1")
            elif [[ -d "$1" ]]; then
                log_message_with_timestamp "Skipping directory: $1 (use wildcards like $1/* to process files)" "$SEVERITY_MEDIUM"
            else
                # Try glob expansion for wildcards
                for file in $1; do
                    if [[ -f "$file" ]]; then
                        LOG_FILES+=("$file")
                    elif [[ "$file" == "$1" ]]; then
                        # No expansion happened, might be invalid path
                        log_message_with_timestamp "Warning: File not found: $1" "$SEVERITY_MEDIUM"
                    fi
                done
            fi
            shift
            ;;
    esac
done

# Create output directory
create_output_directory_structure "$OUTPUT_DIR"

# Main processing logic
if [[ "$INTERACTIVE_MODE" == true ]]; then
    log_message_with_timestamp "Running in interactive mode" "$SEVERITY_INFO"
    run_interactive_mode
elif [[ "$AUTO_MODE" == true ]]; then
    log_message_with_timestamp "Running in automated mode" "$SEVERITY_INFO"
    run_auto_mode
elif [[ -n "$SSH_CONNECTION" ]]; then
    log_message_with_timestamp "Processing remote log via SSH" "$SEVERITY_INFO"
    REMOTE_LOG_FILE=$(setup_ssh_remote_processing "$SSH_CONNECTION")
    if [[ $? -eq 0 ]]; then
        LOG_FILE_PATH="$REMOTE_LOG_FILE"
        REMOTE_PROCESSING_MODE=true
    else
        log_message_with_timestamp "Failed to setup remote processing" "$SEVERITY_CRITICAL"
        exit 1
    fi
fi

# Process log files - handle single or multiple files
if [[ ${#LOG_FILES[@]} -gt 0 ]]; then
    # Multiple files - process each one using process_log_file function
    for log_file in "${LOG_FILES[@]}"; do
        if [[ -f "$log_file" ]]; then
            process_log_file "$log_file"
        else
            log_message_with_timestamp "Skipping invalid file: $log_file" "$SEVERITY_MEDIUM"
        fi
    done
elif [[ -n "$LOG_FILE_PATH" ]]; then
    # Single file - use existing LOG_FILE_PATH logic
    log_message_with_timestamp "Processing log file: $LOG_FILE_PATH" "$SEVERITY_INFO"
    
    # Validate file
    if ! validate_file_existence_and_permissions "$LOG_FILE_PATH"; then
        exit 1
    fi
    
    # Detect or use specified log format
    if [[ -z "$LOG_FORMAT" ]]; then
        LOG_FORMAT=$(detect_log_format_automatically "$LOG_FILE_PATH")
        log_message_with_timestamp "Auto-detected log format: $LOG_FORMAT" "$SEVERITY_INFO"
    else
        log_message_with_timestamp "Using specified log format: $LOG_FORMAT" "$SEVERITY_INFO"
    fi
    
    # Extract error patterns
    extract_error_patterns_from_log "$LOG_FILE_PATH" "$LOG_FORMAT"
    
    # Generate output files with better segregation
    current_date=$(date +"%m-%d")
    current_time=$(date +"%H%M")
    base_filename=$(basename "$LOG_FILE_PATH" .log)
    log_type=$(basename "$LOG_FILE_PATH" | cut -d'.' -f1)
    json_output_file="$OUTPUT_DIR/json/${log_type}_${current_date}_${current_time}.json"
    
    # Generate JSON report
    generate_json_error_report "$json_output_file" "$LOG_FILE_PATH" "$LOG_FORMAT"
    
    # Also output JSON to stdout if redirecting (for backward compatibility)
    if [[ ! -t 1 ]]; then
        # stdout is redirected, also output JSON content
        cat "$json_output_file"
    fi
    
    # Generate CSV report if requested
    csv_output_file=""
    if [[ "$FORCE_JSON" == true ]] || [[ -n "${csv_report:-}" ]]; then
        csv_output_file="$OUTPUT_DIR/csv/${log_type}_${current_date}_${current_time}.csv"
        generate_csv_error_report "$csv_output_file" "$LOG_FILE_PATH" "$LOG_FORMAT"
    fi
    
    # Save local copies with host-based naming if this was remote processing
    if [[ "${REMOTE_PROCESSING_MODE:-false}" == true ]] && [[ -n "${SSH_CONNECTION:-}" ]]; then
        remote_host=$(echo "$SSH_CONNECTION" | cut -d':' -f1 | cut -d'@' -f2)
        remote_file=$(echo "$SSH_CONNECTION" | cut -d':' -f2-)
        save_local_copies "$remote_host" "$remote_file" "$json_output_file" "$csv_output_file"
    fi
    
    # Chain Python consumer for advanced analysis
    if command -v python3 >/dev/null 2>&1; then
        chain_python_consumer_processing "$json_output_file"
        
        # Send results back to remote host if this was remote processing
        if [[ "${REMOTE_PROCESSING_MODE:-false}" == true ]] && [[ -n "${SSH_CONNECTION:-}" ]]; then
            # Find the most recent advanced analysis file
            advanced_analysis_file="$OUTPUT_DIR/json/advanced_analysis_$(date +%m-%d_%H%M).json"
            if [[ -f "$advanced_analysis_file" ]]; then
                send_results_back_to_host "$SSH_CONNECTION" "$advanced_analysis_file"
            else
                # Fallback to original JSON report
                send_results_back_to_host "$SSH_CONNECTION" "$json_output_file"
            fi
        fi
    else
        log_message_with_timestamp "Python3 not available - skipping advanced analysis" "$SEVERITY_MEDIUM"
        
        # Send original JSON report back to remote host if this was remote processing
        if [[ "${REMOTE_PROCESSING_MODE:-false}" == true ]] && [[ -n "${SSH_CONNECTION:-}" ]]; then
            send_results_back_to_host "$SSH_CONNECTION" "$json_output_file"
        fi
    fi
    
    log_message_with_timestamp "Log processing completed successfully" "$SEVERITY_INFO"
    log_message_with_timestamp "Output files available in: $OUTPUT_DIR" "$SEVERITY_INFO"
    
elif [[ "$INTERACTIVE_MODE" != true ]]; then
    log_message_with_timestamp "No log file specified and not in interactive mode" "$SEVERITY_HIGH"
    log_message_with_timestamp "Use --interactive for guided setup or specify a log file" "$SEVERITY_INFO"
    display_usage_information
fi

# Final cleanup and summary
log_message_with_timestamp "CA Error Manager Script execution completed" "$SEVERITY_INFO"
log_message_with_timestamp "Check $OUTPUT_DIR for analysis results" "$SEVERITY_INFO"
