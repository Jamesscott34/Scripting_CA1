#!/usr/bin/env python3
"""
CA Error Consumer

Basic error report analysis and processing tool

This programme provides essential error analysis capabilities:

- JSON error report analysis

- Statistical analysis of errors

- Pattern recognition

- Alert generation

- Recommendations

- Results export to JSON

- Report comparison and trend analysis

Author: SBA2400 James Scott

Dependencies: json, datetime, collections, argparse, re, hashlib

Usage Examples:

    python3 CA_error_consumer.py error_report.json

    python3 CA_error_consumer.py error_report.json --output analysis_results.json

    python3 CA_error_consumer.py error_report.json --alerts-only

    python3 CA_error_consumer.py error_report.json --severity-filter HIGH,CRITICAL

    python3 CA_error_consumer.py error_report.json --compare old_report.json

    python3 CA_error_consumer.py error_report.json --compare old_report.json --compare-output comparison.json

    python3 CA_error_consumer.py --interactive  # Interactive mode
"""

import json
import sys
import os
import argparse
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, List, Any, Optional
import hashlib


class CAErrorReportConsumer:
    """
    Simplified Error Report Analysis and Processing class

    This class provides basic analysis of JSON error reports, including
    statistical analysis, pattern recognition, alert generation, and
    recommendation systems.
    """

    def __init__(self, json_file_path: str):
        """
        Initialize the CA Error Report Consumer

        Args:
            json_file_path (str): Path to the JSON error report file
        """
        self.json_file_path = json_file_path
        self.report_data = None
        self.analysis_results = {}
        self.load_report_data()

    def load_report_data(self) -> None:
        """
        Load and parse JSON error report from file

        Raises:
            SystemExit: If file cannot be loaded or parsed
        """
        try:
            with open(self.json_file_path, "r", encoding="utf-8") as file:
                self.report_data = json.load(file)
            print(f"✅ Successfully loaded error report: {self.json_file_path}")
            # Validate report structure
            if not self.validate_report_structure():
                raise ValueError("Invalid report structure")
        except FileNotFoundError:
            print(f"❌ Error: Report file not found: {self.json_file_path}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"❌ Error: Invalid JSON format in report: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error loading report: {e}")
            sys.exit(1)

    def validate_report_structure(self) -> bool:
        """
        Validate that the loaded report has the expected structure

        Returns:
            bool: True if structure is valid, False otherwise
        """
        try:
            # Check for required top-level keys
            if "error_analysis_report" not in self.report_data:
                # Try alternative structure with errors_by_severity
                if "errors_by_severity" in self.report_data:
                    return True
                print("❌ Error: Missing 'error_analysis_report' key in JSON")
                return False

            report = self.report_data["error_analysis_report"]
            # Check for either error_entries or errors_by_severity
            if "error_entries" not in report and "errors_by_severity" not in report:
                print("❌ Error: Missing 'error_entries' or 'errors_by_severity' in report")
                return False

            return True
        except Exception as e:
            print(f"❌ Error validating report structure: {e}")
            return False

    def generate_statistical_analysis(self) -> Dict[str, Any]:
        """
        Generate comprehensive statistical analysis of errors
        
        This function performs all statistical calculations that were moved from bash script.
        It calculates distributions, percentages, and advanced metrics.

        Returns:
            Dict[str, Any]: Statistical analysis results
        """
        if not self.report_data:
            return {}

        try:
            # Support both structure formats
            error_report = self.report_data.get("error_analysis_report", {})
            errors_by_severity = self.report_data.get("errors_by_severity", {})
            
            # Get error entries - support both formats
            error_entries = []
            if error_report.get("error_entries"):
                error_entries = error_report.get("error_entries", [])
            elif errors_by_severity:
                # Flatten errors_by_severity structure
                for severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                    error_entries.extend(errors_by_severity.get(severity, []))

            malformed_entries = error_report.get("malformed_entries", [])

            # Count errors by severity - Python handles all statistical calculations
            severity_counts = Counter()
            category_counts = Counter()
            
            for entry in error_entries:
                severity = entry.get("severity", "UNKNOWN")
                category = entry.get("category", "error")
                severity_counts[severity] += 1
                category_counts[category] += 1

            # Calculate percentages and distributions
            total_errors = len(error_entries)
            severity_distribution = {}
            severity_percentages = {}
            
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                count = severity_counts.get(severity, 0)
                percentage = (count / total_errors * 100) if total_errors > 0 else 0
                severity_distribution[severity.lower()] = count
                severity_percentages[severity] = round(percentage, 2)

            # Analyze error patterns - Python's sophisticated analysis
            error_patterns = self.analyze_error_patterns(error_entries)

            # Source analysis - Python identifies services from content
            source_analysis = self.analyze_error_sources(error_entries)

            # Category analysis with percentages
            category_distribution = {}
            category_percentages = {}
            for category in ["security", "performance", "connectivity", "error"]:
                count = category_counts.get(category, 0)
                percentage = (count / total_errors * 100) if total_errors > 0 else 0
                category_distribution[category] = count
                category_percentages[category] = round(percentage, 2)

            return {
                "severity_distribution": severity_distribution,
                "severity_percentages": severity_percentages,
                "category_distribution": category_distribution,
                "category_percentages": category_percentages,
                "error_patterns": error_patterns,
                "source_analysis": source_analysis,
                "total_errors": total_errors,
                "total_malformed": len(malformed_entries),
                "malformed_analysis": self.analyze_malformed_entries(malformed_entries),
                "statistical_metadata": {
                    "calculated_by": "Python consumer",
                    "calculation_timestamp": datetime.now().isoformat(),
                },
            }

        except Exception as e:
            print(f"❌ Error generating statistical analysis: {e}")
            return {}

    def analyze_error_patterns(self, error_entries: List[Dict]) -> Dict[str, int]:
        """
        Analyze error patterns - uses existing category from bash and adds detailed sub-patterns

        This function leverages the basic categorization done by bash (security/performance/connectivity)
        and adds more detailed pattern analysis for advanced insights.

        Args:
            error_entries (List[Dict]): List of error entry dictionaries

        Returns:
            Dict[str, int]: Pattern analysis results
        """
        patterns = defaultdict(int)
        
        # Use existing category from bash categorization (avoids duplication)
        category_counts = Counter(entry.get("category", "error") for entry in error_entries)
        
        # Basic categories from bash are already available
        for category, count in category_counts.items():
            if category in ["security", "performance", "connectivity"]:
                patterns[f"{category}_issues"] = count

        # Add detailed sub-pattern analysis only for additional insights
        # (not duplicating what bash already categorized)
        for entry in error_entries:
            content = entry.get("content", "").lower()
            category = entry.get("category", "error")
            
            # Only do additional analysis for entries not well-categorized
            # or to add sub-pattern details
            if category == "error" or category == "":
                # Network and connectivity issues (only if not already categorized)
                if any(keyword in content for keyword in ["connection", "connect", "network", "timeout", "refused"]):
                    patterns["network_connectivity"] += 1
                
                # Permission and access issues
                if any(keyword in content for keyword in ["permission", "denied", "access", "unauthorized", "forbidden"]):
                    patterns["permission_access"] += 1
                
                # Resource issues
                if any(keyword in content for keyword in ["memory", "disk", "space", "resource", "out of"]):
                    patterns["resource_issues"] += 1
                
                # Authentication issues (can be sub-pattern of security)
                if any(keyword in content for keyword in ["authentication", "login", "password", "credential", "auth"]):
                    patterns["authentication_issues"] += 1
                
                # Database issues
                if any(keyword in content for keyword in ["database", "sql", "query", "table", "connection pool"]):
                    patterns["database_issues"] += 1
            
            # Add detailed sub-patterns for already-categorized entries
            # (provides additional insights without duplicating basic categorization)
            if category == "security":
                # Security sub-patterns
                if any(keyword in content for keyword in ["authentication", "login", "password"]):
                    patterns["authentication_failures"] += 1
                if any(keyword in content for keyword in ["firewall", "blocked", "intrusion", "attack"]):
                    patterns["intrusion_attempts"] += 1
            elif category == "performance":
                # Performance sub-patterns
                if any(keyword in content for keyword in ["memory", "disk", "space"]):
                    patterns["resource_constraints"] += 1
            elif category == "connectivity":
                # Connectivity sub-patterns
                if any(keyword in content for keyword in ["timeout", "refused", "connection"]):
                    patterns["connection_failures"] += 1

        return dict(patterns)

    def analyze_error_sources(self, error_entries: List[Dict]) -> Dict[str, int]:
        """
        Analyze error sources and services

        Args:
            error_entries (List[Dict]): List of error entry dictionaries

        Returns:
            Dict[str, int]: Source analysis results
        """
        sources = defaultdict(int)

        for entry in error_entries:
            content = entry.get("content", "")

            # Common service identifiers
            if "sshd" in content.lower():
                sources["ssh_daemon"] += 1
            elif "apache" in content.lower() or "httpd" in content.lower():
                sources["apache_web_server"] += 1
            elif "nginx" in content.lower():
                sources["nginx_web_server"] += 1
            elif "mysql" in content.lower() or "mariadb" in content.lower():
                sources["mysql_database"] += 1
            elif "postgresql" in content.lower() or "postgres" in content.lower():
                sources["postgresql_database"] += 1
            elif "kernel" in content.lower():
                sources["kernel"] += 1
            elif "systemd" in content.lower():
                sources["systemd"] += 1
            elif "docker" in content.lower():
                sources["docker"] += 1
            elif "fail2ban" in content.lower():
                sources["fail2ban"] += 1
            elif "redis" in content.lower():
                sources["redis_cache"] += 1
            elif "mongodb" in content.lower() or "mongo" in content.lower():
                sources["mongodb_database"] += 1
            elif "elasticsearch" in content.lower():
                sources["elasticsearch"] += 1
            elif "rabbitmq" in content.lower():
                sources["rabbitmq_message_broker"] += 1
            elif "kafka" in content.lower():
                sources["kafka_message_broker"] += 1
            elif "jenkins" in content.lower():
                sources["jenkins_ci_cd"] += 1
            elif "gitlab" in content.lower():
                sources["gitlab_version_control"] += 1
            elif "prometheus" in content.lower():
                sources["prometheus_monitoring"] += 1
            elif "grafana" in content.lower():
                sources["grafana_dashboard"] += 1
            elif "vault" in content.lower():
                sources["hashicorp_vault"] += 1
            else:
                sources["unknown_source"] += 1

        return dict(sources)

    def analyze_malformed_entries(self, malformed_entries: List[Dict]) -> Dict[str, Any]:
        """
        Analyze malformed log entries

        Args:
            malformed_entries (List[Dict]): List of malformed entry dictionaries

        Returns:
            Dict[str, Any]: Malformed entry analysis
        """
        if not malformed_entries:
            return {"total": 0, "issues": {}}

        issues = defaultdict(int)
        for entry in malformed_entries:
            issue_type = entry.get("issue_type", "unknown")
            issues[issue_type] += 1

        error_report = self.report_data.get("error_analysis_report", {})
        total_errors = len(error_report.get("error_entries", []))
        total_malformed = len(malformed_entries)
        total_all = total_malformed + total_errors
        percentage = (total_malformed / total_all) * 100 if total_all else 0

        return {"total": total_malformed, "issues": dict(issues), "percentage_of_total": percentage}

    def generate_alert_conditions(self) -> List[Dict[str, Any]]:
        """
        Generate alert conditions based on analysis results

        Returns:
            List[Dict[str, Any]]: List of alert conditions
        """
        stats = self.generate_statistical_analysis()
        alerts = []

        if not stats:
            return alerts

        # Critical error threshold
        critical_count = stats["severity_distribution"].get("CRITICAL", 0)
        if critical_count > 5:
            alerts.append(
                {
                    "type": "CRITICAL_ERROR_SPIKE",
                    "severity": "CRITICAL",
                    "message": f"High number of critical errors detected: {critical_count}",
                    "count": critical_count,
                    "threshold": 5,
                    "recommendation": "Immediate investigation required for critical system errors",
                }
            )

        # High error threshold
        high_count = stats["severity_distribution"].get("HIGH", 0)
        if high_count > 20:
            alerts.append(
                {
                    "type": "HIGH_ERROR_VOLUME",
                    "severity": "HIGH",
                    "message": f"High volume of high-severity errors: {high_count}",
                    "count": high_count,
                    "threshold": 20,
                    "recommendation": "Review system configuration and investigate error sources",
                }
            )

        # Pattern-based alerts - uses category distribution from bash (avoids duplication)
        category_dist = stats.get("category_distribution", {})
        
        # Use bash's category classification for basic alerts
        if category_dist.get("connectivity", 0) > 15:
            alerts.append(
                {
                    "type": "NETWORK_CONNECTIVITY_ISSUES",
                    "severity": "HIGH",
                    "message": f'Multiple network connectivity errors: {category_dist["connectivity"]}',
                    "count": category_dist["connectivity"],
                    "threshold": 15,
                    "recommendation": "Check network configuration, DNS resolution, and service availability",
                }
            )

        if category_dist.get("performance", 0) > 8:
            alerts.append(
                {
                    "type": "RESOURCE_CONSTRAINTS",
                    "severity": "MEDIUM",
                    "message": f'Resource-related errors detected: {category_dist["performance"]}',
                    "count": category_dist["performance"],
                    "threshold": 8,
                    "recommendation": "Monitor system resources (CPU, memory, disk space) and consider scaling",
                }
            )
        
        # Additional detailed pattern alerts (sub-patterns not covered by basic categories)
        patterns = stats.get("error_patterns", {})
        if patterns.get("authentication_failures", 0) > 10:
            alerts.append(
                {
                    "type": "AUTHENTICATION_PROBLEMS",
                    "severity": "HIGH",
                    "message": f'Multiple authentication failures: {patterns["authentication_failures"]}',
                    "count": patterns["authentication_failures"],
                    "threshold": 10,
                    "recommendation": "Review user accounts, password policies, and authentication mechanisms",
                }
            )

        # Malformed entries alert
        malformed_analysis = stats.get("malformed_analysis", {})
        if malformed_analysis.get("total", 0) > 20:
            alerts.append(
                {
                    "type": "MALFORMED_LOG_ENTRIES",
                    "severity": "MEDIUM",
                    "message": f'High number of malformed log entries: {malformed_analysis["total"]}',
                    "count": malformed_analysis["total"],
                    "threshold": 20,
                    "recommendation": "Check log rotation configuration and application logging standards",
                }
            )

        return alerts

    def generate_recommendations(self) -> List[str]:
        """
        Generate actionable recommendations based on analysis

        Returns:
            List[str]: List of recommendations
        """
        stats = self.generate_statistical_analysis()
        recommendations = []

        if not stats:
            return ["Unable to generate recommendations - analysis failed"]

        # Severity-based recommendations
        severity_dist = stats.get("severity_distribution", {})
        if severity_dist.get("CRITICAL", 0) > 0:
            recommendations.append("🚨 IMMEDIATE ACTION: Investigate critical errors - system stability may be compromised")
        if severity_dist.get("HIGH", 0) > 10:
            recommendations.append("⚠️  HIGH PRIORITY: Review system configuration for high-severity errors")

        # Pattern-based recommendations - uses category distribution from bash (avoids duplication)
        category_dist = stats.get("category_distribution", {})
        
        # Use bash's category classification for basic recommendations (avoids duplication)
        if category_dist.get("connectivity", 0) > 5:
            recommendations.append("🌐 NETWORK: Check network connectivity, DNS resolution, and firewall rules")
        if category_dist.get("security", 0) > 5:
            recommendations.append("🛡️  SECURITY: Review security policies, intrusion detection, and access controls")
        if category_dist.get("performance", 0) > 3:
            recommendations.append("💾 RESOURCES: Monitor system resources and consider capacity planning")
        
        # Additional detailed pattern recommendations (sub-patterns not covered by basic categories)
        patterns = stats.get("error_patterns", {})
        if patterns.get("authentication_failures", 0) > 3:
            recommendations.append("👤 AUTHENTICATION: Review user accounts, password policies, and authentication logs")
        if patterns.get("database_issues", 0) > 2:
            recommendations.append("🗄️  DATABASE: Check database connectivity, query performance, and connection pools")
        if patterns.get("permission_access", 0) > 5:
            recommendations.append("🔐 PERMISSIONS: Review file permissions, user access controls, and SELinux policies")

        # Source-based recommendations
        sources = stats.get("source_analysis", {})
        if sources.get("ssh_daemon", 0) > 10:
            recommendations.append("🔑 SSH: Review SSH configuration, key management, and failed login attempts")
        if sources.get("apache_web_server", 0) > 5 or sources.get("nginx_web_server", 0) > 5:
            recommendations.append("🌐 WEB SERVER: Check web server configuration, SSL certificates, and application errors")
        if sources.get("mysql_database", 0) > 5 or sources.get("postgresql_database", 0) > 5:
            recommendations.append("🗄️  DATABASE: Review database configuration, connection pooling, and query performance")
        if sources.get("redis_cache", 0) > 3:
            recommendations.append("⚡ REDIS: Check Redis configuration, memory usage, and connection limits")
        if sources.get("mongodb_database", 0) > 3:
            recommendations.append("🍃 MONGODB: Review MongoDB configuration, replica set status, and disk space")
        if sources.get("elasticsearch", 0) > 3:
            recommendations.append("🔍 ELASTICSEARCH: Check cluster health, index status, and disk space")
        if sources.get("rabbitmq_message_broker", 0) > 3 or sources.get("kafka_message_broker", 0) > 3:
            recommendations.append("📨 MESSAGE BROKER: Review queue status, consumer lag, and broker configuration")
        if sources.get("jenkins_ci_cd", 0) > 3:
            recommendations.append("🔧 JENKINS: Check build pipeline status, job failures, and resource usage")
        if sources.get("gitlab_version_control", 0) > 3:
            recommendations.append("📚 GITLAB: Review repository status, CI/CD pipelines, and backup procedures")
        if sources.get("prometheus_monitoring", 0) > 3:
            recommendations.append("📊 PROMETHEUS: Check monitoring targets, alert rules, and storage retention")
        if sources.get("grafana_dashboard", 0) > 3:
            recommendations.append("📈 GRAFANA: Review dashboard performance, data source connectivity, and user access")
        if sources.get("hashicorp_vault", 0) > 3:
            recommendations.append("🔐 VAULT: Check secret engine status, authentication methods, and audit logs")
        if sources.get("docker", 0) > 5:
            recommendations.append("🐳 DOCKER: Review container health, resource usage, and registry connectivity")

        # Malformed entries recommendations
        malformed = stats.get("malformed_analysis", {})
        if malformed.get("total", 0) > 10:
            recommendations.append("📝 LOGGING: Review log format standards and application logging configuration")

        if not recommendations:
            recommendations.append("✅ SYSTEM STATUS: No immediate action required - system appears stable")

        return recommendations

    def export_analysis_results(self, output_file: str) -> Dict[str, Any]:
        """
        Export analysis results to JSON file

        Args:
            output_file (str): Path to output file

        Returns:
            Dict[str, Any]: Analysis results dictionary
        """
        try:
            stats = self.generate_statistical_analysis()
            alerts = self.generate_alert_conditions()
            recommendations = self.generate_recommendations()

            # Add enhanced summary statistics to match bash format expectations
            enhanced_stats = stats.copy()
            if "error_severity_distribution" not in enhanced_stats:
                # Add severity distribution in bash-compatible format
                enhanced_stats["error_severity_distribution"] = stats.get("severity_distribution", {})
            
            results = {
                "analysis_metadata": {
                    "analysis_timestamp": datetime.now().isoformat(),
                    "source_report": self.json_file_path,
                    "analyzer_version": "1.0.0",
                    "analysis_duration_seconds": 0,
                    "note": "All statistical calculations performed by Python consumer",
                },
                "statistical_analysis": enhanced_stats,
                "alert_conditions": alerts,
                "recommendations": recommendations,
                "summary": {
                    "total_alerts": len(alerts),
                    "critical_alerts": len([a for a in alerts if a.get("severity") == "CRITICAL"]),
                    "high_alerts": len([a for a in alerts if a.get("severity") == "HIGH"]),
                    "total_recommendations": len(recommendations),
                    "total_errors": stats.get("total_errors", 0),
                },
            }

            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)

            print(f"✅ Analysis results exported to: {output_file}")
            return results

        except Exception as e:
            print(f"❌ Error exporting analysis results: {e}")
            return {}

    def print_summary_report(self, severity_filter: Optional[List[str]] = None) -> None:
        """
        Print a formatted summary report to console

        Args:
            severity_filter (Optional[List[str]]): Filter alerts by severity levels
        """
        stats = self.generate_statistical_analysis()
        alerts = self.generate_alert_conditions()
        recommendations = self.generate_recommendations()

        # Apply severity filter if specified
        if severity_filter:
            alerts = [a for a in alerts if a.get("severity") in severity_filter]

        print("\n" + "=" * 80)
        print("🔍 CA ERROR ANALYSIS REPORT")
        print("=" * 80)

        # Summary statistics
        print("\n📊 SUMMARY STATISTICS:")
        print(f"  Total Errors: {stats.get('total_errors', 0)}")
        print(f"  Total Malformed Entries: {stats.get('total_malformed', 0)}")

        # Severity distribution
        print("\n📈 SEVERITY DISTRIBUTION:")
        severity_dist = stats.get("severity_distribution", {})
        for severity, count in sorted(severity_dist.items()):
            print(f"  {severity}: {count}")

        # Error patterns
        print("\n🔍 ERROR PATTERNS:")
        patterns = stats.get("error_patterns", {})
        for pattern, count in sorted(patterns.items(), key=lambda x: x[1], reverse=True):
            if count > 0:
                print(f"  {pattern.replace('_', ' ').title()}: {count}")

        # Error sources
        print("\n🏢 ERROR SOURCES:")
        sources = stats.get("source_analysis", {})
        for source, count in sorted(sources.items(), key=lambda x: x[1], reverse=True):
            if count > 0:
                print(f"  {source.replace('_', ' ').title()}: {count}")

        # Alerts
        if alerts:
            print(f"\n🚨 ALERT CONDITIONS ({len(alerts)} total):")
            for alert in alerts:
                severity_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(alert.get("severity"), "⚪")
                print(f"  {severity_emoji} {alert['type']}: {alert['message']}")
        else:
            print("\n✅ NO ALERT CONDITIONS DETECTED")

        # Recommendations
        print(f"\n💡 RECOMMENDATIONS ({len(recommendations)} total):")
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")

        print("\n" + "=" * 80)

    def print_alerts(self) -> None:
        """Print alerts to stdout (for --alerts-only mode)"""
        alerts = self.generate_alert_conditions()

        if not alerts:
            print("✅ No alerts generated - no critical issues detected")
            return

        print("=" * 80)
        print("🚨 ALERT SUMMARY")
        print("=" * 80)
        print()

        for alert in alerts:
            severity = alert.get("severity", "UNKNOWN")
            alert_type = alert.get("type", "unknown")
            message = alert.get("message", "No message")
            count = alert.get("count", 0)

            severity_symbol = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")

            print(f"{severity_symbol} [{severity}] {alert_type}")
            print(f"   {message}")
            print(f"   Count: {count}")
            print()

        print("=" * 80)

    def _hash_content(self, content: str) -> str:
        """
        Create a hash of error content for comparison

        Args:
            content (str): Error content string

        Returns:
            str: SHA256 hash of the content
        """
        return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]

    def compare_reports(self, other_report_path: str) -> Dict[str, Any]:
        """
        Compare two error reports to identify persistent issues and trends

        Args:
            other_report_path (str): Path to the other JSON error report file

        Returns:
            Dict[str, Any]: Comparison analysis results
        """
        try:
            # Load the other report
            with open(other_report_path, "r", encoding="utf-8") as file:
                other_report_data = json.load(file)

            # Get errors from current report
            error_report = self.report_data.get("error_analysis_report", {})
            errors_by_severity_current = self.report_data.get("errors_by_severity", {})
            
            # Support both formats for current report
            current_errors = []
            if error_report.get("error_entries"):
                current_errors = error_report.get("error_entries", [])
            elif errors_by_severity_current:
                for severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                    current_errors.extend(errors_by_severity_current.get(severity, []))

            # Get errors from other report
            other_error_report = other_report_data.get("error_analysis_report", {})
            errors_by_severity_other = other_report_data.get("errors_by_severity", {})
            
            other_errors = []
            if other_error_report.get("error_entries"):
                other_errors = other_error_report.get("error_entries", [])
            elif errors_by_severity_other:
                for severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                    other_errors.extend(errors_by_severity_other.get(severity, []))

            # Create content hashes for comparison
            current_hashes = {self._hash_content(e.get("content", "")): e for e in current_errors}
            other_hashes = {self._hash_content(e.get("content", "")): e for e in other_errors}

            # Find persistent errors (exist in both reports)
            persistent_hashes = set(current_hashes.keys()) & set(other_hashes.keys())
            persistent_errors = [current_hashes[h] for h in persistent_hashes]

            # Find new errors (only in current report)
            new_hashes = set(current_hashes.keys()) - set(other_hashes.keys())
            new_errors = [current_hashes[h] for h in new_hashes]

            # Find resolved errors (only in other report)
            resolved_hashes = set(other_hashes.keys()) - set(current_hashes.keys())
            resolved_errors = [other_hashes[h] for h in resolved_hashes]

            # Compare severity distributions
            current_severity = Counter(e.get("severity", "UNKNOWN") for e in current_errors)
            other_severity = Counter(e.get("severity", "UNKNOWN") for e in other_errors)

            # Calculate trends
            severity_trends = {}
            all_severities = set(current_severity.keys()) | set(other_severity.keys())
            for severity in all_severities:
                current_count = current_severity.get(severity, 0)
                other_count = other_severity.get(severity, 0)
                difference = current_count - other_count
                percent_change = ((current_count - other_count) / other_count * 100) if other_count > 0 else 0
                severity_trends[severity] = {
                    "current": current_count,
                    "previous": other_count,
                    "difference": difference,
                    "percent_change": round(percent_change, 2),
                    "trend": "increasing" if difference > 0 else "decreasing" if difference < 0 else "stable",
                }

            # Compare error patterns
            current_patterns = self.analyze_error_patterns(current_errors)
            other_patterns = self.analyze_error_patterns(other_errors)

            pattern_trends = {}
            all_patterns = set(current_patterns.keys()) | set(other_patterns.keys())
            for pattern in all_patterns:
                current_count = current_patterns.get(pattern, 0)
                other_count = other_patterns.get(pattern, 0)
                difference = current_count - other_count
                pattern_trends[pattern] = {
                    "current": current_count,
                    "previous": other_count,
                    "difference": difference,
                    "trend": "increasing" if difference > 0 else "decreasing" if difference < 0 else "stable",
                }

            # Calculate overall similarity
            total_current = len(current_errors)
            total_other = len(other_errors)
            total_common = len(persistent_errors)

            similarity_score = (total_common / max(total_current, total_other) * 100) if max(total_current, total_other) > 0 else 0

            return {
                "comparison_metadata": {
                    "current_report": self.json_file_path,
                    "previous_report": other_report_path,
                    "comparison_timestamp": datetime.now().isoformat(),
                    "similarity_score": round(similarity_score, 2),
                },
                "error_comparison": {
                    "current_total": total_current,
                    "previous_total": total_other,
                    "persistent_errors": len(persistent_errors),
                    "new_errors": len(new_errors),
                    "resolved_errors": len(resolved_errors),
                    "persistent_error_details": persistent_errors[:10],
                    "new_error_details": new_errors[:10],
                    "resolved_error_details": resolved_errors[:10],
                },
                "severity_trends": severity_trends,
                "pattern_trends": pattern_trends,
                "summary": {
                    "overall_similarity_percent": round(similarity_score, 2),
                    "errors_increased": total_current > total_other,
                    "errors_decreased": total_current < total_other,
                    "errors_unchanged": total_current == total_other,
                    "net_change": total_current - total_other,
                    "percent_change": round(((total_current - total_other) / total_other * 100) if total_other > 0 else 0, 2),
                },
            }

        except FileNotFoundError:
            print(f"❌ Error: Comparison report file not found: {other_report_path}")
            return {}
        except json.JSONDecodeError as e:
            print(f"❌ Error: Invalid JSON format in comparison report: {e}")
            return {}
        except Exception as e:
            print(f"❌ Error during comparison: {e}")
            return {}

    def print_comparison_report(self, comparison_results: Dict[str, Any]) -> None:
        """
        Print a formatted comparison report to console

        Args:
            comparison_results (Dict[str, Any]): Comparison analysis results
        """
        if not comparison_results:
            print("❌ No comparison data available")
            return

        metadata = comparison_results.get("comparison_metadata", {})
        error_comp = comparison_results.get("error_comparison", {})
        severity_trends = comparison_results.get("severity_trends", {})
        pattern_trends = comparison_results.get("pattern_trends", {})
        summary = comparison_results.get("summary", {})

        print("\n" + "=" * 80)
        print("📊 REPORT COMPARISON ANALYSIS")
        print("=" * 80)

        # Metadata
        print("\n📁 COMPARISON METADATA:")
        print(f"  Current Report: {metadata.get('current_report', 'N/A')}")
        print(f"  Previous Report: {metadata.get('previous_report', 'N/A')}")
        print(f"  Similarity Score: {metadata.get('similarity_score', 0)}%")

        # Error comparison
        print("\n📈 ERROR COMPARISON:")
        print(f"  Current Total: {error_comp.get('current_total', 0)}")
        print(f"  Previous Total: {error_comp.get('previous_total', 0)}")
        print(f"  Persistent Errors: {error_comp.get('persistent_errors', 0)} (appeared in both reports)")
        print(f"  New Errors: {error_comp.get('new_errors', 0)} (only in current)")
        print(f"  Resolved Errors: {error_comp.get('resolved_errors', 0)} (only in previous)")

        # Summary trends
        print("\n📊 OVERALL TRENDS:")
        net_change = summary.get("net_change", 0)
        percent_change = summary.get("percent_change", 0)

        if summary.get("errors_increased"):
            print(f"  ⚠️  Error count INCREASED by {net_change} ({percent_change}%)")
        elif summary.get("errors_decreased"):
            print(f"  ✅ Error count DECREASED by {abs(net_change)} ({abs(percent_change)}%)")
        else:
            print(f"  ➡️  Error count UNCHANGED")

        # Severity trends
        if severity_trends:
            print("\n🎯 SEVERITY TRENDS:")
            for severity, trend_data in sorted(severity_trends.items()):
                diff = trend_data.get("difference", 0)
                trend = trend_data.get("trend", "stable")
                emoji = "📈" if trend == "increasing" else "📉" if trend == "decreasing" else "➡️"
                print(f"  {emoji} {severity}: {trend_data.get('current', 0)} (was {trend_data.get('previous', 0)}, {diff:+d})")

        # Pattern trends
        if pattern_trends:
            print("\n🔍 PATTERN TRENDS:")
            for pattern, trend_data in sorted(pattern_trends.items(), key=lambda x: abs(x[1].get("difference", 0)), reverse=True):
                diff = trend_data.get("difference", 0)
                trend = trend_data.get("trend", "stable")
                emoji = "📈" if trend == "increasing" else "📉" if trend == "decreasing" else "➡️"
                pattern_name = pattern.replace("_", " ").title()
                print(f"  {emoji} {pattern_name}: {trend_data.get('current', 0)} (was {trend_data.get('previous', 0)}, {diff:+d})")

        # Persistent errors (top examples)
        persistent_details = error_comp.get("persistent_error_details", [])
        if persistent_details:
            print(f"\n🔄 PERSISTENT ERRORS (showing {min(5, len(persistent_details))} examples):")
            for i, error in enumerate(persistent_details[:5], 1):
                content = error.get("content", "N/A")[:80] + "..." if len(error.get("content", "")) > 80 else error.get("content", "N/A")
                print(f"  {i}. [{error.get('severity', 'UNKNOWN')}] {content}")

        # New errors (top examples)
        new_details = error_comp.get("new_error_details", [])
        if new_details:
            print(f"\n🆕 NEW ERRORS (showing {min(5, len(new_details))} examples):")
            for i, error in enumerate(new_details[:5], 1):
                content = error.get("content", "N/A")[:80] + "..." if len(error.get("content", "")) > 80 else error.get("content", "N/A")
                print(f"  {i}. [{error.get('severity', 'UNKNOWN')}] {content}")

        # Resolved errors (top examples)
        resolved_details = error_comp.get("resolved_error_details", [])
        if resolved_details:
            print(f"\n✅ RESOLVED ERRORS (showing {min(5, len(resolved_details))} examples):")
            for i, error in enumerate(resolved_details[:5], 1):
                content = error.get("content", "N/A")[:80] + "..." if len(error.get("content", "")) > 80 else error.get("content", "N/A")
                print(f"  {i}. [{error.get('severity', 'UNKNOWN')}] {content}")

        print("\n" + "=" * 80)


def auto_mode():
    """
    Run the consumer in automated mode with optimal settings
    """
    print("\n" + "=" * 70)
    print("🤖 CA ERROR CONSUMER - AUTOMATED MODE")
    print("=" * 70)
    print("Running automated error analysis with optimal settings...")

    # Look for JSON files in error_reports directory
    json_file = None
    error_reports_dir = "error_reports/json"
    if os.path.exists(error_reports_dir):
        json_files = [f for f in os.listdir(error_reports_dir) if f.endswith(".json")]
        if json_files:
            # Use the most recent file
            json_files.sort(key=lambda x: os.path.getmtime(os.path.join(error_reports_dir, x)), reverse=True)
            json_file = os.path.join(error_reports_dir, json_files[0])
            print(f"🎯 Using most recent error report: {json_file}")

    # Create sample file if none found
    if not json_file:
        print("📝 No error reports found. Creating sample error report...")
        json_file = "sample_auto_error_report.json"
        sample_data = {
            "error_analysis_report": {
                "metadata": {
                    "script_name": "CA_error_manager.sh",
                    "script_version": "1.0.0",
                    "analysis_timestamp": datetime.now().isoformat(),
                    "source_file": "auto_sample.log",
                    "detected_log_format": "syslog",
                },
                "summary_statistics": {"total_error_entries": 8, "total_malformed_entries": 3},
                "error_entries": [
                    {"line_number": 1, "content": "ERROR: Database connection failed - Connection timeout", "severity": "HIGH"},
                    {"line_number": 2, "content": "WARNING: High memory usage detected - 90% utilization", "severity": "MEDIUM"},
                    {"line_number": 3, "content": "CRITICAL: System disk full - Only 50MB free space", "severity": "CRITICAL"},
                    {"line_number": 4, "content": "INFO: User login successful - User: admin", "severity": "INFO"},
                    {"line_number": 5, "content": "ERROR: Network timeout - Failed to reach external API", "severity": "HIGH"},
                    {"line_number": 6, "content": "WARNING: SSL certificate expires soon - 3 days remaining", "severity": "MEDIUM"},
                    {"line_number": 7, "content": "ERROR: Failed to connect to API - HTTP 500 error", "severity": "HIGH"},
                    {"line_number": 8, "content": "CRITICAL: Service unavailable - Web server down", "severity": "CRITICAL"},
                ],
                "malformed_entries": [
                    {"line_number": 1, "content": "Invalid log entry format", "issue_type": "format_violation"},
                    {"line_number": 2, "content": "Corrupted timestamp data", "issue_type": "format_violation"},
                    {"line_number": 3, "content": "Missing severity level", "issue_type": "format_violation"},
                ],
            }
        }
        try:
            with open(json_file, "w") as f:
                json.dump(sample_data, f, indent=2)
            print(f"✅ Sample error report created: {json_file}")
        except Exception as e:
            print(f"❌ Error creating sample file: {e}")
            return None

    # Optimal settings for automated analysis
    output_file = f"ca_auto_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    print("📊 Analysis Configuration:")
    print(f"   Input file: {json_file}")
    print("   Analysis type: Complete analysis")
    print(f"   Output file: {output_file}")
    print("\n🚀 Starting automated error analysis...")
    print("=" * 70)

    try:
        consumer = CAErrorReportConsumer(json_file)
        # Perform complete analysis
        consumer.print_summary_report()
        # Export analysis results
        consumer.export_analysis_results(output_file)

        print("\n" + "=" * 70)
        print("✅ AUTOMATED ERROR ANALYSIS COMPLETED!")
        print("=" * 70)
        print(f"📁 Analysis results saved to: {output_file}")

        # Show alert summary
        alerts = consumer.generate_alert_conditions()
        if alerts:
            print("🚨 Alert Summary:")
            print(f"   Total alerts: {len(alerts)}")
            alert_types = {}
            for alert in alerts:
                alert_type = alert.get("type", "Unknown")
                alert_types[alert_type] = alert_types.get(alert_type, 0) + 1
            for alert_type, count in alert_types.items():
                print(f"     - {alert_type}: {count}")
        else:
            print("✅ No critical alerts detected")

        return consumer

    except KeyboardInterrupt:
        print("\n❌ Analysis interrupted by user")
        return None
    except Exception as e:
        print(f"\n❌ Analysis failed: {e}")
        return None


def interactive_mode():
    """
    Run the consumer in interactive mode with comprehensive user guidance
    """
    print("\n" + "=" * 70)
    print("📊 CA ERROR CONSUMER - INTERACTIVE MODE")
    print("=" * 70)
    print("Welcome! This interactive mode will guide you through error report analysis.")
    print("You can analyze JSON error reports and get detailed insights.")

    # JSON file selection with detailed guidance
    print("\n" + "=" * 50)
    print("📁 JSON FILE SELECTION")
    print("=" * 50)
    print("Choose how to select your error report file:")
    print("1. Enter file path manually")
    print("2. Browse error_reports directory")
    print("3. Use sample file")

    json_file = None
    while True:
        file_choice = input("\nChoose option (1-3): ").strip()
        if file_choice == "1":
            print("\n📝 Manual File Path:")
            print("Examples: error_report.json, /path/to/report.json")
            print("Note: File must be a valid JSON error report")
            json_file = input("Enter path to JSON error report file: ").strip()
            if json_file:
                if os.path.exists(json_file):
                    print(f"✅ File found: {json_file}")
                    break
                else:
                    print("❌ File not found. Please check the path")
                    retry = input("Try again? (y/n): ").strip().lower()
                    if retry not in ["y", "yes"]:
                        continue
            else:
                print("❌ File path cannot be empty")
        elif file_choice == "2":
            print("\n📁 Browsing error_reports directory...")
            error_reports_dir = "error_reports/json"
            if os.path.exists(error_reports_dir):
                json_files = [f for f in os.listdir(error_reports_dir) if f.endswith(".json")]
                if json_files:
                    print(f"\nAvailable JSON files in {error_reports_dir}:")
                    for i, file in enumerate(json_files, 1):
                        file_path = os.path.join(error_reports_dir, file)
                        file_size = os.path.getsize(file_path)
                        print(f"  {i}. {file} ({file_size} bytes)")
                    file_choice = input(f"\nChoose file (1-{len(json_files)}): ").strip()
                    if file_choice.isdigit() and 1 <= int(file_choice) <= len(json_files):
                        json_file = os.path.join(error_reports_dir, json_files[int(file_choice) - 1])
                        print(f"✅ Selected: {json_file}")
                        break
                    else:
                        print("❌ Invalid choice")
                else:
                    print(f"❌ No JSON files found in {error_reports_dir}")
                    print("💡 Tip: Run CA_error_manager.sh first to generate error reports")
            else:
                print(f"❌ Directory not found: {error_reports_dir}")
                print("💡 Tip: Run CA_error_manager.sh first to create the directory")
        elif file_choice == "3":
            print("\n📝 Sample File:")
            print("Using a sample error report for demonstration")
            sample_file = "sample_error_report.json"
            sample_data = {
                "error_analysis_report": {
                    "metadata": {
                        "script_name": "CA_error_manager.sh",
                        "script_version": "1.0.0",
                        "analysis_timestamp": "2024-01-01T12:00:00Z",
                        "source_file": "sample.log",
                        "detected_log_format": "syslog",
                    },
                    "summary_statistics": {"total_error_entries": 5, "total_malformed_entries": 2},
                    "error_entries": [
                        {"line_number": 1, "content": "ERROR: Database connection failed", "severity": "HIGH"},
                        {"line_number": 2, "content": "WARNING: High memory usage detected", "severity": "MEDIUM"},
                        {"line_number": 3, "content": "CRITICAL: System disk full", "severity": "CRITICAL"},
                        {"line_number": 4, "content": "INFO: User login successful", "severity": "INFO"},
                        {"line_number": 5, "content": "ERROR: Network timeout", "severity": "HIGH"},
                    ],
                    "malformed_entries": [
                        {"line_number": 1, "content": "Invalid log entry", "issue_type": "format_violation"},
                        {"line_number": 2, "content": "Corrupted data", "issue_type": "format_violation"},
                    ],
                }
            }
            try:
                with open(sample_file, "w") as f:
                    json.dump(sample_data, f, indent=2)
                json_file = sample_file
                print(f"✅ Sample file created: {sample_file}")
                break
            except Exception as e:
                print(f"❌ Error creating sample file: {e}")
                continue
        else:
            print("❌ Invalid choice. Please enter 1-3")

    # Analysis mode selection with detailed guidance
    print("\n" + "=" * 50)
    print("🔍 ANALYSIS MODE SELECTION")
    print("=" * 50)
    print("Choose how to analyze the error report:")
    print("1. Complete analysis (recommended)")
    print("2. Quick alerts check")
    print("3. Save analysis to file")
    print("4. Filter by severity levels")
    print("5. Compare with another report")
    print("6. Custom analysis options")

    mode_choice = None
    severity_filter = None
    output_file = None
    compare_file = None

    while True:
        mode_choice = input("\nChoose analysis mode (1-6): ").strip()
        if mode_choice == "1":
            print("✅ Complete analysis selected")
            print("This will show:")
            print("  • Summary statistics")
            print("  • Error patterns")
            print("  • Alert conditions")
            print("  • Recommendations")
            break
        elif mode_choice == "2":
            print("✅ Quick alerts check selected")
            print("This will show only critical alerts and warnings")
            break
        elif mode_choice == "3":
            print("\n📝 Save Analysis to File:")
            print("This will save detailed analysis results to a JSON file")
            output_file = input("Enter output file path (e.g., analysis_results.json): ").strip()
            if output_file:
                if not output_file.endswith(".json"):
                    output_file += ".json"
                print(f"✅ Analysis will be saved to: {output_file}")
                break
            else:
                print("❌ Output file path cannot be empty")
        elif mode_choice == "4":
            print("\n📝 Severity Filter:")
            print("Available severity levels:")
            print("  • CRITICAL: Critical system errors")
            print("  • HIGH: High-severity errors")
            print("  • MEDIUM: Medium-severity warnings")
            print("  • LOW: Low-severity notices")
            print("  • INFO: Informational messages")
            print("\nExamples: HIGH,CRITICAL or MEDIUM,HIGH")
            severity_input = input("Enter severity levels (comma-separated): ").strip()
            if severity_input:
                severity_filter = [s.strip().upper() for s in severity_input.split(",")]
                valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
                invalid_severities = [s for s in severity_filter if s not in valid_severities]
                if invalid_severities:
                    print(f"❌ Invalid severity levels: {', '.join(invalid_severities)}")
                    continue
                print(f"✅ Filtering by: {', '.join(severity_filter)}")
                break
            else:
                print("❌ Severity levels cannot be empty")
        elif mode_choice == "5":
            print("\n📝 Compare Reports:")
            print("This will compare the current report with another report")
            compare_file = input("Enter path to the other JSON report file: ").strip()
            if compare_file:
                if os.path.exists(compare_file):
                    print(f"✅ Comparison file found: {compare_file}")
                    break
                else:
                    print("❌ Comparison file not found. Please check the path")
                    continue
            else:
                print("❌ Comparison file path cannot be empty")
        elif mode_choice == "6":
            print("\n📝 Custom Analysis Options:")
            print("Choose additional options:")
            print("1. Show only error patterns")
            print("2. Show only recommendations")
            print("3. Show only source analysis")
            print("4. Export to multiple formats")
            custom_choice = input("Choose custom option (1-4): ").strip()
            if custom_choice in ["1", "2", "3", "4"]:
                print(f"✅ Custom option {custom_choice} selected")
                break
            else:
                print("❌ Invalid custom option")
        else:
            print("❌ Invalid choice. Please enter 1-6")

    # Show analysis summary
    print("\n" + "=" * 50)
    print("📊 ANALYSIS SUMMARY")
    print("=" * 50)
    print(f"Input file: {json_file}")
    print(f"Analysis mode: {mode_choice}")
    if mode_choice == "3":
        print(f"Output file: {output_file}")
    elif mode_choice == "4":
        print(f"Severity filter: {', '.join(severity_filter)}")
    elif mode_choice == "5":
        print(f"Comparison file: {compare_file}")

    # Confirm analysis
    print("\n" + "=" * 50)
    confirm = input("🚀 Start the error analysis? (y/n): ").strip().lower()
    if confirm not in ["y", "yes"]:
        print("❌ Analysis cancelled by user")
        return None

    # Run analysis
    print("\n🚀 Starting error analysis...")
    print("=" * 70)

    try:
        consumer = CAErrorReportConsumer(json_file)

        if mode_choice == "2":
            # Show only alerts
            consumer.print_alerts()
        elif mode_choice == "3":
            # Save analysis to file
            consumer.export_analysis_results(output_file)
            print(f"\n✅ Analysis saved to: {output_file}")
        elif mode_choice == "4":
            # Filter by severity
            consumer.print_summary_report(severity_filter)
        elif mode_choice == "5":
            # Compare reports
            comparison_results = consumer.compare_reports(compare_file)
            if comparison_results:
                consumer.print_comparison_report(comparison_results)
                save_comparison = input("\n💾 Save comparison results to JSON? (y/n): ").strip().lower()
                if save_comparison in ["y", "yes"]:
                    comp_output = input("Enter output file path (e.g., comparison.json): ").strip()
                    if comp_output:
                        if not comp_output.endswith(".json"):
                            comp_output += ".json"
                        try:
                            with open(comp_output, "w", encoding="utf-8") as f:
                                json.dump(comparison_results, f, indent=2, ensure_ascii=False)
                            print(f"✅ Comparison results saved to: {comp_output}")
                        except Exception as e:
                            print(f"❌ Error saving comparison: {e}")
            else:
                print("❌ Comparison failed - no results generated")
        else:
            # Complete analysis
            consumer.print_summary_report()

        print("\n" + "=" * 70)
        print("✅ ERROR ANALYSIS COMPLETED!")
        print("=" * 70)
        return consumer

    except KeyboardInterrupt:
        print("\n❌ Analysis interrupted by user")
        return None
    except Exception as e:
        print(f"\n❌ Analysis failed: {e}")
        return None


def main():
    """
    Main function to handle command line arguments and execute analysis
    """
    parser = argparse.ArgumentParser(
        description="CA Error Consumer - Simplified Error Report Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:

  python3 CA_error_consumer.py error_report.json

  python3 CA_error_consumer.py error_report.json --output analysis_results.json

  python3 CA_error_consumer.py error_report.json --alerts-only

  python3 CA_error_consumer.py error_report.json --severity-filter HIGH,CRITICAL

  python3 CA_error_consumer.py error_report.json --compare old_report.json

  python3 CA_error_consumer.py error_report.json --compare old_report.json --compare-output comparison.json

  python3 CA_error_consumer.py --interactive

        """,
    )

    parser.add_argument("json_file", nargs="?", help="Path to JSON error report file")
    parser.add_argument("--interactive", action="store_true", help="Run in interactive mode")
    parser.add_argument("--auto", "-a", action="store_true", help="Run automated analysis with optimal settings")
    parser.add_argument("-o", "--output", help="Output file for analysis results (JSON format)")
    parser.add_argument("--alerts-only", action="store_true", help="Show only alert conditions (no detailed analysis)")
    parser.add_argument("--severity-filter", help="Filter alerts by severity levels (comma-separated: HIGH,CRITICAL)")
    parser.add_argument("--compare", help="Compare with another JSON report file", type=str, metavar="FILE")
    parser.add_argument("--compare-output", help="Save comparison results to JSON file", type=str, metavar="FILE")
    parser.add_argument("--version", action="version", version="CA Error Consumer 1.0.0")

    args = parser.parse_args()

    # Interactive mode
    if args.interactive or not args.json_file:
        interactive_mode()
        return

    # Auto mode
    if args.auto:
        auto_mode()
        return

    # Validate input file
    if not os.path.exists(args.json_file):
        print(f"❌ Error: JSON file not found: {args.json_file}")
        sys.exit(1)

    # Parse severity filter
    severity_filter = None
    if args.severity_filter:
        severity_filter = [s.strip().upper() for s in args.severity_filter.split(",")]
        valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        invalid_severities = [s for s in severity_filter if s not in valid_severities]
        if invalid_severities:
            print(f"❌ Error: Invalid severity levels: {', '.join(invalid_severities)}")
            print(f"Valid levels: {', '.join(valid_severities)}")
            sys.exit(1)

    try:
        # Initialize consumer and load data
        consumer = CAErrorReportConsumer(args.json_file)

        # Handle comparison mode
        if args.compare:
            comparison_results = consumer.compare_reports(args.compare)
            if comparison_results:
                # Print comparison to stdout
                consumer.print_comparison_report(comparison_results)
                # Save comparison JSON if requested
                if args.compare_output:
                    try:
                        with open(args.compare_output, "w", encoding="utf-8") as f:
                            json.dump(comparison_results, f, indent=2, ensure_ascii=False)
                        print(f"\n✅ Comparison JSON saved to: {args.compare_output}")
                    except Exception as e:
                        print(f"❌ Error saving comparison JSON: {e}", file=sys.stderr)
                        sys.exit(1)
            else:
                print("❌ Comparison failed - no results generated", file=sys.stderr)
                sys.exit(1)
        elif args.alerts_only:
            # Show only alerts
            consumer.print_alerts()
        else:
            # Generate output file if specified
            if args.output:
                consumer.export_analysis_results(args.output)
                print(f"✅ Analysis completed and saved to: {args.output}")
            # Print summary report
            consumer.print_summary_report(severity_filter)

    except KeyboardInterrupt:
        print("\n❌ Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error during analysis: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
