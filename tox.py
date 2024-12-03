#!/usr/bin/env python3
from abc import ABC, abstractmethod
import os
import re
import stat
import hashlib
import argparse
import logging
import concurrent.futures
import json
import time
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List, Dict, Set, Optional, Iterator
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
import magic
import yaml
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TimeElapsedColumn
from rich.panel import Panel
from rich import box

class FindingSeverity(Enum):
    """Enum for finding severity levels with comparison support"""
    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3
    INFO = 4

    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented

    def get_color(self) -> str:
        """Get the color associated with the severity level"""
        return {
            self.CRITICAL: "red",
            self.HIGH: "red3",
            self.MEDIUM: "yellow",
            self.LOW: "green",
            self.INFO: "blue"
        }[self]

    def get_name(self) -> str:
        """Get the string name of the severity level"""
        return self.name

@dataclass
class Finding:
    """Data class for security findings"""
    severity: FindingSeverity
    finding_type: str
    path: str
    details: str
    evidence: Optional[str] = None

class SecurityAnalyzer(ABC):
    """Abstract base class for security analyzers"""
    def __init__(self, root_path: Path):
        self.root_path = root_path
        self.findings: List[Finding] = []
        self._lock = Lock()
        self._excluded_dirs = {'.git', '.svn', 'node_modules', '__pycache__', 'vendor'}
        self._excluded_extensions = {'.min.js', '.min.css', '.map', '.woff', '.ttf', '.eot', 
                                   '.jpg', '.png', '.gif', '.ico', '.svg'}

    @abstractmethod
    def analyze(self) -> None:
        """Perform security analysis"""
        pass

    def add_finding(self, finding: Finding) -> None:
        """Thread-safe method to add a finding to the results"""
        with self._lock:
            self.findings.append(finding)

    def get_files_to_analyze(self) -> Iterator[Path]:
        """Get files that need to be analyzed, excluding common irrelevant paths"""
        for path in self.root_path.rglob("*"):
            if any(excluded in path.parts for excluded in self._excluded_dirs):
                continue
            if path.suffix.lower() in self._excluded_extensions:
                continue
            yield path

class BinaryAnalyzer(SecurityAnalyzer):
    """Enhanced analyzer for binary files and executables"""
    
    def __init__(self, root_path: Path):
        super().__init__(root_path)
        self.known_safe_hashes = set()  # Could be populated from a database
        self.interesting_strings = {
            'network': [
                r'(?:http|ftp|telnet)://',
                r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}',
                r'(?:wlan|eth)[0-9]+',
                r'(?:tcp|udp|icmp)'
            ],
            'shell': [
                r'system\(',
                r'exec\(',
                r'spawn\(',
                r'fork\(',
                r'/bin/sh',
                r'/bin/bash'
            ],
            'firmware': [
                r'boot',
                r'flash',
                r'upgrade',
                r'firmware',
                r'device',
                r'hardware'
            ]
        }

    def analyze(self) -> None:
        """Analyze binary files using parallel processing"""
        with ThreadPoolExecutor() as executor:
            list(executor.map(self._analyze_file, self.get_files_to_analyze()))

    def _analyze_file(self, path: Path) -> None:
        """Analyze a single binary file"""
        if not path.is_file():
            return

        try:
            # Check file type
            file_type = magic.from_file(str(path))
            file_mime = magic.from_file(str(path), mime=True)

            if any(x in file_mime for x in ['application/x-executable', 'application/x-sharedlib']):
                if "ELF" in file_type:
                    self._analyze_elf_binary(path, file_type)
                else:
                    self._analyze_generic_binary(path, file_type)

        except Exception as e:
            logging.warning(f"Error analyzing binary {path}: {str(e)}")

    def _analyze_elf_binary(self, path: Path, file_type: str) -> None:
        """Enhanced ELF binary analysis"""
        try:
            # Calculate hash
            with open(path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

            if file_hash in self.known_safe_hashes:
                return

            # Check permissions
            mode = os.stat(path).st_mode
            
            # Check for SUID/SGID
            if mode & stat.S_ISUID or mode & stat.S_ISGID:
                self.add_finding(Finding(
                    severity=FindingSeverity.HIGH,
                    finding_type="privileged_binary",
                    path=str(path),
                    details=f"Binary with SUID/SGID permissions found",
                    evidence=f"File: {file_type}, Hash: {file_hash}, Mode: {oct(mode)}"
                ))

            # Check for world-writable executables
            if mode & stat.S_IWOTH:
                self.add_finding(Finding(
                    severity=FindingSeverity.CRITICAL,
                    finding_type="writable_binary",
                    path=str(path),
                    details=f"World-writable binary found",
                    evidence=f"File: {file_type}, Hash: {file_hash}, Mode: {oct(mode)}"
                ))

            # String analysis
            strings_output = self._extract_strings(path)
            for category, patterns in self.interesting_strings.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, strings_output, re.IGNORECASE)
                    for match in matches:
                        self.add_finding(Finding(
                            severity=FindingSeverity.MEDIUM,
                            finding_type=f"interesting_{category}_usage",
                            path=str(path),
                            details=f"Binary contains interesting {category}-related string",
                            evidence=f"Found: {match.group(0)}"
                        ))

            # Basic security checks using readelf if available
            try:
                readelf_output = subprocess.run(['readelf', '-a', str(path)], 
                                              capture_output=True, 
                                              text=True).stdout
                
            except subprocess.SubprocessError:
                pass  # readelf not available

        except Exception as e:
            logging.warning(f"Error analyzing ELF binary {path}: {str(e)}")

    def _extract_strings(self, path: Path) -> str:
        """Extract readable strings from binary"""
        try:
            result = subprocess.run(['strings', str(path)], 
                                  capture_output=True, 
                                  text=True)
            return result.stdout
        except Exception:
            return ""

class CredentialAnalyzer(SecurityAnalyzer):
    """Enhanced analyzer for hardcoded credentials and sensitive information"""
    
    def __init__(self, root_path: Path):
        super().__init__(root_path)
        # Add common test/example values to reduce false positives
        self.common_test_values = {
            'test', 'example', 'sample', 'dummy', 'default', 'password123',
            'changeme', 'placeholder', '[password]', '{password}', '<password>'
        }
        
        self.SENSITIVE_FILES = {
            'shadow': r'.*/shadow$',
            'passwd': r'.*/passwd$',
            'credentials': r'.*credentials.*',
            'keystore': r'.*\.keystore$',
            'private_key': r'.*\.key$',
            'certificate': r'.*\.crt$',
            'certificates': r'.*\.p(?:12|em|fx)$',
            'ssh_keys': r'.*(?:id_(?:rsa|dsa|ecdsa|ed25519)|ssh_host_.*_key)$',
            'database': r'.*\.(?:db|sqlite|sqlite3)$',
            'backup': r'.*\.(?:bak|backup|old)$',
            'firmware': r'.*\.(?:bin|fw|image)$'
        }

        self.CREDENTIAL_PATTERNS = {
            'hardcoded_password': (
                r'(?i)(?<!example_)(?<!sample_)(?:password|pwd|passwd)\s*[=:]\s*[\'"](?![<{])[a-zA-Z0-9@#$%^&*+=\-_.]{3,}[\'"]',
                FindingSeverity.HIGH
            ),
            'default_password': (
                r'(?i)(?:default_password|factory_password|initial_password)\s*[=:]\s*[\'"][a-zA-Z0-9@#$%^&*+=\-_.]{3,}[\'"]',
                FindingSeverity.CRITICAL
            ),
            'api_key': (
                r'(?i)(?:api_key|api_secret|access_key|secret_key)\s*[=:]\s*[\'"](?![\s<{])[a-zA-Z0-9_\-]{16,}[\'"]',
                FindingSeverity.HIGH
            ),
            'private_key_content': (
                r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----',
                FindingSeverity.CRITICAL
            ),
            'basic_auth': (
                r'(?i)(?:authorization|auth):\s*basic\s+[a-zA-Z0-9+/]{20,}={0,2}(?![a-zA-Z0-9+/])',
                FindingSeverity.HIGH
            ),
            'jwt_token': (
                r'(?i)(?:jwt|token|auth).*[\'"][a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+[\'"]',
                FindingSeverity.HIGH
            ),
            'encryption_key': (
                r'(?i)(?:encryption_key|cipher_key|aes_key)\s*[=:]\s*[\'"][a-fA-F0-9]{32,}[\'"]',
                FindingSeverity.CRITICAL
            )
        }

    def _is_test_value(self, value: str) -> bool:
        """Check if a value appears to be a test/example credential"""
        value_lower = value.lower()
        return (
            any(test in value_lower for test in self.common_test_values) or
            bool(re.match(r'^[a-z]+\d{1,3}$', value_lower)) or  # e.g. admin123
            bool(re.match(r'^.*(test|demo|sample).*$', value_lower))
        )

    def analyze(self) -> None:
        """Analyze files for credentials using parallel processing"""
        with ThreadPoolExecutor() as executor:
            list(executor.map(self._analyze_file, self.get_files_to_analyze()))

    def _analyze_file(self, path: Path) -> None:
        """Analyze a single file for credentials"""
        if not path.is_file():
            return

        try:
            # Skip large files
            if path.stat().st_size > 10 * 1024 * 1024:  # Skip files larger than 10MB
                return

            # Skip binary files
            file_type = magic.from_file(str(path))
            if any(x in file_type.lower() for x in ['executable', 'binary', 'image', 'font']):
                return

            # Check if it's a known sensitive file
            for file_type, pattern in self.SENSITIVE_FILES.items():
                if re.match(pattern, str(path)):
                    self.add_finding(Finding(
                        severity=FindingSeverity.HIGH,
                        finding_type="sensitive_file",
                        path=str(path),
                        details=f"Sensitive file found: {file_type}",
                        evidence=f"File pattern: {pattern}"
                    ))

            # Check file content for credentials
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                if not self._is_documentation_or_template(content):
                    self._scan_for_credentials(content, path)

        except Exception as e:
            logging.debug(f"Error scanning file {path}: {str(e)}")

    def _is_documentation_or_template(self, content: str) -> bool:
        """Check if content appears to be documentation or template"""
        return (
            re.search(r'<!DOCTYPE|<html|<body|<script', content, re.IGNORECASE) or
            '```' in content or  # Markdown code blocks
            'Example:' in content or
            'Sample:' in content
        )

    def _scan_for_credentials(self, content: str, path: Path) -> None:
        """Scan file content for credential patterns with improved false positive handling"""
        for cred_type, (pattern, severity) in self.CREDENTIAL_PATTERNS.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                matched_text = match.group(0)
                
                # Skip if the match looks like test/example data
                if self._is_test_value(matched_text):
                    continue
                
                # Skip if the match looks like help text or UI elements
                if any(x in matched_text.lower() for x in [
                    '<b>', '<i>', '<div>', 'enter', 'input', 'example',
                    'sample', 'placeholder', 'your_', 'template'
                ]):
                    continue
                
                # Skip if the match is too long (likely documentation)
                if len(matched_text) > 200:
                    continue
                
                # Skip if the match contains HTML-like formatting
                if re.search(r'<[^>]+>', matched_text):
                    continue

                self.add_finding(Finding(
                    severity=severity,
                    finding_type=cred_type,
                    path=str(path),
                    details=f"Potential {cred_type.replace('_', ' ')} found",
                    evidence=matched_text
                ))

class ConfigAnalyzer(SecurityAnalyzer):
    """Enhanced analyzer for configuration files"""
    
    def __init__(self, root_path: Path):
        super().__init__(root_path)
        self.CONFIG_PATTERNS = {
            'init': r'.*/etc/init\.d/.*',
            'config': r'.*\.conf$',
            'ini': r'.*\.ini$',
            'env': r'.*\.env$',
            'json_config': r'.*config.*\.json$',
            'yaml_config': r'.*config.*\.ya?ml$',
            'xml_config': r'.*\.xml$',  # Basic XML pattern
            'docker': r'Dockerfile|docker-compose\.ya?ml',
            'systemd': r'.*/systemd/.*\.service$',
            'nginx': r'.*nginx.*\.conf$',
            'apache': r'.*apache2?.*\.conf$'
        }

        # Add specific paths for common IoT config locations
        self.COMMON_CONFIG_PATHS = {
            'device_config': r'.*/var/config/.*\.xml$',
            'system_config': r'.*/etc/.*\.xml$',
            'app_config': r'.*/usr/share/.*\.xml$',
            'web_config': r'.*/var/www/.*\.xml$',
            'dbus_config': r'.*/usr/share/xml/dbus-.*\.xml$',
            'network_config': r'.*/var/config/network/.*\.xml$',
            'wireless_config': r'.*/var/config/wireless/.*\.xml$',
            'app_data': r'.*/var/lib/.*/.*\.xml$',
        }

        # Merge both pattern dictionaries
        self.CONFIG_PATTERNS.update(self.COMMON_CONFIG_PATHS)

        self.SECURITY_PATTERNS = {
            'debug_mode': (
                r'debug\s*[=:]\s*(true|1|yes|on)',
                FindingSeverity.MEDIUM,
                "Debug mode enabled"
            ),
            'insecure_permission': (
                r'chmod\s+[0-7]*777|chmod\s+[0-7]*666',
                FindingSeverity.HIGH,
                "Insecure file permissions"
            ),
            'default_credential': (
                r'default[-_](?:password|user|admin)',
                FindingSeverity.HIGH,
                "Default credentials in use"
            ),
            'weak_ssl': (
                r'ssl_protocol.*TLSv1\.0|ssl_protocol.*SSLv[23]',
                FindingSeverity.HIGH,
                "Weak SSL/TLS configuration"
            ),
            'open_port': (
                r'port\s*[=:]\s*(?:23|21|20|2222|2323)',
                FindingSeverity.MEDIUM,
                "Potentially dangerous port configured"
            ),
            'root_login': (
                r'permit_root_login\s+yes|root\s+login',
                FindingSeverity.HIGH,
                "Root login enabled"
            ),
            'telnet_enabled': (
                r'telnet[d]?\s+start|enable\s+telnet',
                FindingSeverity.CRITICAL,
                "Telnet service enabled"
            ),
            'psk_key': (
                r'(?i)(?:psk|pre[-_]shared[-_]key)\s*[=:]\s*[\'"][^\'"\s]{8,}[\'"]',
                FindingSeverity.HIGH,
                "Pre-shared key found"
            ),
            'wifi_psk': (
                r'(?i)(?:wpa[-_]psk|wifi[-_]psk|wireless[-_]key)\s*[=:]\s*[\'"][^\'"\s]{8,}[\'"]',
                FindingSeverity.HIGH,
                "WiFi pre-shared key found"
            )
        }

    def _should_analyze_file(self, path: Path) -> bool:
        """Determine if a file should be analyzed based on its path and type"""
        try:
            str_path = str(path)
            # Skip ALL shared library files
            if any(part.startswith('libxml') for part in path.parts):
                return False
                
            # Skip any .so files in lib directories
            if 'lib' in path.parts and any(part.endswith('.so') or '.so.' in part for part in path.parts):
                return False
                
            # Skip catalog files and other known non-config XMLs
            if any(x in path.name.lower() for x in ['catalog', 'schema', 'template']):
                return False

            # Explicitly look for config.xml in any directory
            if path.name == 'config.xml':
                return True

            # Check against our patterns
            for pattern in self.CONFIG_PATTERNS.values():
                if re.match(pattern, str_path):
                    # Debug when pattern matches
                    # print(f"Pattern match: {pattern} -> {str_path}")
                    return True

            return False

        except Exception as e:
            logging.debug(f"Error checking file {path}: {str(e)}")
            return False

    def analyze(self) -> None:
        """Analyze configuration files using parallel processing"""
        with ThreadPoolExecutor() as executor:
            files_to_analyze = [
                path for path in self.get_files_to_analyze()
                if self._should_analyze_file(path)
            ]
            list(executor.map(self._analyze_file, files_to_analyze))

    def _analyze_file(self, path: Path) -> None:
        """Analyze a single configuration file"""
        if not path.is_file():
            return

        try:
            # Check if file matches known config patterns
            config_type = None
            for type_name, pattern in self.CONFIG_PATTERNS.items():
                if re.match(pattern, str(path)):
                    config_type = type_name
                    break

            if config_type:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    # Parse and analyze structured configs
                    if path.suffix == '.xml':
                        self._analyze_xml_config(path, content)
                    elif path.suffix in {'.json', '.yaml', '.yml'}:
                        self._analyze_structured_config(path, content, config_type)
                    else:
                        self._analyze_text_config(path, content, config_type)

        except Exception as e:
            logging.debug(f"Error analyzing config file {path}: {str(e)}")

    def _analyze_xml_config(self, path: Path, content: str) -> None:
        """Analyze XML configuration files"""
        try:
            # Add INFO finding for config.xml files
            if path.name == 'config.xml':
                self.add_finding(Finding(
                    severity=FindingSeverity.INFO,
                    finding_type="xml_config_file",
                    path=str(path),
                    details="Configuration file found",
                    evidence=f"Config file at: {str(path)}"
                ))

            # Rest of existing XML patterns
            xml_patterns = {
                'xml_psk': (
                    r'<(?:key|psk|password)[^>]*>([^<]+)</(?:key|psk|password)>',
                    FindingSeverity.HIGH,
                    "Pre-shared key or password in XML"
                ),
                'xml_wifi_config': (
                    r'<(?:wireless|wifi|wlan)[^>]*>.*?</(?:wireless|wifi|wlan)>',
                    FindingSeverity.MEDIUM,
                    "Wireless configuration found"
                ),
                'xml_debug': (
                    r'<debug[^>]*>(?:true|1|yes|on)</debug>',
                    FindingSeverity.MEDIUM,
                    "Debug mode enabled in XML config"
                ),
                'xml_credentials': (
                    r'<(?:credentials|authentication)[^>]*>.*?</(?:credentials|authentication)>',
                    FindingSeverity.HIGH,
                    "Credential configuration found"
                )
            }

            # Check for XML-specific patterns
            for pattern_name, (pattern, severity, description) in xml_patterns.items():
                matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
                for match in matches:
                    # Skip if it looks like a template or example
                    if any(template in match.group(0).lower() for template in 
                          ['${', '{$', '<%', '%>', 'example', 'template']):
                        continue

                    self.add_finding(Finding(
                        severity=severity,
                        finding_type=f"xml_{pattern_name}",
                        path=str(path),
                        details=description,
                        evidence=match.group(0)[:200]  # Limit evidence length
                    ))

            # Check network-specific configurations
            self._check_network_config(path, content)

            # Also check for regular security patterns in XML content
            self._analyze_text_config(path, content, 'xml')

        except Exception as e:
            logging.debug(f"Error analyzing XML config {path}: {str(e)}")

    def _check_network_config(self, path: Path, content: str) -> None:
        """Check network-related configurations"""
        network_patterns = {
            'weak_wifi': (
                r'(?i)(?:encryption|security)[^>]*>(?:none|wep)</(?:encryption|security)>',
                FindingSeverity.CRITICAL,
                "Weak or no WiFi encryption"
            ),
            'open_wifi': (
                r'(?i)(?:authentication|auth-mode)[^>]*>open</(?:authentication|auth-mode)>',
                FindingSeverity.HIGH,
                "Open WiFi authentication"
            ),
            'hidden_psk': (
                r'(?i)(?<!example)(?<!template)(?:psk|key)[^>]*>[^<]{8,}</(?:psk|key)>',
                FindingSeverity.HIGH,
                "Hidden pre-shared key found"
            )
        }

        for pattern_name, (pattern, severity, description) in network_patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                self.add_finding(Finding(
                    severity=severity,
                    finding_type=f"network_{pattern_name}",
                    path=str(path),
                    details=description,
                    evidence=match.group(0)
                ))

    def _analyze_structured_config(self, path: Path, content: str, config_type: str) -> None:
        """Analyze structured configuration files with improved checks"""
        try:
            if path.suffix == '.json':
                config = json.loads(content)
            else:  # YAML
                config = yaml.safe_load(content)

            self._check_nested_config(config, str(path))
            
            # Check for specific service configurations
            if config_type == 'docker':
                self._check_docker_config(config, path)
            elif 'nginx' in config_type:
                self._check_web_server_config(config, path)

        except Exception as e:
            logging.debug(f"Error parsing structured config {path}: {str(e)}")

    def _check_docker_config(self, config: dict, path: Path) -> None:
        """Check Docker-specific security configurations"""
        if isinstance(config, dict):
            # Check for privileged containers
            if config.get('privileged') is True:
                self.add_finding(Finding(
                    severity=FindingSeverity.HIGH,
                    finding_type="docker_privileged",
                    path=str(path),
                    details="Container running in privileged mode",
                    evidence="privileged: true"
                ))
            
            # Check for host network mode
            if config.get('network_mode') == 'host':
                self.add_finding(Finding(
                    severity=FindingSeverity.MEDIUM,
                    finding_type="docker_host_network",
                    path=str(path),
                    details="Container using host network mode",
                    evidence="network_mode: host"
                ))

    def _analyze_text_config(self, path: Path, content: str, config_type: str) -> None:
        """Analyze text-based configuration files with context awareness"""
        # Check for known security patterns
        for pattern_name, (pattern, severity, description) in self.SECURITY_PATTERNS.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                # Skip false positives in comments
                line = content[max(0, match.start() - 50):min(len(content), match.end() + 50)]
                if re.match(r'\s*[#;]', line):
                    continue

                self.add_finding(Finding(
                    severity=severity,
                    finding_type=f"config_{pattern_name}",
                    path=str(path),
                    details=description,
                    evidence=match.group(0)
                ))
        
        # Additional checks based on config type
        if config_type == 'init':
            self._check_init_script(path, content)
        elif config_type in {'nginx', 'apache'}:
            self._check_web_server_config_text(path, content)

    def _check_init_script(self, path: Path, content: str) -> None:
        """Analyze initialization scripts for security issues"""
        init_patterns = {
            'unsafe_curl': (
                r'curl\s+-k\s+https?://|wget\s+--no-check-certificate',
                FindingSeverity.HIGH,
                "Insecure download without SSL verification"
            ),
            'dangerous_wildcard': (
                r'chmod\s+-R|chown\s+-R',
                FindingSeverity.MEDIUM,
                "Recursive permission/ownership change"
            ),
            'dangerous_eval': (
                r'eval\s*[\(`]|exec\s*[\(`]',
                FindingSeverity.HIGH,
                "Dangerous command evaluation"
            )
        }

        for pattern_name, (pattern, severity, description) in init_patterns.items():
            if re.search(pattern, content):
                self.add_finding(Finding(
                    severity=severity,
                    finding_type=f"init_{pattern_name}",
                    path=str(path),
                    details=description,
                    evidence=f"Found pattern: {pattern}"
                ))

class FirmwareSpecificAnalyzer(SecurityAnalyzer):
    """New analyzer for firmware-specific security issues"""
    
    def __init__(self, root_path: Path):
        super().__init__(root_path)
        self.interesting_files = {
            'device_tree': r'.*\.dtb$',
            'kernel': r'.*(?:vmlinux|zImage|uImage).*',
            'rootfs': r'.*(?:rootfs|squashfs|jffs2|ubifs).*',
            'bootloader': r'.*(?:uboot|bootloader)\.(?:bin|img)$',
            'update_package': r'.*(?:update|upgrade|flash)\.(?:bin|img)$'
        }
        
        self.interesting_paths = {
            '/etc/init.d',
            '/etc/cron',
            '/etc/config',
            '/etc/rc.d',
            '/usr/bin',
            '/usr/sbin',
            '/bin',
            '/sbin'
        }

    def analyze(self) -> None:
        """Analyze firmware-specific security issues"""
        with ThreadPoolExecutor() as executor:
            list(executor.map(self._analyze_path, self.get_files_to_analyze()))

    def _analyze_path(self, path: Path) -> None:
        """Analyze a single path for firmware-specific issues"""
        if not path.exists():
            return

        # Check for interesting firmware components
        for component_type, pattern in self.interesting_files.items():
            if re.match(pattern, str(path)):
                self._analyze_firmware_component(path, component_type)

        # Check for potentially dangerous paths
        if any(str(path).endswith(ipath) for ipath in self.interesting_paths):
            self._analyze_system_path(path)

    def _analyze_firmware_component(self, path: Path, component_type: str) -> None:
        """Analyze a specific firmware component"""
        if not path.is_file():
            return

        try:
            file_size = path.stat().st_size
            file_type = magic.from_file(str(path))
            
            self.add_finding(Finding(
                severity=FindingSeverity.INFO,
                finding_type="firmware_component",
                path=str(path),
                details=f"Found {component_type} component",
                evidence=f"Size: {file_size}, Type: {file_type}"
            ))

            # Additional checks based on component type
            if component_type == 'bootloader':
                self._check_bootloader_security(path)
            elif component_type == 'update_package':
                self._check_update_package(path)

        except Exception as e:
            logging.warning(f"Error analyzing firmware component {path}: {str(e)}")

    def _check_bootloader_security(self, path: Path) -> None:
        """Check bootloader for common security issues"""
        try:
            with open(path, 'rb') as f:
                content = f.read()
                
            # Look for common unsafe patterns
            patterns = [
                (r'console=ttyS?\d*,\d+\s+root=', "Exposed serial console"),
                (r'init=/bin/sh', "Direct shell access"),
                (r'rw\s+init=/bin/bash', "Read-write root with shell")
            ]

            for pattern, issue in patterns:
                if re.search(pattern.encode(), content):
                    self.add_finding(Finding(
                        severity=FindingSeverity.HIGH,
                        finding_type="bootloader_security",
                        path=str(path),
                        details=f"Potentially insecure bootloader configuration: {issue}",
                        evidence=f"Found pattern: {pattern}"
                    ))

        except Exception as e:
            logging.debug(f"Error checking bootloader {path}: {str(e)}")

    def _check_update_package(self, path: Path) -> None:
        """Analyze firmware update package"""
        try:
            # Check for unencrypted/unsigned firmware
            with open(path, 'rb') as f:
                header = f.read(4096)  # Read first 4KB for header analysis
                
            if not any(sig in header for sig in [b'PKCS7', b'SSL', b'SIGN']):
                self.add_finding(Finding(
                    severity=FindingSeverity.HIGH,
                    finding_type="unsigned_firmware",
                    path=str(path),
                    details="Firmware update package appears to be unsigned",
                    evidence="No signature block found in header"
                ))

        except Exception as e:
            logging.debug(f"Error checking update package {path}: {str(e)}")

    def _analyze_system_path(self, path: Path) -> None:
        """Analyze system paths for security issues"""
        try:
            if path.is_file():
                # Check permissions
                mode = path.stat().st_mode
                if mode & stat.S_IWOTH:
                    self.add_finding(Finding(
                        severity=FindingSeverity.HIGH,
                        finding_type="writable_system_file",
                        path=str(path),
                        details="World-writable file in system path",
                        evidence=f"Mode: {oct(mode)}"
                    ))

                # Check for unusual SUID/SGID in system paths
                if mode & (stat.S_ISUID | stat.S_ISGID):
                    self.add_finding(Finding(
                        severity=FindingSeverity.HIGH,
                        finding_type="suid_system_file",
                        path=str(path),
                        details="SUID/SGID file in system path",
                        evidence=f"Mode: {oct(mode)}"
                    ))

        except Exception as e:
            logging.debug(f"Error analyzing system path {path}: {str(e)}")

class FirmwareAnalyzer:
    """Enhanced main firmware analysis coordinator"""
    
    def __init__(self, root_path: str):
        self.root_path = Path(root_path)
        self.analyzers: List[SecurityAnalyzer] = [
            BinaryAnalyzer(self.root_path),
            CredentialAnalyzer(self.root_path),
            ConfigAnalyzer(self.root_path),
            FirmwareSpecificAnalyzer(self.root_path)
        ]
        self.findings: List[Finding] = []
        self.console = Console()
        self.report_generator = ReportGenerator(self.console)

    def analyze(self) -> None:
        """Run all security analyzers with progress tracking"""
        start_time = time.time()
        
        with Progress(
            SpinnerColumn(),
            *Progress.get_default_columns(),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            task = progress.add_task("[cyan]Analyzing firmware...", total=len(self.analyzers))
            
            for analyzer in self.analyzers:
                analyzer.analyze()
                self.findings.extend(analyzer.findings)
                progress.advance(task)

        # Deduplicate and sort findings
        self.findings = self._deduplicate_findings(self.findings)
        self.findings.sort(key=lambda x: (x.severity.value, x.finding_type))

        scan_time = time.time() - start_time
        self.report_generator.generate_report(self.findings, scan_time)

    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """Deduplicate findings based on type, path, and evidence"""
        seen = set()
        unique_findings = []
        
        for finding in findings:
            key = (finding.finding_type, finding.path, finding.evidence)
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
        
        return unique_findings
    
class ReportGenerator:
    """Report generator with enhanced hierarchical findings organization"""
    
    def __init__(self, console: Console):
        self.console = console

    def generate_report(self, findings: List[Finding], scan_time: float) -> None:
        """Generate a hierarchically organized security report"""
        self._print_header(scan_time)
        self._print_quick_stats(findings)
        self._print_hierarchical_findings(findings)

    def _print_header(self, scan_time: float) -> None:
        """Print minimal header with key scan info"""
        header = Panel(
            "[bold white]IoT Firmware Security Analysis Report[/]",
            border_style="blue",
            padding=(1, 2)
        )
        self.console.print(header)
        self.console.print(f"[dim]Scan completed in {scan_time:.2f} seconds[/]")
        self.console.print()

    def _print_quick_stats(self, findings: List[Finding]) -> None:
        """Print key statistics in a concise format"""
        if not findings:
            self.console.print("[yellow]No security findings detected.[/]")
            return

        severity_counts = {severity: 0 for severity in FindingSeverity}
        for finding in findings:
            severity_counts[finding.severity] += 1

        total_files = len({f.path for f in findings})
        
        stats_table = Table.grid(padding=(0, 4))
        stats_table.add_column(style="bold")
        stats_table.add_column(style="bold")
        
        # Add total counts
        stats_table.add_row(
            "Total Files Affected:",
            str(total_files)
        )
        stats_table.add_row(
            "Total Findings:",
            str(len(findings))
        )
        
        # Add severity counts
        for severity, count in severity_counts.items():
            if count > 0:
                stats_table.add_row(
                    f"[{severity.get_color()}]{severity.get_name()}:[/]",
                    f"[{severity.get_color()}]{count}[/]"
                )

        self.console.print(Panel(stats_table, title="[bold]Quick Stats", border_style="blue"))
        self.console.print()

    def _print_hierarchical_findings(self, findings: List[Finding]) -> None:
        """Print findings hierarchically grouped by file and type"""
        if not findings:
            return

        # Group findings by file path
        findings_by_file = {}
        for finding in findings:
            if finding.path not in findings_by_file:
                findings_by_file[finding.path] = []
            findings_by_file[finding.path].append(finding)

        # Sort files by highest severity finding
        sorted_files = sorted(
            findings_by_file.items(),
            key=lambda x: (min(f.severity.value for f in x[1]), x[0])
        )

        for file_path, file_findings in sorted_files:
            # Group findings by type for this file
            findings_by_type = {}
            for finding in file_findings:
                if finding.finding_type not in findings_by_type:
                    findings_by_type[finding.finding_type] = []
                findings_by_type[finding.finding_type].append(finding)

            # Get the highest severity for this file
            highest_severity = min(f.severity for f in file_findings)
            color = highest_severity.get_color()

            # Create file header
            self.console.print(f"\n[{color}]{'═' * 120}[/]")
            file_panel = Panel(
                f"[bold]{file_path}[/]",
                border_style=color,
                padding=(0, 1)
            )
            self.console.print(file_panel)

            # Create findings table for this file
            findings_table = Table(
                box=box.SIMPLE,
                show_header=False,
                padding=(0, 2),
                show_edge=False
            )
            findings_table.add_column(width=20)  # For finding type
            findings_table.add_column(width=90)  # For evidence

            for finding_type, grouped_findings in sorted(findings_by_type.items(), key=lambda x: x[0]):
                type_severity = min(f.severity for f in grouped_findings)
                type_color = type_severity.get_color()
                
                # Add finding type header
                findings_table.add_row(
                    f"[bold {type_color}]{finding_type.replace('_', ' ').title()}[/]",
                    f"[{type_color}]Severity: {type_severity.get_name()}[/]"
                )
                
                # Add unique evidence
                unique_evidence = sorted(set(
                    f.evidence for f in grouped_findings if f.evidence
                ))
                
                for evidence in unique_evidence:
                    findings_table.add_row(
                        "",  # Empty first column for indentation
                        f"[dim]➜ {evidence}[/]"
                    )
                
                # Add spacing between finding types
                findings_table.add_row("", "")

            self.console.print(findings_table)
            self.console.print(f"[{color}]{'═' * 120}[/]")

def setup_logging() -> None:
    """Configure logging with enhanced formatting"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Add file handler for debug logging
    debug_handler = logging.FileHandler('firmware_analysis_debug.log')
    debug_handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s')
    debug_handler.setFormatter(formatter)
    logging.getLogger().addHandler(debug_handler)

def main() -> None:
    """Enhanced main entry point with additional options"""
    parser = argparse.ArgumentParser(
        description='Analyze extracted IoT firmware for security issues',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/firmware
  %(prog)s -v /path/to/firmware
  %(prog)s --exclude-paths /path/to/exclude --output report.json /path/to/firmware
        """
    )
    parser.add_argument('root_path', 
                       help='Path to the extracted firmware root directory')
    parser.add_argument('-v', '--verbose', 
                       action='store_true', 
                       help='Enable verbose logging')
    parser.add_argument('--exclude-paths', 
                       help='Comma-separated list of paths to exclude from analysis')
    parser.add_argument('--output', 
                       help='Output file for JSON report')
    parser.add_argument('--severity-threshold',
                       choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
                       default='INFO',
                       help='Minimum severity level to report')
    args = parser.parse_args()

    # Setup logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    # Initialize and run analyzer
    try:
        analyzer = FirmwareAnalyzer(args.root_path)
        
        # Add excluded paths if specified
        if args.exclude_paths:
            excluded = set(args.exclude_paths.split(','))
            for a in analyzer.analyzers:
                a._excluded_dirs.update(excluded)

        analyzer.analyze()

        # Export JSON report if requested
        if args.output:
            severity_threshold = getattr(FindingSeverity, args.severity_threshold)
            filtered_findings = [
                {
                    'severity': f.severity.name,
                    'finding_type': f.finding_type,
                    'path': f.path,
                    'details': f.details,
                    'evidence': f.evidence
                }
                for f in analyzer.findings
                if f.severity.value <= severity_threshold.value
            ]
            
            with open(args.output, 'w') as f:
                json.dump({
                    'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'firmware_path': args.root_path,
                    'findings': filtered_findings
                }, f, indent=2)
            
            print(f"\nDetailed JSON report written to: {args.output}")

    except Exception as e:
        logging.error(f"Error during firmware analysis: {str(e)}")
        raise

if __name__ == "__main__":
    setup_logging()
    main()
