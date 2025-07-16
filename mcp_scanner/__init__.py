"""MCP Security Scanner - A comprehensive security scanner for Model Context Protocol servers."""

__version__ = "1.0.0"
__author__ = "MCP Security Team"
__email__ = "security@mcp.dev"

from .scanner import SecurityScanner
from .models.vulnerability import Vulnerability, VulnerabilitySeverity
from .models.scan_result import ScanResult

__all__ = [
    "SecurityScanner",
    "Vulnerability", 
    "VulnerabilitySeverity",
    "ScanResult"
]
