"""Models package for the MCP security scanner."""

from .vulnerability import Vulnerability, VulnerabilitySeverity, VulnerabilityType
from .scan_result import ScanResult

__all__ = [
    'Vulnerability',
    'VulnerabilitySeverity', 
    'VulnerabilityType',
    'ScanResult'
]
