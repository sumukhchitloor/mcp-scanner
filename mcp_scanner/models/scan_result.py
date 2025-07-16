"""Scan result data model for the MCP security scanner."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional
import json

from .vulnerability import Vulnerability, VulnerabilitySeverity


@dataclass
class ScanResult:
    """Data model for scan results."""
    
    target_path: str
    start_time: datetime
    end_time: Optional[datetime] = None
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    errors: List[str] = field(default_factory=list)
    scanner_version: str = "1.0.0"
    config_used: Optional[Dict[str, Any]] = None
    
    @property
    def scan_duration(self) -> float:
        """Get scan duration in seconds."""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0
    
    @property
    def total_vulnerabilities(self) -> int:
        """Get total number of vulnerabilities found."""
        return len(self.vulnerabilities)
    
    def get_vulnerabilities_by_severity(self) -> Dict[str, List[Vulnerability]]:
        """Group vulnerabilities by severity level."""
        grouped = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': []
        }
        
        for vuln in self.vulnerabilities:
            grouped[vuln.severity.value].append(vuln)
        
        return grouped
    
    def get_vulnerabilities_by_type(self) -> Dict[str, List[Vulnerability]]:
        """Group vulnerabilities by type."""
        grouped = {}
        
        for vuln in self.vulnerabilities:
            vuln_type = vuln.type.value
            if vuln_type not in grouped:
                grouped[vuln_type] = []
            grouped[vuln_type].append(vuln)
        
        return grouped
    
    def get_vulnerabilities_by_file(self) -> Dict[str, List[Vulnerability]]:
        """Group vulnerabilities by file path."""
        grouped = {}
        
        for vuln in self.vulnerabilities:
            file_path = vuln.file_path
            if file_path not in grouped:
                grouped[file_path] = []
            grouped[file_path].append(vuln)
        
        return grouped
    
    def get_severity_counts(self) -> Dict[str, int]:
        """Get count of vulnerabilities by severity."""
        counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
        
        for vuln in self.vulnerabilities:
            counts[vuln.severity.value] += 1
        
        return counts
    
    def get_files_with_vulnerabilities(self) -> List[str]:
        """Get list of files that have vulnerabilities."""
        files = set()
        for vuln in self.vulnerabilities:
            files.add(vuln.file_path)
        return sorted(list(files))
    
    def get_highest_severity(self) -> Optional[VulnerabilitySeverity]:
        """Get the highest severity level found."""
        if not self.vulnerabilities:
            return None
        
        severities = [vuln.severity for vuln in self.vulnerabilities]
        severity_order = [
            VulnerabilitySeverity.CRITICAL,
            VulnerabilitySeverity.HIGH,
            VulnerabilitySeverity.MEDIUM,
            VulnerabilitySeverity.LOW
        ]
        
        for severity in severity_order:
            if severity in severities:
                return severity
        
        return None
    
    def filter_by_severity(self, min_severity: VulnerabilitySeverity) -> 'ScanResult':
        """Create a new ScanResult with vulnerabilities filtered by minimum severity."""
        severity_order = {
            VulnerabilitySeverity.CRITICAL: 4,
            VulnerabilitySeverity.HIGH: 3,
            VulnerabilitySeverity.MEDIUM: 2,
            VulnerabilitySeverity.LOW: 1
        }
        
        min_score = severity_order[min_severity]
        filtered_vulns = [
            vuln for vuln in self.vulnerabilities
            if severity_order[vuln.severity] >= min_score
        ]
        
        # Create new scan result with filtered vulnerabilities
        new_result = ScanResult(
            target_path=self.target_path,
            start_time=self.start_time,
            end_time=self.end_time,
            vulnerabilities=filtered_vulns,
            files_scanned=self.files_scanned,
            files_skipped=self.files_skipped,
            errors=self.errors.copy(),
            scanner_version=self.scanner_version,
            config_used=self.config_used
        )
        
        return new_result
    
    def add_vulnerability(self, vulnerability: Vulnerability):
        """Add a vulnerability to the scan result."""
        self.vulnerabilities.append(vulnerability)
    
    def add_error(self, error: str):
        """Add an error message to the scan result."""
        self.errors.append(error)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to dictionary format."""
        return {
            'target_path': self.target_path,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'scan_duration': self.scan_duration,
            'files_scanned': self.files_scanned,
            'files_skipped': self.files_skipped,
            'total_vulnerabilities': self.total_vulnerabilities,
            'vulnerabilities': [vuln.to_dict() for vuln in self.vulnerabilities],
            'severity_counts': self.get_severity_counts(),
            'errors': self.errors,
            'scanner_version': self.scanner_version,
            'config_used': self.config_used
        }
    
    def to_json(self) -> str:
        """Convert scan result to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
    
    def get_summary(self) -> str:
        """Get a brief summary of the scan result."""
        severity_counts = self.get_severity_counts()
        return (f"Scan Summary: {self.total_vulnerabilities} vulnerabilities found in "
                f"{self.files_scanned} files ({self.scan_duration:.1f}s)\n"
                f"Critical: {severity_counts['CRITICAL']}, "
                f"High: {severity_counts['HIGH']}, "
                f"Medium: {severity_counts['MEDIUM']}, "
                f"Low: {severity_counts['LOW']}")
    
    def __str__(self) -> str:
        """String representation of the scan result."""
        return self.get_summary()
    
    def __repr__(self) -> str:
        """Detailed representation of the scan result."""
        return (f"ScanResult(target='{self.target_path}', "
                f"vulnerabilities={self.total_vulnerabilities}, "
                f"files_scanned={self.files_scanned}, "
                f"duration={self.scan_duration:.1f}s)")
