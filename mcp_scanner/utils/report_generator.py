"""Report generation utilities for the MCP security scanner."""

import json
from typing import List
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from rich.columns import Columns

from ..models.scan_result import ScanResult
from ..models.vulnerability import Vulnerability
from .logger import get_logger

logger = get_logger(__name__)


class ReportGenerator:
    """Generates reports in different formats from scan results."""
    
    def __init__(self):
        self.console = Console()
    
    def generate_json_report(self, scan_result: ScanResult) -> str:
        """
        Generate a JSON report from scan results.
        
        Args:
            scan_result: Scan result object
            
        Returns:
            JSON report as string
        """
        return scan_result.to_json()
    
    def generate_table_report(self, scan_result: ScanResult) -> str:
        """
        Generate a rich table report from scan results.
        
        Args:
            scan_result: Scan result object
            
        Returns:
            Formatted table report as string
        """
        # Capture console output
        with self.console.capture() as capture:
            self._print_table_report(scan_result)
        
        return capture.get()
    
    def _print_table_report(self, scan_result: ScanResult):
        """Print table report to console."""
        # Header
        self.console.print(f"\n[bold blue]MCP Security Scanner Report[/bold blue]")
        self.console.print(f"[blue]Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/blue]")
        self.console.print(f"[blue]Target: {scan_result.target_path}[/blue]")
        self.console.print(f"[blue]Duration: {scan_result.scan_duration:.1f}s[/blue]\n")
        
        # Summary stats
        severity_counts = scan_result.get_severity_counts()
        summary_data = [
            f"[red]Critical: {severity_counts['CRITICAL']}[/red]",
            f"[orange3]High: {severity_counts['HIGH']}[/orange3]", 
            f"[yellow]Medium: {severity_counts['MEDIUM']}[/yellow]",
            f"[blue]Low: {severity_counts['LOW']}[/blue]"
        ]
        
        summary_panel = Panel(
            "\n".join(summary_data),
            title="Vulnerability Summary",
            title_align="left"
        )
        self.console.print(summary_panel)
        
        if not scan_result.vulnerabilities:
            self.console.print("\n[green]✅ No vulnerabilities found![/green]")
            return
        
        # Vulnerabilities table
        table = Table(title="Vulnerabilities Found", show_header=True, header_style="bold magenta")
        table.add_column("Severity", justify="center", style="bold", width=10)
        table.add_column("Type", style="cyan", width=15)
        table.add_column("File", style="blue", width=25)
        table.add_column("Line", justify="right", width=6)
        table.add_column("Description", no_wrap=False)  # Allow wrapping for full descriptions
        table.add_column("Detector", justify="center", width=10)
        table.add_column("Confidence", justify="center", width=10)
        
        # Sort vulnerabilities by severity and file
        sorted_vulns = sorted(
            scan_result.vulnerabilities,
            key=lambda v: (v.get_severity_score(), v.file_path, v.line_number),
            reverse=True
        )
        
        for vuln in sorted_vulns:
            # Format severity with color
            severity_color = vuln.get_color_code()
            severity_text = f"[{severity_color}]{vuln.severity.value}[/{severity_color}]"
            
            # Show full description - only truncate if extremely long (more than 500 chars)
            description = vuln.description
            if len(description) > 500:
                description = description[:497] + "..."
            
            # Confidence color coding
            confidence_color = "green" if vuln.confidence >= 80 else "yellow" if vuln.confidence >= 60 else "red"
            confidence_text = f"[{confidence_color}]{vuln.confidence}%[/{confidence_color}]"
            
            # Detector formatting
            detector_color = "blue" if vuln.detector == "static_analyzer" else "magenta"
            detector_text = "Static" if vuln.detector == "static_analyzer" else "AI"
            detector_display = f"[{detector_color}]{detector_text}[/{detector_color}]"
            
            # Format file path (show relative path)
            file_display = vuln.file_path
            if scan_result.target_path in file_display:
                file_display = file_display.replace(scan_result.target_path, "").lstrip("/\\")
            
            table.add_row(
                severity_text,
                vuln.type.value.replace("_", " ").title(),
                file_display,
                str(vuln.line_number),
                description,
                detector_display,
                confidence_text
            )
        
        self.console.print("\n")
        self.console.print(table)
        
        # File summary
        files_with_vulns = scan_result.get_files_with_vulnerabilities()
        if files_with_vulns:
            self.console.print(f"\n[bold]Files with vulnerabilities:[/bold]")
            for file_path in files_with_vulns[:10]:  # Show first 10
                file_display = file_path
                if scan_result.target_path in file_display:
                    file_display = file_display.replace(scan_result.target_path, "").lstrip("/\\")
                
                file_vulns = [v for v in scan_result.vulnerabilities if v.file_path == file_path]
                vuln_count = len(file_vulns)
                self.console.print(f"  • {file_display} ({vuln_count} issues)")
            
            if len(files_with_vulns) > 10:
                self.console.print(f"  ... and {len(files_with_vulns) - 10} more files")
        
        # Errors
        if scan_result.errors:
            self.console.print(f"\n[bold red]Errors encountered:[/bold red]")
            for error in scan_result.errors[:5]:  # Show first 5
                self.console.print(f"  • [red]{error}[/red]")
            
            if len(scan_result.errors) > 5:
                self.console.print(f"  ... and {len(scan_result.errors) - 5} more errors")
    
    def generate_markdown_report(self, scan_result: ScanResult) -> str:
        """
        Generate a markdown report from scan results.
        
        Args:
            scan_result: Scan result object
            
        Returns:
            Markdown report as string
        """
        lines = []
        
        # Header
        lines.append("# MCP Security Scanner Report")
        lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**Target:** `{scan_result.target_path}`")
        lines.append(f"**Duration:** {scan_result.scan_duration:.1f}s")
        lines.append(f"**Files Scanned:** {scan_result.files_scanned}")
        lines.append("")
        
        # Summary
        severity_counts = scan_result.get_severity_counts()
        lines.append("## Summary")
        lines.append("| Severity | Count |")
        lines.append("|----------|--------|")
        lines.append(f"| 🔴 Critical | {severity_counts['CRITICAL']} |")
        lines.append(f"| 🟠 High | {severity_counts['HIGH']} |")
        lines.append(f"| 🟡 Medium | {severity_counts['MEDIUM']} |")
        lines.append(f"| 🔵 Low | {severity_counts['LOW']} |")
        lines.append(f"| **Total** | **{scan_result.total_vulnerabilities}** |")
        lines.append("")
        
        if not scan_result.vulnerabilities:
            lines.append("✅ **No vulnerabilities found!**")
            return "\n".join(lines)
        
        # Vulnerabilities by severity
        vulnerabilities_by_severity = scan_result.get_vulnerabilities_by_severity()
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            vulns = vulnerabilities_by_severity.get(severity, [])
            if not vulns:
                continue
            
            severity_emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}
            lines.append(f"## {severity_emoji[severity]} {severity.title()} Severity ({len(vulns)} issues)")
            lines.append("")
            
            for vuln in vulns:
                lines.append(f"### {vuln.type.value.replace('_', ' ').title()}")
                lines.append(f"**File:** `{vuln.file_path}:{vuln.line_number}`")
                lines.append(f"**Description:** {vuln.description}")
                lines.append(f"**Recommendation:** {vuln.recommendation}")
                lines.append(f"**Confidence:** {vuln.confidence}%")
                lines.append(f"**Detected by:** {vuln.detector.replace('_', ' ').title()}")
                
                if vuln.code_snippet:
                    lines.append("")
                    lines.append("**Code:**")
                    lines.append("```")
                    lines.append(vuln.code_snippet)
                    lines.append("```")
                
                lines.append("")
                lines.append("---")
                lines.append("")
        
        # Files with vulnerabilities
        files_with_vulns = scan_result.get_files_with_vulnerabilities()
        if files_with_vulns:
            lines.append("## Files with Vulnerabilities")
            lines.append("")
            for file_path in files_with_vulns:
                file_vulns = [v for v in scan_result.vulnerabilities if v.file_path == file_path]
                lines.append(f"- `{file_path}` ({len(file_vulns)} issues)")
            lines.append("")
        
        # Errors
        if scan_result.errors:
            lines.append("## Errors")
            lines.append("")
            for error in scan_result.errors:
                lines.append(f"- ❌ {error}")
            lines.append("")
        
        return "\n".join(lines)
    
    def generate_detailed_vulnerability_report(self, vulnerability: Vulnerability) -> str:
        """
        Generate a detailed report for a single vulnerability.
        
        Args:
            vulnerability: Vulnerability object
            
        Returns:
            Detailed vulnerability report
        """
        lines = []
        
        lines.append(f"# {vulnerability.type.value.replace('_', ' ').title()} Vulnerability")
        lines.append("")
        lines.append(f"**ID:** {vulnerability.id}")
        lines.append(f"**Severity:** {vulnerability.severity.value}")
        lines.append(f"**File:** `{vulnerability.file_path}:{vulnerability.line_number}`")
        lines.append(f"**CWE ID:** {vulnerability.cwe_id}")
        lines.append(f"**Confidence:** {vulnerability.confidence}%")
        lines.append(f"**Detected by:** {vulnerability.detector}")
        
        if vulnerability.rule_name:
            lines.append(f"**Rule:** {vulnerability.rule_name}")
        
        lines.append("")
        lines.append("## Description")
        lines.append(vulnerability.description)
        lines.append("")
        
        lines.append("## Recommendation")
        lines.append(vulnerability.recommendation)
        lines.append("")
        
        if vulnerability.code_snippet:
            lines.append("## Code Snippet")
            lines.append("```")
            lines.append(vulnerability.code_snippet)
            lines.append("```")
            lines.append("")
        
        if vulnerability.additional_info:
            lines.append("## Additional Information")
            for key, value in vulnerability.additional_info.items():
                lines.append(f"- **{key.replace('_', ' ').title()}:** {value}")
            lines.append("")
        
        return "\n".join(lines)
