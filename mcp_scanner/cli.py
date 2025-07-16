#!/usr/bin/env python3
"""
MCP Security Scanner CLI
Main command-line interface for the MCP security scanner.
"""

import os
import sys
import json
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from dotenv import load_dotenv

from .scanner import SecurityScanner
from .models.vulnerability import VulnerabilitySeverity
from .utils.logger import setup_logger
from .utils.report_generator import ReportGenerator

# Load environment variables
load_dotenv()

console = Console()
logger = setup_logger()


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """MCP Security Scanner - Detect vulnerabilities in MCP servers."""
    pass


@cli.command()
@click.argument('folder_path', type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option('--static-only', is_flag=True, help='Run only static analysis')
@click.option('--ai-only', is_flag=True, help='Run only AI analysis')
@click.option('--output-format', 
              type=click.Choice(['json', 'table', 'markdown'], case_sensitive=False),
              default='table',
              help='Output format (default: table)')
@click.option('--severity',
              type=str,
              help='Filter by severity levels (comma-separated: critical,high,medium,low)')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--ignore-patterns',
              type=str,
              help='File patterns to ignore (comma-separated)')
@click.option('--config',
              type=click.Path(exists=True),
              help='Custom config file path')
@click.option('--api-key',
              type=str,
              help='API key for the AI provider (or set corresponding env var)')
@click.option('--ai-provider',
              type=click.Choice(['openai', 'claude', 'gemini'], case_sensitive=False),
              default='openai',
              help='AI provider to use (default: openai)')
@click.option('--model',
              type=str,
              help='AI model to use (default depends on provider)')
@click.option('--output', '-o',
              type=click.Path(),
              help='Output file path (default: stdout)')
@click.option('--max-workers',
              type=int,
              default=4,
              help='Maximum number of worker processes (default: 4)')
def scan(folder_path: str, static_only: bool, ai_only: bool, output_format: str,
         severity: Optional[str], verbose: bool, ignore_patterns: Optional[str],
         config: Optional[str], api_key: Optional[str], ai_provider: str, model: Optional[str],
         output: Optional[str], max_workers: int):
    """Scan a folder for security vulnerabilities in MCP servers."""
    
    if verbose:
        logger.setLevel("DEBUG")
        console.print("[green]Verbose mode enabled[/green]")
    
    # Validate mutually exclusive options
    if static_only and ai_only:
        console.print("[red]Error: --static-only and --ai-only are mutually exclusive[/red]")
        sys.exit(1)
    
    # Handle API key for different providers
    provider_lower = ai_provider.lower()
    api_key_set = False
    
    if api_key:
        # Set the appropriate environment variable based on provider
        if provider_lower == 'openai':
            os.environ['OPENAI_API_KEY'] = api_key
        elif provider_lower == 'claude':
            os.environ['ANTHROPIC_API_KEY'] = api_key
        elif provider_lower == 'gemini':
            os.environ['GEMINI_API_KEY'] = api_key
        api_key_set = True
    
    # Check if API key is available for the selected provider
    if not ai_only:
        if provider_lower == 'openai' and not (api_key_set or os.getenv('OPENAI_API_KEY')):
            console.print(f"[yellow]Warning: No OpenAI API key provided. AI analysis will be skipped.[/yellow]")
            console.print(f"[yellow]Set OPENAI_API_KEY environment variable or use --api-key option.[/yellow]")
            static_only = True
        elif provider_lower == 'claude' and not (api_key_set or os.getenv('ANTHROPIC_API_KEY')):
            console.print(f"[yellow]Warning: No Anthropic API key provided. AI analysis will be skipped.[/yellow]")
            console.print(f"[yellow]Set ANTHROPIC_API_KEY environment variable or use --api-key option.[/yellow]")
            static_only = True
        elif provider_lower == 'gemini' and not (api_key_set or os.getenv('GEMINI_API_KEY')):
            console.print(f"[yellow]Warning: No Gemini API key provided. AI analysis will be skipped.[/yellow]")
            console.print(f"[yellow]Set GEMINI_API_KEY environment variable or use --api-key option.[/yellow]")
            static_only = True
    
    # Parse severity filters
    severity_filters = None
    if severity:
        try:
            severity_filters = [
                VulnerabilitySeverity(s.strip().upper()) 
                for s in severity.split(',')
            ]
        except ValueError as e:
            console.print(f"[red]Error: Invalid severity level: {e}[/red]")
            sys.exit(1)
    
    # Parse ignore patterns
    ignore_list = []
    if ignore_patterns:
        ignore_list = [pattern.strip() for pattern in ignore_patterns.split(',')]
    
    try:
        # Initialize scanner
        scanner = SecurityScanner(
            config_path=config,
            ignore_patterns=ignore_list,
            max_workers=max_workers,
            verbose=verbose,
            ai_provider=ai_provider,
            ai_model=model
        )
        
        console.print(f"[bold blue]MCP Security Scanner v1.0.0[/bold blue]")
        console.print(f"[blue]Scanning: {folder_path}[/blue]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task("Scanning files...", total=None)
            
            # Run scan
            scan_result = scanner.scan_directory(
                folder_path,
                static_only=static_only,
                ai_only=ai_only,
                progress_callback=lambda msg: progress.update(task, description=msg)
            )
        
        # Filter results by severity
        if severity_filters:
            scan_result.vulnerabilities = [
                vuln for vuln in scan_result.vulnerabilities
                if vuln.severity in severity_filters
            ]
        
        # Generate report
        report_generator = ReportGenerator()
        
        if output_format == 'json':
            report = report_generator.generate_json_report(scan_result)
        elif output_format == 'markdown':
            report = report_generator.generate_markdown_report(scan_result)
        else:  # table
            # For table format, print directly instead of capturing
            if output:
                report = report_generator.generate_table_report(scan_result)
            else:
                report_generator._print_table_report(scan_result)
                report = ""
        
        # Output results
        if output:
            with open(output, 'w', encoding='utf-8') as f:
                if output_format == 'table':
                    # For file output, generate captured report
                    report = report_generator.generate_table_report(scan_result)
                f.write(report)
            console.print(f"[green]Report saved to: {output}[/green]")
        elif report:  # Only print if we have a report to print
            console.print(report)
        
        # Print summary
        console.print(f"\n[bold]Summary:[/bold]")
        console.print(f"Files analyzed: {scan_result.files_scanned}")
        console.print(f"Time taken: {scan_result.scan_duration:.1f}s")
        console.print(f"Total vulnerabilities: {len(scan_result.vulnerabilities)}")
        
        # Group by severity
        severity_counts = {}
        for vuln in scan_result.vulnerabilities:
            severity_counts[vuln.severity.value] = severity_counts.get(vuln.severity.value, 0) + 1
        
        for severity_level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = severity_counts.get(severity_level, 0)
            if count > 0:
                color = {
                    'CRITICAL': 'red',
                    'HIGH': 'orange3',
                    'MEDIUM': 'yellow',
                    'LOW': 'blue'
                }.get(severity_level, 'white')
                console.print(f"- {severity_level.title()}: [{color}]{count}[/{color}]")
        
        # Exit with error code if critical or high vulnerabilities found
        critical_high_count = (
            severity_counts.get('CRITICAL', 0) + 
            severity_counts.get('HIGH', 0)
        )
        if critical_high_count > 0:
            sys.exit(1)
            
    except Exception as e:
        console.print(f"[red]Error during scan: {e}[/red]")
        if verbose:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)


@cli.command()
def version():
    """Show version information."""
    console.print("MCP Security Scanner v1.0.0")
    console.print("A comprehensive security scanner for Model Context Protocol servers")


@cli.command()
@click.argument('rule_name', required=False)
def list_rules(rule_name: Optional[str]):
    """List available security rules."""
    from .rules import get_all_rules
    
    rules = get_all_rules()
    
    if rule_name:
        # Show details for specific rule
        rule = rules.get(rule_name.lower())
        if not rule:
            console.print(f"[red]Rule '{rule_name}' not found[/red]")
            sys.exit(1)
        
        console.print(f"[bold]{rule.__class__.__name__}[/bold]")
        console.print(f"Description: {rule.description}")
        console.print(f"Severity: {rule.severity}")
        console.print(f"Enabled: {rule.enabled}")
    else:
        # List all rules
        table = Table(title="Available Security Rules")
        table.add_column("Rule Name", style="cyan", no_wrap=True)
        table.add_column("Description", style="white")
        table.add_column("Severity", justify="center")
        table.add_column("Enabled", justify="center")
        
        for name, rule in rules.items():
            enabled = "[green]✓[/green]" if rule.enabled else "[red]✗[/red]"
            severity_color = {
                'CRITICAL': 'red',
                'HIGH': 'orange3', 
                'MEDIUM': 'yellow',
                'LOW': 'blue'
            }.get(rule.severity.value, 'white')
            
            table.add_row(
                name,
                rule.description,
                f"[{severity_color}]{rule.severity.value}[/{severity_color}]",
                enabled
            )
        
        console.print(table)


def main():
    """Main entry point for the CLI."""
    cli()


if __name__ == '__main__':
    main()
