"""Static analyzer for rule-based vulnerability detection."""

import uuid
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

from ..models.vulnerability import Vulnerability
from ..rules import get_enabled_rules
from ..utils.logger import get_logger
from ..utils.file_handler import FileHandler

logger = get_logger(__name__)


class StaticAnalyzer:
    """Rule-based static analyzer for vulnerability detection."""
    
    def __init__(self, max_workers: int = 2):
        """
        Initialize the static analyzer.
        
        Args:
            max_workers: Maximum number of worker threads for parallel processing
        """
        self.max_workers = max_workers
        self.rules = get_enabled_rules()
        logger.info(f"Loaded {len(self.rules)} security rules")
        logger.info(f"Using {self.max_workers} worker threads for static analysis")
    
    def scan_file(self, file_path: str, content: str) -> List[Vulnerability]:
        """
        Scan a single file for vulnerabilities.
        
        Args:
            file_path: Path to the file
            content: File content as string
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        # Skip extremely large files to prevent performance issues
        if len(content) > 2_000_000:  # 2MB limit
            logger.warning(f"Skipping large file {file_path} ({len(content):,} chars)")
            return vulnerabilities
        
        # Skip binary files (likely to have null bytes)
        if '\x00' in content:
            logger.debug(f"Skipping binary file {file_path}")
            return vulnerabilities
        
        logger.debug(f"Scanning {file_path} with {len(self.rules)} rules...")
        
        for rule_name, rule in self.rules.items():
            try:
                # Check if rule should scan this file
                if not rule.should_scan_file(file_path):
                    continue
                
                # Scan file with rule
                rule_vulnerabilities = rule.scan_file(file_path, content)
                vulnerabilities.extend(rule_vulnerabilities)
                
                logger.debug(f"Rule {rule_name} found {len(rule_vulnerabilities)} issues in {file_path}")
                
            except Exception as e:
                logger.error(f"Error running rule {rule_name} on {file_path}: {e}")
                continue
        
        # Remove duplicates based on file, line, and type
        unique_vulnerabilities = self._remove_duplicates(vulnerabilities)
        
        logger.debug(f"Found {len(unique_vulnerabilities)} unique vulnerabilities in {file_path}")
        return unique_vulnerabilities
    
    def scan_files(self, file_paths: List[str], file_handler: FileHandler, 
                   progress_callback=None) -> List[Vulnerability]:
        """
        Scan multiple files for vulnerabilities in parallel.
        
        Args:
            file_paths: List of file paths to scan
            file_handler: File handler for reading files
            progress_callback: Optional callback for progress updates
            
        Returns:
            List of all vulnerabilities found
        """
        all_vulnerabilities = []
        
        if not file_paths:
            return all_vulnerabilities
        
        start_time = time.time()
        
        # Use thread pool for parallel processing
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all files for processing
            future_to_file = {}
            
            for file_path in file_paths:
                try:
                    content = file_handler.read_file(file_path)
                    if content is None:
                        logger.warning(f"Could not read file: {file_path}")
                        continue
                    
                    future = executor.submit(self.scan_file, file_path, content)
                    future_to_file[future] = file_path
                    
                except Exception as e:
                    logger.error(f"Error submitting file {file_path} for scanning: {e}")
                    continue
            
            # Collect results as they complete
            completed = 0
            total = len(future_to_file)
            
            for future in as_completed(future_to_file, timeout=300):  # 5 minute timeout
                file_path = future_to_file[future]
                completed += 1
                
                try:
                    vulnerabilities = future.result(timeout=30)  # 30 second per file timeout
                    all_vulnerabilities.extend(vulnerabilities)
                    
                    if progress_callback:
                        progress_callback(f"Scanned {completed}/{total} files ({file_path})")
                    
                    logger.debug(f"Completed scanning {file_path} ({completed}/{total})")
                    
                except TimeoutError:
                    logger.warning(f"Timeout scanning file {file_path} - skipping")
                    continue
                except Exception as e:
                    logger.error(f"Error scanning file {file_path}: {e}")
                    continue
        
        end_time = time.time()
        duration = end_time - start_time
        
        logger.info(f"Static analysis completed in {duration:.1f}s")
        logger.info(f"Found {len(all_vulnerabilities)} vulnerabilities across {len(file_paths)} files")
        
        return all_vulnerabilities
    
    def _remove_duplicates(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """
        Remove duplicate vulnerabilities based on file, line, and type.
        
        Args:
            vulnerabilities: List of vulnerabilities
            
        Returns:
            List of unique vulnerabilities
        """
        seen = set()
        unique_vulnerabilities = []
        
        for vuln in vulnerabilities:
            # Create a key based on file, line, and type
            key = (vuln.file_path, vuln.line_number, vuln.type.value)
            
            if key not in seen:
                seen.add(key)
                unique_vulnerabilities.append(vuln)
            else:
                logger.debug(f"Removing duplicate vulnerability: {vuln.id}")
        
        return unique_vulnerabilities
    
    def get_rule_stats(self) -> Dict[str, Any]:
        """
        Get statistics about loaded rules.
        
        Returns:
            Dictionary with rule statistics
        """
        stats = {
            'total_rules': len(self.rules),
            'enabled_rules': len([r for r in self.rules.values() if r.enabled]),
            'rules_by_severity': {},
            'rules_by_type': {}
        }
        
        for rule in self.rules.values():
            # Count by severity
            severity = rule.severity.value
            stats['rules_by_severity'][severity] = stats['rules_by_severity'].get(severity, 0) + 1
            
            # Count by type
            vuln_type = rule.vulnerability_type.value
            stats['rules_by_type'][vuln_type] = stats['rules_by_type'].get(vuln_type, 0) + 1
        
        return stats
    
    def validate_rules(self) -> List[str]:
        """
        Validate all loaded rules for correctness.
        
        Returns:
            List of validation errors
        """
        errors = []
        
        for rule_name, rule in self.rules.items():
            try:
                # Check if rule has required properties
                if not rule.name:
                    errors.append(f"Rule {rule_name} has no name")
                
                if not rule.description:
                    errors.append(f"Rule {rule_name} has no description")
                
                if not rule.get_patterns():
                    errors.append(f"Rule {rule_name} has no patterns")
                
                # Try to compile patterns
                for pattern_name, pattern in rule.get_patterns().items():
                    try:
                        import re
                        re.compile(pattern)
                    except re.error as e:
                        errors.append(f"Rule {rule_name} pattern {pattern_name} is invalid: {e}")
                
            except Exception as e:
                errors.append(f"Error validating rule {rule_name}: {e}")
        
        return errors
