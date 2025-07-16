"""Main security scanner for MCP servers."""

import os
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Callable

from .models.scan_result import ScanResult
from .models.vulnerability import Vulnerability
from .analyzers.static_analyzer import StaticAnalyzer
from .analyzers.ai_analyzer import AIAnalyzer
from .utils.file_handler import FileHandler
from .utils.logger import get_logger

logger = get_logger(__name__)


class SecurityScanner:
    """Main security scanner class for MCP servers."""
    
    def __init__(self, config_path: Optional[str] = None, 
                 ignore_patterns: Optional[List[str]] = None,
                 max_workers: int = 4, verbose: bool = False,
                 ai_provider: str = "openai", ai_model: Optional[str] = None):
        """
        Initialize the security scanner.
        
        Args:
            config_path: Path to configuration file (optional)
            ignore_patterns: File patterns to ignore
            max_workers: Maximum number of worker processes
            verbose: Enable verbose logging
            ai_provider: AI provider to use (openai, claude, gemini)
            ai_model: AI model to use (optional, uses provider default)
        """
        self.config_path = config_path
        self.max_workers = max_workers
        self.verbose = verbose
        self.ai_provider = ai_provider
        self.ai_model = ai_model
        
        # Initialize components
        self.file_handler = FileHandler(ignore_patterns=ignore_patterns)
        self.static_analyzer = StaticAnalyzer(max_workers=max_workers)
        self.ai_analyzer = None  # Initialize only when needed
        
        logger.info("Security scanner initialized")
        
        if verbose:
            logger.setLevel("DEBUG")
    
    def scan_directory(self, directory: str, static_only: bool = False, 
                      ai_only: bool = False, progress_callback: Optional[Callable] = None) -> ScanResult:
        """
        Scan a directory for security vulnerabilities.
        
        Args:
            directory: Directory path to scan
            static_only: Run only static analysis
            ai_only: Run only AI analysis
            progress_callback: Optional callback for progress updates
            
        Returns:
            ScanResult object with findings
        """
        start_time = datetime.now()
        directory = os.path.abspath(directory)
        
        logger.info(f"Starting security scan of: {directory}")
        
        # Initialize scan result
        scan_result = ScanResult(
            target_path=directory,
            start_time=start_time
        )
        
        try:
            # Validate directory
            if not os.path.exists(directory):
                raise ValueError(f"Directory does not exist: {directory}")
            
            if not os.path.isdir(directory):
                raise ValueError(f"Path is not a directory: {directory}")
            
            # Get files to scan
            if progress_callback:
                progress_callback("Discovering files...")
            
            file_paths = list(self.file_handler.get_scannable_files(directory))
            scan_result.files_scanned = len(file_paths)
            
            if not file_paths:
                logger.warning("No scannable files found")
                scan_result.end_time = datetime.now()
                return scan_result
            
            logger.info(f"Found {len(file_paths)} files to scan")
            
            # Run static analysis (unless ai_only)
            if not ai_only:
                if progress_callback:
                    progress_callback("Running static analysis...")
                
                logger.info("Starting static analysis")
                static_vulnerabilities = self.static_analyzer.scan_files(
                    file_paths, self.file_handler, progress_callback
                )
                scan_result.vulnerabilities.extend(static_vulnerabilities)
                logger.info(f"Static analysis found {len(static_vulnerabilities)} vulnerabilities")
            
            # Run AI analysis (unless static_only)
            if not static_only and self._is_ai_available():
                if progress_callback:
                    progress_callback("Running AI analysis...")
                
                try:
                    # Initialize AI analyzer if needed
                    if self.ai_analyzer is None:
                        self.ai_analyzer = AIAnalyzer(
                            provider=self.ai_provider,
                            model=self.ai_model,
                            max_workers=1  # Conservative for API limits
                        )
                    
                    # Test connection first
                    if not self.ai_analyzer.test_connection():
                        logger.error("AI analyzer connection test failed")
                        scan_result.add_error(f"AI analysis failed: Could not connect to {self.ai_provider} API")
                    else:
                        logger.info(f"Starting AI analysis with {self.ai_provider}")
                        
                        # Intelligently select files for AI analysis
                        ai_file_paths = self._select_files_for_ai_analysis(file_paths, scan_result.vulnerabilities)
                        logger.info(f"Selected {len(ai_file_paths)} files for AI analysis out of {len(file_paths)} total files")
                        
                        ai_vulnerabilities = self.ai_analyzer.scan_files(
                            ai_file_paths, self.file_handler, progress_callback
                        )
                        scan_result.vulnerabilities.extend(ai_vulnerabilities)
                        logger.info(f"AI analysis found {len(ai_vulnerabilities)} vulnerabilities")
                
                except Exception as e:
                    logger.error(f"AI analysis failed: {e}")
                    scan_result.add_error(f"AI analysis failed: {e}")
            
            elif not static_only:
                logger.warning("OpenAI API key not found, skipping AI analysis")
                scan_result.add_error("AI analysis skipped: No OpenAI API key provided")
            
            # Deduplicate vulnerabilities
            scan_result.vulnerabilities = self._deduplicate_vulnerabilities(scan_result.vulnerabilities)
            
            scan_result.end_time = datetime.now()
            
            logger.info(f"Scan completed in {scan_result.scan_duration:.1f}s")
            logger.info(f"Total vulnerabilities found: {len(scan_result.vulnerabilities)}")
            
            # Log summary by severity
            severity_counts = scan_result.get_severity_counts()
            for severity, count in severity_counts.items():
                if count > 0:
                    logger.info(f"  {severity}: {count}")
            
            return scan_result
            
        except Exception as e:
            logger.error(f"Error during scan: {e}")
            scan_result.add_error(str(e))
            scan_result.end_time = datetime.now()
            return scan_result
    
    def scan_file(self, file_path: str, static_only: bool = False, 
                  ai_only: bool = False) -> List[Vulnerability]:
        """
        Scan a single file for vulnerabilities.
        
        Args:
            file_path: Path to the file to scan
            static_only: Run only static analysis
            ai_only: Run only AI analysis
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            # Read file content
            content = self.file_handler.read_file(file_path)
            if content is None:
                logger.error(f"Could not read file: {file_path}")
                return []
            
            # Run static analysis
            if not ai_only:
                static_vulns = self.static_analyzer.scan_file(file_path, content)
                vulnerabilities.extend(static_vulns)
            
            # Run AI analysis
            if not static_only and self._is_ai_available():
                try:
                    if self.ai_analyzer is None:
                        self.ai_analyzer = AIAnalyzer(
                            provider=self.ai_provider,
                            model=self.ai_model
                        )
                    
                    ai_vulns = self.ai_analyzer.scan_file(file_path, content)
                    vulnerabilities.extend(ai_vulns)
                    
                except Exception as e:
                    logger.error(f"AI analysis failed for {file_path}: {e}")
            
            # Deduplicate
            vulnerabilities = self._deduplicate_vulnerabilities(vulnerabilities)
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            return []
    
    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
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
                # Keep the one with higher confidence
                existing_vuln = next(v for v in unique_vulnerabilities 
                                   if (v.file_path, v.line_number, v.type.value) == key)
                if vuln.confidence > existing_vuln.confidence:
                    unique_vulnerabilities.remove(existing_vuln)
                    unique_vulnerabilities.append(vuln)
        
        return unique_vulnerabilities
    
    def validate_setup(self) -> List[str]:
        """
        Validate the scanner setup and configuration.
        
        Returns:
            List of validation errors
        """
        errors = []
        
        try:
            # Validate static analyzer rules
            rule_errors = self.static_analyzer.validate_rules()
            errors.extend(rule_errors)
            
            # Test AI analyzer if API key is available
            if self._is_ai_available():
                try:
                    if self.ai_analyzer is None:
                        self.ai_analyzer = AIAnalyzer(
                            provider=self.ai_provider,
                            model=self.ai_model
                        )
                    
                    if not self.ai_analyzer.test_connection():
                        errors.append("AI analyzer connection test failed")
                        
                except Exception as e:
                    errors.append(f"AI analyzer initialization failed: {e}")
            
        except Exception as e:
            errors.append(f"Scanner validation failed: {e}")
        
        return errors
    
    def get_scanner_info(self) -> dict:
        """
        Get information about the scanner configuration.
        
        Returns:
            Dictionary with scanner information
        """
        info = {
            'version': '1.0.0',
            'max_workers': self.max_workers,
            'verbose': self.verbose,
            'static_analyzer': {
                'enabled': True,
                'rules': self.static_analyzer.get_rule_stats()
            },
            'ai_analyzer': {
                'enabled': bool(os.getenv('OPENAI_API_KEY')),
                'model': 'gpt-4' if os.getenv('OPENAI_API_KEY') else None
            },
            'file_handler': {
                'max_file_size': self.file_handler.max_file_size,
                'ignore_patterns': len(self.file_handler.ignore_spec.patterns)
            }
        }
        
        return info
    
    def _is_ai_available(self) -> bool:
        """Check if AI analysis is available based on the selected provider."""
        if self.ai_provider == "openai":
            return bool(os.getenv('OPENAI_API_KEY'))
        elif self.ai_provider == "claude":
            return bool(os.getenv('ANTHROPIC_API_KEY'))
        elif self.ai_provider == "gemini":
            return bool(os.getenv('GEMINI_API_KEY'))
        return False
    
    def _select_files_for_ai_analysis(self, all_files: List[str], static_vulnerabilities: List) -> List[str]:
        """
        Intelligently select files for AI analysis based on priority.
        
        Args:
            all_files: All available files
            static_vulnerabilities: Vulnerabilities found by static analysis
            
        Returns:
            Prioritized list of files for AI analysis (max 25)
        """
        from collections import defaultdict
        import os
        
        MAX_AI_FILES = 25  # Increased from 20 for better coverage
        
        # Skip files that are definitely not worth AI analysis
        def should_skip_file(file_path: str) -> bool:
            file_lower = file_path.lower()
            skip_patterns = [
                # Build and dependency files
                'package-lock.json', 'yarn.lock', 'composer.lock',
                'node_modules/', '.git/', 'build/',
                # Documentation and config that rarely has vulns
                'license', 'changelog', '.vscode/', '.github/', '.gitignore',
                # Binary and media files
                '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
                '.woff', '.woff2', '.ttf', '.eot'
            ]
            return any(pattern in file_lower for pattern in skip_patterns)
        
        # Filter out files we should skip
        candidate_files = [f for f in all_files if not should_skip_file(f)]
        
        if len(candidate_files) <= MAX_AI_FILES:
            return candidate_files
        
        # Priority scoring system
        file_scores = {}
        
        # Files with static vulnerabilities get priority
        files_with_vulns = defaultdict(int)
        for vuln in static_vulnerabilities:
            files_with_vulns[vuln.file_path] += 1
        
        for file_path in candidate_files:
            score = 0
            file_lower = file_path.lower()
            file_name = os.path.basename(file_path).lower()
            
            # High priority: Files with static vulnerabilities
            if file_path in files_with_vulns:
                score += files_with_vulns[file_path] * 10  # 10 points per vulnerability
            
            # High priority: Core application files
            if any(keyword in file_lower for keyword in [
                'main.', 'index.', 'app.', 'server.', 'api.', 'cli.',
                'auth', 'login', 'admin', 'user', 'security'
            ]):
                score += 15
            
            # Medium priority: Source code files
            if any(file_path.endswith(ext) for ext in ['.py', '.js', '.ts', '.php', '.java', '.go', '.rs']):
                score += 8
            
            # Medium priority: Security-related files
            if any(keyword in file_lower for keyword in [
                'security', 'auth', 'validate', 'sanitize', 'permission',
                'token', 'crypto', 'encrypt', 'hash', 'password'
            ]):
                score += 12
            
            # Medium priority: Database and network files
            if any(keyword in file_lower for keyword in [
                'database', 'db', 'sql', 'model', 'entity',
                'network', 'http', 'request', 'response'
            ]):
                score += 8
            
            # Lower priority: Test files (but still analyze some)
            if any(keyword in file_lower for keyword in ['test', 'spec', '__test__']):
                score += 3
            
            # Lower priority: Configuration files
            if any(keyword in file_lower for keyword in ['config', 'setting']):
                score += 5
            
            # File size consideration (prefer smaller files for better analysis)
            try:
                file_size = os.path.getsize(file_path)
                if file_size < 10000:  # Small files get bonus
                    score += 3
                elif file_size > 100000:  # Large files get penalty
                    score -= 5
            except:
                pass
            
            file_scores[file_path] = score
        
        # Sort by score (descending) and take top files
        sorted_files = sorted(file_scores.items(), key=lambda x: x[1], reverse=True)
        selected_files = [file_path for file_path, score in sorted_files[:MAX_AI_FILES]]
        
        # Ensure we have at least some files with vulnerabilities
        vuln_files = [f for f in selected_files if f in files_with_vulns]
        if len(vuln_files) < 5 and len(files_with_vulns) > 0:
            # Add more files with vulnerabilities if we don't have enough
            additional_vuln_files = [f for f in files_with_vulns.keys() 
                                   if f not in selected_files and not should_skip_file(f)]
            selected_files.extend(additional_vuln_files[:5 - len(vuln_files)])
            selected_files = selected_files[:MAX_AI_FILES]  # Maintain limit
        
        logger.info(f"AI file selection: {len(vuln_files)} files with static vulns, "
                   f"{len(selected_files)} total selected")
        
        return selected_files
