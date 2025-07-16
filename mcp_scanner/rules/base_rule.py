"""Base class for all security rules."""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Pattern
import re
import bisect

from ..models.vulnerability import Vulnerability, VulnerabilitySeverity, VulnerabilityType


class BaseRule(ABC):
    """Base class for all security vulnerability detection rules."""
    
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.patterns: Dict[str, Pattern[str]] = {}
        self._compile_patterns()
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Rule name identifier."""
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what this rule detects."""
        pass
    
    @property
    @abstractmethod
    def severity(self) -> VulnerabilitySeverity:
        """Default severity level for vulnerabilities detected by this rule."""
        pass
    
    @property
    @abstractmethod
    def vulnerability_type(self) -> VulnerabilityType:
        """Type of vulnerability this rule detects."""
        pass
    
    @property
    @abstractmethod
    def cwe_id(self) -> str:
        """CWE (Common Weakness Enumeration) identifier."""
        pass
    
    @abstractmethod
    def get_patterns(self) -> Dict[str, str]:
        """Get the regex patterns used by this rule."""
        pass
    
    def _compile_patterns(self):
        """Compile regex patterns for better performance."""
        patterns = self.get_patterns()
        self.patterns = {
            name: re.compile(pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            for name, pattern in patterns.items()
        }
    
    def scan_file(self, file_path: str, content: str) -> List[Vulnerability]:
        """
        Scan file content for vulnerabilities.
        
        Args:
            file_path: Path to the file being scanned
            content: File content as string
            
        Returns:
            List of vulnerabilities found
        """
        if not self.enabled:
            return []
        
        vulnerabilities = []
        lines = content.splitlines()
        
        # Pre-compute line start positions for fast line number lookup
        line_starts = [0]
        for i, char in enumerate(content):
            if char == '\n':
                line_starts.append(i + 1)
        
        for pattern_name, pattern in self.patterns.items():
            for match in pattern.finditer(content):
                # Find line number using binary search on pre-computed line starts
                line_number = bisect.bisect_right(line_starts, match.start())
                
                # Get code snippet (current line and context)
                start_line = max(0, line_number - 3)
                end_line = min(len(lines), line_number + 2)
                code_snippet = '\n'.join(lines[start_line:end_line])
                
                # Create vulnerability
                vulnerability = self._create_vulnerability(
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=code_snippet,
                    match=match,
                    pattern_name=pattern_name
                )
                
                if vulnerability:
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _create_vulnerability(self, file_path: str, line_number: int, 
                            code_snippet: str, match: re.Match, 
                            pattern_name: str) -> Vulnerability:
        """
        Create a vulnerability object from a pattern match.
        
        Args:
            file_path: Path to the file
            line_number: Line number where vulnerability was found
            code_snippet: Code snippet containing the vulnerability
            match: Regex match object
            pattern_name: Name of the pattern that matched
            
        Returns:
            Vulnerability object
        """
        # Generate unique ID
        vuln_id = f"{self.name}_{file_path}_{line_number}_{pattern_name}"
        vuln_id = vuln_id.replace('/', '_').replace('\\', '_')
        
        # Get specific description and recommendation
        description = self.get_vulnerability_description(pattern_name, match)
        recommendation = self.get_vulnerability_recommendation(pattern_name, match)
        confidence = self.get_confidence_score(pattern_name, match)
        
        return Vulnerability(
            id=vuln_id,
            type=self.vulnerability_type,
            severity=self.severity,
            file_path=file_path,
            line_number=line_number,
            code_snippet=code_snippet,
            description=description,
            recommendation=recommendation,
            confidence=confidence,
            detector='static_analyzer',
            rule_name=self.name,
            cwe_id=self.cwe_id,
            additional_info={
                'pattern_name': pattern_name,
                'matched_text': match.group(0)
            }
        )
    
    def get_vulnerability_description(self, pattern_name: str, match: re.Match) -> str:
        """
        Get specific description for a vulnerability.
        Can be overridden by subclasses for pattern-specific descriptions.
        """
        return f"{self.description} (Pattern: {pattern_name})"
    
    def get_vulnerability_recommendation(self, pattern_name: str, match: re.Match) -> str:
        """
        Get specific recommendation for fixing a vulnerability.
        Can be overridden by subclasses for pattern-specific recommendations.
        """
        return "Review and fix the identified security issue"
    
    def get_confidence_score(self, pattern_name: str, match: re.Match) -> int:
        """
        Get confidence score for a vulnerability (0-100).
        Can be overridden by subclasses for pattern-specific confidence.
        """
        return 80  # Default confidence
    
    def is_false_positive(self, match: re.Match, context: str) -> bool:
        """
        Check if a match is likely a false positive.
        Can be overridden by subclasses for custom false positive detection.
        """
        return False
    
    def should_scan_file(self, file_path: str) -> bool:
        """
        Determine if this rule should scan the given file.
        Can be overridden by subclasses for file-specific logic.
        """
        return True
    
    def __str__(self) -> str:
        return f"{self.name} ({self.severity.value})"
    
    def __repr__(self) -> str:
        return f"BaseRule(name='{self.name}', enabled={self.enabled})"
