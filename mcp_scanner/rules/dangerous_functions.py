"""High-confidence dangerous function detection rule."""

from typing import Dict
import re

from .base_rule import BaseRule
from ..models.vulnerability import VulnerabilitySeverity, VulnerabilityType


class DangerousFunctionsRule(BaseRule):
    """Detects dangerous function usage with high confidence patterns."""
    
    @property
    def name(self) -> str:
        return "dangerous_functions"
    
    @property
    def description(self) -> str:
        return "Detects dangerous function calls that could lead to security vulnerabilities"
    
    @property
    def severity(self) -> VulnerabilitySeverity:
        return VulnerabilitySeverity.HIGH
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.COMMAND_INJECTION
    
    @property
    def cwe_id(self) -> str:
        return "CWE-78"
    
    def get_patterns(self) -> Dict[str, str]:
        return {
            # Command Execution (High Confidence Only)
            'os_system_concat': r'os\.system\s*\(\s*[^)]*[\+%]',  # os.system with concatenation
            'os_system_format': r'os\.system\s*\([^)]*\.format\s*\(',  # os.system with .format()
            'subprocess_shell_concat': r'subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True[^)]*[\+%]',  # subprocess with shell=True + concat
            'subprocess_shell_format': r'subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True[^)]*\.format',  # subprocess with shell=True + format
            
            # Code Execution (High Confidence Only)
            'eval_request_data': r'eval\s*\(\s*request\.',  # eval with request data
            'eval_user_input': r'eval\s*\(\s*input\s*\(',  # eval with user input
            'exec_request_data': r'exec\s*\(\s*request\.',  # exec with request data
            'exec_user_input': r'exec\s*\(\s*input\s*\(',  # exec with user input
            
            # SQL Injection (Basic High-Confidence Patterns)
            'sql_string_concat': r'(?:SELECT|INSERT|UPDATE|DELETE).*[\+%].*(?:WHERE|VALUES)',  # SQL with concatenation
            'cursor_execute_concat': r'cursor\.execute\s*\([^)]*[\+%][^)]*\)',  # cursor.execute with concatenation
            'query_format_string': r'(?:query|sql)\s*=\s*["\'](?:SELECT|INSERT|UPDATE|DELETE).*["\'].*[\+%]',  # Query building with +
            
            # Deserialization (High Confidence)
            'pickle_loads_unsafe': r'pickle\.loads?\s*\([^)]*(?:input|request)',  # pickle.loads with user input
            'yaml_unsafe_load': r'yaml\.(?:load|unsafe_load)\s*\([^)]*(?:input|request)',  # yaml.load with user input
            
            # File Operations (High Confidence)
            'open_user_input': r'open\s*\([^)]*(?:input\s*\(|request\.)',  # open() with user input
            'file_path_traversal': r'open\s*\([^)]*\.\.[/\\]',  # open() with path traversal
            
            # Template Injection (High Confidence)
            'template_string_user_input': r'Template\s*\([^)]*(?:input|request)',  # Template with user input
            'format_string_user_input': r'["\'].*\{\}.*["\']\.format\s*\([^)]*(?:input|request)',  # .format() with user input
        }
    
    def get_vulnerability_description(self, pattern_name: str, match: re.Match) -> str:
        descriptions = {
            'os_system_concat': "Command execution using os.system() with string concatenation",
            'os_system_format': "Command execution using os.system() with string formatting",
            'subprocess_shell_concat': "Subprocess call with shell=True and string concatenation",
            'subprocess_shell_format': "Subprocess call with shell=True and string formatting",
            'eval_request_data': "Code execution using eval() with request data",
            'eval_user_input': "Code execution using eval() with user input",
            'exec_request_data': "Code execution using exec() with request data",
            'exec_user_input': "Code execution using exec() with user input",
            'sql_string_concat': "SQL query construction using string concatenation",
            'cursor_execute_concat': "Database cursor execution with string concatenation",
            'query_format_string': "SQL query building with string concatenation",
            'pickle_loads_unsafe': "Unsafe pickle deserialization with user input",
            'yaml_unsafe_load': "Unsafe YAML loading with user input",
            'open_user_input': "File opening with user-controlled input",
            'file_path_traversal': "File operation with potential path traversal",
            'template_string_user_input': "Template rendering with user input",
            'format_string_user_input': "String formatting with user input",
        }
        return descriptions.get(pattern_name, "Dangerous function call detected")
    
    def get_vulnerability_recommendation(self, pattern_name: str, match: re.Match) -> str:
        recommendations = {
            'os_system_concat': "Use subprocess with shell=False and validate all inputs",
            'os_system_format': "Use subprocess with shell=False and validate all inputs",
            'subprocess_shell_concat': "Use subprocess with shell=False and pass arguments as list",
            'subprocess_shell_format': "Use subprocess with shell=False and pass arguments as list",
            'eval_request_data': "Avoid eval() entirely. Use ast.literal_eval() for safe evaluation",
            'eval_user_input': "Avoid eval() entirely. Use ast.literal_eval() for safe evaluation",
            'exec_request_data': "Avoid exec() with user input. Use safer alternatives",
            'exec_user_input': "Avoid exec() with user input. Use safer alternatives",
            'sql_string_concat': "Use parameterized queries or prepared statements",
            'cursor_execute_concat': "Use parameterized queries with cursor.execute()",
            'query_format_string': "Use parameterized queries instead of string formatting",
            'pickle_loads_unsafe': "Avoid pickle with untrusted data. Use JSON or validate input",
            'yaml_unsafe_load': "Use yaml.safe_load() instead of yaml.load()",
            'open_user_input': "Validate and sanitize file paths before opening",
            'file_path_traversal': "Use os.path.abspath() and validate paths to prevent traversal",
            'template_string_user_input': "Sanitize user input before template rendering",
            'format_string_user_input': "Validate and sanitize user input before string formatting",
        }
        return recommendations.get(pattern_name, "Validate and sanitize all user inputs")
    
    def get_confidence_score(self, pattern_name: str, match: re.Match) -> int:
        # Very high confidence patterns
        very_high_confidence = {
            'os_system_concat': 95,
            'os_system_format': 95,
            'subprocess_shell_concat': 95,
            'subprocess_shell_format': 95,
            'eval_request_data': 100,
            'eval_user_input': 100,
            'exec_request_data': 100,
            'exec_user_input': 100,
            'pickle_loads_unsafe': 95,
            'yaml_unsafe_load': 90,
        }
        
        # High confidence patterns
        high_confidence = {
            'sql_string_concat': 85,
            'cursor_execute_concat': 90,
            'query_format_string': 85,
            'open_user_input': 80,
            'file_path_traversal': 90,
            'template_string_user_input': 85,
            'format_string_user_input': 80,
        }
        
        if pattern_name in very_high_confidence:
            return very_high_confidence[pattern_name]
        elif pattern_name in high_confidence:
            return high_confidence[pattern_name]
        else:
            return 85
    
    def is_false_positive(self, match: re.Match, context: str) -> bool:
        """Check for common false positive patterns."""
        matched_text = match.group(0)
        context_lower = context.lower()
        
        # Skip test files and examples
        if any(indicator in context_lower for indicator in [
            'test_', '_test', 'example', 'demo', 'sample'
        ]):
            return True
        
        # Skip comments and documentation
        if any(indicator in context_lower for indicator in [
            '# ', '//', '/*', '"""', "'''"
        ]):
            return True
        
        # Skip obvious safe patterns
        safe_patterns = [
            'shell=False',  # subprocess with shell=False is safe
            'sanitized',    # Already sanitized input
            'validated',    # Already validated input
            'escaped',      # Already escaped input
        ]
        
        for pattern in safe_patterns:
            if pattern in context_lower:
                return True
        
        return False
    
    def should_scan_file(self, file_path: str) -> bool:
        """Only scan relevant file types."""
        relevant_extensions = ['.py', '.js', '.ts', '.php', '.rb', '.java', '.go', '.rs', '.cpp', '.c']
        return any(file_path.endswith(ext) for ext in relevant_extensions)
