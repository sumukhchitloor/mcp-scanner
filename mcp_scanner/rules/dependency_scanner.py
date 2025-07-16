"""Dependency vulnerability detection rule for high-confidence security issues."""

from typing import Dict
import re

from .base_rule import BaseRule
from ..models.vulnerability import VulnerabilitySeverity, VulnerabilityType


class DependencyVulnerabilityRule(BaseRule):
    """Detects known vulnerable dependencies and insecure package usage."""
    
    @property
    def name(self) -> str:
        return "dependency_vulnerability"
    
    @property
    def description(self) -> str:
        return "Detects known vulnerable dependencies and insecure package configurations"
    
    @property
    def severity(self) -> VulnerabilitySeverity:
        return VulnerabilitySeverity.HIGH
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.DEPENDENCY_VULNERABILITY
    
    @property
    def cwe_id(self) -> str:
        return "CWE-1104"
    
    def get_patterns(self) -> Dict[str, str]:
        return {
            # Known vulnerable packages - high confidence
            'vulnerable_requests': r'requests\s*[<>=!]*\s*(?:2\.(?:[0-9]|1[0-7])\.|1\.)',
            'vulnerable_flask': r'Flask\s*[<>=!]*\s*(?:0\.|1\.0\.)',
            'vulnerable_django': r'Django\s*[<>=!]*\s*(?:1\.|2\.0\.|2\.1\.)',
            'vulnerable_pillow': r'Pillow\s*[<>=!]*\s*(?:[0-7]\.|8\.0\.|8\.1\.|8\.2\.)',
            'vulnerable_pyyaml': r'PyYAML\s*[<>=!]*\s*(?:[0-4]\.|5\.0|5\.1|5\.2|5\.3)',
            'vulnerable_urllib3': r'urllib3\s*[<>=!]*\s*(?:1\.(?:[0-9]|1[0-9]|2[0-4])\.)',
            'vulnerable_numpy': r'numpy\s*[<>=!]*\s*(?:1\.(?:[0-9]|1[0-5])\.)',
            'vulnerable_tensorflow': r'tensorflow\s*[<>=!]*\s*(?:1\.|2\.0\.|2\.1\.|2\.2\.)',
            
            # Insecure dependency patterns
            'http_pip_install': r'pip\s+install\s+[^-].*?--index-url\s+http://',
            'unverified_ssl_pip': r'pip\s+install\s+.*?--trusted-host',
            'dev_dependencies_prod': r'(?:requirements|install_requires).*?(?:pytest|mock|debug)',
            
            # Package integrity issues
            'no_version_pinning': r'(?:install_requires|requirements).*?["\'][a-zA-Z0-9_-]+["\'](?!\s*[<>=!])',
            'wildcard_versions': r'(?:install_requires|requirements).*?["\'][a-zA-Z0-9_-]+\s*[>]=?\s*\*',
            'pre_release_versions': r'(?:install_requires|requirements).*?["\'][a-zA-Z0-9_-]+.*?(?:alpha|beta|rc|dev)',
            
            # Typosquatting detection (common misspellings)
            'typosquatting_requests': r'(?:reqeusts|request|reqests|requsts)',
            'typosquatting_urllib': r'(?:urlib|urllib2|urlib3)',
            'typosquatting_numpy': r'(?:numpyp|numpi|numbpy)',
            
            # Private repository without authentication
            'insecure_private_repo': r'(?:index-url|extra-index-url).*?http://(?!localhost|127\.0\.0\.1)',
        }
    
    def get_vulnerability_description(self, pattern_name: str, match: re.Match) -> str:
        descriptions = {
            'vulnerable_requests': "Vulnerable version of requests library detected",
            'vulnerable_flask': "Vulnerable version of Flask framework detected",
            'vulnerable_django': "Vulnerable version of Django framework detected",
            'vulnerable_pillow': "Vulnerable version of Pillow (PIL) library detected",
            'vulnerable_pyyaml': "Vulnerable version of PyYAML library detected",
            'vulnerable_urllib3': "Vulnerable version of urllib3 library detected",
            'vulnerable_numpy': "Vulnerable version of NumPy library detected",
            'vulnerable_tensorflow': "Vulnerable version of TensorFlow library detected",
            'http_pip_install': "Insecure HTTP repository URL in pip install detected",
            'unverified_ssl_pip': "Unverified SSL/TLS host in pip configuration detected",
            'dev_dependencies_prod': "Development dependencies in production requirements detected",
            'no_version_pinning': "Unpinned dependency version detected",
            'wildcard_versions': "Wildcard version specification detected",
            'pre_release_versions': "Pre-release dependency version detected",
            'typosquatting_requests': "Potential typosquatting of 'requests' package detected",
            'typosquatting_urllib': "Potential typosquatting of 'urllib' package detected",
            'typosquatting_numpy': "Potential typosquatting of 'numpy' package detected",
            'insecure_private_repo': "Insecure private repository URL detected"
        }
        return descriptions.get(pattern_name, self.description)
    
    def get_vulnerability_recommendation(self, pattern_name: str, match: re.Match) -> str:
        recommendations = {
            'vulnerable_requests': "Update to requests>=2.18.0 or latest stable version",
            'vulnerable_flask': "Update to Flask>=1.1.0 or latest stable version",
            'vulnerable_django': "Update to Django>=2.2.0 or latest LTS version",
            'vulnerable_pillow': "Update to Pillow>=8.3.0 or latest stable version",
            'vulnerable_pyyaml': "Update to PyYAML>=5.4 or latest stable version",
            'vulnerable_urllib3': "Update to urllib3>=1.25.0 or latest stable version",
            'vulnerable_numpy': "Update to NumPy>=1.16.0 or latest stable version",
            'vulnerable_tensorflow': "Update to TensorFlow>=2.3.0 or latest stable version",
            'http_pip_install': "Use HTTPS repositories and enable SSL verification",
            'unverified_ssl_pip': "Remove --trusted-host and fix SSL certificate issues",
            'dev_dependencies_prod': "Separate development and production dependencies",
            'no_version_pinning': "Pin dependency versions for reproducible builds",
            'wildcard_versions': "Use specific version ranges instead of wildcards",
            'pre_release_versions': "Use stable releases in production environments",
            'typosquatting_requests': "Verify package name spelling - should be 'requests'",
            'typosquatting_urllib': "Verify package name spelling - should be 'urllib3'",
            'typosquatting_numpy': "Verify package name spelling - should be 'numpy'",
            'insecure_private_repo': "Use HTTPS for private repository URLs"
        }
        return recommendations.get(pattern_name, "Review and update dependency configuration")
    
    def get_confidence_score(self, pattern_name: str, match: re.Match) -> int:
        confidence_scores = {
            'vulnerable_requests': 95,
            'vulnerable_flask': 95,
            'vulnerable_django': 95,
            'vulnerable_pillow': 90,
            'vulnerable_pyyaml': 90,
            'vulnerable_urllib3': 90,
            'vulnerable_numpy': 85,
            'vulnerable_tensorflow': 85,
            'http_pip_install': 95,
            'unverified_ssl_pip': 90,
            'dev_dependencies_prod': 75,
            'no_version_pinning': 70,
            'wildcard_versions': 80,
            'pre_release_versions': 75,
            'typosquatting_requests': 85,
            'typosquatting_urllib': 85,
            'typosquatting_numpy': 85,
            'insecure_private_repo': 90
        }
        return confidence_scores.get(pattern_name, 80)
    
    def should_scan_file(self, file_path: str) -> bool:
        """Only scan dependency-related files."""
        dependency_files = {
            'requirements.txt', 'requirements-dev.txt', 'requirements-prod.txt',
            'setup.py', 'setup.cfg', 'pyproject.toml', 'Pipfile', 'Pipfile.lock',
            'package.json', 'package-lock.json', 'yarn.lock', 'pom.xml', 'build.gradle'
        }
        
        import os
        filename = os.path.basename(file_path.lower())
        return filename in dependency_files or file_path.endswith(('.txt', '.py', '.toml', '.json', '.xml'))
