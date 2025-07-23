"""Insecure configuration detection rule for high-confidence security issues."""

from typing import Dict
import re

from .base_rule import BaseRule
from ..models.vulnerability import VulnerabilitySeverity, VulnerabilityType


class InsecureConfigurationRule(BaseRule):
    """Detects insecure configuration patterns with high confidence."""
    
    @property
    def name(self) -> str:
        return "insecure_configuration"
    
    @property
    def description(self) -> str:
        return "Detects insecure configuration patterns and dangerous settings"
    
    @property
    def severity(self) -> VulnerabilitySeverity:
        return VulnerabilitySeverity.HIGH
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.INSECURE_CONFIGURATION
    
    @property
    def cwe_id(self) -> str:
        return "CWE-16"
    
    def get_patterns(self) -> Dict[str, str]:
        return {
            # Flask/Django debug mode in production
            'flask_debug_true': r'(?:DEBUG\s*=\s*True|debug\s*=\s*True|app\.debug\s*=\s*True)',
            'django_debug_true': r'DEBUG\s*=\s*True',
            'flask_secret_key_weak': r'SECRET_KEY\s*=\s*["\'](?:secret|key|dev|test|changeme|your-secret-key|flask)',
            
            # Database configuration issues
            'database_host_public': r'(?:HOST|host)\s*[=:]\s*["\'](?:0\.0\.0\.0|\*)["\']',
            'database_no_password': r'(?:PASSWORD|password)\s*[=:]\s*["\']["\']',
            'sqlite_world_readable': r'sqlite:///[^/].*?\.db',
            
            # SSL/TLS configuration issues
            'ssl_verify_false': r'(?:SSL_VERIFY|ssl_verify|verify)\s*[=:]\s*False',
            'ssl_disable_warnings': r'urllib3\.disable_warnings\(',
            'ssl_no_cert_verification': r'ssl\._create_unverified_context',
            'ssl_weak_ciphers': r'ssl\.OP_(?:NO_SSLv2|NO_SSLv3|NO_TLSv1)',
            
            # CORS configuration
            'cors_allow_all_origins': r'(?:CORS_ORIGINS|Access-Control-Allow-Origin).*?\*',
            'cors_allow_credentials_wildcard': r'Access-Control-Allow-Credentials.*?true.*?\*',
            
            # Authentication and session security
            'session_no_httponly': r'(?:session|cookie).*?httponly\s*[=:]\s*False',
            'session_no_secure': r'(?:session|cookie).*?secure\s*[=:]\s*False',
            'session_no_samesite': r'(?:session|cookie).*?samesite\s*[=:]\s*None',
            'weak_password_policy': r'MIN_PASSWORD_LENGTH\s*[=:]\s*[1-5]',
            
            # Server configuration
            'server_expose_version': r'(?:Server|server)\s*[=:]\s*["\'][^"\']*(?:Apache|nginx|Python)[^"\']*["\']',
            'server_bind_all_interfaces': r'(?:host|HOST)\s*[=:]\s*["\']0\.0\.0\.0["\']',
            'server_no_timeout': r'(?:timeout|TIMEOUT)\s*[=:]\s*(?:0|None)',
            
            # Environment and configuration
            'production_with_test_config': r'ENVIRONMENT\s*[=:]\s*["\'](?:test|dev|development)["\']',
            'hardcoded_encryption_key': r'ENCRYPTION_KEY\s*[=:]\s*["\'][A-Za-z0-9+/=]{16,}["\']',
            'log_level_debug_prod': r'LOG_LEVEL\s*[=:]\s*["\'](?:DEBUG|debug)["\']',
            
            # Cloud configuration issues
            'aws_public_bucket': r'PublicReadWrite|PublicRead.*?Write',
            'azure_public_storage': r'public-read|public-read-write',
            'gcp_public_bucket': r'allUsers.*?READER',
            
            # Container security
            'docker_privileged_mode': r'privileged\s*[=:]\s*true',
            'docker_run_as_root': r'USER\s+(?:0|root)',
            
            # File permissions
            'file_permissions_777': r'chmod\s+777',
            'file_permissions_666': r'chmod\s+666',
            'umask_permissive': r'umask\s+0[0-2][0-7]',
            
            # API configuration
            'api_no_rate_limiting': r'(?:@app\.route|@api\.)(?!.*rate_limit)',
            'api_no_authentication': r'@app\.route.*?methods.*?POST(?!.*@login_required|@auth)',
            'json_api_no_validation': r'request\.json(?!.*validate|.*schema)',
        }
    
    def get_vulnerability_description(self, pattern_name: str, match: re.Match) -> str:
        descriptions = {
            'flask_debug_true': "Flask debug mode enabled (dangerous in production)",
            'django_debug_true': "Django debug mode enabled (dangerous in production)",
            'flask_secret_key_weak': "Weak Flask secret key detected",
            'database_host_public': "Database configured to bind to all interfaces",
            'database_no_password': "Database configured without password",
            'sqlite_world_readable': "SQLite database potentially world-readable",
            'ssl_verify_false': "SSL certificate verification disabled",
            'ssl_disable_warnings': "SSL warnings disabled",
            'ssl_no_cert_verification': "SSL certificate verification bypassed",
            'ssl_weak_ciphers': "Weak SSL/TLS cipher configuration",
            'cors_allow_all_origins': "CORS configured to allow all origins",
            'cors_allow_credentials_wildcard': "CORS credentials with wildcard origin",
            'session_no_httponly': "Session cookies without HTTPOnly flag",
            'session_no_secure': "Session cookies without Secure flag",
            'session_no_samesite': "Session cookies without SameSite protection",
            'weak_password_policy': "Weak password length requirement",
            'server_expose_version': "Server version information exposed",
            'server_bind_all_interfaces': "Server configured to bind to all interfaces",
            'server_no_timeout': "Server configured without timeout limits",
            'production_with_test_config': "Production environment with test configuration",
            'hardcoded_encryption_key': "Hardcoded encryption key in configuration",
            'log_level_debug_prod': "Debug logging enabled in production",
            'aws_public_bucket': "AWS S3 bucket configured for public access",
            'azure_public_storage': "Azure storage configured for public access",
            'gcp_public_bucket': "GCP bucket configured for public access",
            'docker_privileged_mode': "Docker container configured in privileged mode",
            'docker_run_as_root': "Docker container explicitly running as root",
            'file_permissions_777': "File permissions set to world-writable (777)",
            'file_permissions_666': "File permissions set to world-writable (666)",
            'umask_permissive': "Permissive umask configuration detected",
            'api_no_rate_limiting': "API endpoint without rate limiting",
            'api_no_authentication': "API endpoint without authentication",
            'json_api_no_validation': "JSON API without input validation"
        }
        return descriptions.get(pattern_name, self.description)
    
    def get_vulnerability_recommendation(self, pattern_name: str, match: re.Match) -> str:
        recommendations = {
            'flask_debug_true': "Set DEBUG=False in production environments",
            'django_debug_true': "Set DEBUG=False in production settings",
            'flask_secret_key_weak': "Use a strong, randomly generated secret key",
            'database_host_public': "Bind database to specific interface, not 0.0.0.0",
            'database_no_password': "Configure strong database authentication",
            'sqlite_world_readable': "Place SQLite database in secure directory with proper permissions",
            'ssl_verify_false': "Enable SSL certificate verification",
            'ssl_disable_warnings': "Remove SSL warning disabling code",
            'ssl_no_cert_verification': "Enable SSL certificate verification",
            'ssl_weak_ciphers': "Configure strong SSL/TLS ciphers",
            'cors_allow_all_origins': "Specify allowed origins instead of using wildcard",
            'cors_allow_credentials_wildcard': "Do not use credentials with wildcard CORS",
            'session_no_httponly': "Enable HTTPOnly flag on session cookies",
            'session_no_secure': "Enable Secure flag on session cookies",
            'session_no_samesite': "Set SameSite to Strict or Lax for cookies",
            'weak_password_policy': "Increase minimum password length to at least 8 characters",
            'server_expose_version': "Hide server version information",
            'server_bind_all_interfaces': "Bind to specific interface instead of 0.0.0.0",
            'server_no_timeout': "Configure appropriate timeout values",
            'production_with_test_config': "Use production-appropriate environment configuration",
            'hardcoded_encryption_key': "Store encryption keys in secure key management",
            'log_level_debug_prod': "Use INFO or WARNING log level in production",
            'aws_public_bucket': "Review and restrict S3 bucket permissions",
            'azure_public_storage': "Review and restrict Azure storage permissions",
            'gcp_public_bucket': "Review and restrict GCP bucket permissions",
            'docker_privileged_mode': "Remove privileged mode unless absolutely necessary",
            'docker_run_as_root': "Configure container to run as non-root user",
            'file_permissions_777': "Use more restrictive file permissions",
            'file_permissions_666': "Use more restrictive file permissions",
            'umask_permissive': "Use more restrictive umask (e.g., 077 or 022)",
            'api_no_rate_limiting': "Implement rate limiting on API endpoints",
            'api_no_authentication': "Implement authentication for API endpoints",
            'json_api_no_validation': "Validate all JSON input data"
        }
        return recommendations.get(pattern_name, "Review and secure configuration settings")
    
    def get_confidence_score(self, pattern_name: str, match: re.Match) -> int:
        confidence_scores = {
            'flask_debug_true': 95,
            'django_debug_true': 95,
            'flask_secret_key_weak': 90,
            'database_host_public': 85,
            'database_no_password': 95,
            'sqlite_world_readable': 80,
            'ssl_verify_false': 90,
            'ssl_disable_warnings': 85,
            'ssl_no_cert_verification': 95,
            'ssl_weak_ciphers': 80,
            'cors_allow_all_origins': 85,
            'cors_allow_credentials_wildcard': 95,
            'session_no_httponly': 85,
            'session_no_secure': 85,
            'session_no_samesite': 80,
            'weak_password_policy': 80,
            'server_expose_version': 75,
            'server_bind_all_interfaces': 80,
            'server_no_timeout': 75,
            'production_with_test_config': 85,
            'hardcoded_encryption_key': 90,
            'log_level_debug_prod': 80,
            'aws_public_bucket': 90,
            'azure_public_storage': 90,
            'gcp_public_bucket': 90,
            'docker_privileged_mode': 85,
            'docker_run_as_root': 85,
            'file_permissions_777': 90,
            'file_permissions_666': 90,
            'umask_permissive': 75,
            'api_no_rate_limiting': 70,
            'api_no_authentication': 80,
            'json_api_no_validation': 75
        }
        return confidence_scores.get(pattern_name, 80)
    
    def should_scan_file(self, file_path: str) -> bool:
        """Only scan configuration-related files."""
        config_files = {
            'settings.py', 'config.py', 'configuration.py', 'app.py', 'main.py',
            'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
            '.env', '.env.prod', '.env.production', '.env.dev', '.env.development',
            'nginx.conf', 'apache.conf', 'httpd.conf', 'uwsgi.ini', 'gunicorn.conf.py'
        }
        
        import os
        filename = os.path.basename(file_path.lower())
        return (filename in config_files or 
                file_path.endswith(('.conf', '.ini', '.yaml', '.yml', '.json', '.py', '.env')))
