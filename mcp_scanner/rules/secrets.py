"""High-confidence secret detection rule."""

from typing import Dict
import re

from .base_rule import BaseRule
from ..models.vulnerability import VulnerabilitySeverity, VulnerabilityType


class SecretsRule(BaseRule):
    """Detects hardcoded secrets with high confidence patterns."""
    
    @property
    def name(self) -> str:
        return "secrets"
    
    @property
    def description(self) -> str:
        return "Detects hardcoded secrets, API keys, and credentials with high confidence"
    
    @property
    def severity(self) -> VulnerabilitySeverity:
        return VulnerabilitySeverity.CRITICAL
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.CREDENTIALS
    
    @property
    def cwe_id(self) -> str:
        return "CWE-798"
    
    def get_patterns(self) -> Dict[str, str]:
        return {
            # API Keys & Tokens (High Confidence)
            'openai_api_key': r'sk-[A-Za-z0-9]{48}',
            'github_token': r'ghp_[A-Za-z0-9]{36}',
            'github_oauth': r'gho_[A-Za-z0-9]{36}',
            'github_app': r'ghu_[A-Za-z0-9]{36}',
            'github_refresh': r'ghr_[A-Za-z0-9]{36}',
            'aws_access_key': r'(AKIA|ASIA)[0-9A-Z]{16}',
            'aws_secret_key': r'(?:aws[_-]?secret|secret[_-]?access[_-]?key)\s*[:=]\s*["\'][A-Za-z0-9/+=]{40}["\']',
            'stripe_key': r'sk_(test|live)_[A-Za-z0-9]{24}',
            'stripe_publishable': r'pk_(test|live)_[A-Za-z0-9]{24}',
            'jwt_token': r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
            'anthropic_key': r'sk-ant-[A-Za-z0-9_-]{95}',
            'gemini_key': r'AIza[A-Za-z0-9_-]{35}',
            
            # Database Credentials (High Confidence)
            'db_password_hardcoded': r'(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{8,}["\']',
            'mongodb_connection': r'mongodb://[^:]+:[^@]+@[^/]+',
            'mysql_connection': r'mysql://[^:]+:[^@]+@[^/]+',
            'postgres_connection': r'postgres://[^:]+:[^@]+@[^/]+',
            'redis_connection': r'redis://[^:]+:[^@]+@[^/]+',
            
            # Private Keys (High Confidence)
            'ssh_private_key': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            'ssl_private_key': r'-----BEGIN PRIVATE KEY-----',
            'pgp_private_key': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
            
            # Common Secret Patterns (High Confidence)
            'slack_token': r'xox[baprs]-[A-Za-z0-9-]{10,}',
            'discord_token': r'[MN][A-Za-z\d]{23}\.[A-Za-z\d]{6}\.[A-Za-z\d]{27}',
            'telegram_bot': r'\d{8,10}:[A-Za-z0-9_-]{35}',
            'twilio_account': r'AC[0-9a-fA-F]{32}',
            'sendgrid_key': r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
            
            # OAuth & Auth Tokens (High Confidence)
            'bearer_token': r'Bearer\s+[A-Za-z0-9_-]{20,}',
            'basic_auth_header': r'Basic\s+[A-Za-z0-9+/]+=*',
            
            # Cloud Provider Keys
            'azure_key': r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            'gcp_service_account': r'"private_key":\s*"-----BEGIN PRIVATE KEY-----',
        }
    
    def get_vulnerability_description(self, pattern_name: str, match: re.Match) -> str:
        descriptions = {
            'openai_api_key': "OpenAI API key detected in source code",
            'github_token': "GitHub personal access token detected in source code",
            'github_oauth': "GitHub OAuth token detected in source code",
            'github_app': "GitHub App token detected in source code",
            'github_refresh': "GitHub refresh token detected in source code",
            'aws_access_key': "AWS access key detected in source code",
            'aws_secret_key': "AWS secret key detected in source code",
            'stripe_key': "Stripe secret key detected in source code",
            'stripe_publishable': "Stripe publishable key detected in source code",
            'jwt_token': "JWT token detected in source code",
            'anthropic_key': "Anthropic API key detected in source code",
            'gemini_key': "Google Gemini API key detected in source code",
            'db_password_hardcoded': "Database password hardcoded in source code",
            'mongodb_connection': "MongoDB connection string with credentials detected",
            'mysql_connection': "MySQL connection string with credentials detected",
            'postgres_connection': "PostgreSQL connection string with credentials detected",
            'redis_connection': "Redis connection string with credentials detected",
            'ssh_private_key': "SSH private key detected in source code",
            'ssl_private_key': "SSL private key detected in source code",
            'pgp_private_key': "PGP private key detected in source code",
            'slack_token': "Slack token detected in source code",
            'discord_token': "Discord bot token detected in source code",
            'telegram_bot': "Telegram bot token detected in source code",
            'twilio_account': "Twilio account SID detected in source code",
            'sendgrid_key': "SendGrid API key detected in source code",
            'bearer_token': "Bearer token detected in source code",
            'basic_auth_header': "Basic authentication header detected in source code",
            'azure_key': "Azure key/GUID detected in source code",
            'gcp_service_account': "GCP service account private key detected in source code",
        }
        return descriptions.get(pattern_name, "Hardcoded secret detected in source code")
    
    def get_vulnerability_recommendation(self, pattern_name: str, match: re.Match) -> str:
        recommendations = {
            'openai_api_key': "Store OpenAI API key in environment variables or secure vault",
            'github_token': "Store GitHub tokens in environment variables or GitHub Secrets",
            'aws_access_key': "Use IAM roles or store AWS credentials in AWS credentials file",
            'aws_secret_key': "Store AWS credentials securely, never in source code",
            'stripe_key': "Store Stripe keys in environment variables or secure configuration",
            'jwt_token': "Store JWT tokens securely, not in source code",
            'anthropic_key': "Store Anthropic API key in environment variables",
            'gemini_key': "Store Google API key in environment variables",
            'db_password_hardcoded': "Use environment variables or secure credential storage",
            'mongodb_connection': "Use environment variables for database connection strings",
            'mysql_connection': "Use environment variables for database connection strings",
            'postgres_connection': "Use environment variables for database connection strings",
            'redis_connection': "Use environment variables for database connection strings",
            'ssh_private_key': "Store private keys securely outside of source code",
            'ssl_private_key': "Store private keys securely outside of source code",
            'pgp_private_key': "Store private keys securely outside of source code",
            'slack_token': "Store Slack tokens in environment variables",
            'discord_token': "Store Discord tokens in environment variables",
            'telegram_bot': "Store Telegram bot tokens in environment variables",
            'twilio_account': "Store Twilio credentials in environment variables",
            'sendgrid_key': "Store SendGrid API key in environment variables",
            'bearer_token': "Store tokens securely, not in source code",
            'basic_auth_header': "Avoid hardcoding authentication headers",
            'azure_key': "Store Azure credentials in environment variables",
            'gcp_service_account': "Store GCP service account keys securely",
        }
        return recommendations.get(pattern_name, "Store secrets securely using environment variables or secret management systems")
    
    def get_confidence_score(self, pattern_name: str, match: re.Match) -> int:
        # High confidence for most secret patterns
        high_confidence_patterns = {
            'openai_api_key': 100,
            'github_token': 100,
            'github_oauth': 100,
            'github_app': 100,
            'github_refresh': 100,
            'aws_access_key': 100,
            'stripe_key': 100,
            'stripe_publishable': 100,
            'anthropic_key': 100,
            'ssh_private_key': 100,
            'ssl_private_key': 100,
            'pgp_private_key': 100,
            'slack_token': 95,
            'discord_token': 95,
            'telegram_bot': 95,
            'twilio_account': 95,
            'sendgrid_key': 95,
            'gcp_service_account': 100,
        }
        
        medium_confidence_patterns = {
            'aws_secret_key': 90,  # Requires context
            'jwt_token': 85,       # Could be example
            'gemini_key': 90,
            'db_password_hardcoded': 85,
            'mongodb_connection': 95,
            'mysql_connection': 95,
            'postgres_connection': 95,
            'redis_connection': 95,
            'bearer_token': 80,
            'basic_auth_header': 75,
            'azure_key': 80,
        }
        
        if pattern_name in high_confidence_patterns:
            return high_confidence_patterns[pattern_name]
        elif pattern_name in medium_confidence_patterns:
            return medium_confidence_patterns[pattern_name]
        else:
            return 85
    
    def is_false_positive(self, match: re.Match, context: str) -> bool:
        """Check for common false positive patterns."""
        matched_text = match.group(0)
        context_lower = context.lower()
        
        # Skip obvious examples and placeholders
        false_positive_indicators = [
            'example', 'sample', 'test', 'fake', 'placeholder', 'your_key_here',
            'replace_with', 'insert_key', 'dummy', 'mock', 'todo', 'xxx'
        ]
        
        for indicator in false_positive_indicators:
            if indicator in matched_text.lower() or indicator in context_lower:
                return True
        
        # Skip documentation contexts
        doc_indicators = ['```', 'readme', 'doc', 'comment', '#', '//', '/*']
        for indicator in doc_indicators:
            if indicator in context_lower:
                return True
        
        return False
