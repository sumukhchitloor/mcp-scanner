"""Security rules package for the MCP security scanner."""

from .base_rule import BaseRule
from .secrets import SecretsRule
from .dangerous_functions import DangerousFunctionsRule
from .insecure_configuration import InsecureConfigurationRule

# Focused rules for high-confidence detections only
ALL_RULES = [
    SecretsRule,                    # CRITICAL: API keys, credentials, private keys
    DangerousFunctionsRule,         # HIGH: Command injection, code execution  
    InsecureConfigurationRule,      # HIGH: Dangerous configuration settings
]

def get_all_rules():
    """Get all available security rules as instances."""
    return {rule().name: rule() for rule in ALL_RULES}

def get_rule_by_name(rule_name: str) -> BaseRule:
    """Get a specific rule by name."""
    rules = get_all_rules()
    return rules.get(rule_name.lower())

def get_enabled_rules():
    """Get all enabled security rules with lazy loading."""
    enabled_rules = {}
    
    for rule_class in ALL_RULES:
        try:
            instance = rule_class()
            if instance.enabled:
                enabled_rules[instance.name] = instance
        except Exception as e:
            print(f"Error loading rule {rule_class.__name__}: {e}")
            continue
    
    return enabled_rules

__all__ = [
    'BaseRule',
    'SecretsRule',
    'DangerousFunctionsRule', 
    'InsecureConfigurationRule',
    'ALL_RULES',
    'get_all_rules',
    'get_rule_by_name',
    'get_enabled_rules'
]
