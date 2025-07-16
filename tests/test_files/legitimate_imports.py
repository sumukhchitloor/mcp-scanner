"""
Test file with legitimate relative imports that should NOT trigger path traversal
"""

# These should NOT trigger path traversal false positives
import sys
sys.path.append('../src')

from ..utils import helper_function
from ./components import Button
from ../../shared import constants

# Legitimate file operations
with open('./config.json', 'r') as f:
    config = f.read()

# Legitimate AWS usage (should NOT trigger with our improved pattern)
import os
AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')

# But this SHOULD trigger (has explicit context)
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY1234567890"
