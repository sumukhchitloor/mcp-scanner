"""
Test cases to validate false positive improvements
"""

import unittest
import tempfile
import os
from pathlib import Path
from mcp_scanner.scanner import Scanner
from mcp_scanner.utils import FileHandler


class TestFalsePositiveReduction(unittest.TestCase):
    """Test that our improved patterns reduce false positives"""
    
    def setUp(self):
        self.scanner = Scanner()
        self.file_handler = FileHandler()
    
    def test_aws_secret_patterns(self):
        """Test that AWS secret patterns only match real credentials"""
        
        # Create test files
        legitimate_content = '''
# These should NOT trigger false positives
import os
aws_access_key = os.environ.get('AWS_ACCESS_KEY_ID')
aws_secret = os.environ.get('AWS_SECRET_ACCESS_KEY')
config = {"integrity": "sha512-VGhpcyBpcmNiDA+LRQoL9YyXdB1/LJW5TkKNEL5d7F7cQIK1LZ2T5k"}
'''
        
        suspicious_content = '''
# These SHOULD trigger detections
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY1234567890"
SECRET_KEY = "AKIAIOSFODNN7EXAMPLE1234567890abcdef1234567890"
'''
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Write test files
            legit_file = os.path.join(temp_dir, 'legitimate.py')
            sus_file = os.path.join(temp_dir, 'suspicious.py')
            
            with open(legit_file, 'w') as f:
                f.write(legitimate_content)
            with open(sus_file, 'w') as f:
                f.write(suspicious_content)
            
            # Scan
            result = self.scanner.scan_directory(temp_dir, self.file_handler, static_only=True)
            
            # Check results
            legit_vulns = [v for v in result.vulnerabilities if 'legitimate.py' in v.file_path]
            sus_vulns = [v for v in result.vulnerabilities if 'suspicious.py' in v.file_path and v.type == 'credentials']
            
            # Assertions
            self.assertEqual(len(legit_vulns), 0, f"False positives in legitimate code: {legit_vulns}")
            self.assertGreater(len(sus_vulns), 0, "Should detect real AWS credentials")
    
    def test_path_traversal_patterns(self):
        """Test that path traversal patterns don't trigger on legitimate imports"""
        
        legitimate_content = '''
# These should NOT trigger path traversal false positives
import sys
sys.path.append('../src')
from ..utils import helper
from ../../shared import constants
with open('./config.json', 'r') as f:
    data = f.read()
'''
        
        suspicious_content = '''
# These SHOULD trigger path traversal detection
file_path = "../../../etc/passwd"
with open(user_input + "/../../../etc/passwd", 'r') as f:
    data = f.read()
'''
        
        with tempfile.TemporaryDirectory() as temp_dir:
            legit_file = os.path.join(temp_dir, 'legitimate_paths.py')
            sus_file = os.path.join(temp_dir, 'suspicious_paths.py')
            
            with open(legit_file, 'w') as f:
                f.write(legitimate_content)
            with open(sus_file, 'w') as f:
                f.write(suspicious_content)
            
            # Scan
            result = self.scanner.scan_directory(temp_dir, self.file_handler, static_only=True)
            
            # Check results
            legit_vulns = [v for v in result.vulnerabilities if 'legitimate_paths.py' in v.file_path and v.type == 'file_security']
            sus_vulns = [v for v in result.vulnerabilities if 'suspicious_paths.py' in v.file_path and v.type == 'file_security']
            
            # Assertions
            self.assertEqual(len(legit_vulns), 0, f"False positives in legitimate paths: {legit_vulns}")
            self.assertGreater(len(sus_vulns), 0, "Should detect real path traversal")

    def test_package_lock_exclusion(self):
        """Test that package-lock.json files are excluded"""
        
        package_lock_content = '''{
  "name": "test-project",
  "lockfileVersion": 2,
  "packages": {
    "": {
      "integrity": "sha512-VGhpcyBpcmNiDA+LRQoL9YyXdB1/LJW5TkKNEL5d7F7cQIK1LZ2T5kzQY3Vj3aZDi0xrW8hJ0FdHUOo7bQBcKQ=="
    }
  }
}'''
        
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = os.path.join(temp_dir, 'package-lock.json')
            with open(lock_file, 'w') as f:
                f.write(package_lock_content)
            
            # Scan - package-lock.json should be excluded by file handler
            result = self.scanner.scan_directory(temp_dir, self.file_handler, static_only=True)
            
            # Check that package-lock.json was not scanned
            scanned_files = [f for f in result.files_scanned if 'package-lock.json' in f]
            self.assertEqual(len(scanned_files), 0, "package-lock.json should be excluded from scanning")


if __name__ == '__main__':
    unittest.main()
