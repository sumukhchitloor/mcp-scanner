"""File handling utilities for the MCP security scanner."""

import os
import pathspec
from pathlib import Path
from typing import List, Set, Generator, Optional
import mimetypes

from .logger import get_logger

logger = get_logger(__name__)

# File extensions to scan
SCANNABLE_EXTENSIONS = {
    '.py', '.js', '.ts', '.java', '.php', '.rb', '.go', '.rs', '.cpp', '.c',
    '.cs', '.scala', '.kt', '.swift', '.json', '.yml', '.yaml', '.xml', '.sql',
    '.sh', '.bash', '.ps1', '.bat', '.cmd', '.dockerfile', '.tf'
}

# File patterns to ignore by default
DEFAULT_IGNORE_PATTERNS = [
    '*.pyc',
    '*.pyo', 
    '__pycache__/*',
    '.git/*',
    '.svn/*',
    '.hg/*',
    'node_modules/*',
    '.venv/*',
    'venv/*',
    '*.egg-info/*',
    'dist/*',
    'build/*',
    '.tox/*',
    '.coverage',
    '*.log',
    '*.tmp',
    'package-lock.json',
    'yarn.lock',
    'composer.lock',
    'Gemfile.lock',
    'poetry.lock',
    'Pipfile.lock',
    '.vite/*',
    '.next/*',
    '.nuxt/*',
    'target/*',
    'out/*',
    'coverage/*',
    '*.min.js',
    '*.min.css',
    '*.map',
    '*.d.ts',
    'webpack.config.*',
    'rollup.config.*',
    'test_*.py',
    '*_test.py',
    'tests/*.py',
    'spec/*.py',
    '*.spec.py',
    'debug_*.py',
    'quick_test.py',
    'minimal_test.py',
    'tests/*',
    'test/*',
    '**/tests/*',
    '**/test/*',
    '*.test.*',
    '*.spec.*',
    '**/integration/*',
    '**/unit/*'
]


class FileHandler:
    """Handles file operations for the security scanner."""
    
    def __init__(self, ignore_patterns: Optional[List[str]] = None, max_file_size: int = 5 * 1024 * 1024):
        """
        Initialize file handler.
        
        Args:
            ignore_patterns: List of patterns to ignore (gitignore style)
            max_file_size: Maximum file size to scan in bytes (default: 5MB, reduced for performance)
        """
        self.max_file_size = max_file_size
        
        # Combine default ignore patterns with user-provided ones
        all_patterns = DEFAULT_IGNORE_PATTERNS.copy()
        if ignore_patterns:
            all_patterns.extend(ignore_patterns)
        
        self.ignore_spec = pathspec.PathSpec.from_lines('gitwildmatch', all_patterns)
        
    def get_scannable_files(self, directory: str) -> Generator[str, None, None]:
        """
        Get all scannable files in a directory recursively.
        
        Args:
            directory: Directory path to scan
            
        Yields:
            File paths that should be scanned
        """
        directory_path = Path(directory).resolve()
        
        if not directory_path.exists():
            logger.error(f"Directory does not exist: {directory}")
            return
        
        if not directory_path.is_dir():
            logger.error(f"Path is not a directory: {directory}")
            return
        
        for root, dirs, files in os.walk(directory_path):
            # Filter directories to avoid scanning ignored ones
            relative_root = os.path.relpath(root, directory_path)
            if relative_root != '.' and self.ignore_spec.match_file(relative_root):
                dirs.clear()  # Don't recurse into ignored directories
                continue
            
            for file in files:
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, directory_path)
                
                # Check if file should be ignored
                if self.ignore_spec.match_file(relative_path):
                    continue
                
                # Check if file is scannable
                if self.is_scannable_file(file_path):
                    yield file_path
    
    def is_scannable_file(self, file_path: str) -> bool:
        """
        Check if a file should be scanned.
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if file should be scanned, False otherwise
        """
        try:
            # Check file extension
            if not any(file_path.lower().endswith(ext) for ext in SCANNABLE_EXTENSIONS):
                return False
            
            # Check file size
            if os.path.getsize(file_path) > self.max_file_size:
                logger.debug(f"Skipping large file: {file_path}")
                return False
            
            # Check if file is readable
            if not os.access(file_path, os.R_OK):
                logger.debug(f"Cannot read file: {file_path}")
                return False
            
            # Check if it's a text file
            if not self.is_text_file(file_path):
                logger.debug(f"Skipping binary file: {file_path}")
                return False
            
            return True
            
        except (OSError, IOError) as e:
            logger.debug(f"Error checking file {file_path}: {e}")
            return False
    
    def is_text_file(self, file_path: str) -> bool:
        """
        Check if a file is a text file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if file is text, False if binary
        """
        # First check by extension
        _, ext = os.path.splitext(file_path.lower())
        if ext in SCANNABLE_EXTENSIONS:
            return True
        
        # Check MIME type
        mime_type, _ = mimetypes.guess_type(file_path)
        if mime_type and mime_type.startswith('text/'):
            return True
        
        # Check file content (read first 8192 bytes)
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(8192)
                if b'\0' in chunk:  # Binary files often contain null bytes
                    return False
                
                # Try to decode as UTF-8
                try:
                    chunk.decode('utf-8')
                    return True
                except UnicodeDecodeError:
                    # Try other common encodings
                    for encoding in ['latin-1', 'cp1252', 'ascii']:
                        try:
                            chunk.decode(encoding)
                            return True
                        except UnicodeDecodeError:
                            continue
                    return False
                    
        except (OSError, IOError):
            return False
    
    def read_file(self, file_path: str) -> Optional[str]:
        """
        Read file content safely.
        
        Args:
            file_path: Path to the file
            
        Returns:
            File content as string, or None if error
        """
        try:
            # Try UTF-8 first
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except UnicodeDecodeError:
            # Try other encodings
            for encoding in ['latin-1', 'cp1252', 'ascii']:
                try:
                    with open(file_path, 'r', encoding=encoding) as f:
                        return f.read()
                except UnicodeDecodeError:
                    continue
            
            logger.warning(f"Could not decode file: {file_path}")
            return None
            
        except (OSError, IOError) as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return None
