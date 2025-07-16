# MCP Security Scanner

A comprehensive Python-based security scanner specifically designed for Model Context Protocol (MCP) servers. The scanner detects vulnerabilities through both static analysis using pattern matching and AI-powered analysis using OpenAI's API.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Status](https://img.shields.io/badge/status-stable-green.svg)

## 🚀 Features

### Security Detection
- **10+ Vulnerability Types**: Command injection, SQL injection, tool poisoning, authentication issues, credential management, file security, input validation, prompt injection, cryptography issues, and network security
- **Pattern-Based Static Analysis**: 100+ regex patterns for detecting known vulnerability patterns
- **AI-Powered Analysis**: Multiple AI provider support (OpenAI, Claude, Gemini) for intelligent code analysis and vulnerability detection
- **MCP-Specific Detection**: Specialized rules for MCP tool poisoning, prompt injection, and configuration vulnerabilities

### Analysis Capabilities
- **Parallel Processing**: Multi-threaded file scanning for performance
- **Confidence Scoring**: Each vulnerability includes a confidence score (0-100%)
- **CWE Mapping**: Vulnerabilities mapped to Common Weakness Enumeration (CWE) standards
- **Severity Classification**: Critical, High, Medium, Low severity levels

### Output & Reporting
- **Multiple Formats**: JSON, Markdown, and Rich table outputs
- **Detailed Reports**: Comprehensive vulnerability details with recommendations
- **File Filtering**: Smart gitignore-style pattern exclusion
- **Progress Tracking**: Real-time scanning progress with Rich UI

## 📋 Requirements

- Python 3.8+
- OpenAI API key (optional, for AI analysis)

## 🛠️ Installation

### Development Setup
```bash
# Clone repository
git clone https://github.com/yourusername/mcp-security-scanner.git
cd mcp-security-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate.fish  # For fish shell

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .
```

## 🚀 Quick Start

### Basic Usage
```bash
# Scan a directory with default settings
mcp-scanner scan /path/to/mcp/project

# Scan with static analysis only (no AI)
mcp-scanner scan /path/to/project --static-only

# Scan with AI analysis (requires OpenAI API key)
export OPENAI_API_KEY="your-api-key"
mcp-scanner scan /path/to/project

# Filter by severity
mcp-scanner scan /path/to/project --severity CRITICAL,HIGH

# Output to file
mcp-scanner scan /path/to/project --output report.json --output-format json
```

### Command Line Interface

#### Scan Command
```bash
mcp-scanner scan [OPTIONS] FOLDER_PATH

Options:
  --output-format [table|json|markdown]  Output format (default: table)
  --output PATH                          Output file path
  --static-only                          Use only static analysis
  --ai-only                              Use only AI analysis  
  --severity TEXT                        Filter by severity (CRITICAL,HIGH,MEDIUM,LOW)
  --ignore TEXT                          Ignore patterns (can be used multiple times)
  --api-key TEXT                         OpenAI API key
  --model TEXT                           AI model to use (default: gpt-4)
  --verbose                              Enable verbose output
  --help                                 Show help message
```

#### Other Commands
```bash
# Show all available security rules
mcp-scanner list-rules

# Show version information
mcp-scanner version
```

## Quick Start

```bash
# Basic scan
mcp-scanner scan /path/to/mcp-server

# Static analysis only
mcp-scanner scan /path/to/mcp-server --static-only

# AI analysis with custom API key
mcp-scanner scan /path/to/mcp-server --ai-only --api-key sk-...

# Filter by severity
mcp-scanner scan /path/to/mcp-server --severity critical,high

# Custom output format
mcp-scanner scan /path/to/mcp-server --output-format json > report.json
```

## Configuration

Set your OpenAI API key:
```bash
export OPENAI_API_KEY=sk-your-api-key-here
```

## CLI Options

- `--static-only`: Run only static analysis
- `--ai-only`: Run only AI analysis
- `--output-format`: Output format (json, table, markdown)
- `--severity`: Filter by severity (critical, high, medium, low)
- `--verbose`: Verbose output
- `--ignore-patterns`: File patterns to ignore
- `--config`: Custom config file path
- `--api-key`: OpenAI API key

## Project Structure

```
mcp-security-scanner/
├── mcp_scanner/           # Main package
│   ├── cli.py            # CLI interface
│   ├── scanner.py        # Core scanner logic
│   ├── rules/            # Vulnerability detection rules
│   ├── analyzers/        # Static and AI analyzers
│   ├── models/           # Data models
│   ├── utils/            # Utilities
│   └── config/           # Configuration files
├── tests/                # Test files
├── requirements.txt      # Dependencies
└── setup.py             # Package setup
```

## Development

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Install in development mode: `pip install -e .`
4. Run tests: `python -m pytest tests/`

## 🔍 Vulnerability Types

### 1. Command Injection (CRITICAL)
- OS command execution with user input
- Subprocess calls with shell=True
- Eval/exec with user data

**Example Detection:**
```python
# Detected as CRITICAL
os.system(f"rm {user_input}")
subprocess.call(user_command, shell=True)
```

### 2. SQL Injection (HIGH) 
- String concatenation in SQL queries
- Missing parameterized queries
- ORM raw query vulnerabilities

**Example Detection:**
```python
# Detected as HIGH
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

### 3. Tool Poisoning (HIGH)
- Hidden Unicode characters in tool names
- Suspicious base64 content
- Tool description manipulation
- Homograph attacks

**Example Detection:**
```json
{
  "name": "admin_tool‌‍",  // Hidden Unicode characters
  "description": "VGhpcyBpcyBoaWRkZW4gY29udGVudA=="  // Base64 content
}
```

### 4. Authentication Issues (HIGH)
- Missing authentication decorators
- Hardcoded credentials
- Weak session management
- Authentication bypass

### 5. Credential Management (CRITICAL)
- Hardcoded API keys
- Exposed database passwords
- AWS credentials in code
- JWT secrets in source

### 6. File Security (HIGH)
- Path traversal vulnerabilities
- Unsafe file operations
- Pickle deserialization
- Zip slip attacks

### 7. Input Validation (MEDIUM)
- Missing input validation
- Weak regex patterns
- Direct request data usage
- XSS vulnerabilities

### 8. Prompt Injection (HIGH)
- Direct user input to LLM
- System prompt exposure
- Instruction override attempts
- Context injection

### 9. Cryptography Issues (MEDIUM)
- Weak algorithms (MD5, SHA1, DES)
- Hardcoded encryption keys
- Small RSA key sizes
- Missing salt in hashes

### 10. Network Security (MEDIUM)
- HTTP instead of HTTPS
- SSL verification disabled
- CORS wildcards
- Missing security headers

## 📊 Example Output

### Table Format
```
MCP Security Scanner Report
Generated: 2025-07-14 13:44:50
Target: /path/to/project
Duration: 0.5s

╭─ Vulnerability Summary ──────────────────────────────────────╮
│ Critical: 5                                                  │
│ High: 12                                                     │
│ Medium: 3                                                    │
│ Low: 0                                                       │
╰──────────────────────────────────────────────────────────────╯

                    Vulnerabilities Found                     
┏━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┓
┃ Severity   ┃ Type            ┃ File                 ┃ Line   ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━┩
│ CRITICAL   │ Command         │ server.py            │   45   │
│            │ Injection       │                      │        │
│ CRITICAL   │ Credentials     │ config.py            │   12   │
│ HIGH       │ SQL Injection   │ database.py          │   78   │
└────────────┴─────────────────┴──────────────────────┴────────┘
```

### JSON Format
```json
{
  "target_path": "/path/to/project",
  "start_time": "2025-07-14T13:44:50.123456",
  "end_time": "2025-07-14T13:44:50.654321", 
  "scan_duration": 0.53,
  "files_scanned": 25,
  "total_vulnerabilities": 20,
  "vulnerabilities": [
    {
      "id": "command_injection_server.py_45_os_system_concat",
      "type": "command_injection",
      "severity": "CRITICAL",
      "file_path": "/path/to/project/server.py",
      "line_number": 45,
      "code_snippet": "os.system(f'rm {filename}')",
      "description": "Direct command execution with string concatenation",
      "recommendation": "Use subprocess with parameterized arguments",
      "confidence": 95,
      "cwe_id": "CWE-78",
      "rule_name": "command_injection"
    }
  ]
}
```

## ⚙️ Configuration

### Environment Variables
```bash
# OpenAI API Configuration
export OPENAI_API_KEY="your-openai-api-key"
export OPENAI_MODEL="gpt-4"  # Optional, defaults to gpt-4

# Scanner Configuration  
export MCP_SCANNER_IGNORE_PATTERNS="*.log,temp/*"
export MCP_SCANNER_MAX_FILE_SIZE="1048576"  # 1MB limit
```

### Ignore Patterns
Create a `.mcp-ignore` file in your project root:
```
# Ignore patterns (gitignore-style)
*.pyc
__pycache__/
.git/
node_modules/
*.log
temp/
```

## 🧪 Testing

### Run Tests
```bash
# Test the scanner with provided test files
mcp-scanner scan tests/test_files/ --static-only

# Should detect ~48 vulnerabilities across test files
```

### Test Files
The project includes test files with known vulnerabilities:
- `tests/test_files/vulnerable_mcp_server.py` - Python vulnerabilities
- `tests/test_files/mcp_config.json` - MCP configuration issues
- `tests/test_files/additional_vulns.py` - Additional test cases
- `tests/test_files/insecure_config.json` - Insecure configurations

## 🤝 Contributing

### Development Guidelines
1. **Security Rules**: Extend `BaseRule` class for new vulnerability types
2. **Patterns**: Add regex patterns to `mcp_scanner/config/patterns.py`
3. **Tests**: Include test cases for new rules in `tests/`
4. **Documentation**: Update README and docstrings

### Code Quality
- Follow PEP 8 style guidelines
- Use type hints throughout
- Write comprehensive docstrings
- Include logging for debugging
- Maintain test coverage

### Adding New Rules
```python
from .base_rule import BaseRule
from ..models.vulnerability import VulnerabilitySeverity, VulnerabilityType

class MyCustomRule(BaseRule):
    @property
    def name(self) -> str:
        return "my_custom_rule"
    
    @property 
    def severity(self) -> VulnerabilitySeverity:
        return VulnerabilitySeverity.HIGH
        
    def get_patterns(self) -> Dict[str, str]:
        return {
            'my_pattern': r'dangerous_function\([^)]*\)'
        }
```

## 📈 Performance

### Benchmarks
- **Small Projects** (< 100 files): ~1-2 seconds
- **Medium Projects** (100-1000 files): ~5-15 seconds  
- **Large Projects** (1000+ files): ~30-60 seconds

### Optimization Tips
- Use `--static-only` for faster scanning without AI
- Set appropriate file size limits
- Use ignore patterns to exclude large binary files
- Enable parallel processing (enabled by default)

## 🔒 Security Considerations

### API Key Safety
- Never commit API keys to version control
- Use environment variables or secure key management
- Consider rate limiting for OpenAI API calls
- Monitor API usage and costs

### False Positives
- Review high-confidence (>90%) vulnerabilities first
- Use context to determine if issues are exploitable
- Consider implementing allow-lists for known safe patterns
- Regularly update patterns to reduce false positives

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Click](https://click.palletsprojects.com/) for CLI framework
- [Rich](https://rich.readthedocs.io/) for beautiful terminal output
- [OpenAI](https://openai.com/) for AI-powered analysis
- [Model Context Protocol](https://github.com/anthropics/model-context-protocol) for MCP specifications
