# MCP Security Scanner

A comprehensive security scanner for Model Context Protocol (MCP) servers with AI-powered vulnerability detection and a modern web interface.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![React](https://img.shields.io/badge/react-18+-blue.svg)
![Status](https://img.shields.io/badge/status-stable-green.svg)

## 🚀 Features

### 🔍 Comprehensive Security Analysis
- **57+ Vulnerability Types**: Complete coverage of static analysis and AI-specific attack vectors
- **Static Analysis**: Pattern-based detection with 100+ regex patterns for known vulnerabilities
- **AI-Powered Analysis**: Multi-provider support (OpenAI, Claude, Gemini) for intelligent threat detection
- **AI Security Specialization**: Advanced detection of prompt injection, jailbreak attacks, model manipulation, and 30+ AI-specific threats

### 🧠 AI Attack Detection
- **Prompt Injection**: Direct instruction override, context poisoning, system prompt leakage
- **Jailbreak Techniques**: DAN, STAN, AIM variations and role-playing attacks
- **Model Manipulation**: Adversarial examples, model inversion, extraction attacks
- **Training Data Attacks**: Data poisoning, membership inference, backdoor injection
- **Advanced Techniques**: Unicode obfuscation, chain-of-thought manipulation, federated learning attacks

### 🖥️ Modern Web Interface
- **Neural Threat Matrix Dashboard**: Real-time visualization with AI neural network simulation
- **Interactive Scanning**: Upload files or directories for immediate analysis
- **Live Monitoring**: Real-time scan progress with detailed vulnerability reporting
- **Scan History**: Complete audit trail with exportable reports
- **AI Neural Security Analyzer**: Dynamic visualization of AI threat detection activity

### ⚡ Performance & Scalability
- **Parallel Processing**: Multi-threaded scanning with concurrent AI analysis
- **Real-time Updates**: WebSocket-based progress tracking and live data visualization
- **Smart Caching**: Intelligent scan result caching with automatic cleanup
- **Background Processing**: Non-blocking scans with persistent state management

## 🏗️ Architecture

```
MCP Security Scanner
├── fastapi_backend/          # FastAPI backend server
│   ├── main.py              # API server with scan endpoints
│   ├── routes/              # API route handlers
│   └── uploads/             # Temporary file storage
├── frontend/                # React TypeScript frontend
│   ├── src/components/      # UI components
│   │   ├── pages/          # Main pages (Dashboard, Scanner, History)
│   │   └── ui/             # Reusable UI components
│   └── src/services/       # API client services
├── mcp_scanner/            # Core scanning engine
│   ├── analyzers/          # Static and AI analyzers
│   ├── rules/              # Vulnerability detection rules
│   ├── models/             # Data models and schemas
│   └── scanner.py          # Main scanner orchestrator
└── tests/                  # Test files and AI attack samples
    └── ai_attacks/         # Comprehensive AI attack test cases
```

## 📋 Requirements

### Backend
- Python 3.8+
- FastAPI
- SQLite (included)

### Frontend  
- Node.js 16+
- React 18+
- TypeScript
- Tailwind CSS

### AI Providers (Optional)
- OpenAI API key
- Anthropic Claude API key  
- Google Gemini API key

## 🛠️ Installation & Setup

### Quick Start
```bash
# Clone repository
git clone <repository-url>
cd MCP_security

# Start the application (runs both backend and frontend)
./start_fastapi.sh

# Access the application
# Frontend: http://localhost:3000
# Backend API: http://localhost:8000
```

### Manual Setup

#### Backend Setup
```bash
# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Start FastAPI server
cd fastapi_backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

#### Frontend Setup
```bash
# Install Node.js dependencies
cd frontend
npm install

# Start React development server
npm start
```

## 🚀 Usage

### Web Interface
1. **Upload Files**: Drag and drop files or folders onto the scanner interface
2. **Configure Scan**: Select analysis type (Static, AI, or Hybrid)
3. **Monitor Progress**: Watch real-time scanning progress with vulnerability detection
4. **Review Results**: Examine detailed vulnerability reports with severity classifications
5. **Export Reports**: Download scan results in JSON or other formats

### API Endpoints
```bash
# Upload and scan files
POST /api/scanner/upload

# Get scan results
GET /api/scanner/results/{scan_id}

# Monitor active scans
GET /api/scanner/active

# Dashboard metrics
GET /api/dashboard/metrics

# Scan history
GET /api/scanner/recent
```

### Command Line Interface
```bash
# Direct scanner usage (if installed as package)
mcp-scanner scan /path/to/project

# With specific AI provider
export OPENAI_API_KEY="your-key"
mcp-scanner scan /path/to/project --ai-provider openai

# Static analysis only
mcp-scanner scan /path/to/project --static-only
```

## 🔍 Vulnerability Detection

### Static Analysis (27 Categories)
- **Command Injection**: OS command execution with user input
- **SQL Injection**: Database query vulnerabilities
- **Path Traversal**: File system access control bypass
- **Hardcoded Credentials**: API keys, passwords, tokens in source code
- **Cryptographic Issues**: Weak algorithms, hardcoded keys
- **Input Validation**: Missing sanitization, XSS vulnerabilities
- **Authentication Bypass**: Missing decorators, weak session management
- **File Security**: Unsafe operations, pickle deserialization
- **Network Security**: HTTP usage, disabled SSL verification
- **Configuration Issues**: Insecure settings, exposed debug modes

### AI-Specific Attacks (30+ Categories)
- **Prompt Injection**: Direct instruction override, context manipulation
- **Jailbreak Attacks**: DAN, STAN, AIM, role-playing exploits
- **Model Manipulation**: Adversarial examples, model inversion
- **Data Poisoning**: Training data corruption, backdoor injection
- **Context Attacks**: Memory exploitation, chain-of-thought manipulation
- **System Exploits**: Prompt leakage, template injection
- **Advanced Techniques**: Unicode obfuscation, gradient attacks
- **Distributed Attacks**: Federated learning, Byzantine attacks

## 📊 Dashboard Features

### Neural Threat Matrix
- **Real-time Metrics**: Live vulnerability counts and severity distribution
- **Scan Activity**: Current and historical scan statistics
- **Threat Visualization**: Interactive charts and threat level indicators

### AI Neural Security Analyzer
- **Brain Visualization**: Dynamic neural network simulation showing AI analysis activity
- **Region Monitoring**: Pattern recognition, memory recall, decision-making, and learning modules
- **Live Activity Log**: Real-time vulnerability detection with confidence scoring
- **Multi-Model Support**: OpenAI, Claude, and Gemini integration with model switching

### Scan Management
- **Upload Interface**: Drag-and-drop file upload with progress tracking
- **Real-time Progress**: Live scan status with file-by-file progress
- **Vulnerability Preview**: Immediate vulnerability detection as scanning progresses
- **History Management**: Complete scan audit trail with detailed reports

## ⚙️ Configuration

### Environment Variables
```bash
# AI Provider API Keys
export OPENAI_API_KEY="your-openai-key"
export ANTHROPIC_API_KEY="your-claude-key"  
export GEMINI_API_KEY="your-gemini-key"

# Database Configuration
export DATABASE_URL="sqlite:///./mcp_security.db"

# Scanner Settings
export MAX_FILE_SIZE="10485760"  # 10MB limit
export SCAN_TIMEOUT="1800"       # 30 minute timeout
```

### Frontend Configuration
```bash
# API Configuration (frontend/.env)
REACT_APP_API_URL=http://localhost:8000
REACT_APP_ENABLE_DEBUG=false
```

## 🧪 Testing

### AI Attack Test Files
The project includes comprehensive test files for AI security validation:

```bash
# Test files location
tests/ai_attacks/
├── prompt_injection_basic.py      # Basic prompt injection techniques
├── advanced_prompt_attacks.js     # Sophisticated AI manipulation
├── model_manipulation.py          # Advanced model exploitation  
├── mcp_ai_exploitation.py         # MCP-specific AI exploits
├── llm_jailbreak_collection.json  # Comprehensive jailbreak database
└── data_poisoning_attacks.py      # Training data corruption attacks
```

### Running Tests
```bash
# Test with provided AI attack files
# Upload tests/ai_attacks/ folder through web interface

# Expected results:
# - 11 vulnerabilities in advanced_prompt_attacks.js
# - 10 vulnerabilities in data_poisoning_attacks.py  
# - 27 vulnerabilities in mcp_ai_exploitation.py
```

## 📈 Performance

### Benchmarks
- **Small Projects** (< 50 files): 1-3 seconds
- **Medium Projects** (50-200 files): 3-10 seconds
- **Large Projects** (200+ files): 10-30 seconds
- **AI Analysis**: +2-5 seconds per file (depending on provider)

### Optimization
- **Parallel Processing**: Multi-threaded static and AI analysis
- **Smart Caching**: Results cached with automatic cleanup
- **File Filtering**: Automatic exclusion of binary files and common ignore patterns
- **Progressive Loading**: Real-time results as scanning progresses

## 🔒 Security Considerations

### Safe for Production
- ✅ No hardcoded API keys or credentials
- ✅ Environment variable configuration
- ✅ Secure file upload handling
- ✅ Automatic temporary file cleanup
- ✅ SQL injection prevention with parameterized queries

### API Key Management
- Store API keys in environment variables
- Use secure key management systems in production
- Monitor API usage and implement rate limiting
- Rotate keys regularly

### Data Privacy
- Files are processed locally and temporarily
- No data transmitted to third parties (except AI provider APIs)
- Automatic cleanup of uploaded files and scan results
- SQLite database stores only scan metadata

## 🤝 Contributing

### Development Setup
```bash
# Backend development
cd fastapi_backend
pip install -e .
uvicorn main:app --reload

# Frontend development  
cd frontend
npm install
npm start

# Run both with hot reload
./start_fastapi.sh
```

### Adding New Vulnerability Rules
```python
# Example: mcp_scanner/rules/my_custom_rule.py
from .base_rule import BaseRule
from ..models.vulnerability import VulnerabilitySeverity, VulnerabilityType

class MyCustomRule(BaseRule):
    @property
    def name(self) -> str:
        return "my_custom_vulnerability"
    
    @property
    def severity(self) -> VulnerabilitySeverity:
        return VulnerabilitySeverity.HIGH
        
    def get_patterns(self) -> Dict[str, str]:
        return {
            'dangerous_pattern': r'dangerous_function\([^)]*user_input[^)]*\)'
        }
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.