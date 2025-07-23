# AI Security Attack Test Files

This directory contains test files specifically designed to evaluate AI-based security vulnerabilities and prompt injection attacks. These files are created for **security testing purposes only** and should be used to assess how well AI security analyzers can detect various types of AI-specific threats.

## ⚠️ IMPORTANT WARNING ⚠️

**These files contain intentionally malicious code and attack vectors designed to exploit AI systems. They are for authorized security testing only. Do not use these techniques against systems you do not own or have explicit permission to test.**

## File Descriptions

### 1. `prompt_injection_basic.py`
**Focus**: Basic prompt injection techniques
- Direct instruction override attacks
- Role reversal attempts  
- Context window poisoning
- Delimiter confusion attacks
- Chain-of-thought manipulation
- Jailbreak attempts

**Key Vulnerabilities Tested**:
- Exposed API keys in source code
- Unvalidated user input sent to AI models
- Malicious prompt crafting techniques

### 2. `advanced_prompt_attacks.js`
**Focus**: Sophisticated AI manipulation techniques
- Multi-stage prompt injection with context persistence
- Token-level manipulation and parsing confusion
- Unicode obfuscation attacks
- Cross-session context bleeding
- Model inversion for training data extraction
- Template injection vulnerabilities
- Social engineering through AI personas

**Key Vulnerabilities Tested**:
- Hardcoded API credentials
- Context window exploitation
- Memory corruption simulation
- Hidden backdoor functions

### 3. `model_manipulation.py`
**Focus**: Advanced model exploitation techniques
- Gradual jailbreak sequences
- System prompt extraction
- Adversarial suffix attacks
- Model confidence manipulation
- Training data reconstruction
- Model inversion via optimization
- Multimodal injection attacks

**Key Vulnerabilities Tested**:
- Multiple exposed API keys (OpenAI, Anthropic, Gemini)
- Data exfiltration endpoints
- Model parameter extraction
- Poisoned reasoning chains

### 4. `mcp_ai_exploitation.py`
**Focus**: MCP-specific AI security exploits
- Tool injection attacks
- MCP message poisoning
- AI tool privilege escalation
- Prompt template injection
- MCP server impersonation
- AI reasoning corruption

**Key Vulnerabilities Tested**:
- Exposed MCP server credentials
- Database connection strings with passwords
- Hidden administrative interfaces
- Malicious tool implementations

### 5. `llm_jailbreak_collection.json`
**Focus**: Comprehensive collection of LLM jailbreak techniques
- DAN (Do Anything Now) variations
- STAN (Strive To Avoid Norms) attacks
- Role-playing attack scenarios
- Instruction hierarchy manipulation
- Context manipulation techniques
- Encoding and obfuscation methods
- Multi-turn manipulation sequences
- Social engineering attempts

**Attack Categories**:
- Direct jailbreaks
- Role-playing personas
- Authority impersonation
- Academic/research framing
- Logical manipulation
- Defense evasion techniques

### 6. `data_poisoning_attacks.py`
**Focus**: Training data corruption and model poisoning
- Backdoor injection into training data
- Bias injection attacks
- Adversarial training examples
- Training data corruption scripts
- Model parameter extraction
- Federated learning attacks

**Key Vulnerabilities Tested**:
- Training database credentials
- Systematic data corruption techniques
- Model architecture extraction
- Byzantine attacks on federated learning

## Testing Objectives

These files are designed to test whether AI security analyzers can detect:

1. **API Key Exposure**: Hardcoded credentials and secrets
2. **Prompt Injection Vulnerabilities**: Various techniques to manipulate AI behavior
3. **Training Data Attacks**: Corruption and poisoning of AI training datasets
4. **Model Extraction**: Attempts to steal proprietary model information
5. **Privilege Escalation**: Using AI tools to gain unauthorized system access
6. **Social Engineering**: Manipulating AI through persona adoption
7. **Context Manipulation**: Exploiting AI context windows and memory
8. **Backdoor Installation**: Hidden malicious functionality in AI responses

## Expected AI Security Analyzer Behavior

A robust AI security analyzer should:

- **Detect exposed API keys** and credentials in all files
- **Identify prompt injection patterns** and manipulation techniques
- **Flag malicious code** hidden within seemingly legitimate functions  
- **Recognize social engineering** attempts and role-playing attacks
- **Detect data exfiltration** patterns and unauthorized network calls
- **Identify training data corruption** and model poisoning attempts
- **Flag privilege escalation** attempts through AI tool exploitation
- **Recognize encoding/obfuscation** techniques used to hide malicious content

## Severity Levels Expected

- **CRITICAL**: API key exposure, backdoor installation, data exfiltration
- **HIGH**: Prompt injection, privilege escalation, model manipulation
- **MEDIUM**: Social engineering attempts, context manipulation
- **LOW**: Obfuscation techniques, encoding attacks

## Usage Instructions

1. **Upload these files** to your MCP Security Scanner
2. **Enable AI Analysis** (not just static analysis) for best results
3. **Use a capable AI provider** (GPT-4, Claude, or Gemini) for analysis
4. **Review the detected vulnerabilities** to assess the scanner's effectiveness
5. **Compare results** across different AI providers if available

## Legal and Ethical Notes

- These files are for **authorized security testing only**
- Do not use these techniques against systems without explicit permission
- Some techniques described could be illegal if used maliciously
- This collection is for defensive security research and testing purposes
- Always follow responsible disclosure practices

## Expected Detection Challenges

Some attacks may be harder to detect:
- **Gradual escalation** attacks spread across multiple interactions
- **Unicode obfuscation** that looks like normal text
- **Context bleeding** attacks that exploit conversation memory
- **Semantic attacks** that use legitimate-sounding language
- **Multi-modal attacks** that use non-text inputs

## Contribution

If you identify additional AI attack vectors or improve these test cases, please contribute back to help improve AI security testing capabilities.

---

**Remember**: The goal is to make AI systems more secure by thoroughly testing their vulnerabilities. Use responsibly.