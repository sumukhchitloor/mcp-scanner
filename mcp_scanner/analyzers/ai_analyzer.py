"""AI-powered analyzer for advanced vulnerability detection with multiple LLM providers."""

import os
import json
import time
import uuid
from typing import List, Dict, Any, Optional, Union
import asyncio
from concurrent.futures import ThreadPoolExecutor
from enum import Enum

# Import AI providers with graceful fallbacks
try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

from ..models.vulnerability import Vulnerability, VulnerabilitySeverity, VulnerabilityType
from ..utils.logger import get_logger

logger = get_logger(__name__)


class LLMProvider(Enum):
    """Supported LLM providers."""
    OPENAI = "openai"
    CLAUDE = "claude"
    GEMINI = "gemini"


class AIAnalyzer:
    """AI-powered analyzer using various LLM providers for vulnerability detection."""
    
    def __init__(self, provider: Union[str, LLMProvider] = LLMProvider.OPENAI,
                 api_key: Optional[str] = None, model: Optional[str] = None, 
                 max_workers: int = 2, rate_limit_delay: float = 0.5):
        """
        Initialize the AI analyzer with specified LLM provider.
        
        Args:
            provider: LLM provider to use (openai, claude, gemini)
            api_key: API key for the provider (if None, uses environment variable)
            model: Model to use for analysis (if None, uses default for provider)
            max_workers: Maximum number of parallel API calls
            rate_limit_delay: Delay between API calls (reduced from 1.0 to 0.5 for performance)
        """
        # Convert string to enum if needed
        if isinstance(provider, str):
            try:
                self.provider = LLMProvider(provider.lower())
            except ValueError:
                raise ValueError(f"Unsupported provider: {provider}. Supported: {[p.value for p in LLMProvider]}")
        else:
            self.provider = provider
        
        self.max_workers = max_workers
        self.rate_limit_delay = rate_limit_delay
        
        # Initialize the specific provider
        self._initialize_provider(api_key, model)
        
        logger.info(f"Initialized AI analyzer with {self.provider.value} using model {self.model}")

    def _initialize_provider(self, api_key: Optional[str], model: Optional[str]):
        """Initialize the specific AI provider."""
        if self.provider == LLMProvider.OPENAI:
            self._initialize_openai(api_key, model)
        elif self.provider == LLMProvider.CLAUDE:
            self._initialize_claude(api_key, model)
        elif self.provider == LLMProvider.GEMINI:
            self._initialize_gemini(api_key, model)
        else:
            raise ValueError(f"Provider {self.provider} not implemented")

    def _initialize_openai(self, api_key: Optional[str], model: Optional[str]):
        """Initialize OpenAI provider."""
        if not OPENAI_AVAILABLE:
            raise ImportError("OpenAI library not available. Install with: pip install openai")
        
        self.api_key = api_key or os.getenv('OPENAI_API_KEY')
        if not self.api_key:
            raise ValueError("OpenAI API key is required. Set OPENAI_API_KEY environment variable or pass api_key parameter.")
        
        self.model = model or "gpt-4"
        self.client = openai.OpenAI(api_key=self.api_key)

    def _initialize_claude(self, api_key: Optional[str], model: Optional[str]):
        """Initialize Anthropic Claude provider."""
        if not ANTHROPIC_AVAILABLE:
            raise ImportError("Anthropic library not available. Install with: pip install anthropic")
        
        self.api_key = api_key or os.getenv('ANTHROPIC_API_KEY')
        if not self.api_key:
            raise ValueError("Anthropic API key is required. Set ANTHROPIC_API_KEY environment variable or pass api_key parameter.")
        
        self.model = model or "claude-3-sonnet-20240229"
        self.client = anthropic.Anthropic(api_key=self.api_key)

    def _initialize_gemini(self, api_key: Optional[str], model: Optional[str]):
        """Initialize Google Gemini provider."""
        if not GEMINI_AVAILABLE:
            raise ImportError("Google Generative AI library not available. Install with: pip install google-generativeai")
        
        # Set API key - try different environment variables
        self.api_key = api_key or os.getenv('GEMINI_API_KEY') or os.getenv('GOOGLE_API_KEY')
        if not self.api_key:
            raise ValueError("Gemini API key is required. Set GEMINI_API_KEY environment variable or pass api_key parameter.")
        
        self.model = model or "gemini-2.5-flash"
        
        # Configure the API key
        genai.configure(api_key=self.api_key)
        self.client = genai.GenerativeModel(self.model)
    
    def scan_file(self, file_path: str, content: str) -> List[Vulnerability]:
        """
        Scan a single file using AI analysis with intelligent handling for large files.
        
        Args:
            file_path: Path to the file
            content: File content as string
            
        Returns:
            List of vulnerabilities found
        """
        try:
            # Dynamic file size limits based on provider and content complexity
            max_size = self._get_dynamic_file_size_limit(content)
                
            if len(content) > max_size:
                # For very large files, use intelligent chunking
                return self._scan_large_file_chunked(file_path, content)
            
            # Generate comprehensive analysis prompt
            prompt = self._generate_analysis_prompt(file_path, content)
            
            # Call appropriate AI API with timeout
            response = self._call_ai_api_with_timeout(prompt)
            
            # Parse response and create vulnerabilities
            vulnerabilities = self._parse_ai_response(response, file_path)
            
            logger.debug(f"AI analysis found {len(vulnerabilities)} vulnerabilities in {file_path}")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error during AI analysis of {file_path}: {e}")
            return []

    def _call_ai_api(self, prompt: str) -> str:
        """Call the appropriate AI API based on the provider."""
        if self.provider == LLMProvider.OPENAI:
            return self._call_openai_api(prompt)
        elif self.provider == LLMProvider.CLAUDE:
            return self._call_claude_api(prompt)
        elif self.provider == LLMProvider.GEMINI:
            return self._call_gemini_api(prompt)
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")

    def _call_openai_api(self, prompt: str) -> str:
        """Call OpenAI API."""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are an elite cybersecurity expert specializing in Model Context Protocol (MCP) security analysis. You have deep expertise in AI/LLM security, protocol vulnerabilities, and modern attack vectors. Your analysis is thorough, precise, and considers both traditional security flaws and cutting-edge MCP-specific threats."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=4000  # Increased for more detailed analysis
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            logger.error(f"OpenAI API call failed: {e}")
            raise

    def _call_claude_api(self, prompt: str) -> str:
        """Call Anthropic Claude API."""
        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=4000,  # Increased for more detailed analysis
                temperature=0.1,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            return message.content[0].text.strip()
        except Exception as e:
            logger.error(f"Claude API call failed: {e}")
            raise

    def _call_gemini_api(self, prompt: str) -> str:
        """Call Google Gemini API."""
        try:
            response = self.client.generate_content(prompt)
            return response.text.strip()
        except Exception as e:
            logger.error(f"Gemini API call failed: {e}")
            raise
    
    def scan_files(self, file_paths: List[str], file_handler, progress_callback=None) -> List[Vulnerability]:
        """
        Scan multiple files using AI analysis with rate limiting.
        
        Args:
            file_paths: List of file paths to scan
            file_handler: File handler for reading files
            progress_callback: Optional callback for progress updates
            
        Returns:
            List of all vulnerabilities found
        """
        all_vulnerabilities = []
        
        if not file_paths:
            return all_vulnerabilities
        
        start_time = time.time()
        completed = 0
        total = len(file_paths)
        scanned_count = 0
        skipped_count = 0
        
        logger.info(f"AI analysis starting on {total} files with {self.provider} provider")
        
        # Process files with rate limiting
        for file_path in file_paths:
            try:
                # Read file content
                content = file_handler.read_file(file_path)
                if content is None:
                    logger.warning(f"AI scan: Could not read file {file_path} - file reading failed")
                    continue
                
                # Quick pre-filter: skip files that are clearly not worth AI analysis
                skip_reason = self._get_skip_reason(file_path, content)
                if skip_reason:
                    logger.info(f"AI scan: Skipping {file_path} - {skip_reason}")
                    skipped_count += 1
                    completed += 1
                    continue
                
                # File will be analyzed
                logger.info(f"AI scan: Analyzing {file_path} ({len(content):,} chars)")
                scanned_count += 1
                
                # Analyze file
                vulnerabilities = self.scan_file(file_path, content)
                all_vulnerabilities.extend(vulnerabilities)
                
                if vulnerabilities:
                    logger.info(f"AI scan: Found {len(vulnerabilities)} vulnerabilities in {file_path}")
                else:
                    logger.debug(f"AI scan: No vulnerabilities found in {file_path}")
                
                completed += 1
                
                if progress_callback:
                    progress_callback(f"AI analyzed {completed}/{total} files ({file_path})")
                
                # Rate limiting delay
                if completed < total:
                    time.sleep(self.rate_limit_delay)
                
            except Exception as e:
                logger.error(f"Error during AI analysis of {file_path}: {e}")
                completed += 1
                continue
        
        end_time = time.time()
        duration = end_time - start_time
        
        logger.info(f"AI analysis completed in {duration:.1f}s")
        logger.info(f"AI scan summary: {scanned_count} files analyzed, {skipped_count} files skipped")
        logger.info(f"Found {len(all_vulnerabilities)} vulnerabilities across {scanned_count} analyzed files")
        
        return all_vulnerabilities
    
    def _generate_analysis_prompt(self, file_path: str, content: str) -> str:
        """Generate comprehensive analysis prompt for the AI model."""
        
        # Analyze file context to provide better guidance
        file_extension = file_path.split('.')[-1].lower()
        is_config_file = any(x in file_path.lower() for x in ['config', 'settings', '.json', '.yaml', '.yml'])
        is_test_file = any(x in file_path.lower() for x in ['test', 'spec', '__test__', '.test.', '.spec.'])
        is_signature_file = 'signature' in file_path.lower()
        is_detector_file = any(x in file_path.lower() for x in ['detector', 'validation', 'security'])
        
        context_guidance = ""
        if is_signature_file or is_detector_file:
            context_guidance = """
⚠️ **SIGNATURE/DETECTOR FILE DETECTED**
This file contains security detection patterns and validation logic.
DO NOT flag the security patterns themselves as vulnerabilities.
ONLY report implementation flaws in the detection logic."""
        elif is_config_file:
            context_guidance = """
⚠️ **CONFIGURATION FILE DETECTED**
Focus ONLY on hardcoded secrets and credentials.
Ignore structural patterns and schema definitions."""
        elif is_test_file:
            context_guidance = """
⚠️ **TEST FILE DETECTED**
Ignore test patterns and example vulnerabilities.
Only flag actual security flaws in test infrastructure."""
        
        # Determine if this looks like security detection code
        detection_keywords = ['regex', 'pattern', 'detect', 'signature', 'vulnerability', 'injection', 'traversal']
        is_likely_detection_code = any(keyword in content.lower() for keyword in detection_keywords) and len(content) < 50000
        
        if is_likely_detection_code:
            context_guidance += """
⚠️ **SECURITY DETECTION CODE DETECTED**
This appears to be security detection/validation code.
Focus on implementation flaws, not the patterns being detected."""
        
        prompt = f"""You are an elite cybersecurity expert who excels at distinguishing between actual vulnerabilities and security detection code. Your mission is to find REAL exploitable security flaws while avoiding false positives.

=== FILE ANALYSIS ===
File: {file_path}
Type: {file_extension.upper()} file
Size: {len(content)} characters
{context_guidance}

=== CODE TO ANALYZE ===
```{file_extension}
{content}
```

=== CRITICAL ANALYSIS RULES ===

🎯 **ZERO TOLERANCE FOR FALSE POSITIVES**

**AUTOMATICALLY IGNORE:**
1. **Security Detection Patterns** - Files containing regex patterns to detect vulnerabilities
2. **Validation Logic** - Code that validates or checks for security issues
3. **Test Files** - Any testing code or example vulnerabilities
4. **Configuration Schema** - JSON/YAML structure definitions
5. **Documentation** - Comments explaining security concepts
6. **Error Messages** - Security-related error text or logging

**ONLY REPORT IF:**
✅ **Exploitable by external attacker**
✅ **Missing security controls** 
✅ **User input reaches dangerous function**
✅ **Production code (not test/example)**

=== VULNERABILITY CATEGORIES (STRICT CRITERIA) ===

🔴 **CRITICAL** - Must have clear attack vector:

**Command Injection:**
- User input → os.system/subprocess with shell=True
- Must trace: user data → command execution
- Ignore: hardcoded commands, internal tools

**Code Injection:**
- User input → eval()/exec()
- Template injection with user data
- Dynamic imports from external sources

🟠 **HIGH** - Clear security impact required:

**SQL Injection:**
- User input → string concatenation in SQL
- Must show: external data → query construction
- Ignore: internal queries, ORM usage

**Authentication Bypass:**
- Externally accessible sensitive operations without auth
- Must be: user-facing + privileged functionality
- Ignore: internal helpers, configuration

**File Path Traversal:**
- User input → file operations without validation
- Must show: external path → file system access
- Ignore: internal file ops, relative imports

🟡 **MEDIUM** - Definite security weakness:

**Information Disclosure:**
- Sensitive data exposed to unauthorized users
- Production stack traces in responses
- Credentials in accessible locations

=== CONTEXT-SPECIFIC FILTERING ===

**FOR DETECTOR/SIGNATURE FILES:**
- These contain patterns to DETECT vulnerabilities
- The patterns themselves are NOT vulnerabilities
- Only flag implementation bugs in detection logic

**FOR CONFIGURATION FILES:**
- Only flag: hardcoded secrets, API keys, passwords
- Ignore: schema structure, type definitions

**FOR VALIDATION/SECURITY CODE:**
- This code is PREVENTING vulnerabilities
- Only flag if the prevention logic has flaws
- Don't flag the patterns being checked

=== OUTPUT REQUIREMENTS ===

Return ONLY valid JSON. For each ACTUAL vulnerability:

```json
{{
  "type": "command_injection|sql_injection|authentication|file_security|information_disclosure|other",
  "severity": "CRITICAL|HIGH|MEDIUM",
  "line_number": <exact_line>,
  "code_snippet": "<1-2 lines max, escape quotes>",
  "description": "<WHY this is exploitable>",
  "attack_vector": "<HOW attacker would exploit>",
  "recommendation": "<Specific fix>",
  "confidence": <85-100 for real vulns>
}}
```

**If no real vulnerabilities exist, return: []**

**Remember: Security detection code is NOT vulnerable. Pattern definitions are NOT vulnerabilities. Better to miss one than create false positives.**

ANALYZE NOW:"""
        
        return prompt
    
    def _parse_ai_response(self, response: str, file_path: str) -> List[Vulnerability]:
        """
        Parse AI response and create vulnerability objects.
        
        Args:
            response: AI response text
            file_path: Path to the analyzed file
            
        Returns:
            List of vulnerability objects
        """
        vulnerabilities = []
        
        try:
            # Clean and preprocess the response
            cleaned_response = self._clean_ai_response(response)
            
            # Try to extract JSON from response
            json_start = cleaned_response.find('[')
            json_end = cleaned_response.rfind(']') + 1
            
            if json_start == -1 or json_end == 0:
                logger.warning(f"No JSON found in AI response for {file_path}")
                return []
            
            json_text = cleaned_response[json_start:json_end]
            
            # Additional cleaning for problematic escape sequences
            json_text = self._fix_json_escapes(json_text)
            
            ai_vulnerabilities = json.loads(json_text)
            
            if not isinstance(ai_vulnerabilities, list):
                logger.warning(f"AI response is not a list for {file_path}")
                return []
            
            # Create vulnerability objects
            for i, ai_vuln in enumerate(ai_vulnerabilities):
                try:
                    vulnerability = self._create_vulnerability_from_ai(ai_vuln, file_path, i)
                    if vulnerability:
                        vulnerabilities.append(vulnerability)
                except Exception as e:
                    logger.error(f"Error creating vulnerability from AI response: {e}")
                    continue
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI response as JSON for {file_path}: {e}")
            # Log the problematic JSON for debugging
            logger.debug(f"Problematic JSON: {json_text[:500]}...")
        except Exception as e:
            logger.error(f"Error parsing AI response for {file_path}: {e}")
        
        return vulnerabilities

    def _clean_ai_response(self, response: str) -> str:
        """Clean AI response to improve JSON parsing."""
        # Remove markdown code blocks
        response = response.replace('```json', '').replace('```', '')
        
        # Remove common prefixes/suffixes
        lines = response.strip().split('\n')
        cleaned_lines = []
        
        for line in lines:
            line = line.strip()
            # Skip explanation lines
            if any(prefix in line.lower() for prefix in ['analysis:', 'vulnerabilities found:', 'summary:']):
                continue
            cleaned_lines.append(line)
        
        return '\n'.join(cleaned_lines)

    def _fix_json_escapes(self, json_text: str) -> str:
        """Fix common JSON escape sequence issues."""
        import re
        
        # First, handle the most common issue: unescaped quotes in code snippets
        # Look for patterns like: "code_snippet": "some code with "quotes" here",
        def escape_quotes_in_field(match):
            field_name = match.group(1)
            content = match.group(2)
            # Escape internal quotes
            escaped_content = content.replace('"', '\\"')
            return f'"{field_name}": "{escaped_content}"'
        
        # Fix quotes in specific fields that commonly contain code
        json_text = re.sub(r'"(code_snippet|description|attack_vector|recommendation)":\s*"([^"]*(?:[^\\"]"[^"]*)*)"', escape_quotes_in_field, json_text)
        
        # Fix other escape sequences
        json_text = re.sub(r'(?<!\\)\\(?!["\\/bfnrtu])', r'\\\\', json_text)
        
        return json_text
    
    def _create_vulnerability_from_ai(self, ai_vuln: Dict[str, Any], 
                                    file_path: str, index: int) -> Optional[Vulnerability]:
        """
        Create a Vulnerability object from AI analysis result.
        
        Args:
            ai_vuln: AI vulnerability dictionary
            file_path: Path to the file
            index: Index of vulnerability in response
            
        Returns:
            Vulnerability object or None if invalid
        """
        try:
            # Validate required fields
            required_fields = ['type', 'severity', 'line_number', 'description', 'recommendation']
            for field in required_fields:
                if field not in ai_vuln:
                    logger.warning(f"Missing required field '{field}' in AI vulnerability")
                    return None
            
            # Enhanced vulnerability type mapping including new categories
            vuln_type_mapping = {
                'command_injection': VulnerabilityType.COMMAND_INJECTION,
                'sql_injection': VulnerabilityType.SQL_INJECTION,
                'tool_poisoning': VulnerabilityType.TOOL_POISONING,
                'authentication': VulnerabilityType.AUTHENTICATION,
                'credentials': VulnerabilityType.CREDENTIALS,
                'file_security': VulnerabilityType.FILE_SECURITY,
                'input_validation': VulnerabilityType.INPUT_VALIDATION,
                'prompt_injection': VulnerabilityType.PROMPT_INJECTION,
                'cryptography': VulnerabilityType.CRYPTOGRAPHY,
                'network_security': VulnerabilityType.NETWORK_SECURITY,
                # New MCP-specific and emerging threat categories
                'information_disclosure': VulnerabilityType.INFORMATION_DISCLOSURE,
                'file_system_security': VulnerabilityType.FILE_SYSTEM_SECURITY,
                'error_handling': VulnerabilityType.ERROR_HANDLING,
                'ai_model_security': VulnerabilityType.AI_MODEL_SECURITY,
                'mcp_protocol': VulnerabilityType.MCP_PROTOCOL,
                'steganography': VulnerabilityType.STEGANOGRAPHY,
                'supply_chain': VulnerabilityType.SUPPLY_CHAIN,
                'other': VulnerabilityType.OTHER
            }
            
            vuln_type = vuln_type_mapping.get(ai_vuln['type'])
            if not vuln_type:
                logger.warning(f"Unknown vulnerability type: {ai_vuln['type']}")
                vuln_type = VulnerabilityType.OTHER
            
            # Map severity
            try:
                severity = VulnerabilitySeverity(ai_vuln['severity'])
            except ValueError:
                logger.warning(f"Invalid severity: {ai_vuln['severity']}")
                severity = VulnerabilitySeverity.MEDIUM
            
            # Generate unique ID
            vuln_id = f"ai_{file_path}_{ai_vuln['line_number']}_{index}_{uuid.uuid4().hex[:8]}"
            vuln_id = vuln_id.replace('/', '_').replace('\\', '_')
            
            # Get confidence score
            confidence = ai_vuln.get('confidence', 75)
            if not isinstance(confidence, int) or not 0 <= confidence <= 100:
                confidence = 75
            
            # Extract CWE reference if provided
            cwe_id = ai_vuln.get('cwe_reference', None)
            
            # Build enhanced additional info with new fields
            additional_info = {
                'ai_model': self.model,
                'ai_provider': self.provider.value,
                'ai_analysis_index': index,
                'original_type': ai_vuln['type']  # Store original AI-provided type
            }
            
            # Add optional enhanced fields from the new prompt
            if 'attack_vector' in ai_vuln:
                additional_info['attack_vector'] = ai_vuln['attack_vector']
            if 'exploitability' in ai_vuln:
                additional_info['exploitability'] = ai_vuln['exploitability']
            if 'business_impact' in ai_vuln:
                additional_info['business_impact'] = ai_vuln['business_impact']
            
            # Create vulnerability
            vulnerability = Vulnerability(
                id=vuln_id,
                type=vuln_type,
                severity=severity,
                file_path=file_path,
                line_number=int(ai_vuln['line_number']),
                code_snippet=ai_vuln.get('code_snippet', ''),
                description=ai_vuln['description'],
                recommendation=ai_vuln['recommendation'],
                confidence=confidence,
                detector='ai_analyzer',
                rule_name='ai_analysis',
                cwe_id=cwe_id,
                additional_info=additional_info
            )
            
            return vulnerability
            
        except Exception as e:
            logger.error(f"Error creating vulnerability from AI data: {e}")
            return None
    
    def test_connection(self) -> bool:
        """
        Test connection to the AI API.
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            if self.provider == LLMProvider.OPENAI:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[{"role": "user", "content": "Hello"}],
                    max_tokens=5,
                    timeout=10.0
                )
                return True
            elif self.provider == LLMProvider.CLAUDE:
                message = self.client.messages.create(
                    model=self.model,
                    max_tokens=5,
                    messages=[{"role": "user", "content": "Hello"}]
                )
                return True
            elif self.provider == LLMProvider.GEMINI:
                response = self.client.generate_content("Hello")
                return True
            else:
                return False
        except Exception as e:
            logger.error(f"{self.provider.value} API connection test failed: {e}")
            return False
    
    def _get_skip_reason(self, file_path: str, content: str) -> Optional[str]:
        """
        Determine if a file should be skipped for AI analysis and return the reason.
        
        Args:
            file_path: Path to the file
            content: File content
            
        Returns:
            Reason for skipping the file, or None if file should be analyzed
        """
        # Skip very large files that would cause timeouts
        if len(content) > 500000:  # 500KB limit
            return f"file too large ({len(content):,} chars, max 500,000)"
        
        # Skip empty or very small files
        if len(content.strip()) < 50:
            return f"file too small ({len(content.strip())} chars, min 50)"
        
        file_lower = file_path.lower()
        content_lower = content.lower()
        
        # Skip package/dependency files
        dependency_patterns = [
            'package-lock.json', 'yarn.lock', 'composer.lock',
            'node_modules', '.git', 'dist', 'build'
        ]
        for pattern in dependency_patterns:
            if pattern in file_lower:
                return f"dependency/build file ({pattern})"
        
        # Skip pure configuration/data files with no logic
        if file_path.endswith(('.json', '.yaml', '.yml')):
            # But analyze if it contains suspicious patterns
            suspicious_json_patterns = [
                'eval', 'exec', 'system', 'shell', 'cmd',
                'password', 'secret', 'key', 'token'
            ]
            if not any(pattern in content_lower for pattern in suspicious_json_patterns):
                return "config file with no suspicious patterns"
        
        # Skip generated/minified code
        generated_indicators = [
            '/*! This file is auto-generated',
            '// This file was automatically generated',
            '# Auto-generated',
            'webpack:',  # Webpack bundles
        ]
        for indicator in generated_indicators:
            if indicator in content:
                return "auto-generated or minified code"
        
        # Skip files that are clearly just data/documentation
        if file_path.endswith(('.md', '.txt', '.rst')):
            return "documentation file"
        
        # Skip binary files that might have been read as text
        if '\x00' in content:  # Null bytes indicate binary
            return "binary file detected"
        
        # Skip pure CSS/styling files
        if file_path.endswith('.css') and not any(keyword in content_lower for keyword in [
            'url(', 'import', 'eval', 'expression'
        ]):
            return "pure CSS file with no dynamic content"
        
        return None

    def _get_dynamic_file_size_limit(self, content: str) -> int:
        """
        Calculate dynamic file size limit based on content complexity and provider.
        
        Args:
            content: File content to analyze
            
        Returns:
            Appropriate file size limit
        """
        # Base limits by provider - significantly reduced for performance
        base_limits = {
            LLMProvider.OPENAI: 50000,    # Reduced from 120000
            LLMProvider.CLAUDE: 80000,    # Reduced from 180000
            LLMProvider.GEMINI: 40000     # Reduced from 100000
        }
        
        base_limit = base_limits.get(self.provider, 30000)
        
        # Adjust based on content complexity
        # Count complexity indicators
        complexity_score = 0
        complexity_indicators = [
            'import ', 'def ', 'class ', 'if ', 'for ', 'while ', 
            'try:', 'except:', '{', '}', '(', ')', '[', ']'
        ]
        
        for indicator in complexity_indicators:
            complexity_score += content.count(indicator)
        
        # Reduce limit for very complex files to prevent timeouts
        if complexity_score > 500:
            return int(base_limit * 0.5)  # Aggressive reduction for complex files
        elif complexity_score > 200:
            return int(base_limit * 0.7)
        else:
            return base_limit
    
    def _scan_large_file_chunked(self, file_path: str, content: str) -> List[Vulnerability]:
        """
        Scan large files by intelligent chunking to avoid timeouts and token limits.
        
        Args:
            file_path: Path to the file
            content: File content
            
        Returns:
            List of vulnerabilities found across all chunks
        """
        try:
            # Skip extremely large files to prevent hanging
            if len(content) > 1000000:  # 1MB limit for chunked analysis
                logger.warning(f"File too large for analysis ({len(content)} chars): {file_path}")
                return []
            
            logger.info(f"Large file detected ({len(content)} chars), using chunked analysis: {file_path}")
            
            # Split content into logical chunks (functions, classes, etc.)
            chunks = self._split_content_intelligently(content)
            all_vulnerabilities = []
            
            # Limit number of chunks to prevent extremely long analysis
            max_chunks = 10
            if len(chunks) > max_chunks:
                logger.warning(f"Too many chunks ({len(chunks)}), limiting to {max_chunks} for {file_path}")
                chunks = chunks[:max_chunks]
            
            for i, chunk in enumerate(chunks):
                if len(chunk.strip()) < 100:  # Skip very small chunks
                    continue
                    
                try:
                    logger.debug(f"Analyzing chunk {i+1}/{len(chunks)} of {file_path}")
                    chunk_vulns = self.scan_file(f"{file_path}:chunk_{i+1}", chunk)
                    
                    # Adjust line numbers to match original file
                    for vuln in chunk_vulns:
                        # Estimate line offset for this chunk
                        lines_before = content[:content.find(chunk)].count('\n')
                        vuln.line_number += lines_before
                        vuln.file_path = file_path  # Restore original file path
                    
                    all_vulnerabilities.extend(chunk_vulns)
                    
                except Exception as e:
                    logger.warning(f"Error analyzing chunk {i+1} of {file_path}: {e}")
                    continue
            
            logger.info(f"Chunked analysis completed for {file_path}: {len(all_vulnerabilities)} vulnerabilities")
            return all_vulnerabilities
            
        except Exception as e:
            logger.error(f"Error in chunked analysis of {file_path}: {e}")
            return []
    
    def _split_content_intelligently(self, content: str) -> List[str]:
        """
        Split content into logical chunks based on code structure.
        
        Args:
            content: File content to split
            
        Returns:
            List of content chunks
        """
        lines = content.split('\n')
        chunks = []
        current_chunk = []
        current_chunk_size = 0
        max_chunk_size = 15000  # Much smaller chunks for better performance
        
        # Identify logical boundaries
        function_starts = []
        class_starts = []
        
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('def ') or stripped.startswith('async def '):
                function_starts.append(i)
            elif stripped.startswith('class '):
                class_starts.append(i)
        
        # Split at logical boundaries
        boundaries = sorted(function_starts + class_starts + [0, len(lines)])
        
        for i in range(len(boundaries) - 1):
            start = boundaries[i]
            end = boundaries[i + 1]
            chunk_lines = lines[start:end]
            chunk_content = '\n'.join(chunk_lines)
            
            # If chunk is still too large, split it further
            if len(chunk_content) > max_chunk_size:
                sub_chunks = self._split_large_chunk(chunk_content, max_chunk_size)
                chunks.extend(sub_chunks)
            elif chunk_content.strip():  # Only add non-empty chunks
                chunks.append(chunk_content)
        
        # If no logical boundaries found, split by size
        if not chunks:
            chunks = self._split_by_size(content, max_chunk_size)
        
        # Filter out very small chunks to avoid noise
        return [chunk for chunk in chunks if len(chunk.strip()) > 200]
    
    def _split_large_chunk(self, content: str, max_size: int) -> List[str]:
        """Split a large chunk into smaller pieces."""
        chunks = []
        lines = content.split('\n')
        current_chunk = []
        current_size = 0
        
        for line in lines:
            line_size = len(line) + 1  # +1 for newline
            
            if current_size + line_size > max_size and current_chunk:
                chunks.append('\n'.join(current_chunk))
                current_chunk = [line]
                current_size = line_size
            else:
                current_chunk.append(line)
                current_size += line_size
        
        if current_chunk:
            chunks.append('\n'.join(current_chunk))
        
        return chunks
    
    def _split_by_size(self, content: str, max_size: int) -> List[str]:
        """Split content by size when no logical boundaries are found."""
        chunks = []
        current_pos = 0
        
        while current_pos < len(content):
            end_pos = min(current_pos + max_size, len(content))
            
            # Try to break at a line boundary
            if end_pos < len(content):
                while end_pos > current_pos and content[end_pos] != '\n':
                    end_pos -= 1
                if end_pos == current_pos:  # No line break found
                    end_pos = min(current_pos + max_size, len(content))
            
            chunk = content[current_pos:end_pos]
            if chunk.strip():
                chunks.append(chunk)
            
            current_pos = end_pos + 1
        
        return chunks
    
    def _call_ai_api_with_timeout(self, prompt: str, timeout: int = 300) -> str:
        """
        Call AI API with timeout to prevent hanging.
        
        Args:
            prompt: Analysis prompt
            timeout: Timeout in seconds (increased to 300 seconds = 5 minutes)
            
        Returns:
            AI response
        """
        import signal
        import threading
        import time
        
        # For systems that don't support signal (Windows), use threading approach
        try:
            def timeout_handler(signum, frame):
                raise TimeoutError(f"AI API call timed out after {timeout} seconds")
            
            # Set timeout for AI API calls
            old_handler = signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(timeout)
            
            try:
                response = self._call_ai_api(prompt)
                signal.alarm(0)  # Cancel timeout
                return response
            except TimeoutError:
                logger.warning(f"AI API call timed out after {timeout} seconds")
                raise
            except Exception as e:
                signal.alarm(0)  # Cancel timeout
                raise e
            finally:
                signal.signal(signal.SIGALRM, old_handler)
                
        except (AttributeError, OSError):
            # Fallback for systems without signal support (Windows)
            result = [None]
            exception = [None]
            
            def target():
                try:
                    result[0] = self._call_ai_api(prompt)
                except Exception as e:
                    exception[0] = e
            
            thread = threading.Thread(target=target)
            thread.daemon = True
            thread.start()
            thread.join(timeout)
            
            if thread.is_alive():
                logger.warning(f"AI API call timed out after {timeout} seconds (threading fallback)")
                raise TimeoutError(f"AI API call timed out after {timeout} seconds")
            
            if exception[0]:
                raise exception[0]
            
            return result[0]
