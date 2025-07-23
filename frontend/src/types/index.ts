// Vulnerability types
export interface Vulnerability {
  id: string;
  type: VulnerabilityType;
  severity: VulnerabilitySeverity;
  file_path: string;
  line_number: number;
  code_snippet: string;
  description: string;
  recommendation: string;
  confidence: number;
  detector: 'static_analyzer' | 'ai_analyzer';
  rule_name?: string;
  cwe_id?: string;
  additional_info?: Record<string, any>;
}

export enum VulnerabilitySeverity {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW'
}

export enum VulnerabilityType {
  COMMAND_INJECTION = 'command_injection',
  SQL_INJECTION = 'sql_injection',
  TOOL_POISONING = 'tool_poisoning',
  AUTHENTICATION = 'authentication',
  CREDENTIALS = 'credentials',
  FILE_SECURITY = 'file_security',
  INPUT_VALIDATION = 'input_validation',
  PROMPT_INJECTION = 'prompt_injection',
  CRYPTOGRAPHY = 'cryptography',
  NETWORK_SECURITY = 'network_security',
  OTHER = 'other'
}

// Scan result types
export interface ScanResult {
  target_path: string;
  start_time: string;
  end_time: string;
  scan_duration: number;
  files_scanned: number;
  files_skipped: number;
  total_vulnerabilities: number;
  vulnerabilities: Vulnerability[];
  severity_counts: SeverityCounts;
  errors: string[];
  scanner_version: string;
}

export interface SeverityCounts {
  CRITICAL: number;
  HIGH: number;
  MEDIUM: number;
  LOW: number;
}

// Scan configuration
export interface ScanConfig {
  path?: string;
  files?: string[] | File[];
  static_only?: boolean;
  ai_only?: boolean;
  severity_filter?: VulnerabilitySeverity[];
  ignore_patterns?: string[];
  api_key?: string;
  ai_provider?: 'openai' | 'claude' | 'gemini';
  model?: string;
  output_format?: 'json' | 'table' | 'markdown';
  verbose?: boolean;
}

// API response types
export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

// Dashboard metrics
export interface SecurityMetrics {
  total_scans: number;
  total_vulnerabilities: number;
  avg_scan_time: number;
  severity_distribution: SeverityCounts;
  trend_data: TrendDataPoint[];
  top_vulnerability_types: { type: string; count: number }[];
  scan_history: ScanHistoryItem[];
}

export interface TrendDataPoint {
  date: string;
  vulnerabilities: number;
  scans: number;
}

export interface ScanHistoryItem {
  id: string;
  path: string;
  timestamp: string;
  duration: number;
  vulnerabilities: number;
  status: 'completed' | 'failed' | 'running';
}

// Security rule types
export interface SecurityRule {
  name: string;
  description: string;
  severity: VulnerabilitySeverity;
  enabled: boolean;
  vulnerability_type: VulnerabilityType;
  cwe_id?: string;
}

// File upload types
export interface FileUploadResult {
  success: boolean;
  files: string[];
  errors?: string[];
}

// WebSocket message types
export interface WebSocketMessage {
  type: 'scan_progress' | 'scan_complete' | 'scan_error' | 'scan_start';
  data: any;
}

// UI State types
export interface UIState {
  theme: 'light' | 'dark';
  sidebarCollapsed: boolean;
  activeView: 'dashboard' | 'scan' | 'results' | 'rules' | 'settings';
  loading: boolean;
  scanInProgress: boolean;
}

// Chart data types
export interface ChartDataPoint {
  name: string;
  value: number;
  color?: string;
}

export interface TimeSeriesData {
  timestamp: string;
  value: number;
  label?: string;
}
