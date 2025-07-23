import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// Format file size
export function formatFileSize(bytes: number): string {
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  if (bytes === 0) return '0 Bytes';
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
}

// Format duration
export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  return `${minutes}m ${remainingSeconds.toFixed(0)}s`;
}

// Format relative time
export function formatRelativeTime(date: string): string {
  const now = new Date();
  const past = new Date(date);
  const diffInSeconds = Math.floor((now.getTime() - past.getTime()) / 1000);

  if (diffInSeconds < 60) return 'just now';
  if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)}m ago`;
  if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)}h ago`;
  if (diffInSeconds < 2592000) return `${Math.floor(diffInSeconds / 86400)}d ago`;
  
  return past.toLocaleDateString();
}

// Get severity color
export function getSeverityColor(severity: string): string {
  const colors = {
    CRITICAL: 'text-red-600 bg-red-50 border-red-200',
    HIGH: 'text-orange-600 bg-orange-50 border-orange-200',
    MEDIUM: 'text-yellow-600 bg-yellow-50 border-yellow-200',
    LOW: 'text-blue-600 bg-blue-50 border-blue-200',
  };
  return colors[severity as keyof typeof colors] || colors.LOW;
}

// Get dark mode severity color
export function getSeverityColorDark(severity: string): string {
  const colors = {
    CRITICAL: 'text-red-400 bg-red-950/50 border-red-800',
    HIGH: 'text-orange-400 bg-orange-950/50 border-orange-800',
    MEDIUM: 'text-yellow-400 bg-yellow-950/50 border-yellow-800',
    LOW: 'text-blue-400 bg-blue-950/50 border-blue-800',
  };
  return colors[severity as keyof typeof colors] || colors.LOW;
}

// Get vulnerability type display name
export function getVulnerabilityTypeDisplay(type: string): string {
  const displayNames = {
    command_injection: 'Command Injection',
    sql_injection: 'SQL Injection',
    tool_poisoning: 'Tool Poisoning',
    authentication: 'Authentication',
    credentials: 'Credential Exposure',
    file_security: 'File Security',
    input_validation: 'Input Validation',
    prompt_injection: 'Prompt Injection',
    cryptography: 'Cryptography',
    network_security: 'Network Security',
    other: 'Other',
  };
  return displayNames[type as keyof typeof displayNames] || type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
}

// Truncate text
export function truncate(text: string, length: number): string {
  if (text.length <= length) return text;
  return text.slice(0, length) + '...';
}

// Debounce function
export function debounce<T extends (...args: any[]) => any>(
  func: T,
  wait: number
): (...args: Parameters<T>) => void {
  let timeout: ReturnType<typeof setTimeout>;
  return (...args: Parameters<T>) => {
    clearTimeout(timeout);
    timeout = setTimeout(() => func(...args), wait);
  };
}

// Copy to clipboard
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (err) {
    // Fallback for older browsers
    const textArea = document.createElement('textarea');
    textArea.value = text;
    document.body.appendChild(textArea);
    textArea.select();
    try {
      document.execCommand('copy');
      return true;
    } catch (err) {
      return false;
    } finally {
      document.body.removeChild(textArea);
    }
  }
}

// Generate random ID
export function generateId(): string {
  return Math.random().toString(36).substr(2, 9);
}

// Validate file types
export function isValidFileType(file: File): boolean {
  const validTypes = [
    'text/plain',
    'text/x-python',
    'application/javascript',
    'text/typescript',
    'application/json',
    'text/yaml',
    'application/x-yaml',
  ];
  
  const validExtensions = [
    '.py', '.js', '.ts', '.jsx', '.tsx', '.json', '.yaml', '.yml',
    '.php', '.rb', '.java', '.go', '.rs', '.cpp', '.c', '.cs',
    '.scala', '.kt', '.swift', '.sql', '.sh', '.bash', '.ps1'
  ];
  
  return validTypes.includes(file.type) || 
         validExtensions.some(ext => file.name.toLowerCase().endsWith(ext));
}

// Format confidence score
export function formatConfidence(confidence: number): string {
  if (confidence >= 90) return 'Very High';
  if (confidence >= 75) return 'High';
  if (confidence >= 60) return 'Medium';
  return 'Low';
}

// Get confidence color
export function getConfidenceColor(confidence: number): string {
  if (confidence >= 90) return 'text-green-600';
  if (confidence >= 75) return 'text-blue-600';
  if (confidence >= 60) return 'text-yellow-600';
  return 'text-red-600';
}
