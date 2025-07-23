import axios from 'axios';
import type { 
  ScanResult, 
  ScanConfig, 
  SecurityMetrics, 
  SecurityRule, 
  ApiResponse,
  FileUploadResult 
} from '@/types';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 300000, // 5 minutes for long scans
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor
api.interceptors.request.use(
  (config) => {
    // Add auth token if available
    const token = localStorage.getItem('auth_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    console.log('API Request:', config.method?.toUpperCase(), config.url); // Debug log
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor
api.interceptors.response.use(
  (response) => {
    console.log('API Response:', response.status, response.config.url); // Debug log
    return response;
  },
  (error) => {
    console.error('API Error:', error.response?.status, error.response?.statusText, error.config?.url); // Debug log
    // Don't redirect on 401 - just log and let components handle it
    if (error.response?.status === 401) {
      console.warn('Authentication error - API key may be missing or invalid');
      localStorage.removeItem('auth_token');
    }
    return Promise.reject(error);
  }
);

export const scannerApi = {
  // Scan operations
  async startScan(config: ScanConfig): Promise<ApiResponse<{ scanId: string; status: string; message: string }>> {
    try {
      // First upload files if they are File objects
      let fileIds: string[] = [];
      
      if (config.files && config.files.length > 0) {
        // Check if files need to be uploaded (are File objects)
        const needsUpload = config.files.some((file: any) => file instanceof File);
        
        if (needsUpload) {
          const uploadResponse = await this.uploadFiles(config.files as any);
          if (!uploadResponse.success || !uploadResponse.data) {
            return {
              success: false,
              error: uploadResponse.error || 'Failed to upload files',
            };
          }
          fileIds = uploadResponse.data.files.map((f: any) => f.id);
        } else {
          // Files are already uploaded, use as-is
          fileIds = config.files as string[];
        }
      }

      const scanConfig = {
        files: fileIds,
        enableAI: !config.static_only,
        enableStatic: !config.ai_only,
        static_only: config.static_only || false,
        ai_only: config.ai_only || false,
        ai_provider: config.ai_provider || 'openai',
        api_key: config.api_key,
        outputFormat: config.output_format || 'json',
        excludePatterns: config.ignore_patterns || [],
        verbose: config.verbose || false,
      };

      const response = await api.post('/api/scanner/scan', scanConfig);
      return {
        success: true,
        data: response.data,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.detail || error.message,
      };
    }
  },

  async getScanStatus(scanId: string): Promise<ApiResponse<{ status: string; progress: number; duration: number }>> {
    try {
      const response = await api.get(`/api/scanner/scan/${scanId}`);
      return {
        success: true,
        data: response.data,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.detail || error.message,
      };
    }
  },

  async getScanResults(scanId: string): Promise<ApiResponse<ScanResult>> {
    try {
      const response = await api.get(`/api/scanner/results/${scanId}`);
      return {
        success: true,
        data: response.data.results,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.detail || error.message,
      };
    }
  },

  async cancelScan(scanId: string): Promise<ApiResponse<void>> {
    try {
      const response = await api.post(`/api/scanner/scan/${scanId}/cancel`);
      
      // Handle both success and "already completed" responses from backend
      if (response.data.success !== false) {
        return { success: true };
      } else {
        return {
          success: false,
          error: response.data.message || 'Failed to cancel scan',
        };
      }
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.detail || error.response?.data?.message || error.message,
      };
    }
  },

  // File operations
  async uploadFiles(files: FileList | File[]): Promise<ApiResponse<FileUploadResult>> {
    try {
      const formData = new FormData();
      const fileArray = Array.isArray(files) ? files : Array.from(files);
      
      fileArray.forEach((file) => {
        formData.append('files', file);
      });

      const response = await api.post('/api/scanner/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      // Transform response to match expected format
      return {
        success: true,
        data: {
          success: response.data.success,
          files: response.data.files.map((f: any) => ({
            id: f.id,
            name: f.originalName,
            path: f.path,
            size: f.size,
          })),
        },
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.detail || error.message,
      };
    }
  },

  async uploadFromGitHub(repoUrl: string): Promise<ApiResponse<FileUploadResult>> {
    try {
      // Note: GitHub upload endpoint not implemented in FastAPI yet
      const response = await api.post('/api/scanner/upload/github', { repo_url: repoUrl });
      return {
        success: true,
        data: response.data,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.detail || error.message,
      };
    }
  },

  // Security rules
  async getSecurityRules(): Promise<ApiResponse<SecurityRule[]>> {
    try {
      const response = await api.get('/api/rules');
      return {
        success: true,
        data: response.data,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.message || error.message,
      };
    }
  },

  async updateSecurityRule(ruleName: string, enabled: boolean): Promise<ApiResponse<void>> {
    try {
      await api.patch(`/api/rules/${ruleName}`, { enabled });
      return { success: true };
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.message || error.message,
      };
    }
  },

  // Recent scans
  async getRecentScans(limit: number = 10): Promise<ApiResponse<{ scans: any[] }>> {
    try {
      const response = await api.get(`/api/scanner/recent?limit=${limit}`);
      return {
        success: true,
        data: response.data,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.detail || error.message,
      };
    }
  },

  // Active scans
  async getActiveScans(): Promise<ApiResponse<{ scans: any[] }>> {
    try {
      const response = await api.get('/api/scanner/active');
      return {
        success: true,
        data: response.data,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.detail || error.message,
      };
    }
  },

  // Dashboard metrics
  async getDashboardMetrics(): Promise<ApiResponse<SecurityMetrics>> {
    try {
      // Get real dashboard metrics from the backend
      const response = await api.get('/api/dashboard/metrics');
      const dashboardData = response.data;
      
      // Transform backend data to match frontend SecurityMetrics interface
      const metrics: SecurityMetrics = {
        total_scans: dashboardData.overview?.total_scans || 0,
        total_vulnerabilities: dashboardData.overview?.total_vulnerabilities || 0,
        avg_scan_time: dashboardData.overview?.avg_scan_duration || 0,
        severity_distribution: {
          CRITICAL: dashboardData.vulnerability_severity?.CRITICAL || 0,
          HIGH: dashboardData.vulnerability_severity?.HIGH || 0,
          MEDIUM: dashboardData.vulnerability_severity?.MEDIUM || 0,
          LOW: dashboardData.vulnerability_severity?.LOW || 0,
        },
        trend_data: dashboardData.time_series?.map((item: any) => ({
          date: item.date,
          scans: item.scans,
          vulnerabilities: item.vulnerabilities,
        })) || [],
        top_vulnerability_types: Object.entries(dashboardData.threat_types || {}).map(([type, count]) => ({
          type: type,
          count: count as number,
        })).sort((a, b) => b.count - a.count).slice(0, 5),
        scan_history: dashboardData.recent_activity?.map((activity: any) => ({
          id: activity.id,
          path: activity.target_path || 'uploaded_files',
          timestamp: activity.timestamp,
          duration: 0, // Duration not provided in recent_activity
          vulnerabilities: activity.vulnerabilities || 0,
          status: activity.status,
        })) || [],
      };

      return {
        success: true,
        data: metrics,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.detail || error.message,
      };
    }
  },

  // Get scan history with full details
  async getScanHistory(limit: number = 50): Promise<ApiResponse<{ scans: any[] }>> {
    try {
      const response = await api.get(`/api/dashboard/scan-history?limit=${limit}`);
      return {
        success: true,
        data: response.data,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.detail || error.message,
      };
    }
  },

  // Health check
  async healthCheck(): Promise<ApiResponse<{ status: string; version: string }>> {
    try {
      const response = await api.get('/api/health');
      return {
        success: true,
        data: response.data,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.detail || error.message,
      };
    }
  },

  // Export results
  async exportResults(scanId: string, format: 'json' | 'pdf' | 'csv'): Promise<Blob> {
    const response = await api.get(`/api/scan/${scanId}/export`, {
      params: { format },
      responseType: 'blob',
    });
    return response.data;
  },
};

export default api;
