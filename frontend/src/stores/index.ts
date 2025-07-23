import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { 
  ScanResult, 
  ScanConfig, 
  Vulnerability, 
  SecurityMetrics,
  UIState 
} from '@/types';

interface ScanStore {
  // Scan state
  currentScan: ScanResult | null;
  scanHistory: ScanResult[];
  isScanning: boolean;
  scanProgress: number;
  scanError: string | null;
  
  // Actions
  setScanResult: (result: ScanResult) => void;
  setScanning: (isScanning: boolean) => void;
  setScanProgress: (progress: number) => void;
  setScanError: (error: string | null) => void;
  addScanToHistory: (scan: ScanResult) => void;
  clearScanHistory: () => void;
}

interface UIStore {
  // UI state
  theme: 'light' | 'dark';
  sidebarCollapsed: boolean;
  activeView: string;
  loading: boolean;
  
  // Actions
  setTheme: (theme: 'light' | 'dark') => void;
  toggleSidebar: () => void;
  setActiveView: (view: string) => void;
  setLoading: (loading: boolean) => void;
}

interface MetricsStore {
  // Metrics state
  metrics: SecurityMetrics | null;
  lastUpdated: string | null;
  
  // Actions
  setMetrics: (metrics: SecurityMetrics) => void;
  clearMetrics: () => void;
}

// Scan store
export const useScanStore = create<ScanStore>()(
  persist(
    (set, get) => ({
      currentScan: null,
      scanHistory: [],
      isScanning: false,
      scanProgress: 0,
      scanError: null,

      setScanResult: (result) => set({ currentScan: result }),
      
      setScanning: (isScanning) => set({ 
        isScanning, 
        scanProgress: isScanning ? 0 : get().scanProgress,
        scanError: isScanning ? null : get().scanError
      }),
      
      setScanProgress: (progress) => set({ scanProgress: progress }),
      
      setScanError: (error) => set({ 
        scanError: error, 
        isScanning: false 
      }),
      
      addScanToHistory: (scan) => set((state) => ({
        scanHistory: [scan, ...state.scanHistory.slice(0, 9)] // Keep last 10
      })),
      
      clearScanHistory: () => set({ scanHistory: [] }),
    }),
    {
      name: 'scan-store',
      partialize: (state) => ({
        scanHistory: state.scanHistory,
        currentScan: state.currentScan,
      }),
    }
  )
);

// UI store
export const useUIStore = create<UIStore>()(
  persist(
    (set) => ({
      theme: 'dark',
      sidebarCollapsed: false,
      activeView: 'dashboard',
      loading: false,

      setTheme: (theme) => set({ theme }),
      toggleSidebar: () => set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed })),
      setActiveView: (view) => set({ activeView: view }),
      setLoading: (loading) => set({ loading }),
    }),
    {
      name: 'ui-store',
    }
  )
);

// Metrics store
export const useMetricsStore = create<MetricsStore>((set) => ({
  metrics: null,
  lastUpdated: null,

  setMetrics: (metrics) => set({ 
    metrics, 
    lastUpdated: new Date().toISOString() 
  }),
  
  clearMetrics: () => set({ 
    metrics: null, 
    lastUpdated: null 
  }),
}));

// Computed selectors
export const useScanSelectors = () => {
  const { currentScan } = useScanStore();
  
  return {
    vulnerabilitiesBySeverity: currentScan?.vulnerabilities.reduce((acc, vuln) => {
      acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>) || {},
    
    vulnerabilitiesByType: currentScan?.vulnerabilities.reduce((acc, vuln) => {
      acc[vuln.type] = (acc[vuln.type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>) || {},
    
    criticalVulnerabilities: currentScan?.vulnerabilities.filter(
      v => v.severity === 'CRITICAL'
    ) || [],
    
    topVulnerableFiles: currentScan?.vulnerabilities.reduce((acc, vuln) => {
      acc[vuln.file_path] = (acc[vuln.file_path] || 0) + 1;
      return acc;
    }, {} as Record<string, number>) || {},
  };
};
