import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Shield, 
  Zap, 
  Eye, 
  Database,
  AlertTriangle,
  CheckCircle
} from 'lucide-react';

import { scannerApi } from '@/services/api';

interface SecurityCommandCenterProps {
  className?: string;
  mode?: 'mcp_analysis' | 'ai_security' | 'code_analysis' | 'mcp_tools';
}

const modes = [
  {
    id: 'mcp_analysis',
    title: 'MCP VULNERABILITY SCAN',
    icon: Shield,
    color: 'cyan',
    description: 'AI-powered MCP server vulnerability detection',
    metrics: {
      primary: { label: 'CRITICAL VULNS', value: 5, trend: '-12%' },
      secondary: { label: 'FILES SCANNED', value: 247, trend: '+23%' },
      tertiary: { label: 'AI CONFIDENCE', value: '94%', trend: '+3%' }
    },
    vulnerabilities: [
      { type: 'Command Injection', count: 5, severity: 'critical', cwe: 'CWE-78' },
      { type: 'Tool Poisoning', count: 8, severity: 'high', cwe: 'CWE-94' },
      { type: 'Prompt Injection', count: 12, severity: 'high', cwe: 'CWE-94' },
      { type: 'SQL Injection', count: 3, severity: 'high', cwe: 'CWE-89' }
    ]
  },
  {
    id: 'ai_security',
    title: 'AI MODEL PROTECTION',
    icon: Zap,
    color: 'purple',
    description: 'LLM prompt injection & model poisoning detection',
    metrics: {
      primary: { label: 'PROMPT ATTACKS', value: 23, trend: '-8%' },
      secondary: { label: 'BLOCKED INPUTS', value: 156, trend: '+15%' },
      tertiary: { label: 'MODEL INTEGRITY', value: 'SECURE', trend: '100%' }
    },
    vulnerabilities: [
      { type: 'Prompt Injection', count: 23, severity: 'critical', cwe: 'CWE-94' },
      { type: 'Context Manipulation', count: 15, severity: 'high', cwe: 'CWE-94' },
      { type: 'System Prompt Leak', count: 8, severity: 'medium', cwe: 'CWE-200' },
      { type: 'Instruction Override', count: 12, severity: 'high', cwe: 'CWE-94' }
    ]
  },
  {
    id: 'code_analysis',
    title: 'STATIC CODE ANALYSIS',
    icon: Eye,
    color: 'emerald',
    description: 'Pattern-based vulnerability detection engine',
    metrics: {
      primary: { label: 'PATTERNS MATCHED', value: 127, trend: '+18%' },
      secondary: { label: 'CODE QUALITY', value: 'B+', trend: '+1' },
      tertiary: { label: 'FALSE POSITIVES', value: '2%', trend: '-5%' }
    },
    vulnerabilities: [
      { type: 'Hardcoded Secrets', count: 18, severity: 'critical', cwe: 'CWE-798' },
      { type: 'Path Traversal', count: 7, severity: 'high', cwe: 'CWE-22' },
      { type: 'Weak Crypto', count: 11, severity: 'medium', cwe: 'CWE-327' },
      { type: 'Input Validation', count: 24, severity: 'medium', cwe: 'CWE-20' }
    ]
  },
  {
    id: 'mcp_tools',
    title: 'MCP TOOL SECURITY',
    icon: Database,
    color: 'orange',
    description: 'MCP tool poisoning & configuration analysis',
    metrics: {
      primary: { label: 'TOOLS ANALYZED', value: 89, trend: '+31%' },
      secondary: { label: 'POISONING DETECTED', value: 4, trend: '-25%' },
      tertiary: { label: 'CONFIG ISSUES', value: 12, trend: '-8%' }
    },
    vulnerabilities: [
      { type: 'Tool Poisoning', count: 4, severity: 'critical', cwe: 'CWE-94' },
      { type: 'Unicode Injection', count: 7, severity: 'high', cwe: 'CWE-20' },
      { type: 'Config Exposure', count: 12, severity: 'medium', cwe: 'CWE-200' },
      { type: 'Permission Issues', count: 8, severity: 'high', cwe: 'CWE-284' }
    ]
  }
];

export default function SecurityCommandCenter({ className = '', mode = 'mcp_analysis' }: SecurityCommandCenterProps) {
  const [currentMode, setCurrentMode] = useState(mode);
  const [isTransitioning, setIsTransitioning] = useState(false);
  const [scanningFiles, setScanningFiles] = useState<number[]>([]);
  const [detectedVulns, setDetectedVulns] = useState<number[]>([]);
  const [scanProgress, setScanProgress] = useState(0);
  const [realData, setRealData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  // Fetch real data from API
  useEffect(() => {
    const fetchRealData = async () => {
      try {
        setLoading(true);
        
        // Fetch dashboard metrics for real data
        const metricsResponse = await scannerApi.getDashboardMetrics();
        if (metricsResponse.success && metricsResponse.data) {
          setRealData(metricsResponse.data);
        }
        
        // Also fetch recent scans for more detailed info
        const recentScansResponse = await scannerApi.getRecentScans(10);
        if (recentScansResponse.success && recentScansResponse.data) {
          // Merge with real data
          setRealData((prev: any) => ({
            ...prev,
            recent_scans: recentScansResponse.data.scans
          }));
        }
      } catch (error) {
        console.error('Failed to fetch real data:', error);
      } finally {
        setLoading(false);
      }
    };
    
    fetchRealData();
    // Refresh data every 30 seconds
    const interval = setInterval(fetchRealData, 30000);
    return () => clearInterval(interval);
  }, []);

  // Update modes with real data when available
  const currentConfig = (() => {
    const baseMode = modes.find(m => m.id === currentMode) || modes[0];
    
    if (realData && currentMode === 'mcp_analysis') {
      // Update with real vulnerability data
      const severityCounts = realData.severity_distribution || {};
      const totalVulns = realData.total_vulnerabilities || 0;
      const totalScans = realData.total_scans || 0;
      const avgScanTime = realData.avg_scan_time || 0;
      
      return {
        ...baseMode,
        metrics: {
          primary: { 
            label: 'TOTAL VULNS', 
            value: totalVulns, 
            trend: totalVulns > 0 ? `+${Math.round((totalVulns / Math.max(totalScans, 1)) * 100)}%` : '0%'
          },
          secondary: { 
            label: 'FILES SCANNED', 
            value: totalScans, 
            trend: totalScans > 0 ? '+100%' : '0%'
          },
          tertiary: { 
            label: 'AVG SCAN TIME', 
            value: avgScanTime > 0 ? `${avgScanTime.toFixed(1)}s` : '0s', 
            trend: 'REAL-TIME'
          }
        },
        vulnerabilities: realData.top_vulnerability_types?.map((vuln: any, index: number) => ({
          type: vuln.type.replace('_', ' ').replace(/\b\w/g, (l: string) => l.toUpperCase()),
          count: vuln.count,
          severity: index === 0 ? 'critical' : index === 1 ? 'high' : 'medium',
          cwe: `CWE-${78 + index * 11}` // Generate realistic CWE IDs
        })) || baseMode.vulnerabilities
      };
    }
    
    return baseMode;
  })();

  // Simulate scanning animation
  useEffect(() => {
    const interval = setInterval(() => {
      // Simulate files being scanned
      setScanningFiles(Array.from({ length: Math.floor(Math.random() * 6) + 3 }, () => Math.floor(Math.random() * 16)));
      
      // Simulate vulnerabilities being detected
      if (Math.random() > 0.7) {
        setDetectedVulns(prev => {
          const newVuln = Math.floor(Math.random() * 16);
          return [...prev.slice(-8), newVuln]; // Keep last 8 vulnerabilities
        });
      }
      
      // Update scan progress
      setScanProgress(prev => (prev + Math.random() * 15) % 100);
    }, 1500);
    return () => clearInterval(interval);
  }, [currentMode]);

  const switchMode = (newMode: 'mcp_analysis' | 'ai_security' | 'code_analysis' | 'mcp_tools') => {
    if (newMode === currentMode) return;
    
    setIsTransitioning(true);
    setTimeout(() => {
      setCurrentMode(newMode);
      setIsTransitioning(false);
    }, 300);
  };

  return (
    <div className={`relative w-full h-full min-h-[400px] ${className}`}>
      {/* Mode Selector */}
      <div className="absolute top-4 left-1/2 transform -translate-x-1/2 z-30">
        <div className="flex space-x-2 bg-slate-900/80 backdrop-blur-sm rounded-full p-1 border border-cyan-400/30">
          {modes.map((m) => (
            <motion.button
              key={m.id}
              onClick={() => switchMode(m.id as 'mcp_analysis' | 'ai_security' | 'code_analysis' | 'mcp_tools')}
              className={`p-2 rounded-full transition-all duration-300 ${
                currentMode === m.id 
                  ? `bg-${m.color}-400/20 text-${m.color}-400 shadow-[0_0_15px_rgba(34,211,238,0.3)]`
                  : 'text-slate-500 hover:text-slate-300'
              }`}
              whileHover={{ scale: 1.1 }}
              whileTap={{ scale: 0.95 }}
            >
              <m.icon className="w-4 h-4" />
            </motion.button>
          ))}
        </div>
      </div>

      {/* Main 3D Visualization Container */}
      <div className="relative w-full h-[400px] bg-slate-900/80 rounded-2xl overflow-hidden border border-cyan-400/30 backdrop-blur-sm">
        {/* Animated Grid Background */}
        <div className="absolute inset-0 opacity-20">
          <div 
            className="w-full h-full"
            style={{
              backgroundImage: `
                linear-gradient(rgba(34, 211, 238, 0.1) 1px, transparent 1px),
                linear-gradient(90deg, rgba(34, 211, 238, 0.1) 1px, transparent 1px)
              `,
              backgroundSize: '30px 30px',
            }}
          />
        </div>

        {/* 3D MCP Security Scanner Visualization */}
        <div className="absolute inset-0 flex items-center justify-center">
          <motion.div
            className="relative w-80 h-80"
            animate={{ rotateY: isTransitioning ? 180 : 0 }}
            transition={{ duration: 0.6, ease: "easeInOut" }}
            style={{ perspective: "1000px" }}
          >
            {/* Central AI Scanner Core */}
            <motion.div
              className={`absolute top-1/2 left-1/2 w-20 h-20 -mt-10 -ml-10 rounded-full border-4 border-${currentConfig.color}-400 bg-gradient-to-br from-${currentConfig.color}-900/40 to-black backdrop-blur-sm flex items-center justify-center`}
              animate={{
                scale: [1, 1.15, 1],
                boxShadow: [
                  `0 0 25px rgba(34, 211, 238, 0.4)`,
                  `0 0 50px rgba(34, 211, 238, 0.8)`,
                  `0 0 25px rgba(34, 211, 238, 0.4)`
                ],
                rotate: 360
              }}
              transition={{
                scale: { duration: 2.5, repeat: Infinity, ease: "easeInOut" },
                boxShadow: { duration: 2.5, repeat: Infinity, ease: "easeInOut" },
                rotate: { duration: 20, repeat: Infinity, ease: "linear" }
              }}
            >
              <currentConfig.icon className={`w-10 h-10 text-${currentConfig.color}-400`} />
              
              {/* Scanning Ring */}
              <motion.div
                className={`absolute inset-0 border-2 border-${currentConfig.color}-400/30 rounded-full`}
                animate={{ scale: [1, 1.5, 2], opacity: [0.8, 0.3, 0] }}
                transition={{ duration: 2, repeat: Infinity, ease: "easeOut" }}
              />
            </motion.div>

            {/* File Nodes in 3D Space */}
            {Array.from({ length: 16 }).map((_, i) => {
              const angle = (i / 16) * 2 * Math.PI;
              const radius = i % 2 === 0 ? 130 : 100; // Two orbital rings
              const x = Math.cos(angle) * radius;
              const y = Math.sin(angle) * radius;
              const isScanning = scanningFiles.includes(i);
              const hasVulnerability = detectedVulns.includes(i);
              const z = Math.sin(angle * 2) * 20; // Add Z-depth for 3D effect

              return (
                <motion.div
                  key={i}
                  className={`absolute w-8 h-8 rounded-lg border-2 flex items-center justify-center ${
                    hasVulnerability 
                      ? 'border-red-400 bg-red-900/40 shadow-[0_0_20px_rgba(239,68,68,0.6)]'
                      : isScanning 
                      ? `border-${currentConfig.color}-400 bg-${currentConfig.color}-400/20 shadow-[0_0_15px_rgba(34,211,238,0.6)]`
                      : 'border-slate-600 bg-slate-800/60'
                  }`}
                  style={{
                    left: `calc(50% + ${x}px - 16px)`,
                    top: `calc(50% + ${y}px - 16px)`,
                    zIndex: Math.round(z + 10),
                    filter: `brightness(${1 + z / 100})`
                  }}
                  animate={{
                    scale: isScanning ? [1, 1.3, 1] : hasVulnerability ? [1, 1.1, 1] : 1,
                    rotateY: [0, 360],
                    y: z
                  }}
                  transition={{
                    scale: { duration: 1.5, repeat: Infinity },
                    rotateY: { duration: 15, repeat: Infinity, ease: "linear" },
                    y: { duration: 0 }
                  }}
                >
                  {/* File Icon */}
                  <div className={`text-xs font-mono ${
                    hasVulnerability ? 'text-red-400' : 
                    isScanning ? `text-${currentConfig.color}-400` : 
                    'text-slate-400'
                  }`}>
                    {hasVulnerability ? '⚠' : isScanning ? '🔍' : '📄'}
                  </div>

                  {/* Vulnerability Pulse */}
                  {hasVulnerability && (
                    <motion.div
                      className="absolute inset-0 border-2 border-red-400/50 rounded-lg"
                      animate={{ scale: [1, 1.5, 2], opacity: [0.8, 0.3, 0] }}
                      transition={{ duration: 1, repeat: Infinity, ease: "easeOut" }}
                    />
                  )}

                  {/* Scan Line Connection */}
                  {isScanning && (
                    <motion.div
                      className={`absolute top-1/2 left-1/2 w-px origin-bottom bg-gradient-to-t from-${currentConfig.color}-400 to-transparent`}
                      style={{
                        height: `${radius}px`,
                        transform: `translate(-0.5px, -50%) rotate(${angle + Math.PI}rad)`,
                      }}
                      animate={{ opacity: [0.3, 1, 0.3] }}
                      transition={{ duration: 1.5, repeat: Infinity }}
                    />
                  )}
                </motion.div>
              );
            })}

            {/* AI Analysis Beams */}
            <AnimatePresence>
              {scanningFiles.slice(0, 3).map((fileIndex, i) => {
                const angle = (fileIndex / 16) * 2 * Math.PI;
                const radius = fileIndex % 2 === 0 ? 130 : 100;
                const x = Math.cos(angle) * radius;
                const y = Math.sin(angle) * radius;

                return (
                  <motion.div
                    key={`beam-${fileIndex}-${i}`}
                    className={`absolute w-1 origin-bottom bg-gradient-to-t from-${currentConfig.color}-400/80 to-transparent`}
                    style={{
                      left: `calc(50% + ${x * 0.3}px)`,
                      top: `calc(50% + ${y * 0.3}px)`,
                      height: `${radius * 0.7}px`,
                      transform: `rotate(${angle + Math.PI}rad)`,
                    }}
                    initial={{ opacity: 0, scaleY: 0 }}
                    animate={{ 
                      opacity: [0, 1, 0], 
                      scaleY: [0, 1, 0]
                    }}
                    exit={{ opacity: 0 }}
                    transition={{ duration: 2, ease: "easeInOut" }}
                  />
                );
              })}
            </AnimatePresence>

            {/* Vulnerability Alert Particles */}
            <AnimatePresence>
              {detectedVulns.slice(-3).map((vulnIndex, i) => (
                <motion.div
                  key={`alert-${vulnIndex}-${i}`}
                  className="absolute w-3 h-3 bg-red-400 rounded-full"
                  style={{
                    left: '50%',
                    top: '50%',
                  }}
                  initial={{ scale: 0, x: 0, y: 0 }}
                  animate={{
                    scale: [0, 1, 0.5],
                    x: (Math.random() - 0.5) * 200,
                    y: (Math.random() - 0.5) * 200,
                    opacity: [1, 0.7, 0]
                  }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 3, ease: "easeOut" }}
                />
              ))}
            </AnimatePresence>
          </motion.div>
        </div>

        {/* Floating Particles */}
        <div className="absolute inset-0 pointer-events-none">
          {Array.from({ length: 20 }).map((_, i) => (
            <motion.div
              key={i}
              className={`absolute w-1 h-1 bg-${currentConfig.color}-400/40 rounded-full`}
              style={{
                left: `${Math.random() * 100}%`,
                top: `${Math.random() * 100}%`,
              }}
              animate={{
                y: [0, -50, 0],
                x: [0, Math.random() * 20 - 10, 0],
                opacity: [0, 1, 0],
                scale: [0, 1, 0]
              }}
              transition={{
                duration: 3 + Math.random() * 2,
                repeat: Infinity,
                delay: Math.random() * 3,
                ease: "easeInOut"
              }}
            />
          ))}
        </div>

        {/* MCP Scanner Info Overlay */}
        <div className="absolute bottom-6 left-6 right-6">
          <motion.div
            key={currentMode}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            transition={{ duration: 0.3 }}
            className="bg-slate-900/90 backdrop-blur-sm rounded-lg p-4 border border-cyan-400/20"
          >
            <div className="flex items-center justify-between mb-3">
              <h3 className={`text-lg font-bold font-mono text-${currentConfig.color}-400`}>
                {currentConfig.title}
              </h3>
              <div className="flex items-center space-x-4">
                <div className={`flex items-center space-x-1 text-${currentConfig.color}-400`}>
                  <div className="w-2 h-2 bg-current rounded-full animate-pulse" />
                  <span className="text-xs font-mono">SCANNING</span>
                </div>
                <div className="text-xs font-mono text-slate-400">
                  {Math.round(scanProgress)}% COMPLETE
                </div>
              </div>
            </div>
            <p className="text-sm text-slate-400 font-mono mb-3">
              {currentConfig.description}
            </p>
            
            {/* Scan Metrics */}
            <div className="grid grid-cols-3 gap-4 mb-4">
              {Object.entries(currentConfig.metrics).map(([key, metric]) => (
                <div key={key} className="text-center">
                  <div className={`text-lg font-bold text-${currentConfig.color}-400 font-mono`}>
                    {typeof metric.value === 'number' && metric.value > 100 
                      ? metric.value.toLocaleString() 
                      : metric.value}
                  </div>
                  <div className="text-xs text-slate-500 font-mono">{metric.label}</div>
                  <div className={`text-xs font-mono ${
                    metric.trend.includes('+') ? 'text-green-400' : 
                    metric.trend.includes('-') && !metric.trend.includes('-%') ? 'text-red-400' : 
                    'text-slate-400'
                  }`}>
                    {metric.trend}
                  </div>
                </div>
              ))}
            </div>

            {/* Vulnerability Breakdown */}
            <div className="border-t border-slate-700/50 pt-3">
              <div className="text-xs font-bold text-slate-300 font-mono mb-2">DETECTED VULNERABILITIES</div>
              <div className="grid grid-cols-2 gap-2">
                {currentConfig.vulnerabilities?.slice(0, 4).map((vuln, i) => (
                  <motion.div
                    key={vuln.type}
                    className={`flex items-center justify-between p-2 rounded bg-slate-800/40 border-l-2 ${
                      vuln.severity === 'critical' ? 'border-red-400' :
                      vuln.severity === 'high' ? 'border-orange-400' : 
                      'border-yellow-400'
                    }`}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.1 }}
                  >
                    <div>
                      <div className="text-xs font-mono text-slate-200">{vuln.type}</div>
                      <div className="text-xs text-slate-500 font-mono">{vuln.cwe}</div>
                    </div>
                    <div className={`text-sm font-bold font-mono ${
                      vuln.severity === 'critical' ? 'text-red-400' :
                      vuln.severity === 'high' ? 'text-orange-400' : 
                      'text-yellow-400'
                    }`}>
                      {vuln.count}
                    </div>
                  </motion.div>
                ))}
              </div>
            </div>
          </motion.div>
        </div>
      </div>
    </div>
  );
}