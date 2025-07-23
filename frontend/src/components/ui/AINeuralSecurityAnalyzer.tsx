import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Brain, 
  Zap, 
  Eye, 
  Target,
  Activity,
  Lightbulb,
  Database
} from 'lucide-react';

import { scannerApi } from '@/services/api';

interface NeuralActivity {
  id: string;
  type: 'pattern_recognition' | 'memory_recall' | 'decision_making' | 'learning';
  intensity: number;
  vulnerability: string;
  confidence: number;
  timestamp: number;
}

interface BrainState {
  overallActivity: number;
  activeRegion: string | null;
  scanningMode: 'static' | 'ai' | 'hybrid';
  threatLevel: 'low' | 'medium' | 'high' | 'critical';
}

export default function AINeuralSecurityAnalyzer({ className = '' }: { className?: string }) {
  const [brainState, setBrainState] = useState<BrainState>({
    overallActivity: 45,
    activeRegion: null,
    scanningMode: 'hybrid',
    threatLevel: 'medium'
  });
  
  const [neuralActivity, setNeuralActivity] = useState<NeuralActivity[]>([]);
  const [aiModel, setAiModel] = useState<'openai' | 'claude' | 'gemini'>('openai');
  const [realVulnerabilities, setRealVulnerabilities] = useState<string[]>([]);
  const [scanData, setScanData] = useState<any>(null);
  const [isActivelyScanning, setIsActivelyScanning] = useState(false);

  // Brain regions - clean and organized
  const brainRegions = [
    { id: 'pattern', name: 'Pattern Recognition', icon: Eye, color: 'cyan', position: 0 },
    { id: 'memory', name: 'Memory Bank', icon: Database, color: 'purple', position: 1 },
    { id: 'analysis', name: 'Threat Analysis', icon: Target, color: 'orange', position: 2 },
    { id: 'learning', name: 'AI Learning', icon: Lightbulb, color: 'emerald', position: 3 }
  ];

  // Fetch real vulnerability data and update brain state
  useEffect(() => {
    const fetchRealData = async () => {
      try {
        console.log('AI Neural Analyzer: Fetching real vulnerability data...');
        
        // Check for active scans first
        try {
          const activeScansResponse = await scannerApi.getActiveScans();
          const hasActiveScans = activeScansResponse.success && 
            activeScansResponse.data && 
            Object.keys(activeScansResponse.data).length > 0;
          setIsActivelyScanning(hasActiveScans);
          
          if (hasActiveScans) {
            console.log('AI Neural Analyzer: Active scans detected!');
          }
        } catch (error) {
          setIsActivelyScanning(false);
        }
        
        // Get dashboard metrics for complete real data
        const metricsResponse = await scannerApi.getDashboardMetrics();
        if (metricsResponse.success && metricsResponse.data) {
          const data = metricsResponse.data;
          const totalVulns = data.total_vulnerabilities || 0;
          const totalScans = data.total_scans || 0;
          const criticalVulns = data.severity_distribution?.CRITICAL || 0;
          const highVulns = data.severity_distribution?.HIGH || 0;
          const mediumVulns = data.severity_distribution?.MEDIUM || 0;
          
          console.log('AI Neural Analyzer: Real data loaded:', { totalVulns, totalScans, criticalVulns, highVulns });
          
          // Extract real vulnerability types from threat_types
          const realVulnTypes: string[] = [];
          if (data.top_vulnerability_types && data.top_vulnerability_types.length > 0) {
            data.top_vulnerability_types.forEach((item: any) => {
              const displayName = item.type.replace(/_/g, ' ').replace(/\b\w/g, (l: string) => l.toUpperCase());
              realVulnTypes.push(displayName);
            });
          }
          
          if (realVulnTypes.length > 0) {
            setRealVulnerabilities(realVulnTypes);
          }
          
          // Update threat level based on real severity distribution
          const threatLevel = criticalVulns > 10 ? 'critical' 
                           : criticalVulns > 0 || highVulns > 10 ? 'high'
                           : highVulns > 0 || mediumVulns > 5 ? 'medium' 
                           : totalVulns > 0 ? 'low'
                           : 'low';
          
          // Calculate realistic activity level based on actual vulnerabilities and scanning status
          let baseActivity = Math.min(98, Math.max(15, 
            (criticalVulns * 15) + (highVulns * 8) + (mediumVulns * 3) + 20
          ));
          
          // Boost activity if actively scanning
          if (isActivelyScanning) {
            baseActivity = Math.min(98, baseActivity + 30);
          }
          
          const activityLevel = baseActivity;
          
          setBrainState(prev => ({
            ...prev,
            threatLevel,
            overallActivity: activityLevel,
            scanningMode: totalScans > 0 ? 'hybrid' : 'static'
          }));
          
          // Store scan data for neural activity
          setScanData({
            totalVulns,
            totalScans,
            vulnerabilityTypes: realVulnTypes,
            severityDistribution: data.severity_distribution,
            threatLevel
          });
        }
        
      } catch (error) {
        console.error('Failed to fetch real vulnerability data:', error);
        // Fall back to comprehensive AI attack types
        setRealVulnerabilities([
          'Prompt Injection', 'Jailbreak Attack', 'Model Inversion', 'Data Poisoning',
          'Adversarial Examples', 'Context Poisoning', 'Backdoor Attack', 'Bias Injection',
          'Model Extraction', 'Memory Exploitation', 'Chain-of-Thought Manipulation',
          'System Prompt Leakage', 'Template Injection', 'Unicode Obfuscation',
          'Federated Learning Attack', 'Byzantine Attack', 'Gradient Attack'
        ]);
      }
    };
    
    fetchRealData();
    // Refresh every 15 seconds for more real-time feel
    const interval = setInterval(fetchRealData, 15000);
    return () => clearInterval(interval);
  }, []);

  const vulnerabilities = realVulnerabilities.length > 0 ? realVulnerabilities : [
    'Command Injection', 'SQL Injection', 'Tool Poisoning', 'Prompt Injection',
    'Hardcoded Secrets', 'Path Traversal', 'Weak Crypto', 'Input Validation'
  ];

  // Generate neural activity based on real vulnerability data
  useEffect(() => {
    if (!scanData || vulnerabilities.length === 0) return;
    
    const interval = setInterval(() => {
      // Create realistic activity based on actual vulnerability types and counts
      const activities: Array<NeuralActivity['type']> = ['pattern_recognition', 'memory_recall', 'decision_making', 'learning'];
      
      // Weight activity types based on threat level
      let activityType: NeuralActivity['type'];
      if (brainState.threatLevel === 'critical') {
        activityType = Math.random() > 0.6 ? 'decision_making' : 'pattern_recognition';
      } else if (brainState.threatLevel === 'high') {
        activityType = Math.random() > 0.5 ? 'pattern_recognition' : 'memory_recall';
      } else {
        activityType = activities[Math.floor(Math.random() * activities.length)];
      }
      
      // Select vulnerability from real data with weighted probability
      const vulnerabilityIndex = scanData.totalVulns > 50 ? 
        Math.floor(Math.random() * Math.min(vulnerabilities.length, 3)) : // Focus on top vulnerabilities if many
        Math.floor(Math.random() * vulnerabilities.length);
      
      // Calculate confidence based on vulnerability severity and type
      let confidence = 85; // Base confidence
      if (scanData.severityDistribution) {
        const criticalCount = scanData.severityDistribution.CRITICAL || 0;
        const highCount = scanData.severityDistribution.HIGH || 0;
        
        if (criticalCount > 0) confidence = Math.random() * 10 + 90; // 90-100% for critical
        else if (highCount > 0) confidence = Math.random() * 15 + 80; // 80-95% for high
        else confidence = Math.random() * 20 + 70; // 70-90% for medium/low
      }
      
      const newActivity: NeuralActivity = {
        id: Math.random().toString(36).substring(2, 11),
        type: activityType,
        intensity: Math.min(100, brainState.overallActivity + (Math.random() * 20 - 10)),
        vulnerability: vulnerabilities[vulnerabilityIndex],
        confidence: Math.round(confidence),
        timestamp: Date.now()
      };

      setNeuralActivity(prev => [...prev.slice(-5), newActivity]);

      // Update active region based on activity type
      const regionMap = {
        'pattern_recognition': 'pattern',
        'memory_recall': 'memory', 
        'decision_making': 'analysis',
        'learning': 'learning'
      };
      
      setBrainState(prev => ({
        ...prev,
        activeRegion: regionMap[activityType],
        // Keep threat level and activity level stable (set by real data)
      }));
    }, isActivelyScanning ? 1500 : 3000); // Faster activity during active scanning

    return () => clearInterval(interval);
  }, [scanData, vulnerabilities, brainState.threatLevel, brainState.overallActivity, isActivelyScanning]);

  const getThreatColor = (level: string) => {
    switch (level) {
      case 'critical': return 'red';
      case 'high': return 'orange';
      case 'medium': return 'yellow';
      case 'low': return 'green';
      default: return 'cyan';
    }
  };

  const getModelInfo = (model: string) => {
    switch (model) {
      case 'openai': return { name: 'GPT-4', color: 'emerald', shape: 'rounded-full' };
      case 'claude': return { name: 'Claude', color: 'purple', shape: 'rounded-3xl' };
      case 'gemini': return { name: 'Gemini', color: 'blue', shape: 'rounded-2xl' };
      default: return { name: 'AI', color: 'cyan', shape: 'rounded-full' };
    }
  };

  const modelInfo = getModelInfo(aiModel);

  return (
    <div className={`min-h-[500px] h-full ${className}`}>
      {/* Clean Header */}
      <div className="mb-6">
        <div className="flex items-center justify-between mb-2">
          <motion.h2
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-xl font-bold text-cyan-400 font-mono"
          >
            AI NEURAL SECURITY ANALYZER
          </motion.h2>
          <div className="flex items-center space-x-4">
            <div className="flex space-x-1 bg-slate-800/40 rounded-lg p-1">
              {['openai', 'claude', 'gemini'].map((model) => (
                <button
                  key={model}
                  onClick={() => setAiModel(model as any)}
                  className={`px-2 py-1 rounded text-xs font-mono transition-all ${
                    aiModel === model 
                      ? `bg-${modelInfo.color}-400/20 text-${modelInfo.color}-400` 
                      : 'text-slate-500 hover:text-slate-300'
                  }`}
                >
                  {getModelInfo(model).name}
                </button>
              ))}
            </div>
            <div className="flex items-center space-x-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-mono text-slate-400">
                {Math.round(brainState.overallActivity)}% Active
              </span>
            </div>
          </div>
        </div>
        <p className="text-sm text-slate-400 font-mono">
          Real-time AI neural network visualization for MCP vulnerability analysis
        </p>
      </div>

      {/* Main Layout - Split into organized sections */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Panel - Brain Regions */}
        <div className="space-y-4">
          <h3 className="text-lg font-bold text-cyan-400 font-mono mb-4">NEURAL REGIONS</h3>
          {brainRegions.map((region) => (
            <motion.div
              key={region.id}
              className={`p-4 bg-slate-800/40 rounded-lg border border-${region.color}-400/30 backdrop-blur-sm`}
              animate={{
                borderColor: brainState.activeRegion === region.id 
                  ? `rgba(34, 211, 238, 0.6)` 
                  : `rgba(34, 211, 238, 0.3)`
              }}
              transition={{ duration: 0.5 }}
            >
              <div className="flex items-center space-x-3">
                <div className={`p-2 rounded-full bg-${region.color}-900/40 border border-${region.color}-400/50`}>
                  <region.icon className={`w-4 h-4 text-${region.color}-400`} />
                </div>
                <div className="flex-1">
                  <h4 className={`text-sm font-bold text-${region.color}-400 font-mono`}>
                    {region.name}
                  </h4>
                  <div className="w-full bg-slate-700/50 rounded-full h-1 mt-2">
                    <motion.div
                      className={`h-1 bg-${region.color}-400 rounded-full`}
                      style={{ 
                        width: brainState.activeRegion === region.id ? '100%' : 
                              isActivelyScanning ? '60%' : '20%'
                      }}
                      transition={{ duration: 0.5 }}
                    />
                  </div>
                </div>
                {brainState.activeRegion === region.id && (
                  <motion.div
                    className={`w-2 h-2 bg-${region.color}-400 rounded-full`}
                    animate={{
                      scale: [1, 1.5, 1],
                      opacity: [1, 0.5, 1]
                    }}
                    transition={{ duration: 1, repeat: Infinity }}
                  />
                )}
              </div>
            </motion.div>
          ))}
        </div>

        {/* Center Panel - Clean Brain Visualization */}
        <div className="bg-slate-900/60 rounded-2xl p-6 border border-cyan-400/30 backdrop-blur-sm" style={{minHeight: '400px'}}>
          <div className="relative w-full h-full flex items-center justify-center">
            
            {/* Clean Central Brain */}
            <motion.div
              className={`relative w-48 h-32 bg-gradient-to-br from-${modelInfo.color}-900/40 to-slate-900/60 ${modelInfo.shape} border-2 border-${modelInfo.color}-400/60 backdrop-blur-sm flex items-center justify-center`}
              animate={{
                boxShadow: [
                  `0 0 15px rgba(34, 211, 238, 0.3)`,
                  `0 0 30px rgba(34, 211, 238, 0.6)`,
                  `0 0 15px rgba(34, 211, 238, 0.3)`
                ]
              }}
              transition={{ duration: 3, repeat: Infinity, ease: "easeInOut" }}
            >
              <motion.div
                animate={{ rotate: 360 }}
                transition={{ duration: 20, repeat: Infinity, ease: "linear" }}
              >
                <Brain className={`w-12 h-12 text-${modelInfo.color}-400`} />
              </motion.div>
              
              {/* Clean Activity Rings */}
              <motion.div
                className={`absolute inset-0 border-2 border-${modelInfo.color}-400/20 ${modelInfo.shape}`}
                animate={{ 
                  scale: [1, 1.2, 1],
                  opacity: [0.5, 0.1, 0.5]
                }}
                transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
              />
              <motion.div
                className={`absolute inset-0 border-2 border-${modelInfo.color}-400/10 ${modelInfo.shape}`}
                animate={{ 
                  scale: [1, 1.4, 1],
                  opacity: [0.3, 0, 0.3]
                }}
                transition={{ duration: 3, repeat: Infinity, ease: "easeInOut", delay: 0.5 }}
              />
            </motion.div>

            {/* Status Indicator */}
            <div className="absolute top-4 right-4 space-y-2">
              {/* Threat Level */}
              <div className={`flex items-center space-x-2 px-3 py-1 rounded-full bg-${getThreatColor(brainState.threatLevel)}-900/40 border border-${getThreatColor(brainState.threatLevel)}-400/50`}>
                <div className={`w-2 h-2 bg-${getThreatColor(brainState.threatLevel)}-400 rounded-full animate-pulse`} />
                <span className={`text-xs font-mono text-${getThreatColor(brainState.threatLevel)}-400`}>
                  {brainState.threatLevel.toUpperCase()}
                </span>
              </div>
              
              {/* Scanning Status */}
              {isActivelyScanning && (
                <motion.div
                  initial={{ opacity: 0, scale: 0.8 }}
                  animate={{ opacity: 1, scale: 1 }}
                  className="flex items-center space-x-2 px-3 py-1 rounded-full bg-cyan-900/40 border border-cyan-400/50"
                >
                  <motion.div 
                    className="w-2 h-2 bg-cyan-400 rounded-full"
                    animate={{ scale: [1, 1.5, 1], opacity: [1, 0.5, 1] }}
                    transition={{ duration: 1, repeat: Infinity }}
                  />
                  <span className="text-xs font-mono text-cyan-400">
                    SCANNING
                  </span>
                </motion.div>
              )}
            </div>

            {/* Activity Meter */}
            <div className="absolute bottom-4 left-1/2 transform -translate-x-1/2">
              <div className="text-center">
                <div className={`text-2xl font-bold text-${modelInfo.color}-400 font-mono`}>
                  {Math.round(brainState.overallActivity)}%
                </div>
                <div className="text-xs text-slate-400 font-mono">Neural Activity</div>
              </div>
            </div>
          </div>
        </div>

        {/* Right Panel - Activity Log */}
        <div className="space-y-4">
          <h3 className="text-lg font-bold text-cyan-400 font-mono mb-4">ACTIVITY LOG</h3>
          <div className="space-y-3 max-h-[400px] overflow-y-auto custom-scrollbar">
            <AnimatePresence>
              {neuralActivity.slice(-6).reverse().map((activity, i) => (
                <motion.div
                  key={activity.id}
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -20 }}
                  transition={{ duration: 0.3, delay: i * 0.1 }}
                  className={`p-3 bg-slate-800/40 rounded-lg border-l-4 ${
                    activity.type === 'pattern_recognition' ? 'border-cyan-400' :
                    activity.type === 'memory_recall' ? 'border-purple-400' :
                    activity.type === 'decision_making' ? 'border-orange-400' : 'border-green-400'
                  } backdrop-blur-sm`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <Zap className="w-4 h-4 text-cyan-400" />
                      <div>
                        <div className="text-xs font-mono text-slate-200">
                          {activity.vulnerability}
                        </div>
                        <div className="text-xs text-slate-500 font-mono">
                          {activity.type.replace('_', ' ')}
                        </div>
                      </div>
                    </div>
                    <div className={`text-xs font-bold font-mono ${
                      activity.confidence > 90 ? 'text-green-400' :
                      activity.confidence > 75 ? 'text-yellow-400' : 'text-red-400'
                    }`}>
                      {Math.round(activity.confidence)}%
                    </div>
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </div>
  );
}