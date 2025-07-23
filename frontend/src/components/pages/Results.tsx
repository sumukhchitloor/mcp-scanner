import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  AlertTriangle, 
  CheckCircle, 
  XCircle,
  Info,
  Filter,
  Download,
  Search,
  Eye,
  ExternalLink,
  Clock,
  Code,
  MapPin,
  ArrowLeft,
  FileText,
  Zap,
  Shield
} from 'lucide-react';

import { scannerApi } from '@/services/api';
import HolographicCard from '@/components/ui/HolographicCard';
import HackerText from '@/components/ui/HackerText';

interface Vulnerability {
  id: string;
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  file_path: string;
  line_number?: number;
  column_number?: number;
  code_snippet?: string;
  recommendation: string;
  confidence?: number;
  cwe?: string;
  rule_id?: string;
  detector?: string;
}

interface ScanResult {
  id: string;
  target_path: string;
  start_time: string;
  end_time: string;
  scan_duration: number;
  files_scanned: number;
  files_skipped: number;
  total_vulnerabilities: number;
  vulnerabilities: Vulnerability[];
  severity_counts: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
  };
  scanner_version: string;
}

export default function Results() {
  const { scanId } = useParams<{ scanId?: string }>();
  const navigate = useNavigate();
  
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);

  // Load scan results
  useEffect(() => {
    const fetchScanResults = async () => {
      if (!scanId) {
        setError('No scan ID provided');
        setLoading(false);
        return;
      }

      try {
        setLoading(true);
        setError(null);
        
        const response = await scannerApi.getScanResults(scanId);
        if (response.success && response.data) {
          setScanResult(response.data);
        } else {
          setError(response.error || 'Failed to load scan results');
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Unknown error occurred');
      } finally {
        setLoading(false);
      }
    };

    fetchScanResults();
  }, [scanId]);

  // Filter vulnerabilities
  const filteredVulnerabilities = scanResult?.vulnerabilities.filter((vuln) => {
    const matchesSeverity = selectedSeverity === 'all' || vuln.severity === selectedSeverity;
    const matchesSearch = !searchTerm || 
      vuln.type.toLowerCase().includes(searchTerm.toLowerCase()) ||
      vuln.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      vuln.file_path.toLowerCase().includes(searchTerm.toLowerCase());
    
    return matchesSeverity && matchesSearch;
  }) || [];

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'red';
      case 'high': return 'orange';
      case 'medium': return 'yellow';
      case 'low': return 'blue';
      default: return 'gray';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return XCircle;
      case 'high': return AlertTriangle;
      case 'medium': return Info;
      case 'low': return CheckCircle;
      default: return Info;
    }
  };

  const getDetectorInfo = (detector?: string) => {
    if (detector === 'ai_analyzer') {
      return {
        label: 'AI',
        color: 'purple',
        icon: Zap
      };
    } else if (detector === 'static_analyzer') {
      return {
        label: 'Static',
        color: 'cyan',
        icon: Code
      };
    } else {
      return {
        label: 'Unknown',
        color: 'gray',
        icon: Info
      };
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <HolographicCard variant="primary">
          <div className="flex items-center space-x-4 p-8">
            <motion.div
              className="w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full"
              animate={{ rotate: 360 }}
              transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
            />
            <div>
              <HackerText 
                text="LOADING SCAN RESULTS"
                className="text-lg font-bold text-cyan-400 mb-2"
                delay={0}
                speed={30}
              />
              <p className="text-slate-400 font-mono text-sm">Fetching vulnerability data...</p>
            </div>
          </div>
        </HolographicCard>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <HolographicCard variant="primary">
          <div className="text-center p-8">
            <XCircle className="w-16 h-16 text-red-400 mx-auto mb-4" />
            <HackerText 
              text="ERROR LOADING RESULTS"
              className="text-xl font-bold text-red-400 mb-4"
              delay={0}
              speed={20}
            />
            <p className="text-slate-300 font-mono mb-6">{error}</p>
            <button
              onClick={() => navigate('/scanner')}
              className="px-6 py-3 bg-cyan-900/30 border border-cyan-400/30 text-cyan-400 rounded-lg hover:bg-cyan-900/50 transition-all duration-200 font-mono font-bold"
            >
              Return to Scanner
            </button>
          </div>
        </HolographicCard>
      </div>
    );
  }

  if (!scanResult) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <HolographicCard variant="primary">
          <div className="text-center p-8">
            <FileText className="w-16 h-16 text-slate-400 mx-auto mb-4" />
            <HackerText 
              text="NO SCAN RESULTS FOUND"
              className="text-xl font-bold text-slate-400 mb-4"
              delay={0}
              speed={20}
            />
            <p className="text-slate-300 font-mono mb-6">The requested scan results could not be found.</p>
            <button
              onClick={() => navigate('/scanner')}
              className="px-6 py-3 bg-cyan-900/30 border border-cyan-400/30 text-cyan-400 rounded-lg hover:bg-cyan-900/50 transition-all duration-200 font-mono font-bold"
            >
              Start New Scan
            </button>
          </div>
        </HolographicCard>
      </div>
    );
  }

  return (
    <div className="space-y-6 min-h-screen relative">
      {/* Cyberpunk Background Effects */}
      <div className="fixed inset-0 pointer-events-none opacity-20">
        <div className="absolute inset-0 bg-gradient-to-br from-cyan-900/20 via-transparent to-purple-900/20" />
      </div>

      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
        className="relative z-10"
      >
        <div className="flex items-center space-x-4 mb-4">
          <motion.button
            onClick={() => navigate('/scanner')}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            className="p-2 bg-slate-800/50 border border-cyan-400/30 rounded-lg text-cyan-400 hover:bg-slate-800/70 transition-all duration-200"
          >
            <ArrowLeft className="w-5 h-5" />
          </motion.button>
          <div>
            <HackerText 
              text="VULNERABILITY ANALYSIS REPORT"
              className="text-4xl font-bold text-transparent bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text"
              delay={100}
              speed={50}
            />
            <p className="text-slate-300 font-mono text-lg mt-2">
              <span className="text-cyan-400">[SCAN]</span> {scanResult.id} • {new Date(scanResult.start_time).toLocaleString()}
            </p>
          </div>
        </div>
      </motion.div>

      {/* Scan Overview */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.1 }}
        className="relative z-10"
      >
        <HolographicCard variant="primary">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-6">
            <div className="text-center">
              <div className="w-16 h-16 bg-red-900/30 border border-red-400/30 rounded-full flex items-center justify-center mx-auto mb-3">
                <AlertTriangle className="w-8 h-8 text-red-400" />
              </div>
              <p className="text-3xl font-bold text-red-400 font-mono">
                {scanResult.total_vulnerabilities}
              </p>
              <p className="text-slate-400 font-mono text-sm">Total Vulnerabilities</p>
            </div>
            
            <div className="text-center">
              <div className="w-16 h-16 bg-cyan-900/30 border border-cyan-400/30 rounded-full flex items-center justify-center mx-auto mb-3">
                <FileText className="w-8 h-8 text-cyan-400" />
              </div>
              <p className="text-3xl font-bold text-cyan-400 font-mono">
                {scanResult.files_scanned}
              </p>
              <p className="text-slate-400 font-mono text-sm">Files Scanned</p>
            </div>
            
            <div className="text-center">
              <div className="w-16 h-16 bg-purple-900/30 border border-purple-400/30 rounded-full flex items-center justify-center mx-auto mb-3">
                <Clock className="w-8 h-8 text-purple-400" />
              </div>
              <p className="text-3xl font-bold text-purple-400 font-mono">
                {scanResult.scan_duration?.toFixed(2)}s
              </p>
              <p className="text-slate-400 font-mono text-sm">Scan Duration</p>
            </div>
            
            <div className="text-center">
              <div className="w-16 h-16 bg-emerald-900/30 border border-emerald-400/30 rounded-full flex items-center justify-center mx-auto mb-3">
                <Shield className="w-8 h-8 text-emerald-400" />
              </div>
              <p className="text-3xl font-bold text-emerald-400 font-mono">
                v{scanResult.scanner_version}
              </p>
              <p className="text-slate-400 font-mono text-sm">Scanner Version</p>
            </div>
          </div>

          {/* Severity Breakdown */}
          <div className="border-t border-slate-700/50 pt-6">
            <h3 className="text-lg font-bold text-cyan-400 font-mono mb-4">[SEVERITY] Distribution</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div className="bg-red-900/20 border border-red-400/30 rounded-lg p-4 text-center">
                <p className="text-red-400 font-mono text-sm font-bold">CRITICAL</p>
                <p className="text-red-400 font-mono text-2xl font-bold mt-1">
                  {scanResult.severity_counts.CRITICAL || 0}
                </p>
              </div>
              <div className="bg-orange-900/20 border border-orange-400/30 rounded-lg p-4 text-center">
                <p className="text-orange-400 font-mono text-sm font-bold">HIGH</p>
                <p className="text-orange-400 font-mono text-2xl font-bold mt-1">
                  {scanResult.severity_counts.HIGH || 0}
                </p>
              </div>
              <div className="bg-yellow-900/20 border border-yellow-400/30 rounded-lg p-4 text-center">
                <p className="text-yellow-400 font-mono text-sm font-bold">MEDIUM</p>
                <p className="text-yellow-400 font-mono text-2xl font-bold mt-1">
                  {scanResult.severity_counts.MEDIUM || 0}
                </p>
              </div>
              <div className="bg-blue-900/20 border border-blue-400/30 rounded-lg p-4 text-center">
                <p className="text-blue-400 font-mono text-sm font-bold">LOW</p>
                <p className="text-blue-400 font-mono text-2xl font-bold mt-1">
                  {scanResult.severity_counts.LOW || 0}
                </p>
              </div>
            </div>
          </div>
        </HolographicCard>
      </motion.div>

      {/* Filters and Search */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.2 }}
        className="relative z-10"
      >
        <HolographicCard variant="secondary">
          <div className="flex flex-col md:flex-row gap-4 items-center justify-between">
            <div className="flex items-center space-x-4">
              <Filter className="w-5 h-5 text-cyan-400" />
              <HackerText 
                text="FILTER VULNERABILITIES"
                className="text-lg font-bold text-cyan-400"
                delay={0}
                speed={25}
              />
            </div>
            
            <div className="flex items-center space-x-4">
              {/* Severity Filter */}
              <select
                value={selectedSeverity}
                onChange={(e) => setSelectedSeverity(e.target.value)}
                className="px-3 py-2 bg-slate-800/50 border border-slate-600 rounded-lg text-slate-200 font-mono text-sm focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400"
              >
                <option value="all">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>

              {/* Search */}
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-slate-400" />
                <input
                  type="text"
                  placeholder="Search vulnerabilities..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10 pr-4 py-2 bg-slate-800/50 border border-slate-600 rounded-lg text-slate-200 font-mono text-sm placeholder-slate-400 focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400"
                />
              </div>

              <div className="text-sm text-slate-400 font-mono">
                {filteredVulnerabilities.length} of {scanResult.total_vulnerabilities} vulnerabilities
              </div>
            </div>
          </div>
        </HolographicCard>
      </motion.div>

      {/* Vulnerabilities List */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.3 }}
        className="relative z-10"
      >
        <HolographicCard variant="primary">
          <div className="mb-6">
            <HackerText 
              text="VULNERABILITY DETAILS"
              className="text-xl font-bold text-cyan-400 mb-2"
              delay={0}
              speed={20}
            />
            <p className="text-slate-400 font-mono text-sm">Detailed analysis of security vulnerabilities found</p>
          </div>

          <div className="space-y-4 max-h-[600px] overflow-y-auto custom-scrollbar">
            <AnimatePresence>
              {filteredVulnerabilities.map((vuln, index) => {
                const SeverityIcon = getSeverityIcon(vuln.severity);
                const severityColor = getSeverityColor(vuln.severity);
                const detectorInfo = getDetectorInfo(vuln.detector);
                const DetectorIcon = detectorInfo.icon;
                
                return (
                  <motion.div
                    key={vuln.id || index}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.3, delay: index * 0.05 }}
                    className={`p-4 bg-slate-800/40 rounded-lg border-l-4 border-${severityColor}-400 hover:bg-slate-800/60 transition-all duration-200 cursor-pointer`}
                    onClick={() => setSelectedVuln(selectedVuln === vuln ? null : vuln)}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center space-x-3 mb-2">
                          <SeverityIcon className={`w-5 h-5 text-${severityColor}-400`} />
                          <span className={`px-2 py-1 rounded text-xs font-bold font-mono bg-${severityColor}-900/30 text-${severityColor}-400`}>
                            {vuln.severity}
                          </span>
                          <div className={`flex items-center space-x-1 px-2 py-1 rounded text-xs font-bold font-mono bg-${detectorInfo.color}-900/30 text-${detectorInfo.color}-400`}>
                            <DetectorIcon className={`w-3 h-3 text-${detectorInfo.color}-400`} />
                            <span>{detectorInfo.label}</span>
                          </div>
                          <span className="text-slate-300 font-mono font-bold">
                            {vuln.type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                          </span>
                          {vuln.cwe && (
                            <span className="text-slate-500 font-mono text-sm">
                              {vuln.cwe}
                            </span>
                          )}
                        </div>
                        
                        <p className="text-slate-300 font-mono text-sm mb-2">
                          {vuln.description}
                        </p>
                        
                        <div className="flex items-center space-x-4 text-xs text-slate-500 font-mono">
                          <div className="flex items-center space-x-1">
                            <MapPin className="w-3 h-3" />
                            <span>{vuln.file_path}</span>
                            {vuln.line_number && <span>:{vuln.line_number}</span>}
                          </div>
                          {vuln.confidence && (
                            <div className="flex items-center space-x-1">
                              <Eye className="w-3 h-3" />
                              <span>{vuln.confidence}% confidence</span>
                            </div>
                          )}
                        </div>

                        {/* Expanded Details */}
                        <AnimatePresence>
                          {selectedVuln === vuln && (
                            <motion.div
                              initial={{ opacity: 0, height: 0 }}
                              animate={{ opacity: 1, height: 'auto' }}
                              exit={{ opacity: 0, height: 0 }}
                              transition={{ duration: 0.3 }}
                              className="mt-4 pt-4 border-t border-slate-700/50 space-y-3"
                            >
                              {vuln.code_snippet && (
                                <div>
                                  <h4 className="text-sm font-bold text-cyan-400 font-mono mb-2">Code Snippet</h4>
                                  <pre className="bg-slate-900/50 p-3 rounded text-xs text-slate-300 font-mono overflow-x-auto">
                                    {vuln.code_snippet}
                                  </pre>
                                </div>
                              )}
                              
                              <div>
                                <h4 className="text-sm font-bold text-emerald-400 font-mono mb-2">Recommendation</h4>
                                <p className="text-slate-300 font-mono text-sm">
                                  {vuln.recommendation}
                                </p>
                              </div>
                              
                              {vuln.rule_id && (
                                <div>
                                  <h4 className="text-sm font-bold text-purple-400 font-mono mb-2">Rule ID</h4>
                                  <p className="text-slate-300 font-mono text-sm">
                                    {vuln.rule_id}
                                  </p>
                                </div>
                              )}
                            </motion.div>
                          )}
                        </AnimatePresence>
                      </div>
                      
                      <button
                        className="ml-4 p-2 text-slate-500 hover:text-cyan-400 transition-colors"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedVuln(selectedVuln === vuln ? null : vuln);
                        }}
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    </div>
                  </motion.div>
                );
              })}
            </AnimatePresence>
            
            {filteredVulnerabilities.length === 0 && (
              <div className="text-center py-12">
                <CheckCircle className="w-16 h-16 text-emerald-400 mx-auto mb-4" />
                <HackerText 
                  text="NO VULNERABILITIES FOUND"
                  className="text-xl font-bold text-emerald-400 mb-2"
                  delay={0}
                  speed={20}
                />
                <p className="text-slate-400 font-mono">
                  {searchTerm || selectedSeverity !== 'all' 
                    ? 'No vulnerabilities match the current filters' 
                    : 'Your code appears to be secure!'}
                </p>
              </div>
            )}
          </div>
        </HolographicCard>
      </motion.div>
    </div>
  );
}