import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Search, 
  Filter, 
  Download,
  AlertTriangle,
  CheckCircle,
  Clock,
  FileSearch,
  Calendar,
  MoreHorizontal,
  X,
  FileText,
  Bug,
  Shield
} from 'lucide-react';

import HolographicCard from '@/components/ui/HolographicCard';
import NeonButton from '@/components/ui/NeonButton';
import HackerText from '@/components/ui/HackerText';
import StatusIndicator from '@/components/ui/StatusIndicator';
import { scannerApi } from '@/services/api';

interface ScanRecord {
  id: string;
  path: string;
  timestamp: string;
  duration: number;
  vulnerabilities: number;
  status: 'completed' | 'failed' | 'running';
  severity: 'low' | 'medium' | 'high' | 'critical';
  fileCount: number;
  scanType: 'full' | 'quick' | 'custom';
}

export default function ScanHistory() {
  const [searchQuery, setSearchQuery] = useState('');
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [selectedScan, setSelectedScan] = useState<string | null>(null);
  const [scanHistory, setScanHistory] = useState<ScanRecord[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [showReportModal, setShowReportModal] = useState(false);
  const [reportScanId, setReportScanId] = useState<string | null>(null);
  const [reportData, setReportData] = useState<any>(null);
  const [isLoadingReport, setIsLoadingReport] = useState(false);

  useEffect(() => {
    const fetchScanHistory = async () => {
      console.log('ScanHistory: Starting to fetch scan history...'); // Debug log
      try {
        console.log('ScanHistory: Calling scannerApi.getScanHistory(50)...'); // Debug log
        const response = await scannerApi.getScanHistory(50);
        console.log('ScanHistory: Received response:', response); // Debug log
        console.log('ScanHistory: Response success:', response.success); // Debug log
        console.log('ScanHistory: Response data:', response.data); // Debug log
        console.log('ScanHistory: Response data scans:', response.data?.scans); // Debug log
        console.log('ScanHistory: Response data scans length:', response.data?.scans?.length); // Debug log
        
        if (response.success && response.data?.scans) {
          console.log('ScanHistory: Processing scans...'); // Debug log
          const formattedScans: ScanRecord[] = response.data.scans.map((scan: any) => {
            // Determine severity based on vulnerability counts
            const getSeverity = (vulnCount: number): 'low' | 'medium' | 'high' | 'critical' => {
              if (vulnCount === 0) return 'low';
              if (vulnCount <= 3) return 'medium';
              if (vulnCount <= 10) return 'high';
              return 'critical';
            };

            return {
              id: scan.id,
              path: scan.target_path || 'uploaded_files',
              timestamp: scan.start_time || new Date().toISOString(),
              duration: scan.duration || 0,
              vulnerabilities: scan.total_vulnerabilities || 0,
              status: scan.status === 'completed' ? 'completed' : 
                     scan.status === 'failed' ? 'failed' : 'running',
              severity: getSeverity(scan.total_vulnerabilities || 0),
              fileCount: scan.files_scanned || 0,
              scanType: scan.ai_provider ? 'full' : 'quick'
            };
          });
          console.log('ScanHistory: Formatted scans:', formattedScans); // Debug log
          console.log('ScanHistory: Setting scan history state...'); // Debug log
          
          // Use React.startTransition to batch the state updates
          React.startTransition(() => {
            setScanHistory(formattedScans);
            setIsLoading(false);
            console.log('ScanHistory: Scan history state set successfully'); // Debug log
          });
        } else {
          console.log('ScanHistory: API response not successful or no scans data:', response); // Debug log
          React.startTransition(() => {
            setIsLoading(false);
          });
        }
      } catch (error) {
        console.error('ScanHistory: Failed to fetch scan history:', error);
        React.startTransition(() => {
          setIsLoading(false);
        });
      }
    };

    fetchScanHistory();
  }, []);

  // Debug log to track state changes
  useEffect(() => {
    console.log('ScanHistory: scanHistory state changed:', scanHistory.length, 'scans'); // Debug log
  }, [scanHistory]);

  useEffect(() => {
    console.log('ScanHistory: isLoading state changed:', isLoading); // Debug log
  }, [isLoading]);

  const filteredScans = scanHistory.filter(scan => {
    const matchesSearch = scan.path.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesFilter = filterStatus === 'all' || scan.status === filterStatus;
    return matchesSearch && matchesFilter;
  });

  // Debug log for filtered scans
  useEffect(() => {
    console.log('ScanHistory: filteredScans changed:', filteredScans.length, 'scans'); // Debug log
    console.log('ScanHistory: searchQuery:', searchQuery); // Debug log
    console.log('ScanHistory: filterStatus:', filterStatus); // Debug log
  }, [filteredScans, searchQuery, filterStatus]);

  const getSeverityColor = (severity: string) => {
    const colors = {
      low: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
      medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
      high: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
      critical: 'text-red-400 bg-red-500/10 border-red-500/30'
    };
    return colors[severity as keyof typeof colors] || colors.low;
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckCircle className="w-4 h-4 text-emerald-400" />;
      case 'failed': return <AlertTriangle className="w-4 h-4 text-red-400" />;
      case 'running': return <Clock className="w-4 h-4 text-cyan-400 animate-spin" />;
      default: return <Clock className="w-4 h-4 text-gray-400" />;
    }
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false
    });
  };

  const handleViewReport = async (scanId: string) => {
    setIsLoadingReport(true);
    setReportScanId(scanId);
    setShowReportModal(true);
    
    try {
      const response = await scannerApi.getScanResults(scanId);
      if (response.success && response.data) {
        setReportData(response.data);
      } else {
        console.error('Failed to fetch scan results:', response.error);
        setReportData(null);
      }
    } catch (error) {
      console.error('Error fetching scan results:', error);
      setReportData(null);
    } finally {
      setIsLoadingReport(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <HolographicCard variant="primary">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div>
            <HackerText 
              text="SCAN HISTORY DATABASE"
              className="text-3xl font-bold text-white mb-2"
              delay={200}
              speed={30}
            />
            <p className="text-slate-300 font-mono">
              Complete archive of security scan operations
            </p>
          </div>
          
          <div className="flex items-center space-x-4">
            <StatusIndicator status="online" label="ARCHIVE ONLINE" />
            <NeonButton variant="primary" size="sm">
              <Download className="w-4 h-4 mr-2" />
              Export Data
            </NeonButton>
          </div>
        </div>
      </HolographicCard>

      {/* Search and Filter */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <HolographicCard variant="secondary" className="lg:col-span-2">
          <div className="flex items-center space-x-3">
            <Search className="w-5 h-5 text-cyan-400" />
            <input
              type="text"
              placeholder="Search scan paths..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="flex-1 bg-transparent text-white placeholder-slate-400 border-none outline-none font-mono"
            />
          </div>
        </HolographicCard>

        <HolographicCard variant="secondary">
          <div className="flex items-center space-x-3">
            <Filter className="w-5 h-5 text-cyan-400" />
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="flex-1 bg-transparent text-white border-none outline-none font-mono"
            >
              <option value="all" className="bg-slate-800">All Status</option>
              <option value="completed" className="bg-slate-800">Completed</option>
              <option value="failed" className="bg-slate-800">Failed</option>
              <option value="running" className="bg-slate-800">Running</option>
            </select>
          </div>
        </HolographicCard>
      </div>

      {/* Scan Results Table */}
      <HolographicCard variant="primary">
        <div className="mb-6">
          <h3 className="text-xl font-mono text-cyan-400 mb-2">SCAN RECORDS</h3>
          <p className="text-sm text-slate-400 font-mono">
            {filteredScans.length} records found
          </p>
        </div>

        <div className="space-y-3">
          {isLoading ? (
            <div className="text-center py-12">
              <div className="inline-flex items-center space-x-2 text-cyan-400">
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-cyan-400"></div>
                <span className="text-sm font-mono">Loading scan history...</span>
              </div>
            </div>
          ) : filteredScans.length === 0 ? (
            <div className="text-center py-12">
              <FileSearch className="w-12 h-12 text-slate-500 mx-auto mb-4" />
              <h3 className="text-lg font-mono text-slate-400 mb-2">No scan history found</h3>
              <p className="text-sm text-slate-500">
                {searchQuery || filterStatus !== 'all' ? 'Try adjusting your filters' : 'Run your first security scan to see results here'}
              </p>
            </div>
          ) : (
            <AnimatePresence>
              {filteredScans.map((scan, index) => (
              <motion.div
                key={scan.id}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 20 }}
                transition={{ duration: 0.2, delay: index * 0.05 }}
                className={`
                  bg-slate-800/50 rounded-lg border border-slate-600/30 p-4 
                  hover:border-cyan-400/50 transition-all duration-150 cursor-pointer
                  ${selectedScan === scan.id ? 'border-cyan-400/50 bg-cyan-500/5' : ''}
                `}
                onClick={() => setSelectedScan(selectedScan === scan.id ? null : scan.id)}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-4 flex-1">
                    {getStatusIcon(scan.status)}
                    
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center space-x-3 mb-1">
                        <span className="text-white font-mono font-medium truncate">
                          {scan.path}
                        </span>
                        <span className={`
                          px-2 py-1 text-xs font-mono rounded border
                          ${getSeverityColor(scan.severity)}
                        `}>
                          {scan.severity.toUpperCase()}
                        </span>
                        <span className="px-2 py-1 text-xs font-mono bg-slate-700/50 text-slate-300 rounded">
                          {scan.scanType.toUpperCase()}
                        </span>
                      </div>
                      
                      <div className="flex items-center space-x-4 text-sm text-slate-400 font-mono">
                        <span className="flex items-center space-x-1">
                          <Calendar className="w-3 h-3" />
                          <span>{formatTimestamp(scan.timestamp)}</span>
                        </span>
                        <span>{scan.duration}s</span>
                        <span>{scan.fileCount} files</span>
                        <span className={scan.vulnerabilities > 0 ? 'text-red-400' : 'text-emerald-400'}>
                          {scan.vulnerabilities} vulnerabilities
                        </span>
                      </div>
                    </div>
                  </div>

                  <motion.div
                    animate={{ rotate: selectedScan === scan.id ? 90 : 0 }}
                    transition={{ duration: 0.2 }}
                  >
                    <MoreHorizontal className="w-5 h-5 text-slate-400" />
                  </motion.div>
                </div>

                {/* Expanded Details */}
                <AnimatePresence>
                  {selectedScan === scan.id && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: 'auto', opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      transition={{ duration: 0.3 }}
                      className="mt-4 pt-4 border-t border-slate-600/30 overflow-hidden"
                    >
                      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 text-sm font-mono">
                        <div>
                          <span className="text-slate-400">Scan ID:</span>
                          <div className="text-cyan-400">{scan.id}</div>
                        </div>
                        <div>
                          <span className="text-slate-400">Duration:</span>
                          <div className="text-white">{scan.duration} seconds</div>
                        </div>
                        <div>
                          <span className="text-slate-400">Files Scanned:</span>
                          <div className="text-white">{scan.fileCount}</div>
                        </div>
                        <div>
                          <span className="text-slate-400">Result:</span>
                          <div className={scan.vulnerabilities > 0 ? 'text-red-400' : 'text-emerald-400'}>
                            {scan.vulnerabilities} issues found
                          </div>
                        </div>
                      </div>
                      
                      <div className="mt-4 flex space-x-2">
                        <NeonButton 
                          variant="secondary" 
                          size="sm"
                          onClick={() => handleViewReport(scan.id)}
                        >
                          View Report
                        </NeonButton>
                        <NeonButton variant="secondary" size="sm">
                          Re-scan
                        </NeonButton>
                        <NeonButton variant="secondary" size="sm">
                          Export
                        </NeonButton>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </motion.div>
              ))}
            </AnimatePresence>
          )}
        </div>
      </HolographicCard>

      {/* Report Modal */}
      <AnimatePresence>
        {showReportModal && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4"
            onClick={() => setShowReportModal(false)}
          >
            <motion.div
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              transition={{ type: 'spring', damping: 20, stiffness: 300 }}
              className="bg-slate-900/95 border border-cyan-400/30 rounded-xl max-w-4xl w-full max-h-[90vh] overflow-hidden"
              onClick={(e) => e.stopPropagation()}
            >
              {/* Modal Header */}
              <div className="flex items-center justify-between p-6 border-b border-slate-700/50">
                <div>
                  <h2 className="text-xl font-mono text-cyan-400">VULNERABILITY REPORT</h2>
                  <p className="text-sm text-slate-400 font-mono">
                    Scan ID: {reportScanId?.substring(0, 8)}...
                  </p>
                </div>
                <button
                  onClick={() => setShowReportModal(false)}
                  className="p-2 hover:bg-slate-800 rounded-lg transition-colors"
                >
                  <X className="w-5 h-5 text-slate-400" />
                </button>
              </div>

              {/* Modal Content */}
              <div className="p-6 overflow-y-auto max-h-[70vh]">
                {isLoadingReport ? (
                  <div className="flex items-center justify-center py-12">
                    <div className="flex items-center space-x-3">
                      <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-cyan-400"></div>
                      <span className="text-cyan-400 font-mono">Loading scan results...</span>
                    </div>
                  </div>
                ) : reportData ? (
                  <div className="space-y-6">
                    {/* Summary */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700/50">
                        <div className="flex items-center space-x-2">
                          <FileText className="w-5 h-5 text-cyan-400" />
                          <span className="font-mono text-sm text-slate-300">Files Scanned</span>
                        </div>
                        <div className="text-xl font-mono text-white mt-1">
                          {reportData.files_scanned || 0}
                        </div>
                      </div>
                      <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700/50">
                        <div className="flex items-center space-x-2">
                          <Bug className="w-5 h-5 text-red-400" />
                          <span className="font-mono text-sm text-slate-300">Vulnerabilities</span>
                        </div>
                        <div className="text-xl font-mono text-white mt-1">
                          {reportData.total_vulnerabilities || 0}
                        </div>
                      </div>
                      <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700/50">
                        <div className="flex items-center space-x-2">
                          <Clock className="w-5 h-5 text-blue-400" />
                          <span className="font-mono text-sm text-slate-300">Duration</span>
                        </div>
                        <div className="text-xl font-mono text-white mt-1">
                          {reportData.scan_duration || 0}s
                        </div>
                      </div>
                    </div>

                    {/* Vulnerabilities List */}
                    {reportData.vulnerabilities && reportData.vulnerabilities.length > 0 ? (
                      <div>
                        <h3 className="text-lg font-mono text-cyan-400 mb-4">VULNERABILITIES FOUND</h3>
                        <div className="space-y-4">
                          {reportData.vulnerabilities.map((vuln: any, index: number) => (
                            <div key={index} className="bg-slate-800/30 rounded-lg p-4 border border-slate-700/30">
                              <div className="flex items-start justify-between mb-3">
                                <div className="flex items-center space-x-3">
                                  <div className={`px-2 py-1 rounded text-xs font-mono ${
                                    vuln.severity === 'CRITICAL' ? 'bg-red-900/50 text-red-400 border border-red-500/30' :
                                    vuln.severity === 'HIGH' ? 'bg-orange-900/50 text-orange-400 border border-orange-500/30' :
                                    vuln.severity === 'MEDIUM' ? 'bg-yellow-900/50 text-yellow-400 border border-yellow-500/30' :
                                    'bg-blue-900/50 text-blue-400 border border-blue-500/30'
                                  }`}>
                                    {vuln.severity}
                                  </div>
                                  <div className="text-sm font-mono text-slate-300">
                                    {vuln.type?.replace(/_/g, ' ').toUpperCase()}
                                  </div>
                                </div>
                                <div className="text-xs font-mono text-slate-500">
                                  {vuln.detector === 'ai_analyzer' ? 'AI Detection' : 'Static Analysis'}
                                </div>
                              </div>
                              
                              <div className="mb-3">
                                <h4 className="text-sm font-mono text-cyan-300 mb-1">Description:</h4>
                                <p className="text-sm text-slate-300">{vuln.description}</p>
                              </div>
                              
                              <div className="mb-3">
                                <h4 className="text-sm font-mono text-cyan-300 mb-1">Location:</h4>
                                <p className="text-sm text-slate-300 font-mono">
                                  {vuln.file_path}:{vuln.line_number}
                                </p>
                              </div>
                              
                              {vuln.code_snippet && (
                                <div className="mb-3">
                                  <h4 className="text-sm font-mono text-cyan-300 mb-1">Code:</h4>
                                  <pre className="text-xs bg-slate-900/50 p-2 rounded border border-slate-700/50 overflow-x-auto">
                                    <code className="text-slate-300">{vuln.code_snippet}</code>
                                  </pre>
                                </div>
                              )}
                              
                              <div>
                                <h4 className="text-sm font-mono text-cyan-300 mb-1">Recommendation:</h4>
                                <p className="text-sm text-slate-300">{vuln.recommendation}</p>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    ) : (
                      <div className="text-center py-8">
                        <Shield className="w-12 h-12 text-emerald-400 mx-auto mb-3" />
                        <h3 className="text-lg font-mono text-emerald-400 mb-2">No Vulnerabilities Found</h3>
                        <p className="text-sm text-slate-400">This scan completed without detecting any security issues.</p>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="text-center py-12">
                    <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-3" />
                    <h3 className="text-lg font-mono text-red-400 mb-2">Failed to Load Report</h3>
                    <p className="text-sm text-slate-400">Unable to retrieve scan results. Please try again.</p>
                  </div>
                )}
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}