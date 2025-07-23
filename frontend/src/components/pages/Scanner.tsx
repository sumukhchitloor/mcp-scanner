import React, { useState, useCallback, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Upload, 
  FolderOpen, 
  Settings, 
  Play,
  FileText,
  AlertTriangle,
  CheckCircle,
  X,
  Plus,
  Zap,
  Brain,
  Search,
  Shield,
  Key,
  Cpu,
  Bot,
  StopCircle,
  Clock,
  Bug
} from 'lucide-react';
import { useDropzone } from 'react-dropzone';
import HolographicCard from '@/components/ui/HolographicCard';
import TerminalWindow from '@/components/ui/TerminalWindow';
import HackerText from '@/components/ui/HackerText';
import NeonButton from '@/components/ui/NeonButton';
import ScanTimeline from '@/components/dashboard/ScanTimeline';

import { scannerApi } from '@/services/api';
import { getStoredApiKey } from './Settings';

export default function Scanner() {
  const [scanConfig, setScanConfig] = useState({
    enableAI: true,
    enableStatic: true,
    aiProvider: 'openai' as 'openai' | 'claude' | 'gemini',
    model: 'gpt-4',
    outputFormat: 'json'
  });

  const [uploadedFiles, setUploadedFiles] = useState<File[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [showTerminal, setShowTerminal] = useState(false);
  const [scanOutput, setScanOutput] = useState<string[]>([]);
  const [currentStep, setCurrentStep] = useState(0);
  const [scanId, setScanId] = useState<string | null>(null);
  const [scanResults, setScanResults] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [isProcessingFolder, setIsProcessingFolder] = useState(false);
  const [showReportModal, setShowReportModal] = useState(false);
  const [reportData, setReportData] = useState<any>(null);
  const [isLoadingReport, setIsLoadingReport] = useState(false);
  const [isCancelling, setIsCancelling] = useState(false);

  // Fixed 4-step timeline process
  const scanSteps = [
    {
      id: 'step1',
      type: 'scan_start' as const,
      title: 'Security Scan Initiated',
      details: 'Initializing security analysis engine',
      fileName: 'Preparing scan environment...',
      progressRange: [0, 25]
    },
    {
      id: 'step2', 
      type: 'file_processed' as const,
      title: 'File Analysis in Progress',
      details: 'Static code analysis and pattern matching',
      fileName: 'Processing uploaded files...',
      progressRange: [25, 50]
    },
    {
      id: 'step3',
      type: 'threat_detected' as const,
      title: 'Vulnerability Detection',
      details: 'AI-powered threat analysis and classification',
      fileName: 'Scanning for security vulnerabilities...',
      severity: 'medium' as const,
      progressRange: [50, 75]
    },
    {
      id: 'step4',
      type: 'scan_complete' as const,
      title: 'Analysis Complete',
      details: 'Security scan finished successfully',
      fileName: 'Generating comprehensive report...',
      progressRange: [75, 100]
    }
  ];

  // Previous scans for initial display
  const previousScans = [
    {
      id: 'prev1',
      timestamp: '14:29:01',
      type: 'scan_complete' as const,
      title: 'Previous Scan Completed',
      details: '12 vulnerabilities found, 3 critical',
      fileName: '/app/test-server'
    },
    {
      id: 'prev2',
      timestamp: '14:28:22',
      type: 'scan_complete' as const,
      title: 'Scan History Entry',
      details: 'Static analysis finished successfully',
      fileName: 'config.json'
    }
  ];

  // Check for active scans on component mount
  useEffect(() => {
    const checkActiveScans = async () => {
      console.log('Scanner: Starting to check for active scans...'); // Debug log
      try {
        console.log('Scanner: Calling scannerApi.getActiveScans()...'); // Debug log
        // Get active scans to check if any are still running
        const response = await scannerApi.getActiveScans();
        console.log('Scanner: Received response:', response); // Debug log
        if (response.success && response.data?.scans) {
          console.log('Scanner: Found active scans:', response.data.scans); // Debug log
          const runningScan = response.data.scans.find((scan: any) => 
            scan.status === 'running'
          );
          
          console.log('Scanner: Running scan found:', runningScan); // Debug log
          if (runningScan) {
            console.log('Found active scan on page load:', runningScan);
            setScanId(runningScan.id);
            setIsScanning(true);
            setScanProgress(runningScan.progress || 50);
            setScanOutput([
              '[SYSTEM] Reconnected to active scan...',
              `[SCAN] Resuming monitoring of scan ${runningScan.id}`,
              '[STATUS] Scan is currently in progress...'
            ]);
            
            // Start monitoring the existing scan
            monitorExistingScan(runningScan.id);
          } else {
            console.log('Scanner: No running scans found'); // Debug log
          }
        } else {
          console.log('Scanner: API response not successful or no scans data:', response); // Debug log
        }
      } catch (error) {
        console.error('Scanner: Failed to check for active scans:', error);
      }
    };
    
    checkActiveScans();
  }, []);

  const monitorExistingScan = async (scanId: string) => {
    let attempts = 0;
    const maxAttempts = 60; // 2 minutes max
    
    while (attempts < maxAttempts) {
      try {
        const statusResponse = await scannerApi.getScanStatus(scanId);
        if (!statusResponse.success) {
          console.error('Failed to get scan status:', statusResponse.error);
          break;
        }
        
        const status = statusResponse.data;
        setScanProgress(Math.max(50, status.progress || 50));
        setScanOutput(prev => [...prev, `[STATUS] Scan ${status.status}, Progress: ${status.progress}%`]);
        
        if (status.status === 'completed') {
          setScanProgress(100);
          setScanOutput(prev => [...prev, '[SUCCESS] Scan completed successfully!']);
          
          // Get results
          const resultsResponse = await scannerApi.getScanResults(scanId);
          if (resultsResponse.success) {
            setScanResults(resultsResponse.data);
            setScanOutput(prev => [...prev, `[RESULTS] Found ${resultsResponse.data?.total_vulnerabilities || 0} vulnerabilities`]);
          }
          
          setIsScanning(false);
          break;
        } else if (status.status === 'cancelled' || status.status === 'failed') {
          setScanOutput(prev => [...prev, `[INFO] Scan ${status.status}`]);
          setIsScanning(false);
          break;
        }
        
        await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2 seconds
        attempts++;
      } catch (error) {
        console.error('Error monitoring existing scan:', error);
        attempts++;
      }
    }
    
    if (attempts >= maxAttempts) {
      setScanOutput(prev => [...prev, '[ERROR] Scan monitoring timed out']);
      setIsScanning(false);
    }
  };

  const onDrop = useCallback((acceptedFiles: File[]) => {
    setUploadedFiles(prev => [...prev, ...acceptedFiles]);
  }, []);

  const handleFolderUpload = useCallback(async (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(event.target.files || []);
    if (files.length === 0) return;

    setIsProcessingFolder(true);
    setError(null);

    try {
      // Show immediate feedback
      console.log(`Processing ${files.length} files from folder...`);
      
      // Filter supported file types (like CLI does)
      const supportedExtensions = ['.js', '.jsx', '.ts', '.tsx', '.py', '.json', '.yml', '.yaml'];
      
      // Exclude common directories and files that shouldn't be scanned
      const excludePatterns = [
        'node_modules',
        '.git',
        'dist',
        'build',
        '.next',
        'coverage',
        '.cache',
        'public',
        'static',
        'assets',
        '__pycache__',
        '.pytest_cache',
        'venv',
        'env',
        '.env'
      ];
      
      const supportedFiles = files.filter(file => {
        const ext = file.name.toLowerCase().substring(file.name.lastIndexOf('.'));
        const filePath = file.webkitRelativePath || file.name;
        
        // Check if file has supported extension
        if (!supportedExtensions.includes(ext)) {
          return false;
        }
        
        // Check if file is in excluded directory
        const isExcluded = excludePatterns.some(pattern => 
          filePath.toLowerCase().includes(pattern.toLowerCase())
        );
        
        return !isExcluded;
      });

      console.log(`Found ${supportedFiles.length} supported files out of ${files.length} total files`);
      console.log(`Excluded patterns: ${excludePatterns.join(', ')}`);
      
      // Show user feedback about filtering
      if (files.length > supportedFiles.length) {
        console.log(`Filtered out ${files.length - supportedFiles.length} files (unsupported types or excluded directories)`);
      }

      if (supportedFiles.length === 0) {
        setError('No supported files found in the selected folder');
        return;
      }

      // Limit files to prevent overwhelming the system
      if (supportedFiles.length > 1000) {
        setError(`Too many files selected (${supportedFiles.length}). Please select a smaller folder or use the CLI for large projects. Maximum: 1000 files.`);
        return;
      }

      // For large folders, process in smaller batches
      const batchSize = supportedFiles.length > 1000 ? 500 : 100;
      
      // Clear existing files when uploading a folder
      setUploadedFiles([]);
      
      // Process files in batches to prevent UI hanging
      let processedCount = 0;
      for (let i = 0; i < supportedFiles.length; i += batchSize) {
        const batch = supportedFiles.slice(i, i + batchSize);
        setUploadedFiles(prev => [...prev, ...batch]);
        processedCount += batch.length;
        
        console.log(`Processed ${processedCount}/${supportedFiles.length} files`);
        
        // Allow UI to update between batches
        if (i + batchSize < supportedFiles.length) {
          await new Promise(resolve => setTimeout(resolve, 5));
        }
      }

      console.log(`Folder upload complete: ${supportedFiles.length} files ready for scanning`);
    } catch (err) {
      console.error('Error processing folder:', err);
      setError('Failed to process folder contents');
    } finally {
      setIsProcessingFolder(false);
      // Reset the input to allow selecting the same folder again
      event.target.value = '';
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'text/javascript': ['.js', '.jsx'],
      'text/typescript': ['.ts', '.tsx'],
      'text/python': ['.py'],
      'application/json': ['.json'],
      'text/yaml': ['.yml', '.yaml']
    },
    // Remove size limits - let backend handle it
    maxSize: undefined
  });

  const removeFile = (index: number) => {
    setUploadedFiles(prev => prev.filter((_, i) => i !== index));
  };

  const handleViewDetailedResults = async () => {
    if (!scanId) return;
    
    setIsLoadingReport(true);
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


  const getCurrentTimelineData = () => {
    if (!isScanning) {
      return previousScans;
    }

    // Create timeline data based on current progress
    const currentTime = new Date();
    const baseTime = currentTime.getTime();
    
    return scanSteps.map((step, index) => {
      const stepTime = new Date(baseTime + (index * 30000)); // 30 second intervals
      const timestamp = `${stepTime.getHours().toString().padStart(2, '0')}:${stepTime.getMinutes().toString().padStart(2, '0')}:${stepTime.getSeconds().toString().padStart(2, '0')}`;
      
      return {
        ...step,
        timestamp,
        fileName: index === 1 ? uploadedFiles.map(f => f.name).slice(0, 3).join(', ') + (uploadedFiles.length > 3 ? ` +${uploadedFiles.length - 3} more` : '') : step.fileName
      };
    });
  };

  const startScan = async () => {
    if (uploadedFiles.length === 0) {
      setError('Please upload files before starting scan');
      return;
    }

    // Check if AI analysis is enabled and API key is available
    if (scanConfig.enableAI) {
      const apiKey = getStoredApiKey(scanConfig.aiProvider);
      if (!apiKey) {
        setError(`AI analysis enabled but no API key found for ${scanConfig.aiProvider.toUpperCase()}. Please configure API keys in Settings.`);
        return;
      }
    }
    
    try {
      setError(null);
      setIsScanning(true);
      setScanProgress(0);
      setCurrentStep(0);
      setShowTerminal(false);
      setScanOutput(['[SYSTEM] Initializing security scan...']);
      setScanResults(null);

      // Step 1: Upload files
      setScanOutput(prev => [...prev, '[UPLOAD] Uploading files to server...']);
      setScanProgress(10);
      
      const uploadResponse = await scannerApi.uploadFiles(uploadedFiles);
      if (!uploadResponse.success) {
        throw new Error(uploadResponse.error || 'Failed to upload files');
      }
      
      setScanOutput(prev => [...prev, `[UPLOAD] Successfully uploaded ${uploadedFiles.length} files`]);
      setScanProgress(25);
      setCurrentStep(1);

      // Step 2: Start scan
      setScanOutput(prev => [...prev, '[SCAN] Starting vulnerability analysis...']);
      
      const scanConfigRequest = {
        files: uploadedFiles,
        static_only: !scanConfig.enableAI,
        ai_only: !scanConfig.enableStatic,
        output_format: scanConfig.outputFormat,
        ai_provider: scanConfig.aiProvider,
        api_key: scanConfig.enableAI ? getStoredApiKey(scanConfig.aiProvider) : undefined,
        verbose: true
      };

      const scanResponse = await scannerApi.startScan(scanConfigRequest);
      if (!scanResponse.success) {
        throw new Error(scanResponse.error || 'Failed to start scan');
      }

      const newScanId = scanResponse.data?.scanId;
      setScanId(newScanId);
      setScanOutput(prev => [...prev, `[SCAN] Scan started with ID: ${newScanId}`]);
      setScanProgress(40);
      setCurrentStep(2);

      // Step 3: Monitor progress
      setScanOutput(prev => [...prev, '[MONITOR] Monitoring scan progress...']);
      
      const monitorScan = async () => {
        let attempts = 0;
        const maxAttempts = 60; // 2 minutes max
        
        while (attempts < maxAttempts) {
          try {
            const statusResponse = await scannerApi.getScanStatus(newScanId);
            if (!statusResponse.success) {
              throw new Error(statusResponse.error || 'Failed to get scan status');
            }
            
            const status = statusResponse.data;
            setScanProgress(Math.max(50, status.progress || 50));
            setScanOutput(prev => [...prev, `[STATUS] Scan ${status.status}, Progress: ${status.progress}%`]);
            
            if (status.status === 'completed') {
              setScanProgress(90);
              setCurrentStep(3);
              setScanOutput(prev => [...prev, '[SUCCESS] Scan completed successfully!']);
              
              // Get results
              const resultsResponse = await scannerApi.getScanResults(newScanId);
              if (resultsResponse.success) {
                setScanResults(resultsResponse.data);
                setScanProgress(100);
                setScanOutput(prev => [...prev, `[RESULTS] Found ${resultsResponse.data?.total_vulnerabilities || 0} vulnerabilities`]);
              }
              
              setIsScanning(false);
              break;
            } else if (status.status === 'cancelled') {
              setScanOutput(prev => [...prev, '[INFO] Scan was cancelled']);
              setIsScanning(false);
              setScanProgress(0);
              setCurrentStep(0);
              break;
            } else if (status.status === 'failed') {
              throw new Error('Scan failed on server');
            }
            
            await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2 seconds
            attempts++;
          } catch (error) {
            console.error('Error monitoring scan:', error);
            attempts++;
          }
        }
        
        if (attempts >= maxAttempts) {
          throw new Error('Scan monitoring timed out');
        }
      };
      
      await monitorScan();
      
    } catch (error) {
      console.error('Scan error:', error);
      setError(error instanceof Error ? error.message : 'Unknown error occurred');
      setScanOutput(prev => [...prev, `[ERROR] ${error}`]);
      setIsScanning(false);
      setScanProgress(0);
    }
  };

  const cancelScan = async () => {
    if (!scanId || !isScanning) {
      return;
    }

    try {
      setIsCancelling(true);
      setScanOutput(prev => [...prev, '[SYSTEM] Cancelling scan...']);

      const response = await scannerApi.cancelScan(scanId);
      
      if (response.success) {
        setScanOutput(prev => [...prev, '[SYSTEM] Scan cancelled successfully']);
        setIsScanning(false);
        setScanProgress(0);
        setCurrentStep(0);
        setScanId(null);
        setError('Scan was cancelled by user');
      } else {
        // Handle case where scan already completed
        if (response.error?.includes('already completed') || response.error?.includes('already failed')) {
          setScanOutput(prev => [...prev, '[INFO] Scan completed before cancellation could take effect']);
          // Don't throw error, just acknowledge the completion
        } else {
          throw new Error(response.error || 'Failed to cancel scan');
        }
      }
    } catch (error) {
      console.error('Cancel error:', error);
      setScanOutput(prev => [...prev, `[ERROR] Failed to cancel scan: ${error}`]);
      setError(error instanceof Error ? error.message : 'Failed to cancel scan');
    } finally {
      setIsCancelling(false);
    }
  };

  return (
    <div className="space-y-6 min-h-screen relative">
      {/* Cyberpunk Background Effects */}
      <div className="fixed inset-0 pointer-events-none opacity-20">
        <div className="absolute inset-0 bg-gradient-to-br from-cyan-900/20 via-transparent to-purple-900/20" />
        <div className="absolute top-20 left-20 w-32 h-32 bg-cyan-400/10 rounded-full blur-3xl animate-pulse" />
        <div className="absolute bottom-20 right-20 w-48 h-48 bg-purple-400/10 rounded-full blur-3xl animate-pulse delay-1000" />
      </div>

      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
        className="relative z-10"
      >
        <HackerText 
          text="SECURITY SCANNER"
          className="text-4xl font-bold text-transparent bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text mb-4"
          delay={100}
          speed={50}
        />
        <p className="text-slate-300 font-mono text-lg">
          <span className="text-cyan-400">[SYSTEM]</span> Upload files for advanced MCP vulnerability analysis
        </p>
      </motion.div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 relative z-10">
        {/* File Upload Section */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.6, delay: 0.2 }}
          className="xl:col-span-2 space-y-6"
        >
          <HolographicCard variant="primary">
            <div className="mb-6">
              <HackerText 
                text="FILE UPLOAD ZONE"
                className="text-xl font-bold text-cyan-400 mb-2"
                delay={400}
                speed={30}
              />
              <p className="text-slate-400 font-mono text-sm">Drag & drop or click to select files</p>
            </div>

            {/* Cyberpunk Dropzone */}
            <div
              {...getRootProps()}
              className={`relative border-2 border-dashed rounded-xl p-8 text-center transition-all duration-300 cursor-pointer overflow-hidden ${
                isDragActive
                  ? 'border-cyan-400 bg-cyan-900/20 shadow-[0_0_30px_rgba(34,211,238,0.3)]'
                  : 'border-slate-600 hover:border-cyan-400/70 hover:bg-slate-800/50 hover:shadow-[0_0_20px_rgba(34,211,238,0.1)]'
              }`}
            >
              {/* Scanning line effect */}
              {isDragActive && (
                <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-cyan-400 to-transparent animate-pulse" />
              )}

              <input {...getInputProps()} />
              <div className="space-y-4 relative z-10">
                <div className="mx-auto w-16 h-16 bg-slate-800/80 rounded-full flex items-center justify-center border border-cyan-400/30 shadow-[0_0_20px_rgba(34,211,238,0.2)]">
                  <Upload className={`w-8 h-8 transition-colors duration-300 ${
                    isDragActive ? 'text-cyan-400 animate-pulse' : 'text-slate-300'
                  }`} />
                </div>

                {isDragActive ? (
                  <div>
                    <p className="text-lg font-bold text-cyan-400 font-mono animate-pulse">
                      [UPLOADING] Drop files here
                    </p>
                    <p className="text-sm text-slate-400 font-mono">Release to begin transfer</p>
                  </div>
                ) : (
                  <div>
                    <p className="text-lg font-bold text-slate-200 font-mono mb-2">
                      Drop files here or click to browse
                    </p>
                    <p className="text-sm text-slate-400 font-mono">
                      <span className="text-cyan-400">SUPPORTED:</span> .js, .ts, .py, .json, .yml
                    </p>
                    <p className="text-sm text-slate-500 font-mono mt-1">
                      <span className="text-purple-400">NO SIZE LIMITS:</span> Upload any amount of files
                    </p>
                  </div>
                )}
              </div>
            </div>

            {/* Folder Upload Option */}
            <div className="mt-4 border-t border-slate-700/50 pt-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-bold text-purple-400 font-mono">[FOLDER] Upload Entire Directory</p>
                  <p className="text-xs text-slate-500 font-mono">Select a folder to upload all supported files</p>
                </div>
                <div className="relative">
                  <input
                    type="file"
                    /* @ts-ignore */
                    webkitdirectory=""
                    directory=""
                    multiple
                    onChange={handleFolderUpload}
                    disabled={isProcessingFolder}
                    className={`absolute inset-0 w-full h-full opacity-0 ${isProcessingFolder ? 'cursor-not-allowed' : 'cursor-pointer'}`}
                  />
                  <motion.button
                    whileHover={{ scale: isProcessingFolder ? 1 : 1.05 }}
                    whileTap={{ scale: isProcessingFolder ? 1 : 0.95 }}
                    disabled={isProcessingFolder}
                    className={`px-4 py-2 rounded-lg transition-all duration-200 font-mono text-sm font-bold flex items-center space-x-2 ${
                      isProcessingFolder 
                        ? 'bg-slate-800/50 border border-slate-600 text-slate-400 cursor-not-allowed' 
                        : 'bg-purple-900/30 border border-purple-400/30 text-purple-400 hover:bg-purple-900/50 hover:border-purple-400/60'
                    }`}
                  >
                    {isProcessingFolder ? (
                      <>
                        <motion.div
                          className="w-4 h-4 border-2 border-slate-400 border-t-transparent rounded-full"
                          animate={{ rotate: 360 }}
                          transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                        />
                        <span>Processing...</span>
                      </>
                    ) : (
                      <>
                        <FolderOpen className="w-4 h-4" />
                        <span>Browse Folder</span>
                      </>
                    )}
                  </motion.button>
                </div>
              </div>
            </div>

            {/* Uploaded Files */}
            {uploadedFiles.length > 0 && (
              <div className="mt-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-bold text-cyan-400 font-mono">
                    [FILES] Loaded: {uploadedFiles.length}
                  </h3>
                  <div className="text-xs text-slate-500 font-mono">
                    {uploadedFiles.reduce((acc, file) => acc + file.size, 0) / 1024 > 1024 
                      ? `${(uploadedFiles.reduce((acc, file) => acc + file.size, 0) / 1024 / 1024).toFixed(1)}MB`
                      : `${(uploadedFiles.reduce((acc, file) => acc + file.size, 0) / 1024).toFixed(1)}KB`
                    }
                  </div>
                </div>
                <div className="space-y-2 max-h-60 overflow-y-auto custom-scrollbar">
                  {uploadedFiles.length > 100 ? (
                    // For large numbers of files, show summary instead of individual files
                    <div className="p-4 bg-slate-800/40 rounded-lg border border-cyan-400/30">
                      <div className="text-center">
                        <FileText className="w-8 h-8 text-cyan-400 mx-auto mb-2" />
                        <p className="text-lg font-mono font-bold text-cyan-400 mb-1">
                          {uploadedFiles.length} Files Loaded
                        </p>
                        <p className="text-xs text-slate-400 font-mono mb-3">
                          Large directory processed • Ready for scanning
                        </p>
                        <button
                          onClick={() => setUploadedFiles([])}
                          className="px-4 py-2 bg-red-900/30 border border-red-400/30 text-red-400 rounded-lg hover:bg-red-900/50 transition-all duration-200 font-mono text-xs font-bold"
                        >
                          Clear All Files
                        </button>
                      </div>
                    </div>
                  ) : (
                    // For smaller numbers of files, show individual files (no animations)
                    uploadedFiles.map((file, index) => (
                      <div
                        key={index}
                        className="flex items-center justify-between p-3 bg-slate-800/40 rounded-lg border border-slate-700/50 hover:border-cyan-400/30 transition-all duration-200"
                      >
                        <div className="flex items-center space-x-3">
                          <div className="relative">
                            <FileText className="w-5 h-5 text-cyan-400" />
                            <div className="absolute -top-1 -right-1 w-2 h-2 bg-green-400 rounded-full" />
                          </div>
                          <div>
                            <p className="text-sm font-mono font-bold text-slate-200">
                              {file.name}
                            </p>
                            <p className="text-xs text-slate-500 font-mono">
                              {(file.size / 1024).toFixed(1)} KB • Ready for scan
                            </p>
                          </div>
                        </div>
                        <button
                          onClick={() => removeFile(index)}
                          className="p-2 text-slate-500 hover:text-red-400 transition-colors hover:bg-red-400/10 rounded"
                        >
                          <X className="w-4 h-4" />
                        </button>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}


            {/* Enhanced Scan Button */}
            {uploadedFiles.length > 0 && !isScanning && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.4 }}
                className="mt-6"
              >
                <motion.button
                  onClick={startScan}
                  whileHover={{ scale: 1.02, boxShadow: "0 0 25px rgba(34, 211, 238, 0.4)" }}
                  whileTap={{ scale: 0.98 }}
                  className="w-full relative overflow-hidden bg-gradient-to-r from-cyan-500/20 via-blue-500/20 to-purple-500/20 hover:from-cyan-500/30 hover:via-blue-500/30 hover:to-purple-500/30 border-2 border-cyan-400/30 hover:border-cyan-400/60 rounded-xl p-4 group transition-all duration-300"
                >
                  {/* Animated background effect */}
                  <div className="absolute inset-0 bg-gradient-to-r from-cyan-400/5 via-blue-400/5 to-purple-400/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
                  
                  {/* Scanning line effect */}
                  <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-transparent via-cyan-400 to-transparent opacity-60 animate-pulse" />
                  
                  <div className="relative z-10 flex items-center justify-center space-x-3">
                    <div className="w-10 h-10 bg-gradient-to-br from-cyan-400 to-blue-500 rounded-full flex items-center justify-center group-hover:rotate-180 transition-transform duration-500">
                      <Play className="w-5 h-5 text-white ml-0.5" />
                    </div>
                    <div className="text-left">
                      <HackerText 
                        text="INITIATE SECURITY SCAN"
                        className="text-lg font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-purple-400"
                        delay={0}
                        speed={40}
                      />
                      <p className="text-slate-400 font-mono text-sm mt-1">
                        {uploadedFiles.length} files ready • {scanConfig.enableAI ? 'AI + ' : ''}{scanConfig.enableStatic ? 'Static' : ''} Analysis
                      </p>
                    </div>
                  </div>
                  
                  {/* Glowing border effect */}
                  <div className="absolute inset-0 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300 bg-gradient-to-r from-cyan-400/10 via-blue-400/10 to-purple-400/10 blur-sm" />
                </motion.button>
              </motion.div>
            )}

            {/* Error Display */}
            {error && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.3 }}
                className="mt-4 p-4 bg-red-900/20 border border-red-400/30 rounded-lg"
              >
                <div className="flex items-center space-x-2">
                  <AlertTriangle className="w-5 h-5 text-red-400" />
                  <p className="text-red-400 font-mono font-bold text-sm">[ERROR]</p>
                </div>
                <p className="text-red-300 font-mono text-sm mt-2">{error}</p>
              </motion.div>
            )}
          </HolographicCard>
        </motion.div>

        {/* Configuration Panel */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.6, delay: 0.4 }}
          className="space-y-6"
        >
          <HolographicCard variant="secondary">
            <div className="mb-4">
              <HackerText 
                text="ANALYSIS CONFIG"
                className="text-lg font-bold text-purple-400 mb-1"
                delay={600}
                speed={25}
              />
              <p className="text-slate-400 font-mono text-xs">Configure scan parameters</p>
            </div>

            <div className="space-y-4">
              {/* Analysis Types - More Compact */}
              <div>
                <h3 className="text-sm font-bold text-cyan-400 mb-3 font-mono">
                  [ANALYSIS] Methods
                </h3>
                <div className="grid grid-cols-1 gap-2">
                  <motion.label 
                    className="flex items-center space-x-3 p-2 bg-slate-800/30 rounded border border-slate-700/50 hover:border-cyan-400/30 transition-all cursor-pointer"
                    whileHover={{ scale: 1.01 }}
                  >
                    <input
                      type="checkbox"
                      checked={scanConfig.enableStatic}
                      onChange={(e) => setScanConfig(prev => ({ ...prev, enableStatic: e.target.checked }))}
                      className="w-3 h-3 text-cyan-600 bg-slate-700 border-slate-600 rounded focus:ring-cyan-500"
                    />
                    <Search className="w-4 h-4 text-cyan-400" />
                    <div className="flex-1">
                      <span className="text-xs font-bold text-slate-200 font-mono">Static Analysis</span>
                    </div>
                  </motion.label>
                  
                  <motion.label 
                    className="flex items-center space-x-3 p-2 bg-slate-800/30 rounded border border-slate-700/50 hover:border-purple-400/30 transition-all cursor-pointer"
                    whileHover={{ scale: 1.01 }}
                  >
                    <input
                      type="checkbox"
                      checked={scanConfig.enableAI}
                      onChange={(e) => setScanConfig(prev => ({ ...prev, enableAI: e.target.checked }))}
                      className="w-3 h-3 text-purple-600 bg-slate-700 border-slate-600 rounded focus:ring-purple-500"
                    />
                    <Brain className="w-4 h-4 text-purple-400" />
                    <div className="flex-1">
                      <span className="text-xs font-bold text-slate-200 font-mono">AI Analysis</span>
                    </div>
                  </motion.label>
                </div>
              </div>

              {/* AI Provider Selection - Compact */}
              {scanConfig.enableAI && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  transition={{ duration: 0.3 }}
                  className="space-y-3"
                >
                  <h3 className="text-sm font-bold text-purple-400 mb-2 font-mono">
                    [AI] Provider
                  </h3>
                  <div className="grid grid-cols-3 gap-1">
                    {[
                      { id: 'openai', name: 'GPT-4', icon: Bot, color: 'emerald' },
                      { id: 'claude', name: 'Claude', icon: Zap, color: 'orange' },
                      { id: 'gemini', name: 'Gemini', icon: Cpu, color: 'blue' }
                    ].map((provider) => (
                      <motion.label 
                        key={provider.id}
                        className={`flex flex-col items-center p-2 rounded border transition-all cursor-pointer ${
                          scanConfig.aiProvider === provider.id 
                            ? `border-${provider.color}-400 bg-${provider.color}-900/20` 
                            : 'border-slate-700/50 hover:border-slate-600'
                        }`}
                        whileHover={{ scale: 1.02 }}
                      >
                        <input
                          type="radio"
                          name="aiProvider"
                          value={provider.id}
                          checked={scanConfig.aiProvider === provider.id}
                          onChange={(e) => setScanConfig(prev => ({ ...prev, aiProvider: e.target.value as any }))}
                          className="sr-only"
                        />
                        <provider.icon className={`w-4 h-4 text-${provider.color}-400 mb-1`} />
                        <span className="text-xs font-mono text-slate-300">{provider.name}</span>
                      </motion.label>
                    ))}
                  </div>
                  
                  {/* API Key Status */}
                  <div className="mt-3">
                    <div className="flex items-center justify-between p-2 bg-slate-800/30 rounded border border-slate-700/50">
                      <span className="text-xs text-slate-400 font-mono">API Key Status</span>
                      <div className="flex items-center space-x-2">
                        {getStoredApiKey(scanConfig.aiProvider) ? (
                          <>
                            <div className="w-2 h-2 bg-green-400 rounded-full"></div>
                            <span className="text-xs text-green-400 font-mono">Configured</span>
                          </>
                        ) : (
                          <>
                            <div className="w-2 h-2 bg-red-400 rounded-full"></div>
                            <span className="text-xs text-red-400 font-mono">Missing</span>
                          </>
                        )}
                      </div>
                    </div>
                    {!getStoredApiKey(scanConfig.aiProvider) && (
                      <p className="text-xs text-yellow-400 font-mono mt-1">
                        Configure API keys in Settings → AI Provider API Keys
                      </p>
                    )}
                  </div>
                </motion.div>
              )}

              {/* Advanced Settings - Compact */}
              <div className="space-y-3">
                <h3 className="text-sm font-bold text-cyan-400 mb-2 font-mono">
                  [ADVANCED] Settings
                </h3>
                <div>
                  <div>
                    <label className="block text-xs text-slate-400 mb-1 font-mono">
                      Format
                    </label>
                    <select
                      value={scanConfig.outputFormat}
                      onChange={(e) => setScanConfig(prev => ({ ...prev, outputFormat: e.target.value }))}
                      className="w-full px-2 py-1 bg-slate-800/50 border border-slate-600 rounded font-mono text-xs text-slate-200 focus:border-cyan-400"
                    >
                      <option value="json">JSON</option>
                      <option value="yaml">YAML</option>
                      <option value="csv">CSV</option>
                      <option value="html">HTML</option>
                    </select>
                  </div>
                </div>

              </div>

            </div>
          </HolographicCard>

        </motion.div>
      </div>

      {/* Scan Progress Indicator - Shows during scan instead of terminal */}
      {isScanning && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: 20 }}
          transition={{ duration: 0.5 }}
          className="relative z-10"
        >
          <HolographicCard variant="primary">
            <div className="mb-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className="w-3 h-3 bg-cyan-400 rounded-full animate-pulse" />
                  <HackerText 
                    text="SECURITY SCAN IN PROGRESS"
                    className="text-lg font-bold text-cyan-400"
                    delay={0}
                    speed={20}
                  />
                </div>
                <div className="flex items-center space-x-4">
                  <span className="text-sm text-slate-400 font-mono">
                    Progress: {Math.round(scanProgress)}%
                  </span>
                  <div className="flex items-center space-x-2">
                    <div className="w-2 h-2 bg-emerald-400 rounded-full animate-pulse" />
                    <span className="text-xs text-emerald-400 font-mono">ACTIVE</span>
                  </div>
                  <button
                    onClick={cancelScan}
                    disabled={isCancelling || scanProgress >= 90}
                    className="group relative px-3 py-1 text-xs font-mono bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 hover:border-red-500 rounded-md transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <div className="flex items-center space-x-1">
                      <StopCircle className="w-3 h-3" />
                      <span>{isCancelling ? 'STOPPING...' : 'STOP'}</span>
                    </div>
                    {/* Neon glow effect */}
                    <div className="absolute inset-0 rounded-md bg-red-500/20 opacity-0 group-hover:opacity-100 transition-opacity blur-sm -z-10" />
                  </button>
                </div>
              </div>
            </div>
            
            {/* Progress Bar */}
            <div className="mb-4">
              <div className="w-full bg-slate-800/50 rounded-full h-3 overflow-hidden">
                <motion.div
                  className="h-3 bg-gradient-to-r from-cyan-400 to-purple-400 rounded-full shadow-[0_0_15px_rgba(34,211,238,0.6)]"
                  initial={{ width: '0%' }}
                  animate={{ width: `${scanProgress}%` }}
                  transition={{ duration: 0.5 }}
                />
              </div>
            </div>
            
            <div className="flex items-center justify-between text-sm font-mono">
              <span className="text-slate-400">
                Files: {uploadedFiles.length} | Processed: {Math.floor(scanProgress / 100 * uploadedFiles.length)}
              </span>
              <span className="text-cyan-400">
                Scanning in progress...
              </span>
            </div>
          </HolographicCard>
        </motion.div>
      )}

      {/* Operation Timeline - Only show during scanning */}
      {isScanning && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -20 }}
          transition={{ duration: 0.5 }}
          className="relative z-10"
        >
          <HolographicCard variant="secondary">
            <div className="mb-6">
              <div className="flex items-center justify-between">
                <div>
                  <HackerText 
                    text="OPERATION TIMELINE"
                    className="text-xl font-bold text-cyan-400 mb-2"
                    delay={0}
                    speed={25}
                  />
                  <p className="text-sm text-slate-400 font-mono">
                    {isScanning ? 'Real-time security scan progress' : 'Completed security scan operations'}
                  </p>
                </div>
                {isScanning && (
                  <div className="flex items-center space-x-2">
                    <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse" />
                    <span className="text-xs text-green-400 font-mono font-bold">LIVE</span>
                  </div>
                )}
              </div>
            </div>
            
            <ScanTimeline items={getCurrentTimelineData()} currentStep={currentStep} isScanning={isScanning} />
          </HolographicCard>
        </motion.div>
      )}

      {/* Scan Results - Show after timeline */}
      {scanResults && !isScanning && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
          className="relative z-10"
        >
          <HolographicCard variant="success">
            <div className="mb-6">
              <div className="flex items-center space-x-3">
                <div className="w-12 h-12 bg-green-500/20 border border-green-400/30 rounded-full flex items-center justify-center">
                  <CheckCircle className="w-6 h-6 text-green-400" />
                </div>
                <div>
                  <HackerText 
                    text="SCAN COMPLETE"
                    className="text-xl font-bold text-green-400 mb-1"
                    delay={0}
                    speed={30}
                  />
                  <p className="text-slate-400 font-mono text-sm">Security analysis finished successfully</p>
                </div>
              </div>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
              <div className="bg-slate-800/30 rounded-lg p-4 border border-slate-700/50">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400 font-mono text-sm">Vulnerabilities</span>
                  <AlertTriangle className="w-4 h-4 text-orange-400" />
                </div>
                <p className="text-2xl font-bold text-orange-400 font-mono mt-1">
                  {scanResults.total_vulnerabilities || 0}
                </p>
              </div>
              
              <div className="bg-slate-800/30 rounded-lg p-4 border border-slate-700/50">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400 font-mono text-sm">Files Scanned</span>
                  <FileText className="w-4 h-4 text-cyan-400" />
                </div>
                <p className="text-2xl font-bold text-cyan-400 font-mono mt-1">
                  {scanResults.files_scanned || 0}
                </p>
              </div>
              
              <div className="bg-slate-800/30 rounded-lg p-4 border border-slate-700/50">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400 font-mono text-sm">Duration</span>
                  <Zap className="w-4 h-4 text-purple-400" />
                </div>
                <p className="text-2xl font-bold text-purple-400 font-mono mt-1">
                  {scanResults.scan_duration?.toFixed(2)}s
                </p>
              </div>
            </div>
            
            {/* Severity Breakdown */}
            {scanResults.severity_counts && (
              <div className="mb-6">
                <h3 className="text-lg font-bold text-cyan-400 font-mono mb-3">[SEVERITY] Breakdown</h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  <div className="bg-red-900/20 border border-red-400/30 rounded-lg p-3 text-center">
                    <p className="text-red-400 font-mono text-xs font-bold">CRITICAL</p>
                    <p className="text-red-400 font-mono text-xl font-bold mt-1">
                      {scanResults.severity_counts.CRITICAL || 0}
                    </p>
                  </div>
                  <div className="bg-orange-900/20 border border-orange-400/30 rounded-lg p-3 text-center">
                    <p className="text-orange-400 font-mono text-xs font-bold">HIGH</p>
                    <p className="text-orange-400 font-mono text-xl font-bold mt-1">
                      {scanResults.severity_counts.HIGH || 0}
                    </p>
                  </div>
                  <div className="bg-yellow-900/20 border border-yellow-400/30 rounded-lg p-3 text-center">
                    <p className="text-yellow-400 font-mono text-xs font-bold">MEDIUM</p>
                    <p className="text-yellow-400 font-mono text-xl font-bold mt-1">
                      {scanResults.severity_counts.MEDIUM || 0}
                    </p>
                  </div>
                  <div className="bg-blue-900/20 border border-blue-400/30 rounded-lg p-3 text-center">
                    <p className="text-blue-400 font-mono text-xs font-bold">LOW</p>
                    <p className="text-blue-400 font-mono text-xl font-bold mt-1">
                      {scanResults.severity_counts.LOW || 0}
                    </p>
                  </div>
                </div>
              </div>
            )}
            
            {/* Action Buttons */}
            <div className="flex flex-col sm:flex-row gap-3">
              {scanResults.total_vulnerabilities > 0 && (
                <button
                  onClick={handleViewDetailedResults}
                  className="flex-1 px-6 py-3 bg-gradient-to-r from-cyan-500/20 to-blue-500/20 border border-cyan-400/30 text-cyan-400 rounded-lg hover:bg-gradient-to-r hover:from-cyan-500/30 hover:to-blue-500/30 transition-all duration-200 font-mono font-bold text-sm"
                >
                  📋 View Detailed Results
                </button>
              )}
              <button
                onClick={() => {
                  setScanResults(null);
                  setScanOutput([]);
                  setError(null);
                }}
                className="px-6 py-3 bg-slate-700/50 border border-slate-600 text-slate-300 rounded-lg hover:bg-slate-700/70 transition-all duration-200 font-mono text-sm"
              >
                🔄 New Scan
              </button>
            </div>
          </HolographicCard>
        </motion.div>
      )}

      {/* Report Modal - Same as ScanHistory */}
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
                    Scan ID: {scanId?.substring(0, 8)}...
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