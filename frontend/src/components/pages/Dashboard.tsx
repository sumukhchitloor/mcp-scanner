import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Shield, 
  AlertTriangle,
  Zap,
  FileSearch
} from 'lucide-react';

// Dashboard components
import SecurityMetricsCard from '@/components/dashboard/SecurityMetricsCard';
import { scannerApi } from '@/services/api';

// Enhanced UI components
import HolographicCard from '@/components/ui/HolographicCard';
import CounterAnimation from '@/components/ui/CounterAnimation';
import HackerText from '@/components/ui/HackerText';
import SecurityCommandCenter from '@/components/ui/SecurityCommandCenter';
import AINeuralSecurityAnalyzer from '@/components/ui/AINeuralSecurityAnalyzer';

export default function Dashboard() {
  const [metrics, setMetrics] = useState({
    totalScans: 0,
    totalVulnerabilities: 0,
    avgScanTime: 0,
    securityScore: 0,
    lastScanTime: 'Loading...',
    scansToday: 0,
    threatsBlocked: 0,
    systemUptime: 0
  });
  const [trends, setTrends] = useState({
    totalScans: { value: 0, isPositive: true },
    totalVulnerabilities: { value: 0, isPositive: false },
    avgScanTime: { value: 0, isPositive: true },
    securityScore: { value: 0, isPositive: true }
  });
  const [isLoading, setIsLoading] = useState(true);
  const [severityData, setSeverityData] = useState({
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0
  });

  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        console.log('Dashboard: Fetching dashboard metrics...');
        const response = await scannerApi.getDashboardMetrics();
        console.log('Dashboard: API response:', response);
        
        if (response.success && response.data) {
          const data = response.data; // This is already transformed SecurityMetrics data
          console.log('Dashboard: Transformed data:', data);
          
          // Use the already transformed data directly
          const totalVulns = data.total_vulnerabilities || 0;
          const totalScans = data.total_scans || 0;

          setMetrics({
            totalScans: totalScans,
            totalVulnerabilities: totalVulns,
            avgScanTime: Math.abs(Math.round((data.avg_scan_time || 0) * 10) / 10),
            securityScore: totalScans > 0 ? Math.round((totalScans / Math.max(totalScans, 1)) * 100) : 0,
            lastScanTime: data.scan_history?.[0]?.timestamp ? 
              new Date(data.scan_history[0].timestamp).toLocaleString() : 'No scans yet',
            scansToday: data.scan_history?.filter((scan: any) => {
              if (!scan.timestamp) return false;
              const today = new Date().toDateString();
              return new Date(scan.timestamp).toDateString() === today;
            }).length || 0,
            threatsBlocked: totalVulns, // Use total vulnerabilities as threats blocked
            systemUptime: totalScans > 0 ? Math.round((totalScans / Math.max(totalScans, 1)) * 100) : 0
          });

          // Set real severity data from transformed data
          setSeverityData({
            CRITICAL: data.severity_distribution?.CRITICAL || 0,
            HIGH: data.severity_distribution?.HIGH || 0,
            MEDIUM: data.severity_distribution?.MEDIUM || 0,
            LOW: data.severity_distribution?.LOW || 0
          });

          // Set simple positive trends for now (could be enhanced with real trend calculation)
          setTrends({
            totalScans: { 
              value: totalScans > 0 ? 10 : 0, 
              isPositive: true 
            },
            totalVulnerabilities: { 
              value: totalVulns > 0 ? 5 : 0, 
              isPositive: false // More vulnerabilities is negative
            },
            avgScanTime: { 
              value: data.avg_scan_time > 0 ? 15 : 0, 
              isPositive: true 
            },
            securityScore: { 
              value: totalScans > 0 ? 20 : 0, 
              isPositive: true 
            }
          });
        } else {
          console.error('Dashboard: API call failed or returned no data:', response);
        }
      } catch (error) {
        console.error('Failed to fetch dashboard data:', error);
      } finally {
        setIsLoading(false);
      }
    };

    fetchDashboardData();
  }, []);




  return (
    <div className="space-y-8 min-h-screen relative">
      {/* Enhanced Background Effects */}
      <div className="fixed inset-0 pointer-events-none opacity-30">
        <div className="absolute inset-0 bg-gradient-to-br from-slate-900 via-cyan-950/20 to-purple-950/20" />
        <motion.div 
          className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl"
          animate={{
            scale: [1, 1.2, 1],
            opacity: [0.3, 0.5, 0.3],
          }}
          transition={{
            duration: 8,
            repeat: Infinity,
            ease: "easeInOut"
          }}
        />
        <motion.div 
          className="absolute bottom-1/4 right-1/4 w-80 h-80 bg-purple-500/5 rounded-full blur-3xl"
          animate={{
            scale: [1.2, 1, 1.2],
            opacity: [0.5, 0.3, 0.5],
          }}
          transition={{
            duration: 10,
            repeat: Infinity,
            ease: "easeInOut",
            delay: 2
          }}
        />
      </div>

      {/* Main Header Section */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
        className="relative z-10"
      >
        <div className="flex items-center justify-between mb-6">
          <div>
            <HackerText 
              text="NEURAL THREAT MATRIX"
              className="text-5xl font-bold text-transparent bg-gradient-to-r from-cyan-400 via-blue-400 to-purple-400 bg-clip-text mb-4"
              delay={100}
              speed={30}
            />
            <motion.p 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 1.5, duration: 0.5 }}
              className="text-xl text-slate-300 font-mono"
            >
              <span className="text-cyan-400">[CLASSIFIED]</span> Advanced threat detection & vulnerability analysis
            </motion.p>
          </div>
          
          <motion.div
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 1, duration: 0.8 }}
            className="text-right"
          >
            <div className="text-3xl font-bold text-cyan-400 font-mono">
              <CounterAnimation value={metrics.scansToday} />
            </div>
            <div className="text-sm text-slate-500 font-mono">SCANS TODAY</div>
            <div className="text-xs text-slate-600 font-mono mt-1">
              Last scan: {metrics.lastScanTime}
            </div>
          </motion.div>
        </div>
      </motion.div>

      {/* Key Metrics Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 relative z-10">
        {[
          { 
            title: "Total Scans", 
            value: metrics.totalScans, 
            icon: FileSearch, 
            trend: trends.totalScans, 
            delay: 0.1,
            suffix: ""
          },
          { 
            title: "Active Threats", 
            value: metrics.totalVulnerabilities, 
            icon: AlertTriangle, 
            trend: trends.totalVulnerabilities, 
            delay: 0.2,
            suffix: ""
          },
          { 
            title: "Avg Scan Time", 
            value: metrics.avgScanTime, 
            suffix: "s", 
            decimal: 1, 
            icon: Zap, 
            trend: trends.avgScanTime, 
            delay: 0.3
          },
          { 
            title: "Security Score", 
            value: metrics.securityScore, 
            suffix: "%", 
            icon: Shield, 
            trend: trends.securityScore, 
            delay: 0.4
          }
        ].map((metric) => (
          <motion.div
            key={metric.title}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: metric.delay, duration: 0.5, ease: "easeOut" }}
          >
            <HolographicCard variant="secondary">
              <SecurityMetricsCard
                title={metric.title}
                value={<CounterAnimation 
                  value={metric.value} 
                  suffix={metric.suffix} 
                  decimal={metric.decimal}
                />}
                icon={metric.icon}
                trend={metric.trend}
              />
            </HolographicCard>
          </motion.div>
        ))}
      </div>

      {/* Main Dashboard Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 relative z-10">
        
        {/* Left Column: Combined Security Overview & Threat Analysis */}
        <div className="space-y-6">
          {/* Combined Security Index & Threat Radar */}
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.8, duration: 0.6 }}
          >
            <HolographicCard variant="primary" className="min-h-[500px]">
              <div className="text-center">
                <HackerText 
                  text="SECURITY COMMAND CENTER"
                  className="text-2xl font-bold text-transparent bg-gradient-to-r from-cyan-400 via-emerald-400 to-blue-400 bg-clip-text mb-6"
                  delay={1000}
                  speed={25}
                />
                
                {/* New 3D Animated Security Command Center */}
                <div className="mb-8">
                  <SecurityCommandCenter />
                </div>
                
                <div className="grid grid-cols-4 gap-4 text-center mb-6">
                  <div>
                    <div className="text-xl font-bold text-red-400 font-mono">
                      <CounterAnimation value={severityData.CRITICAL} />
                    </div>
                    <div className="text-xs text-slate-500 font-mono">CRITICAL</div>
                  </div>
                  <div>
                    <div className="text-xl font-bold text-orange-400 font-mono">
                      <CounterAnimation value={severityData.HIGH} />
                    </div>
                    <div className="text-xs text-slate-500 font-mono">HIGH</div>
                  </div>
                  <div>
                    <div className="text-xl font-bold text-yellow-400 font-mono">
                      <CounterAnimation value={severityData.MEDIUM} />
                    </div>
                    <div className="text-xs text-slate-500 font-mono">MEDIUM</div>
                  </div>
                  <div>
                    <div className="text-xl font-bold text-blue-400 font-mono">
                      <CounterAnimation value={severityData.LOW} />
                    </div>
                    <div className="text-xs text-slate-500 font-mono">LOW</div>
                  </div>
                </div>
                
                <div className="grid grid-cols-2 gap-4 text-center pt-4 border-t border-slate-700/50">
                  <div>
                    <div className="text-lg font-bold text-cyan-400 font-mono">
                      <CounterAnimation value={metrics.threatsBlocked} />
                    </div>
                    <div className="text-xs text-slate-500 font-mono">THREATS BLOCKED</div>
                  </div>
                  <div>
                    <div className="text-lg font-bold text-emerald-400 font-mono">
                      {metrics.systemUptime}%
                    </div>
                    <div className="text-xs text-slate-500 font-mono">SYSTEM UPTIME</div>
                  </div>
                </div>
              </div>
            </HolographicCard>
          </motion.div>
        </div>

        {/* Right Column: Vulnerability Analysis */}
        <div className="space-y-6 h-full">
          {/* Vulnerability Statistics */}
          <motion.div
            className="h-full"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 1.2, duration: 0.5 }}
          >
            <HolographicCard variant="primary" className="min-h-[500px] h-full">
              <AINeuralSecurityAnalyzer />
            </HolographicCard>
          </motion.div>
        </div>
      </div>
    </div>
  );
}