import React from 'react';
import { motion } from 'framer-motion';
import { Clock, Shield, AlertTriangle, CheckCircle, File, Zap } from 'lucide-react';

interface ScanTimelineItem {
  id: string;
  timestamp: string;
  type: 'scan_start' | 'scan_complete' | 'threat_detected' | 'file_processed';
  title: string;
  details?: string;
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  fileName?: string;
}

interface ScanTimelineProps {
  items: ScanTimelineItem[];
  className?: string;
  currentStep?: number;
  isScanning?: boolean;
}

const typeConfig = {
  scan_start: { icon: Zap, color: 'text-cyan-400', bg: 'bg-cyan-900/20', border: 'border-cyan-400/30' },
  scan_complete: { icon: CheckCircle, color: 'text-green-400', bg: 'bg-green-900/20', border: 'border-green-400/30' },
  threat_detected: { icon: AlertTriangle, color: 'text-red-400', bg: 'bg-red-900/20', border: 'border-red-400/30' },
  file_processed: { icon: File, color: 'text-blue-400', bg: 'bg-blue-900/20', border: 'border-blue-400/30' }
};

export default function ScanTimeline({ items, className = '', currentStep = -1, isScanning = false }: ScanTimelineProps) {
  return (
    <div className={`relative ${className}`}>
      {/* Timeline line */}
      <div className="absolute left-6 top-8 bottom-0 w-px bg-gradient-to-b from-cyan-400/50 via-purple-400/30 to-transparent" />
      
      {/* Progress line that moves down during scan */}
      {isScanning && (
        <motion.div
          className="absolute left-6 top-8 w-px bg-gradient-to-b from-cyan-400 to-purple-400 shadow-[0_0_10px_rgba(34,211,238,0.8)]"
          initial={{ height: 0 }}
          animate={{ height: `${(currentStep + 1) * 100}px` }}
          transition={{ duration: 0.8, ease: "easeInOut" }}
        >
          {/* Moving dot indicator */}
          <motion.div
            className="absolute -left-1 w-3 h-3 bg-cyan-400 rounded-full shadow-[0_0_15px_rgba(34,211,238,0.8)]"
            style={{ top: `${currentStep * 100}px` }}
            animate={{
              boxShadow: [
                '0 0 15px rgba(34,211,238,0.8)',
                '0 0 25px rgba(34,211,238,1)',
                '0 0 15px rgba(34,211,238,0.8)'
              ]
            }}
            transition={{
              duration: 1.5,
              repeat: Infinity,
              ease: "easeInOut"
            }}
          />
        </motion.div>
      )}

      <div className="space-y-6">
        {items.map((item, index) => {
          const config = typeConfig[item.type];
          const IconComponent = config.icon;
          const isCurrentStep = isScanning && index === currentStep;
          const isCompletedStep = isScanning && index < currentStep;
          const isFutureStep = isScanning && index > currentStep;

          return (
            <motion.div
              key={item.id}
              initial={{ opacity: 0, x: -20 }}
              animate={{ 
                opacity: isFutureStep ? 0.4 : 1, 
                x: 0,
                scale: isCurrentStep ? 1.05 : 1
              }}
              transition={{ delay: index * 0.1, duration: 0.5 }}
              className="relative flex items-start space-x-4"
            >
              {/* Timeline node */}
              <motion.div
                className={`relative z-10 p-2 rounded-full ${config.bg} ${config.border} border backdrop-blur-sm ${
                  isCurrentStep ? 'ring-2 ring-cyan-400 ring-offset-2 ring-offset-slate-900' : ''
                } ${isCompletedStep ? 'bg-green-900/30 border-green-400/50' : ''}`}
                animate={{
                  boxShadow: isCurrentStep ? [
                    '0 0 15px rgba(34,211,238,0.3)',
                    '0 0 30px rgba(34,211,238,0.6)',
                    '0 0 15px rgba(34,211,238,0.3)'
                  ] : [
                    '0 0 10px rgba(0,0,0,0.1)',
                    `0 0 20px ${typeConfig[item.type].color.replace('text-', '')}40`,
                    '0 0 10px rgba(0,0,0,0.1)'
                  ]
                }}
                transition={{
                  duration: isCurrentStep ? 1 : 2,
                  repeat: Infinity,
                  ease: "easeInOut"
                }}
              >
                <motion.div
                  animate={isCurrentStep ? {
                    rotate: [0, 360]
                  } : {}}
                  transition={isCurrentStep ? {
                    duration: 2,
                    repeat: Infinity,
                    ease: "linear"
                  } : {}}
                >
                  <IconComponent className={`w-4 h-4 ${
                    isCompletedStep ? 'text-green-400' : 
                    isCurrentStep ? 'text-cyan-400' : 
                    isFutureStep ? 'text-slate-500' : 
                    config.color
                  }`} />
                </motion.div>
              </motion.div>

              {/* Content */}
              <motion.div
                className="flex-1 pb-6"
                initial={{ opacity: 0, y: 10 }}
                animate={{ 
                  opacity: isFutureStep ? 0.4 : 1, 
                  y: 0 
                }}
                transition={{ delay: index * 0.1 + 0.2, duration: 0.4 }}
              >
                <div className={`p-4 rounded-lg ${
                  isCompletedStep ? 'bg-green-900/20 border-green-400/30' : 
                  isCurrentStep ? 'bg-cyan-900/30 border-cyan-400/50' : 
                  isFutureStep ? 'bg-slate-800/20 border-slate-600/30' :
                  config.bg
                } ${
                  isCurrentStep ? 'border-cyan-400/50' :
                  isCompletedStep ? 'border-green-400/30' :
                  config.border
                } border backdrop-blur-sm hover:bg-opacity-60 transition-all duration-200 ${
                  isCurrentStep ? 'shadow-lg shadow-cyan-400/20' : ''
                }`}>
                  <div className="flex items-center justify-between mb-2">
                    <h3 className={`font-bold text-sm font-mono ${
                      isCompletedStep ? 'text-green-400' : 
                      isCurrentStep ? 'text-cyan-400' : 
                      isFutureStep ? 'text-slate-500' : 
                      config.color
                    }`}>
                      {item.title}
                      {isCurrentStep && <span className="ml-2 animate-pulse">●</span>}
                      {isCompletedStep && <span className="ml-2 text-green-400">✓</span>}
                    </h3>
                    <div className="flex items-center space-x-2">
                      <Clock className="w-3 h-3 text-slate-500" />
                      <span className="text-xs text-slate-500 font-mono">
                        {item.timestamp}
                      </span>
                    </div>
                  </div>

                  {item.details && (
                    <p className="text-sm text-slate-300 font-mono mb-2">
                      {item.details}
                    </p>
                  )}

                  {item.fileName && (
                    <div className="flex items-center space-x-2 mt-2">
                      <File className="w-3 h-3 text-slate-500" />
                      <span className="text-xs text-slate-400 font-mono truncate">
                        {item.fileName}
                      </span>
                    </div>
                  )}

                  {item.severity && item.type === 'threat_detected' && (
                    <motion.div
                      className={`inline-block px-2 py-1 mt-2 rounded text-xs font-mono font-bold ${
                        item.severity === 'critical' ? 'bg-red-900/30 text-red-400 border border-red-400/30' :
                        item.severity === 'high' ? 'bg-orange-900/30 text-orange-400 border border-orange-400/30' :
                        item.severity === 'medium' ? 'bg-yellow-900/30 text-yellow-400 border border-yellow-400/30' :
                        'bg-blue-900/30 text-blue-400 border border-blue-400/30'
                      }`}
                      animate={{
                        opacity: item.severity === 'critical' ? [1, 0.5, 1] : 1,
                      }}
                      transition={{
                        duration: 1,
                        repeat: item.severity === 'critical' ? Infinity : 0,
                        ease: "easeInOut"
                      }}
                    >
                      {item.severity.toUpperCase()}
                    </motion.div>
                  )}
                </div>

                {/* Connecting line animation for active scans */}
                {item.type === 'scan_start' && index < items.length - 1 && (
                  <motion.div
                    className="absolute left-6 top-12 w-px bg-gradient-to-b from-cyan-400 to-purple-400"
                    initial={{ height: 0 }}
                    animate={{ height: '60px' }}
                    transition={{ duration: 1, delay: index * 0.1 + 0.5 }}
                  >
                    {/* Animated pulse */}
                    <motion.div
                      className="w-2 h-2 bg-cyan-400 rounded-full -ml-0.5"
                      animate={{
                        y: [0, 60, 0],
                        opacity: [1, 0.3, 1],
                      }}
                      transition={{
                        duration: 2,
                        repeat: Infinity,
                        ease: "easeInOut"
                      }}
                    />
                  </motion.div>
                )}
              </motion.div>
            </motion.div>
          );
        })}
      </div>

      {/* Live indicator at the bottom */}
      <motion.div
        className="flex items-center justify-center mt-6 p-3 bg-slate-800/30 rounded-lg border border-cyan-400/30"
        animate={{
          borderColor: ['rgba(34, 211, 238, 0.3)', 'rgba(34, 211, 238, 0.6)', 'rgba(34, 211, 238, 0.3)']
        }}
        transition={{
          duration: 2,
          repeat: Infinity,
          ease: "easeInOut"
        }}
      >
        <motion.div
          className="w-2 h-2 bg-cyan-400 rounded-full mr-2"
          animate={{
            scale: [1, 1.5, 1],
            opacity: [1, 0.5, 1],
          }}
          transition={{
            duration: 1.5,
            repeat: Infinity,
            ease: "easeInOut"
          }}
        />
        <span className="text-xs font-mono text-cyan-400 font-bold">
          MONITORING ACTIVE
        </span>
      </motion.div>
    </div>
  );
}