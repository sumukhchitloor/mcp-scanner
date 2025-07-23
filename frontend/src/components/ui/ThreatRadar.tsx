import React from 'react';
import { motion } from 'framer-motion';

interface ThreatRadarProps {
  vulnerabilities: { type: string; count: number; severity: 'critical' | 'high' | 'medium' | 'low' }[];
  size?: number;
  className?: string;
}

export default function ThreatRadar({ vulnerabilities = [], size = 200, className = '' }: ThreatRadarProps) {
  const maxCount = Math.max(...vulnerabilities.map(v => v.count), 1);
  
  const getSeverityColor = (severity: string) => {
    const colors = {
      critical: '#ef4444',
      high: '#f97316', 
      medium: '#eab308',
      low: '#3b82f6'
    };
    return colors[severity as keyof typeof colors] || colors.low;
  };

  const getAngle = (index: number, total: number) => {
    return (index * 360) / total;
  };

  const getRadius = (count: number) => {
    return (count / maxCount) * (size * 0.35);
  };

  return (
    <div className={`relative ${className}`} style={{ width: size, height: size }}>
      {/* Radar circles */}
      <div className="absolute inset-0 flex items-center justify-center">
        {[0.25, 0.5, 0.75, 1].map((scale, index) => (
          <motion.div
            key={index}
            className="absolute border border-cyan-400/20 rounded-full"
            style={{ 
              width: size * scale, 
              height: size * scale,
            }}
            animate={{
              opacity: [0.2, 0.4, 0.2],
            }}
            transition={{
              duration: 3,
              repeat: Infinity,
              delay: index * 0.5
            }}
          />
        ))}
      </div>

      {/* Scanning line */}
      <motion.div
        className="absolute inset-0"
        animate={{
          rotate: [0, 360]
        }}
        transition={{
          duration: 4,
          repeat: Infinity,
          ease: "linear"
        }}
      >
        <div 
          className="absolute bg-gradient-to-r from-transparent via-cyan-400/60 to-transparent"
          style={{
            width: size * 0.5,
            height: 1,
            top: '50%',
            left: '50%',
            transformOrigin: '0 0',
            transform: 'translateY(-0.5px)'
          }}
        />
      </motion.div>

      {/* Threat points */}
      <div className="absolute inset-0 flex items-center justify-center">
        {vulnerabilities.map((vuln, index) => {
          const angle = getAngle(index, vulnerabilities.length);
          const radius = getRadius(vuln.count);
          const x = Math.cos((angle - 90) * Math.PI / 180) * radius;
          const y = Math.sin((angle - 90) * Math.PI / 180) * radius;

          return (
            <motion.div
              key={`${vuln.type}-${index}`}
              className="absolute"
              style={{
                transform: `translate(${x}px, ${y}px)`,
              }}
              initial={{ scale: 0, opacity: 0 }}
              animate={{ 
                scale: [0, 1.2, 1],
                opacity: [0, 1, 0.8]
              }}
              transition={{
                duration: 0.8,
                delay: index * 0.2,
                repeat: Infinity,
                repeatDelay: 3
              }}
            >
              <div 
                className="w-3 h-3 rounded-full shadow-lg"
                style={{ 
                  backgroundColor: getSeverityColor(vuln.severity),
                  boxShadow: `0 0 12px ${getSeverityColor(vuln.severity)}80`
                }}
              />
              
              {/* Threat label - positioned to avoid overlap */}
              <motion.div
                className={`absolute left-1/2 transform -translate-x-1/2 bg-slate-800/95 border border-red-400/30 px-2 py-1 rounded text-xs font-mono text-red-400 whitespace-nowrap shadow-lg z-30 ${
                  index % 2 === 0 ? '-top-10' : '-bottom-10'
                }`}
                initial={{ opacity: 0, y: 5, scale: 0.8 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                transition={{ delay: index * 0.2 + 0.5 }}
                style={{
                  backdropFilter: 'blur(8px)'
                }}
              >
                <div className="text-center">
                  <div className="font-bold">{vuln.count}</div>
                  <div className="text-xs opacity-80">{vuln.type.split(' ')[0]}</div>
                </div>
              </motion.div>
            </motion.div>
          );
        })}
      </div>

      {/* Center indicator */}
      <div className="absolute inset-0 flex items-center justify-center">
        <motion.div
          className="w-4 h-4 bg-cyan-400 rounded-full shadow-lg"
          style={{
            boxShadow: '0 0 20px #22d3ee'
          }}
          animate={{
            scale: [1, 1.2, 1],
            opacity: [0.8, 1, 0.8]
          }}
          transition={{
            duration: 2,
            repeat: Infinity
          }}
        />
      </div>

      {/* Radar labels */}
      <div className="absolute inset-0">
        {['N', 'E', 'S', 'W'].map((direction, index) => {
          const angle = index * 90;
          const x = Math.cos((angle - 90) * Math.PI / 180) * (size * 0.45);
          const y = Math.sin((angle - 90) * Math.PI / 180) * (size * 0.45);

          return (
            <div
              key={direction}
              className="absolute text-xs font-mono text-cyan-400/60"
              style={{
                transform: `translate(${x + size/2 - 4}px, ${y + size/2 - 6}px)`,
              }}
            >
              {direction}
            </div>
          );
        })}
      </div>
    </div>
  );
}