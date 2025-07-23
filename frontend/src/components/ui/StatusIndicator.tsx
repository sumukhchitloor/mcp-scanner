import React from 'react';
import { motion } from 'framer-motion';

interface StatusIndicatorProps {
  status: 'online' | 'scanning' | 'offline' | 'alert';
  label: string;
  className?: string;
}

export default function StatusIndicator({ status, label, className = "" }: StatusIndicatorProps) {
  const statusConfig = {
    online: {
      color: 'bg-emerald-400',
      glow: 'shadow-emerald-400/50',
      text: 'text-emerald-400',
      animation: { opacity: [1, 0.6, 1] }
    },
    scanning: {
      color: 'bg-cyan-400',
      glow: 'shadow-cyan-400/50',
      text: 'text-cyan-400',
      animation: { scale: [1, 1.2, 1], opacity: [1, 0.7, 1] }
    },
    offline: {
      color: 'bg-gray-500',
      glow: 'shadow-gray-500/50',
      text: 'text-gray-500',
      animation: { opacity: [0.5, 0.5, 0.5] }
    },
    alert: {
      color: 'bg-red-400',
      glow: 'shadow-red-400/50',
      text: 'text-red-400',
      animation: { scale: [1, 1.3, 1] }
    }
  };

  const config = statusConfig[status];

  return (
    <div className={`flex items-center space-x-2 ${className}`}>
      <motion.div
        className={`w-2 h-2 rounded-full ${config.color} ${config.glow} shadow-lg`}
        animate={config.animation}
        transition={{
          duration: status === 'alert' ? 0.5 : 2,
          repeat: Infinity,
          ease: "easeInOut"
        }}
      />
      <span className={`text-sm font-mono ${config.text}`}>
        {label}
      </span>
    </div>
  );
}