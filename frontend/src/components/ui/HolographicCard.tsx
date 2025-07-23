import React from 'react';
import { motion } from 'framer-motion';

interface HolographicCardProps {
  children: React.ReactNode;
  className?: string;
  variant?: 'primary' | 'secondary';
}

export default function HolographicCard({ 
  children, 
  className = "", 
  variant = 'primary'
}: HolographicCardProps) {
  const variants = {
    primary: 'border-cyan-500/30 bg-slate-900/80 hover:border-cyan-400/50',
    secondary: 'border-slate-600/30 bg-slate-800/80 hover:border-slate-500/50'
  };
  
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, ease: "easeOut" }}
      className={`
        relative group
        rounded-xl border backdrop-blur-sm
        transition-all duration-150 ease-out
        hover:scale-[1.01]
        ${variants[variant]}
        ${className}
      `}
    >
      {/* Subtle corner indicators */}
      <div className="absolute top-2 left-2 w-3 h-3 opacity-60">
        <div className="absolute top-0 left-0 w-full h-[1px] bg-cyan-400" />
        <div className="absolute top-0 left-0 w-[1px] h-full bg-cyan-400" />
      </div>
      <div className="absolute top-2 right-2 w-3 h-3 opacity-60">
        <div className="absolute top-0 right-0 w-full h-[1px] bg-cyan-400" />
        <div className="absolute top-0 right-0 w-[1px] h-full bg-cyan-400" />
      </div>
      
      {/* Content */}
      <div className="relative z-10 p-6">
        {children}
      </div>
      
      {/* Subtle hover glow */}
      <div className="absolute inset-0 rounded-xl bg-cyan-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-150 ease-out" />
    </motion.div>
  );
}
