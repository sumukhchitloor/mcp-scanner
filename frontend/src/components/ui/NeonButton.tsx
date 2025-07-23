import React from 'react';
import { motion } from 'framer-motion';

interface NeonButtonProps {
  children: React.ReactNode;
  onClick?: () => void;
  variant?: 'primary' | 'secondary' | 'danger' | 'success';
  size?: 'sm' | 'md' | 'lg';
  className?: string;
  disabled?: boolean;
  pulse?: boolean;
}

export default function NeonButton({
  children,
  onClick,
  variant = 'primary',
  size = 'md',
  className = "",
  disabled = false,
  pulse = false
}: NeonButtonProps) {
  const variants = {
    primary: {
      bg: 'bg-blue-600/20',
      border: 'border-blue-400',
      text: 'text-blue-400',
      shadow: 'shadow-blue-500/50',
      glow: '#3b82f6'
    },
    secondary: {
      bg: 'bg-purple-600/20',
      border: 'border-purple-400', 
      text: 'text-purple-400',
      shadow: 'shadow-purple-500/50',
      glow: '#8b5cf6'
    },
    danger: {
      bg: 'bg-red-600/20',
      border: 'border-red-400',
      text: 'text-red-400', 
      shadow: 'shadow-red-500/50',
      glow: '#ef4444'
    },
    success: {
      bg: 'bg-green-600/20',
      border: 'border-green-400',
      text: 'text-green-400',
      shadow: 'shadow-green-500/50',
      glow: '#10b981'
    }
  };

  const sizes = {
    sm: 'px-4 py-2 text-sm',
    md: 'px-6 py-3 text-base',
    lg: 'px-8 py-4 text-lg'
  };

  const variantStyles = variants[variant];
  const sizeStyles = sizes[size];

  const baseStyles = 'relative rounded-lg font-semibold font-mono border transition-all duration-150 ease-out backdrop-blur-sm';
  const interactionStyles = !disabled 
    ? 'hover:scale-[1.02] active:scale-[0.98] hover:shadow-lg' 
    : 'opacity-50 cursor-not-allowed';
  
  const buttonClass = `${baseStyles} ${variantStyles.bg} ${variantStyles.border} ${variantStyles.text} ${sizeStyles} ${interactionStyles} ${className}`;

  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={buttonClass}
      style={pulse ? {
        animation: 'pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite'
      } : undefined}
    >
      {/* Content */}
      <span className="relative z-10 flex items-center justify-center">
        {children}
      </span>
      
      {/* Subtle hover glow */}
      <div className="absolute inset-0 rounded-lg bg-gradient-to-r from-transparent via-white/5 to-transparent opacity-0 hover:opacity-100 transition-opacity duration-150" />
    </button>
  );
}
