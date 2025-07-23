import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';

interface CounterAnimationProps {
  value: number;
  duration?: number;
  className?: string;
  prefix?: string;
  suffix?: string;
  decimal?: number;
  onComplete?: () => void;
}

export default function CounterAnimation({
  value,
  duration = 2,
  className = "",
  prefix = "",
  suffix = "",
  decimal = 0,
  onComplete
}: CounterAnimationProps) {
  const [displayValue, setDisplayValue] = useState(0);
  
  useEffect(() => {
    let startTime: number;
    let animationFrame: number;
    
    const animateCount = (timestamp: number) => {
      if (!startTime) startTime = timestamp;
      const progress = Math.min((timestamp - startTime) / (duration * 1000), 1);
      
      // Easing function for smooth animation
      const easeOutQuart = 1 - Math.pow(1 - progress, 4);
      
      const currentValue = easeOutQuart * value;
      setDisplayValue(currentValue);
      
      if (progress < 1) {
        animationFrame = requestAnimationFrame(animateCount);
      } else {
        setDisplayValue(value);
        if (onComplete) onComplete();
      }
    };
    
    animationFrame = requestAnimationFrame(animateCount);
    
    return () => {
      if (animationFrame) {
        cancelAnimationFrame(animationFrame);
      }
    };
  }, [value, duration, onComplete]);
  
  const formatValue = (val: number) => {
    if (decimal > 0) {
      return val.toFixed(decimal);
    }
    return Math.floor(val).toString();
  };
  
  return (
    <motion.span
      initial={{ opacity: 0, scale: 0.5 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.5 }}
      className={`font-mono tabular-nums ${className}`}
    >
      {prefix}
      <motion.span
        key={value}
        initial={{ y: 20, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ duration: 0.3 }}
      >
        {formatValue(displayValue)}
      </motion.span>
      {suffix}
    </motion.span>
  );
}