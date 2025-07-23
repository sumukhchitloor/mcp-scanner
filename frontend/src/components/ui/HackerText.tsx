import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';

interface HackerTextProps {
  text: string;
  className?: string;
  delay?: number;
  speed?: number;
  glitch?: boolean;
}

const characters = '!@#$%^&*()_+-=[]{}|;:,.<>?`~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

export default function HackerText({ 
  text, 
  className = "", 
  delay = 0, 
  speed = 50,
  glitch = false 
}: HackerTextProps) {
  const [displayText, setDisplayText] = useState('');
  const [currentIndex, setCurrentIndex] = useState(0);
  const [isAnimating, setIsAnimating] = useState(false);

  useEffect(() => {
    const startAnimation = () => {
      setIsAnimating(true);
      setCurrentIndex(0);
      setDisplayText('');
    };

    const timer = setTimeout(startAnimation, delay);
    return () => clearTimeout(timer);
  }, [delay, text]);

  useEffect(() => {
    if (!isAnimating || currentIndex >= text.length) {
      if (currentIndex >= text.length) {
        setIsAnimating(false);
      }
      return;
    }

    const interval = setInterval(() => {
      setDisplayText(prev => {
        // Add random characters for scrambling effect
        let scrambled = '';
        for (let i = 0; i <= currentIndex; i++) {
          if (i < currentIndex) {
            scrambled += text[i];
          } else {
            scrambled += characters[Math.floor(Math.random() * characters.length)];
          }
        }
        
        // Add extra random characters at the end
        for (let i = currentIndex + 1; i < Math.min(currentIndex + 3, text.length); i++) {
          scrambled += characters[Math.floor(Math.random() * characters.length)];
        }
        
        return scrambled;
      });

      // Progress to next character after several scramble iterations
      if (Math.random() > 0.7) {
        setCurrentIndex(prev => prev + 1);
      }
    }, speed);

    return () => clearInterval(interval);
  }, [isAnimating, currentIndex, text, speed]);

  // Final cleanup - show correct text
  useEffect(() => {
    if (!isAnimating && currentIndex >= text.length) {
      setDisplayText(text);
    }
  }, [isAnimating, currentIndex, text]);

  return (
    <motion.span 
      className={`font-mono ${glitch ? 'animate-pulse' : ''} ${className}`}
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.2 }}
    >
      {displayText}
      {isAnimating && (
        <motion.span
          animate={{ opacity: [1, 0] }}
          transition={{ duration: 0.5, repeat: Infinity }}
          className="text-cyan-400"
        >
          |
        </motion.span>
      )}
    </motion.span>
  );
}