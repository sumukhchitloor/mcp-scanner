import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

interface TerminalLine {
  id: string;
  text: string;
  type: 'command' | 'output' | 'error' | 'success' | 'warning';
  timestamp?: string;
}

interface TerminalWindowProps {
  title?: string;
  height?: number;
  lines?: TerminalLine[];
  customOutput?: string[];
  autoScroll?: boolean;
  showPrompt?: boolean;
  className?: string;
  typing?: boolean;
  typingSpeed?: number;
  showProgress?: boolean;
  progressValue?: number;
}

const mockSecurityLogs: TerminalLine[] = [
  { id: '1', text: '> mcp-security-scanner --initialize', type: 'command' },
  { id: '2', text: '[INFO] Initializing MCP Security Scanner v2.1.0', type: 'output' },
  { id: '3', text: '[INFO] Loading vulnerability detection modules...', type: 'output' },
  { id: '4', text: '[SUCCESS] Static analyzer module loaded', type: 'success' },
  { id: '5', text: '[SUCCESS] AI-powered analyzer module loaded', type: 'success' },
  { id: '6', text: '[INFO] Scanning /app/mcp-server for vulnerabilities...', type: 'output' },
  { id: '7', text: '[WARNING] Potential SQL injection detected in auth.py:142', type: 'warning' },
  { id: '8', text: '[ERROR] Critical vulnerability found: Command injection in shell_exec.py:89', type: 'error' },
  { id: '9', text: '[INFO] Deep analysis complete. Generating report...', type: 'output' },
  { id: '10', text: '[SUCCESS] Scan completed. 12 vulnerabilities found.', type: 'success' },
  { id: '11', text: '> _', type: 'command' }
];

export default function TerminalWindow({
  title = "Security Terminal",
  height = 400,
  lines = mockSecurityLogs,
  customOutput = [],
  autoScroll = true,
  showPrompt = true,
  className = "",
  typing = true,
  typingSpeed = 50,
  showProgress = false,
  progressValue = 0
}: TerminalWindowProps) {
  const [displayedLines, setDisplayedLines] = useState<TerminalLine[]>([]);
  const [currentLineIndex, setCurrentLineIndex] = useState(0);
  const [currentChar, setCurrentChar] = useState(0);
  const [showCursor, setShowCursor] = useState(true);
  const scrollRef = useRef<HTMLDivElement>(null);

  // Cursor blinking effect
  useEffect(() => {
    const cursorInterval = setInterval(() => {
      setShowCursor(prev => !prev);
    }, 530);

    return () => clearInterval(cursorInterval);
  }, []);

  // Typing animation effect
  useEffect(() => {
    if (!typing || currentLineIndex >= lines.length) return;

    const currentLine = lines[currentLineIndex];
    const isComplete = currentChar >= currentLine.text.length;

    if (isComplete) {
      setTimeout(() => {
        setCurrentLineIndex(prev => prev + 1);
        setCurrentChar(0);
      }, 500);
    } else {
      const timeout = setTimeout(() => {
        setCurrentChar(prev => prev + 1);
      }, typingSpeed);

      return () => clearTimeout(timeout);
    }
  }, [currentChar, currentLineIndex, typing, lines, typingSpeed]);

  // Update displayed lines
  useEffect(() => {
    if (customOutput.length > 0) {
      const customLines: TerminalLine[] = customOutput.map((text, index) => ({
        id: `custom-${index}`,
        text,
        type: text.includes('[ERROR]') ? 'error' : 
              text.includes('[SUCCESS]') || text.includes('[COMPLETE]') ? 'success' :
              text.includes('[WARNING]') ? 'warning' :
              text.startsWith('[') ? 'output' : 'command'
      }));
      setDisplayedLines(customLines);
      return;
    }

    if (!typing) {
      setDisplayedLines(lines);
      return;
    }

    const newDisplayedLines = lines.slice(0, currentLineIndex).concat(
      currentLineIndex < lines.length 
        ? [{
            ...lines[currentLineIndex],
            text: lines[currentLineIndex].text.slice(0, currentChar)
          }]
        : []
    );

    setDisplayedLines(newDisplayedLines);
  }, [currentLineIndex, currentChar, lines, typing, customOutput]);

  // Auto scroll effect
  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [displayedLines, autoScroll]);

  const getLineColor = (type: string) => {
    const colors = {
      command: 'text-cyan-400',
      output: 'text-gray-300',
      error: 'text-red-400',
      success: 'text-green-400',
      warning: 'text-yellow-400'
    };
    return colors[type as keyof typeof colors] || 'text-gray-300';
  };

  const getLinePrefix = (type: string) => {
    const prefixes = {
      command: '$ ',
      output: '',
      error: '❌ ',
      success: '✅ ',
      warning: '⚠️  '
    };
    return prefixes[type as keyof typeof prefixes] || '';
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className={`bg-black/90 backdrop-blur-sm border border-green-500/30 rounded-lg overflow-hidden shadow-2xl ${className}`}
      style={{ height: `${height}px` }}
    >
      {/* Terminal Header */}
      <div className="bg-gray-800/50 border-b border-green-500/30 px-4 py-2 flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <div className="flex space-x-2">
            <div className="w-3 h-3 rounded-full bg-red-500"></div>
            <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
            <div className="w-3 h-3 rounded-full bg-green-500"></div>
          </div>
          <span className="text-green-400 text-sm font-mono ml-4">{title}</span>
        </div>
        <div className="text-green-400/60 text-xs font-mono">
          {new Date().toLocaleTimeString()}
        </div>
      </div>

      {/* Terminal Body */}
      <div 
        ref={scrollRef}
        className="p-4 font-mono text-sm overflow-y-auto scrollbar-thin scrollbar-thumb-green-500/30 scrollbar-track-transparent"
        style={{ height: `${height - 60}px` }}
      >
        <AnimatePresence>
          {displayedLines.map((line, index) => (
            <motion.div
              key={line.id}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.3, delay: index * 0.05 }}
              className={`mb-1 ${getLineColor(line.type)} flex items-start`}
            >
              <span className="flex-shrink-0">
                {getLinePrefix(line.type)}
              </span>
              <span className="flex-1">
                {line.text}
                {index === displayedLines.length - 1 && typing && currentLineIndex < lines.length && (
                  <span className={`inline-block w-2 h-4 bg-green-400 ml-1 ${showCursor ? 'opacity-100' : 'opacity-0'}`}>
                    
                  </span>
                )}
              </span>
            </motion.div>
          ))}
        </AnimatePresence>

        {/* Prompt line when not typing */}
        {showPrompt && (!typing || currentLineIndex >= lines.length) && (
          <div className="text-cyan-400 flex items-center mt-2">
            <span>$ </span>
            <span className={`inline-block w-2 h-4 bg-cyan-400 ml-1 ${showCursor ? 'opacity-100' : 'opacity-0'}`}>
              
            </span>
          </div>
        )}
      </div>

      {/* Scanning line effect */}
      <motion.div
        className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-green-400 to-transparent opacity-60"
        animate={{
          y: [0, height, 0]
        }}
        transition={{
          duration: 3,
          repeat: Infinity,
          ease: "easeInOut"
        }}
      />

      {/* Corner accents */}
      <div className="absolute top-2 left-2 w-4 h-4">
        <div className="absolute top-0 left-0 w-full h-[1px] bg-green-400" />
        <div className="absolute top-0 left-0 w-[1px] h-full bg-green-400" />
      </div>
      <div className="absolute top-2 right-2 w-4 h-4">
        <div className="absolute top-0 right-0 w-full h-[1px] bg-green-400" />
        <div className="absolute top-0 right-0 w-[1px] h-full bg-green-400" />
      </div>
      <div className="absolute bottom-2 left-2 w-4 h-4">
        <div className="absolute bottom-0 left-0 w-full h-[1px] bg-green-400" />
        <div className="absolute bottom-0 left-0 w-[1px] h-full bg-green-400" />
      </div>
      <div className="absolute bottom-2 right-2 w-4 h-4">
        <div className="absolute bottom-0 right-0 w-full h-[1px] bg-green-400" />
        <div className="absolute bottom-0 right-0 w-[1px] h-full bg-green-400" />
      </div>
    </motion.div>
  );
}