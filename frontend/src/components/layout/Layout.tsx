import React from 'react';
import { motion } from 'framer-motion';
import { useNavigate, useLocation } from 'react-router-dom';
import { 
  Shield, 
  BarChart3, 
  Search, 
  FileText, 
  Settings, 
  Menu,
  X,
  Moon,
  Sun,
  Github,
  ExternalLink,
  History
} from 'lucide-react';

import { useUIStore } from '@/stores';
import { cn } from '@/utils/cn';

const navigation = [
  { name: 'Dashboard', href: '/dashboard', icon: BarChart3 },
  { name: 'Scanner', href: '/scanner', icon: Search },
  { name: 'Scan History', href: '/scan-history', icon: History },
  { name: 'Rules', href: '/rules', icon: Shield },
  { name: 'Settings', href: '/settings', icon: Settings },
];

interface LayoutProps {
  children: React.ReactNode;
}

export default function Layout({ children }: LayoutProps) {
  const { theme, sidebarCollapsed, setTheme, toggleSidebar } = useUIStore();
  const navigate = useNavigate();
  const location = useLocation();

  const handleNavigation = (href: string, name: string) => {
    navigate(href);
  };

  // Get current view from location
  const getCurrentView = () => {
    const path = location.pathname;
    if (path === '/' || path === '/dashboard') return 'dashboard';
    if (path.startsWith('/scan-history')) return 'scan history';
    return path.substring(1);
  };

  const activeView = getCurrentView();

  return (
    <div className="flex h-screen bg-gray-50 dark:bg-gray-900">
      {/* Sidebar */}
      <motion.aside
        initial={false}
        animate={{
          width: sidebarCollapsed ? 80 : 280,
        }}
        transition={{ duration: 0.3, ease: 'easeInOut' }}
        className={cn(
          'flex flex-col bg-gradient-to-b from-gray-900 via-gray-900 to-gray-950 dark:from-gray-900 dark:via-gray-900 dark:to-gray-950',
          'border-r border-cyan-500/20 shadow-2xl backdrop-blur-xl',
          'relative overflow-hidden'
        )}
      >
        {/* Cyberpunk glow effect */}
        <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/5 via-transparent to-blue-500/5 pointer-events-none" />
        <div className="absolute top-0 left-0 w-full h-px bg-gradient-to-r from-transparent via-cyan-400/30 to-transparent" />
        
        {/* Logo */}
        <div className="flex items-center justify-between p-6 relative z-10">
          <motion.div
            animate={{ opacity: sidebarCollapsed ? 0 : 1 }}
            transition={{ duration: 0.2 }}
            className="flex items-center space-x-3"
          >
            <div className="w-10 h-10 bg-gradient-to-br from-cyan-400 to-blue-600 rounded-xl flex items-center justify-center shadow-lg border border-cyan-400/30 relative">
              <div className="absolute inset-0 bg-gradient-to-br from-cyan-400/20 to-blue-600/20 rounded-xl blur-sm" />
              <Shield className="w-6 h-6 text-white relative z-10" />
            </div>
            {!sidebarCollapsed && (
              <div>
                <h1 className="text-xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-400">MCP Security</h1>
                <p className="text-sm text-gray-400">Neural Defense System</p>
              </div>
            )}
          </motion.div>
          
          <button
            onClick={toggleSidebar}
            className={cn(
              'p-2 rounded-lg hover:bg-cyan-500/20 border border-transparent hover:border-cyan-400/30',
              'transition-all duration-200 text-cyan-400 hover:text-cyan-300'
            )}
          >
            {sidebarCollapsed ? <Menu className="w-5 h-5" /> : <X className="w-5 h-5" />}
          </button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-4 pb-4 space-y-2 relative z-10">
          {navigation.map((item) => {
            const isActive = activeView === item.name.toLowerCase();
            return (
              <motion.button
                key={item.name}
                onClick={() => handleNavigation(item.href, item.name)}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                className={cn(
                  'w-full flex items-center px-4 py-3 text-left rounded-xl transition-all duration-200 relative group',
                  isActive
                    ? 'bg-gradient-to-r from-cyan-500/20 to-blue-500/20 text-cyan-400 border border-cyan-500/30 shadow-lg shadow-cyan-500/20'
                    : 'hover:bg-gray-800/50 text-gray-300 hover:text-cyan-400 border border-transparent hover:border-cyan-500/20'
                )}
              >
                <item.icon className={cn('w-5 h-5', sidebarCollapsed ? 'mx-auto' : 'mr-3')} />
                {!sidebarCollapsed && (
                  <span className="font-medium">{item.name}</span>
                )}
                {!sidebarCollapsed && isActive && (
                  <motion.div
                    layoutId="activeTab"
                    className="ml-auto w-2 h-2 bg-cyan-400 rounded-full shadow-sm shadow-cyan-400/50"
                  />
                )}
                {isActive && (
                  <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/10 to-blue-500/10 rounded-xl -z-10" />
                )}
              </motion.button>
            );
          })}
        </nav>

        {/* Bottom section */}
        <div className="p-4 border-t border-cyan-500/20 relative z-10">
          <div className="absolute top-0 left-4 right-4 h-px bg-gradient-to-r from-transparent via-cyan-400/30 to-transparent" />
          {/* Theme toggle */}
          <motion.button
            onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            className={cn(
              'w-full flex items-center justify-center p-3 rounded-xl relative group',
              'bg-gray-800/50 hover:bg-cyan-500/20 border border-gray-700 hover:border-cyan-400/30',
              'transition-all duration-200'
            )}
          >
            {theme === 'dark' ? (
              <Sun className="w-5 h-5 text-yellow-400 group-hover:text-yellow-300" />
            ) : (
              <Moon className="w-5 h-5 text-cyan-400 group-hover:text-cyan-300" />
            )}
            {!sidebarCollapsed && (
              <span className="ml-3 text-sm font-medium text-gray-300 group-hover:text-cyan-400">
                {theme === 'dark' ? 'Light Mode' : 'Dark Mode'}
              </span>
            )}
          </motion.button>

          {/* GitHub link */}
          {!sidebarCollapsed && (
            <motion.a
              href="https://github.com/your-repo/mcp-security-scanner"
              target="_blank"
              rel="noopener noreferrer"
              whileHover={{ scale: 1.02 }}
              className="mt-3 w-full flex items-center justify-center p-3 rounded-xl bg-gradient-to-r from-gray-800 to-gray-900 border border-cyan-500/20 text-cyan-400 hover:from-cyan-900/30 hover:to-blue-900/30 hover:border-cyan-400/40 hover:text-cyan-300 transition-all duration-200 shadow-sm"
            >
              <Github className="w-4 h-4 mr-2" />
              <span className="text-sm font-medium">View on GitHub</span>
              <ExternalLink className="w-3 h-3 ml-2" />
            </motion.a>
          )}
        </div>
      </motion.aside>

      {/* Main content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Header - Hide on dashboard */}
        {activeView !== 'dashboard' && (
          <header className="bg-white/80 dark:bg-gray-800/80 backdrop-blur-xl border-b border-gray-200 dark:border-gray-700 px-6 py-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white capitalize">
                  {activeView}
                </h2>
                <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                  {getViewDescription(activeView)}
                </p>
              </div>
              
              {/* Header actions */}
              <div className="flex items-center space-x-4">
                <div className="flex items-center space-x-2">
                  <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                  <span className="text-sm text-gray-600 dark:text-gray-400">Scanner Online</span>
                </div>
              </div>
            </div>
          </header>
        )}

        {/* Main content area */}
        <main className="flex-1 overflow-auto bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-950">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3 }}
            className="p-6"
          >
            {children}
          </motion.div>
        </main>
      </div>
    </div>
  );
}

function getViewDescription(view: string): string {
  const descriptions = {
    dashboard: 'Overview of security metrics and recent scans',
    scanner: 'Run security scans on your MCP servers',
    'scan history': 'Complete archive of all security scan operations',
    rules: 'Configure security rules and detection patterns',
    settings: 'Manage scanner configuration and preferences',
  };
  return descriptions[view as keyof typeof descriptions] || 'MCP Security Scanner';
}
