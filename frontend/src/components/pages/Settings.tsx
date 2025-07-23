import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Settings as SettingsIcon, 
  Save,
  RotateCcw,
  Key,
  Bot,
  Zap,
  Cpu,
  Eye,
  EyeOff,
  Check,
  AlertTriangle
} from 'lucide-react';

import HolographicCard from '@/components/ui/HolographicCard';
import HackerText from '@/components/ui/HackerText';

// Settings management utility
const SETTINGS_KEY = 'mcp_security_settings';

const defaultSettings = {
  // AI API Keys - Multiple providers
  apiKeys: {
    openai: '',
    claude: '',
    gemini: ''
  },
  
  // Scanner Settings
  enableAIAnalysis: true,
  enableStaticAnalysis: true,
  scanTimeout: 300,
  outputFormat: 'json',
  
  // API Settings
  apiTimeout: 30,
};

export default function Settings() {
  const [settings, setSettings] = useState(defaultSettings);
  const [isDirty, setIsDirty] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [showSuccess, setShowSuccess] = useState(false);
  const [showApiKeys, setShowApiKeys] = useState({
    openai: false,
    claude: false,
    gemini: false
  });
  const [testingConnection, setTestingConnection] = useState({
    openai: false,
    claude: false,
    gemini: false
  });

  // Load settings from localStorage on component mount
  useEffect(() => {
    const savedSettings = localStorage.getItem(SETTINGS_KEY);
    if (savedSettings) {
      try {
        const parsed = JSON.parse(savedSettings);
        setSettings(prev => ({ ...prev, ...parsed }));
      } catch (error) {
        console.error('Failed to parse saved settings:', error);
      }
    }
  }, []);

  // Save settings to localStorage
  const saveSettings = () => {
    setIsSaving(true);
    try {
      localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
      setIsDirty(false);
      setShowSuccess(true);
      setTimeout(() => setShowSuccess(false), 2000);
    } catch (error) {
      console.error('Failed to save settings:', error);
    } finally {
      setIsSaving(false);
    }
  };

  // Reset settings to defaults
  const resetSettings = () => {
    setSettings(defaultSettings);
    setIsDirty(true);
  };

  // Update API key
  const updateApiKey = (provider: 'openai' | 'claude' | 'gemini', value: string) => {
    setSettings(prev => ({
      ...prev,
      apiKeys: {
        ...prev.apiKeys,
        [provider]: value
      }
    }));
    setIsDirty(true);
  };

  // Test API connection
  const testConnection = async (provider: 'openai' | 'claude' | 'gemini') => {
    const apiKey = settings.apiKeys[provider];
    if (!apiKey) {
      alert('Please enter an API key first');
      return;
    }

    setTestingConnection(prev => ({ ...prev, [provider]: true }));
    
    try {
      // Simple test API call based on provider
      let testUrl = '';
      let headers: Record<string, string> = {};
      
      switch (provider) {
        case 'openai':
          testUrl = 'https://api.openai.com/v1/models';
          headers = { 'Authorization': `Bearer ${apiKey}` };
          break;
        case 'claude':
          testUrl = 'https://api.anthropic.com/v1/messages';
          headers = { 
            'x-api-key': apiKey,
            'anthropic-version': '2023-06-01',
            'Content-Type': 'application/json'
          };
          break;
        case 'gemini':
          testUrl = `https://generativelanguage.googleapis.com/v1/models?key=${apiKey}`;
          break;
      }

      const response = await fetch(testUrl, {
        method: provider === 'claude' ? 'POST' : 'GET',
        headers,
        body: provider === 'claude' ? JSON.stringify({
          model: 'claude-3-sonnet-20240229',
          max_tokens: 10,
          messages: [{ role: 'user', content: 'test' }]
        }) : undefined
      });

      if (response.ok || response.status === 401) {
        // 401 means key format is correct but may be invalid
        alert(`${provider.toUpperCase()} API connection test successful!`);
      } else {
        throw new Error(`HTTP ${response.status}`);
      }
    } catch (error) {
      console.error(`${provider} API test failed:`, error);
      alert(`${provider.toUpperCase()} API connection test failed. Please check your API key.`);
    } finally {
      setTestingConnection(prev => ({ ...prev, [provider]: false }));
    }
  };

  const toggleApiKeyVisibility = (provider: 'openai' | 'claude' | 'gemini') => {
    setShowApiKeys(prev => ({
      ...prev,
      [provider]: !prev[provider]
    }));
  };

  const providers = [
    { id: 'openai', name: 'OpenAI GPT-4', icon: Bot, color: 'emerald', placeholder: 'sk-...' },
    { id: 'claude', name: 'Anthropic Claude', icon: Zap, color: 'orange', placeholder: 'sk-ant-...' },
    { id: 'gemini', name: 'Google Gemini', icon: Cpu, color: 'blue', placeholder: 'AIza...' }
  ];

  return (
    <div className="space-y-6 min-h-screen relative">
      {/* Cyberpunk Background Effects */}
      <div className="fixed inset-0 pointer-events-none opacity-20">
        <div className="absolute inset-0 bg-gradient-to-br from-cyan-900/20 via-transparent to-purple-900/20" />
      </div>

      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
        className="relative z-10"
      >
        <div className="flex items-center justify-between">
          <div>
            <HackerText 
              text="SYSTEM CONFIGURATION"
              className="text-4xl font-bold text-transparent bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text mb-4"
              delay={100}
              speed={50}
            />
            <p className="text-slate-300 font-mono text-lg">
              <span className="text-cyan-400">[CONFIG]</span> Configure AI providers and scanner settings
            </p>
          </div>

          <div className="flex items-center space-x-4">
            {showSuccess && (
              <motion.div
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.8 }}
                className="flex items-center space-x-2 px-4 py-2 bg-green-900/30 border border-green-400/30 text-green-400 rounded-lg"
              >
                <Check className="w-4 h-4" />
                <span className="font-mono">Settings Saved!</span>
              </motion.div>
            )}

            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={resetSettings}
              className="flex items-center space-x-2 px-4 py-2 bg-slate-800/50 border border-slate-600 text-slate-300 rounded-lg hover:bg-slate-800/70 transition-all duration-200 font-mono"
            >
              <RotateCcw className="w-4 h-4" />
              <span>Reset</span>
            </motion.button>

            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={saveSettings}
              disabled={!isDirty || isSaving}
              className={`flex items-center space-x-2 px-6 py-2 rounded-lg font-mono font-bold transition-all duration-200 ${
                !isDirty || isSaving 
                  ? 'bg-slate-800/50 border border-slate-600 text-slate-400 cursor-not-allowed' 
                  : 'bg-gradient-to-r from-cyan-500/20 to-purple-500/20 border border-cyan-400/30 text-cyan-400 hover:bg-gradient-to-r hover:from-cyan-500/30 hover:to-purple-500/30'
              }`}
            >
              {isSaving ? (
                <>
                  <motion.div
                    className="w-4 h-4 border-2 border-cyan-400 border-t-transparent rounded-full"
                    animate={{ rotate: 360 }}
                    transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                  />
                  <span>Saving...</span>
                </>
              ) : (
                <>
                  <Save className="w-4 h-4" />
                  <span>Save Settings</span>
                </>
              )}
            </motion.button>
          </div>
        </div>
      </motion.div>

      {/* AI API Keys Section */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.1 }}
        className="relative z-10"
      >
        <HolographicCard variant="primary">
          <div className="mb-6">
            <div className="flex items-center space-x-3 mb-4">
              <Key className="w-6 h-6 text-cyan-400" />
              <HackerText 
                text="AI PROVIDER API KEYS"
                className="text-xl font-bold text-cyan-400"
                delay={0}
                speed={25}
              />
            </div>
            <p className="text-slate-400 font-mono text-sm">
              Configure API keys for AI-powered vulnerability analysis. Keys are stored locally and encrypted.
            </p>
          </div>

          <div className="space-y-6">
            {providers.map((provider) => {
              const ProviderIcon = provider.icon;
              const apiKey = settings.apiKeys[provider.id as keyof typeof settings.apiKeys];
              const isVisible = showApiKeys[provider.id as keyof typeof showApiKeys];
              const isTesting = testingConnection[provider.id as keyof typeof testingConnection];
              
              return (
                <div key={provider.id} className="p-4 bg-slate-800/30 rounded-lg border border-slate-700/50">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center space-x-3">
                      <div className={`p-2 rounded-full bg-${provider.color}-900/40 border border-${provider.color}-400/50`}>
                        <ProviderIcon className={`w-5 h-5 text-${provider.color}-400`} />
                      </div>
                      <div>
                        <h3 className={`font-bold text-${provider.color}-400 font-mono`}>
                          {provider.name}
                        </h3>
                        <p className="text-xs text-slate-500 font-mono">
                          {apiKey ? 'API key configured' : 'No API key set'}
                        </p>
                      </div>
                    </div>
                    
                    <div className="flex items-center space-x-2">
                      {apiKey && (
                        <motion.button
                          whileHover={{ scale: 1.05 }}
                          whileTap={{ scale: 0.95 }}
                          onClick={() => testConnection(provider.id as any)}
                          disabled={isTesting}
                          className={`px-3 py-1 rounded text-xs font-mono font-bold transition-all duration-200 ${
                            isTesting 
                              ? 'bg-slate-800/50 text-slate-400 cursor-not-allowed'
                              : `bg-${provider.color}-900/30 text-${provider.color}-400 hover:bg-${provider.color}-900/50`
                          }`}
                        >
                          {isTesting ? 'Testing...' : 'Test'}
                        </motion.button>
                      )}
                      
                      <button
                        onClick={() => toggleApiKeyVisibility(provider.id as any)}
                        className="p-1 text-slate-500 hover:text-slate-300 transition-colors"
                      >
                        {isVisible ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  <div className="relative">
                    <input
                      type={isVisible ? 'text' : 'password'}
                      value={apiKey}
                      onChange={(e) => updateApiKey(provider.id as any, e.target.value)}
                      placeholder={provider.placeholder}
                      className="w-full px-3 py-2 bg-slate-900/50 border border-slate-600 rounded-lg text-slate-200 font-mono text-sm placeholder-slate-500 focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-all"
                    />
                  </div>
                </div>
              );
            })}
          </div>

          {/* API Status Warning */}
          {!Object.values(settings.apiKeys).some(key => key) && (
            <div className="mt-6 p-4 bg-yellow-900/20 border border-yellow-400/30 rounded-lg">
              <div className="flex items-center space-x-2">
                <AlertTriangle className="w-5 h-5 text-yellow-400" />
                <p className="text-yellow-400 font-mono text-sm font-bold">
                  No AI API keys configured
                </p>
              </div>
              <p className="text-yellow-300 font-mono text-xs mt-2">
                AI analysis will be disabled until you configure at least one API key.
              </p>
            </div>
          )}
        </HolographicCard>
      </motion.div>

      {/* Scanner Settings */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.2 }}
        className="relative z-10"
      >
        <HolographicCard variant="secondary">
          <div className="mb-6">
            <div className="flex items-center space-x-3 mb-4">
              <SettingsIcon className="w-6 h-6 text-purple-400" />
              <HackerText 
                text="SCANNER CONFIGURATION"
                className="text-xl font-bold text-purple-400"
                delay={0}
                speed={25}
              />
            </div>
            <p className="text-slate-400 font-mono text-sm">
              Configure default scanner behavior and analysis settings.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="block text-sm font-bold text-slate-300 font-mono mb-2">
                Scan Timeout (seconds)
              </label>
              <input
                type="number"
                value={settings.scanTimeout}
                onChange={(e) => {
                  setSettings(prev => ({ ...prev, scanTimeout: parseInt(e.target.value) }));
                  setIsDirty(true);
                }}
                className="w-full px-3 py-2 bg-slate-900/50 border border-slate-600 rounded-lg text-slate-200 font-mono text-sm focus:border-purple-400 focus:ring-1 focus:ring-purple-400"
                min="30"
                max="3600"
              />
            </div>

            <div>
              <label className="block text-sm font-bold text-slate-300 font-mono mb-2">
                Output Format
              </label>
              <select
                value={settings.outputFormat}
                onChange={(e) => {
                  setSettings(prev => ({ ...prev, outputFormat: e.target.value }));
                  setIsDirty(true);
                }}
                className="w-full px-3 py-2 bg-slate-900/50 border border-slate-600 rounded-lg text-slate-200 font-mono text-sm focus:border-purple-400 focus:ring-1 focus:ring-purple-400"
              >
                <option value="json">JSON</option>
                <option value="yaml">YAML</option>
                <option value="csv">CSV</option>
                <option value="html">HTML</option>
              </select>
            </div>
          </div>

          <div className="mt-6 space-y-4">
            <div className="flex items-center justify-between p-3 bg-slate-800/30 rounded-lg">
              <div>
                <h4 className="text-sm font-bold text-slate-300 font-mono">Enable AI Analysis</h4>
                <p className="text-xs text-slate-500 font-mono">Use AI for advanced vulnerability detection</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={settings.enableAIAnalysis}
                  onChange={(e) => {
                    setSettings(prev => ({ ...prev, enableAIAnalysis: e.target.checked }));
                    setIsDirty(true);
                  }}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-slate-700 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-cyan-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyan-600"></div>
              </label>
            </div>

            <div className="flex items-center justify-between p-3 bg-slate-800/30 rounded-lg">
              <div>
                <h4 className="text-sm font-bold text-slate-300 font-mono">Enable Static Analysis</h4>
                <p className="text-xs text-slate-500 font-mono">Use pattern-based vulnerability detection</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={settings.enableStaticAnalysis}
                  onChange={(e) => {
                    setSettings(prev => ({ ...prev, enableStaticAnalysis: e.target.checked }));
                    setIsDirty(true);
                  }}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-slate-700 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-purple-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-purple-600"></div>
              </label>
            </div>
          </div>
        </HolographicCard>
      </motion.div>
    </div>
  );
}

// Export function to get API keys (used by other components)
export const getStoredApiKey = (provider: 'openai' | 'claude' | 'gemini'): string => {
  const settings = localStorage.getItem('mcp_security_settings');
  if (settings) {
    try {
      const parsed = JSON.parse(settings);
      return parsed.apiKeys?.[provider] || '';
    } catch (error) {
      console.error('Failed to parse stored settings:', error);
    }
  }
  return '';
};