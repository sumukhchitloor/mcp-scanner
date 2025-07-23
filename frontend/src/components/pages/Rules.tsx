import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { 
  Shield, 
  Plus, 
  Search,
  Filter,
  Edit,
  Trash2,
  Eye,
  AlertTriangle,
  Code,
  Settings,
  CheckCircle
} from 'lucide-react';

interface SecurityRule {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  enabled: boolean;
  patterns: string[];
  cweId: string;
  lastModified: string;
  detectionCount: number;
}

export default function Rules() {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [selectedRule, setSelectedRule] = useState<SecurityRule | null>(null);

  // Mock data
  const securityRules: SecurityRule[] = [
    {
      id: 'sql-injection-string-concat',
      name: 'SQL Injection - String Concatenation',
      description: 'Detects SQL injection vulnerabilities through string concatenation in database queries',
      category: 'injection',
      severity: 'CRITICAL',
      enabled: true,
      patterns: ['SELECT.*\\+.*', 'INSERT.*\\+.*', 'UPDATE.*\\+.*', 'DELETE.*\\+.*'],
      cweId: 'CWE-89',
      lastModified: '2025-07-15T10:30:00Z',
      detectionCount: 23
    },
    {
      id: 'command-injection-os-system',
      name: 'Command Injection - OS System',
      description: 'Identifies command injection risks when using os.system() with user input',
      category: 'injection',
      severity: 'HIGH',
      enabled: true,
      patterns: ['os\\.system\\(', 'subprocess\\.call\\(.*shell=True.*\\)'],
      cweId: 'CWE-78',
      lastModified: '2025-07-14T14:20:00Z',
      detectionCount: 15
    },
    {
      id: 'hardcoded-credentials',
      name: 'Hardcoded Credentials',
      description: 'Finds hardcoded passwords, API keys, and other sensitive credentials in source code',
      category: 'authentication',
      severity: 'HIGH',
      enabled: true,
      patterns: ['password\\s*=\\s*["\'].*["\']', 'api_key\\s*=\\s*["\'].*["\']', 'secret\\s*=\\s*["\'].*["\']'],
      cweId: 'CWE-798',
      lastModified: '2025-07-16T09:15:00Z',
      detectionCount: 8
    },
    {
      id: 'path-traversal-user-input',
      name: 'Path Traversal Vulnerability',
      description: 'Detects path traversal vulnerabilities in file operations with user input',
      category: 'file-security',
      severity: 'MEDIUM',
      enabled: true,
      patterns: ['open\\(.*\\+.*\\)', 'file\\(.*\\+.*\\)', '\\.\\./'],
      cweId: 'CWE-22',
      lastModified: '2025-07-13T16:45:00Z',
      detectionCount: 12
    },
    {
      id: 'weak-random-generation',
      name: 'Weak Random Number Generation',
      description: 'Identifies use of predictable random number generators for security purposes',
      category: 'cryptography',
      severity: 'LOW',
      enabled: true,
      patterns: ['random\\.randint\\(', 'random\\.choice\\(', 'random\\.random\\('],
      cweId: 'CWE-338',
      lastModified: '2025-07-12T11:30:00Z',
      detectionCount: 5
    },
    {
      id: 'xss-direct-output',
      name: 'Cross-Site Scripting (XSS)',
      description: 'Detects potential XSS vulnerabilities from direct user input output',
      category: 'input-validation',
      severity: 'MEDIUM',
      enabled: false,
      patterns: ['innerHTML\\s*=.*', 'document\\.write\\(.*\\)', 'eval\\(.*\\)'],
      cweId: 'CWE-79',
      lastModified: '2025-07-11T13:20:00Z',
      detectionCount: 0
    }
  ];

  const categories = [
    { id: 'all', name: 'All Categories', count: securityRules.length },
    { id: 'injection', name: 'Injection', count: securityRules.filter(r => r.category === 'injection').length },
    { id: 'authentication', name: 'Authentication', count: securityRules.filter(r => r.category === 'authentication').length },
    { id: 'file-security', name: 'File Security', count: securityRules.filter(r => r.category === 'file-security').length },
    { id: 'cryptography', name: 'Cryptography', count: securityRules.filter(r => r.category === 'cryptography').length },
    { id: 'input-validation', name: 'Input Validation', count: securityRules.filter(r => r.category === 'input-validation').length }
  ];

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return <AlertTriangle className="w-4 h-4 text-red-600" />;
      case 'HIGH':
        return <AlertTriangle className="w-4 h-4 text-orange-500" />;
      case 'MEDIUM':
        return <AlertTriangle className="w-4 h-4 text-yellow-500" />;
      case 'LOW':
        return <AlertTriangle className="w-4 h-4 text-blue-500" />;
      default:
        return <AlertTriangle className="w-4 h-4 text-gray-500" />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-red-100 text-red-800 border-red-200 dark:bg-red-900 dark:text-red-200 dark:border-red-800';
      case 'HIGH':
        return 'bg-orange-100 text-orange-800 border-orange-200 dark:bg-orange-900 dark:text-orange-200 dark:border-orange-800';
      case 'MEDIUM':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200 dark:bg-yellow-900 dark:text-yellow-200 dark:border-yellow-800';
      case 'LOW':
        return 'bg-blue-100 text-blue-800 border-blue-200 dark:bg-blue-900 dark:text-blue-200 dark:border-blue-800';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200 dark:bg-gray-900 dark:text-gray-200 dark:border-gray-800';
    }
  };

  const filteredRules = securityRules.filter(rule => {
    const matchesCategory = selectedCategory === 'all' || rule.category === selectedCategory;
    const matchesSearch = rule.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         rule.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         rule.cweId.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesCategory && matchesSearch;
  });

  const toggleRule = (ruleId: string) => {
    // TODO: Implement rule toggle logic
    console.log('Toggle rule:', ruleId);
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
        className="flex items-center justify-between"
      >
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
            Security Rules
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            Manage and configure security scanning rules for vulnerability detection
          </p>
        </div>
        
        <motion.button
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          onClick={() => console.log('Create rule functionality not implemented')}
          className="flex items-center space-x-2 px-4 py-2 bg-gradient-to-r from-primary-600 to-secondary-600 hover:from-primary-700 hover:to-secondary-700 text-white rounded-lg transition-all duration-200 shadow-lg"
        >
          <Plus className="w-5 h-5" />
          <span>Create Rule</span>
        </motion.button>
      </motion.div>

      {/* Stats Cards */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.1 }}
        className="grid grid-cols-1 md:grid-cols-4 gap-6"
      >
        <div className="glass-card p-6 rounded-xl">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Total Rules</p>
              <p className="text-3xl font-bold text-gray-900 dark:text-white">
                {securityRules.length}
              </p>
            </div>
            <Shield className="w-8 h-8 text-primary-500" />
          </div>
        </div>

        <div className="glass-card p-6 rounded-xl">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Enabled</p>
              <p className="text-3xl font-bold text-green-600">
                {securityRules.filter(r => r.enabled).length}
              </p>
            </div>
            <CheckCircle className="w-8 h-8 text-green-500" />
          </div>
        </div>

        <div className="glass-card p-6 rounded-xl">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Categories</p>
              <p className="text-3xl font-bold text-blue-600">
                {categories.length - 1}
              </p>
            </div>
            <Filter className="w-8 h-8 text-blue-500" />
          </div>
        </div>

        <div className="glass-card p-6 rounded-xl">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Total Detections</p>
              <p className="text-3xl font-bold text-purple-600">
                {securityRules.reduce((sum, rule) => sum + rule.detectionCount, 0)}
              </p>
            </div>
            <AlertTriangle className="w-8 h-8 text-purple-500" />
          </div>
        </div>
      </motion.div>

      {/* Filters and Search */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.2 }}
        className="glass-card rounded-xl p-6"
      >
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between space-y-4 lg:space-y-0">
          <div className="flex flex-col sm:flex-row sm:items-center space-y-4 sm:space-y-0 sm:space-x-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search rules..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10 pr-4 py-2 w-full sm:w-64 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
              />
            </div>

            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
            >
              {categories.map(category => (
                <option key={category.id} value={category.id}>
                  {category.name} ({category.count})
                </option>
              ))}
            </select>
          </div>

          <div className="text-sm text-gray-600 dark:text-gray-400">
            Showing {filteredRules.length} of {securityRules.length} rules
          </div>
        </div>
      </motion.div>

      {/* Rules List */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.3 }}
        className="space-y-4"
      >
        {filteredRules.map((rule, index) => (
          <motion.div
            key={rule.id}
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.5, delay: index * 0.1 }}
            className="glass-card rounded-xl p-6 hover:shadow-lg transition-all duration-200"
          >
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center space-x-3 mb-2">
                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => toggleRule(rule.id)}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                        rule.enabled ? 'bg-primary-600' : 'bg-gray-300 dark:bg-gray-600'
                      }`}
                    >
                      <span
                        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                          rule.enabled ? 'translate-x-6' : 'translate-x-1'
                        }`}
                      />
                    </button>
                    {getSeverityIcon(rule.severity)}
                  </div>
                  
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                    {rule.name}
                  </h3>
                  
                  <span className={`px-2 py-1 rounded-full text-xs font-medium border ${getSeverityColor(rule.severity)}`}>
                    {rule.severity}
                  </span>
                  
                  <span className="px-2 py-1 bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200 rounded-full text-xs font-medium">
                    {rule.cweId}
                  </span>
                </div>

                <p className="text-gray-600 dark:text-gray-400 mb-3">
                  {rule.description}
                </p>

                <div className="flex items-center space-x-6 text-sm text-gray-500">
                  <span className="capitalize">Category: {rule.category.replace('-', ' ')}</span>
                  <span>Detections: {rule.detectionCount}</span>
                  <span>Patterns: {rule.patterns.length}</span>
                  <span>Modified: {new Date(rule.lastModified).toLocaleDateString()}</span>
                </div>
              </div>

              <div className="flex items-center space-x-2 ml-4">
                <button
                  onClick={() => setSelectedRule(rule)}
                  className="p-2 text-gray-400 hover:text-primary-600 transition-colors"
                  title="View Details"
                >
                  <Eye className="w-5 h-5" />
                </button>
                <button
                  className="p-2 text-gray-400 hover:text-blue-600 transition-colors"
                  title="Edit Rule"
                >
                  <Edit className="w-5 h-5" />
                </button>
                <button
                  className="p-2 text-gray-400 hover:text-red-600 transition-colors"
                  title="Delete Rule"
                >
                  <Trash2 className="w-5 h-5" />
                </button>
              </div>
            </div>
          </motion.div>
        ))}
      </motion.div>

      {/* Rule Detail Modal */}
      {selectedRule && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50"
          onClick={() => setSelectedRule(null)}
        >
          <motion.div
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            className="bg-white dark:bg-gray-800 rounded-xl p-6 max-w-4xl w-full max-h-[90vh] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center space-x-3">
                {getSeverityIcon(selectedRule.severity)}
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
                  {selectedRule.name}
                </h2>
                <span className={`px-3 py-1 rounded-full text-sm font-medium border ${getSeverityColor(selectedRule.severity)}`}>
                  {selectedRule.severity}
                </span>
              </div>
              <button
                onClick={() => setSelectedRule(null)}
                className="p-2 text-gray-400 hover:text-gray-600 transition-colors"
              >
                <Settings className="w-6 h-6" />
              </button>
            </div>

            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                  Description
                </h3>
                <p className="text-gray-600 dark:text-gray-400">
                  {selectedRule.description}
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                    Rule Information
                  </h3>
                  <div className="space-y-2 text-sm">
                    <div className="flex items-center space-x-2">
                      <span className="font-medium">Category:</span>
                      <span className="capitalize">{selectedRule.category.replace('-', ' ')}</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className="font-medium">CWE ID:</span>
                      <span>{selectedRule.cweId}</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className="font-medium">Status:</span>
                      <span className={selectedRule.enabled ? 'text-green-600' : 'text-red-600'}>
                        {selectedRule.enabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </div>
                  </div>
                </div>

                <div>
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                    Statistics
                  </h3>
                  <div className="space-y-2 text-sm">
                    <div className="flex items-center space-x-2">
                      <span className="font-medium">Detections:</span>
                      <span>{selectedRule.detectionCount}</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className="font-medium">Last Modified:</span>
                      <span>{new Date(selectedRule.lastModified).toLocaleString()}</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className="font-medium">Pattern Count:</span>
                      <span>{selectedRule.patterns.length}</span>
                    </div>
                  </div>
                </div>
              </div>

              <div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                  Detection Patterns
                </h3>
                <div className="space-y-2">
                  {selectedRule.patterns.map((pattern, index) => (
                    <div key={index} className="bg-gray-100 dark:bg-gray-900 rounded-lg p-3 font-mono text-sm">
                      <div className="flex items-center space-x-2 mb-1">
                        <Code className="w-4 h-4 text-gray-500" />
                        <span className="text-gray-500">Pattern {index + 1}</span>
                      </div>
                      <pre className="text-blue-600 dark:text-blue-400">
                        {pattern}
                      </pre>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </motion.div>
        </motion.div>
      )}
    </div>
  );
}
