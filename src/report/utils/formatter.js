/**
 * Report Formatter - Data formatting utilities
 */
export class ReportFormatter {
  constructor() {
    this.agentNameMap = this.initializeAgentNames();
    this.riskLevelMap = this.initializeRiskLevels();
    this.complianceMap = this.initializeComplianceMapping();
  }

  /**
   * Initialize agent name mappings
   */
  initializeAgentNames() {
    return {
      resource: 'Resource Monitor',
      system: 'System Security',
      persistence: 'Persistence Analysis',
      process: 'Process Analysis',
      network: 'Network Analysis',
      permission: 'Permission Analysis',
      blockchain: 'Blockchain Security',
      defi: 'DeFi Security'
    };
  }

  /**
   * Initialize risk level mappings
   */
  initializeRiskLevels() {
    return {
      high: {
        label: 'High',
        color: '#dc2626',
        icon: '🔴',
        priority: 1,
        description: 'Immediate attention required'
      },
      medium: {
        label: 'Medium',
        color: '#ca8a04',
        icon: '🟡',
        priority: 2,
        description: 'Should be addressed soon'
      },
      low: {
        label: 'Low',
        color: '#16a34a',
        icon: '🟢',
        priority: 3,
        description: 'Monitor and consider for future improvements'
      },
      unknown: {
        label: 'Unknown',
        color: '#6b7280',
        icon: '⚪',
        priority: 4,
        description: 'Unable to determine risk level'
      }
    };
  }

  /**
   * Initialize compliance framework mappings
   */
  initializeComplianceMapping() {
    return {
      'NIST CSF': {
        'PR.AC': 'Access Control',
        'PR.PT': 'Protective Technology',
        'DE.CM': 'Continuous Monitoring',
        'DE.AE': 'Anomalous Activity'
      },
      'ISO 27001': {
        'A.9': 'Access Control',
        'A.12': 'Operations Security',
        'A.14': 'System Acquisition',
        'A.16': 'Incident Management'
      },
      'SOC 2': {
        'CC6.1': 'Common Criteria',
        'CC6.2': 'Security Operations',
        'CC6.7': 'System Boundaries'
      },
      'PCI DSS': {
        'Req1': 'Firewall Configuration',
        'Req2': 'Default Passwords',
        'Req10': 'Logging and Monitoring'
      }
    };
  }

  /**
   * Format agent name for display
   */
  formatAgentName(agentKey) {
    return this.agentNameMap[agentKey] || 
           agentKey.charAt(0).toUpperCase() + agentKey.slice(1);
  }

  /**
   * Format risk level for display
   */
  formatRiskLevel(risk) {
    return this.riskLevelMap[risk] || this.riskLevelMap.unknown;
  }

  /**
   * Format finding type for display
   */
  formatFindingType(type) {
    return type
      .split(/[\s_-]+/)
      .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
      .join(' ');
  }

  /**
   * Format file size in human readable format
   */
  formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  /**
   * Format duration in human readable format
   */
  formatDuration(seconds) {
    if (seconds < 60) {
      return `${seconds} second${seconds !== 1 ? 's' : ''}`;
    }
    
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    
    if (minutes < 60) {
      return `${minutes} minute${minutes !== 1 ? 's' : ''}${remainingSeconds > 0 ? ` ${remainingSeconds}s` : ''}`;
    }
    
    const hours = Math.floor(minutes / 60);
    const remainingMinutes = minutes % 60;
    
    return `${hours} hour${hours !== 1 ? 's' : ''}${remainingMinutes > 0 ? ` ${remainingMinutes}m` : ''}`;
  }

  /**
   * Format CPU percentage
   */
  formatCPUPercentage(cpu) {
    return `${parseFloat(cpu).toFixed(1)}%`;
  }

  /**
   * Format memory in MB/GB
   */
  formatMemory(bytes) {
    const mb = bytes / (1024 * 1024);
    if (mb < 1024) {
      return `${mb.toFixed(1)} MB`;
    }
    const gb = mb / 1024;
    return `${gb.toFixed(2)} GB`;
  }

  /**
   * Format timestamp
   */
  formatTimestamp(timestamp, format = 'datetime') {
    const date = new Date(timestamp);
    
    switch (format) {
      case 'date':
        return date.toLocaleDateString();
      case 'time':
        return date.toLocaleTimeString();
      case 'datetime':
        return date.toLocaleString();
      case 'iso':
        return date.toISOString();
      case 'relative':
        return this.formatRelativeTime(date);
      default:
        return date.toLocaleString();
    }
  }

  /**
   * Format relative time (e.g., "2 hours ago")
   */
  formatRelativeTime(date) {
    const now = new Date();
    const diffMs = now - date;
    const diffSecs = Math.floor(diffMs / 1000);
    const diffMins = Math.floor(diffSecs / 60);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffDays > 0) {
      return `${diffDays} day${diffDays !== 1 ? 's' : ''} ago`;
    }
    if (diffHours > 0) {
      return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`;
    }
    if (diffMins > 0) {
      return `${diffMins} minute${diffMins !== 1 ? 's' : ''} ago`;
    }
    return `${diffSecs} second${diffSecs !== 1 ? 's' : ''} ago`;
  }

  /**
   * Format process tree for display
   */
  formatProcessTree(processes) {
    const tree = {};
    
    // Build parent-child relationships
    processes.forEach(proc => {
      tree[proc.pid] = { ...proc, children: [] };
    });
    
    // Organize into tree structure
    const roots = [];
    processes.forEach(proc => {
      if (proc.ppid && tree[proc.ppid]) {
        tree[proc.ppid].children.push(tree[proc.pid]);
      } else {
        roots.push(tree[proc.pid]);
      }
    });
    
    return this.formatTreeNode(roots, 0);
  }

  /**
   * Format tree node recursively
   */
  formatTreeNode(nodes, level) {
    let output = '';
    
    nodes.sort((a, b) => a.pid - b.pid).forEach(node => {
      const indent = '  '.repeat(level);
      const prefix = level > 0 ? '├─ ' : '';
      output += `${indent}${prefix}[${node.pid}] ${node.name || 'Unknown'}\n`;
      
      if (node.children && node.children.length > 0) {
        output += this.formatTreeNode(node.children, level + 1);
      }
    });
    
    return output;
  }

  /**
   * Format network connections summary
   */
  formatNetworkSummary(connections) {
    const summary = {
      total: connections.length,
      listening: connections.filter(c => c.state === 'LISTEN').length,
      established: connections.filter(c => c.state === 'ESTABLISHED').length,
      external: connections.filter(c => c.remoteAddress && !c.remoteAddress.startsWith('127.')).length,
      riskyPorts: connections.filter(c => this.isRiskyPort(c.localPort)).length
    };
    
    return `Total: ${summary.total}, Listening: ${summary.listening}, Established: ${summary.established}, External: ${summary.external}, Risky Ports: ${summary.riskyPorts}`;
  }

  /**
   * Check if port is considered risky
   */
  isRiskyPort(port) {
    const riskyPorts = [
      22,    // SSH
      23,    // Telnet
      135,   // RPC
      139,   // NetBIOS
      445,   // SMB
      1433,  // MSSQL
      3389,  // RDP
      5432,  // PostgreSQL
      6379,  // Redis
      27017, // MongoDB
      8080,  // HTTP Alt
      8443   // HTTPS Alt
    ];
    
    return riskyPorts.includes(parseInt(port));
  }

  /**
   * Format compliance mapping
   */
  formatComplianceMapping(finding, frameworks = ['NIST CSF', 'ISO 27001']) {
    const mappings = {};
    
    frameworks.forEach(framework => {
      const frameworkMapping = this.complianceMap[framework];
      if (frameworkMapping) {
        const relevantControls = Object.keys(frameworkMapping).filter(control =>
          this.isRelevantToControl(finding, control)
        );
        mappings[framework] = relevantControls.map(control => ({
          id: control,
          name: frameworkMapping[control]
        }));
      }
    });
    
    return mappings;
  }

  /**
   * Check if finding is relevant to compliance control
   */
  isRelevantToControl(finding, controlId) {
    // Simplified mapping logic - can be enhanced with more sophisticated rules
    const findingText = (finding.type + ' ' + finding.description).toLowerCase();
    
    switch (controlId) {
      case 'PR.AC':
      case 'A.9':
        return findingText.includes('access') || findingText.includes('permission');
      case 'PR.PT':
      case 'A.12':
        return findingText.includes('security') || findingText.includes('protection');
      case 'DE.CM':
        return findingText.includes('monitor') || findingText.includes('log');
      case 'DE.AE':
        return findingText.includes('anomaly') || findingText.includes('suspicious');
      default:
        return false;
    }
  }

/**
   * Calculate risk score (0-100)
   */
  calculateRiskScore(summary) {
    const weights = { high: 10, medium: 5, low: 1 };
    const score = (summary.highRiskFindings * weights.high) +
                 (summary.mediumRiskFindings * weights.medium) +
                 (summary.lowRiskFindings * weights.low);
    
    return Math.min(100, score);
  }

  /**
   * Format risk score with color
   */
  formatRiskScore(score) {
    let color, level;
    
    if (score >= 70) {
      color = '#dc2626';
      level = 'Critical';
    } else if (score >= 40) {
      color = '#ca8a04';
      level = 'High';
    } else if (score >= 20) {
      color = '#f59e0b';
      level = 'Medium';
    } else {
      color = '#16a34a';
      level = 'Low';
    }
    
    return { score, color, level };
  }

  /**
   * Format chart data for visualization
   */
  formatChartData(data, type = 'pie') {
    switch (type) {
      case 'pie':
        return this.formatPieChartData(data);
      case 'bar':
        return this.formatBarChartData(data);
      case 'line':
        return this.formatLineChartData(data);
      default:
        return data;
    }
  }

  /**
   * Format data for pie chart
   */
  formatPieChartData(data) {
    const total = Object.values(data).reduce((sum, val) => sum + val, 0);
    return Object.entries(data).map(([key, value]) => ({
      label: this.formatRiskLevel(key).label,
      value,
      percentage: total > 0 ? Math.round((value / total) * 100) : 0,
      color: this.formatRiskLevel(key).color
    }));
  }

  /**
   * Format data for bar chart
   */
  formatBarChartData(data) {
    return Object.entries(data).map(([key, value]) => ({
      category: key,
      value,
      color: this.formatRiskLevel(key).color
    }));
  }

  /**
   * Format data for line chart
   */
  formatLineChartData(data) {
    return data.map((point, index) => ({
      x: index,
      y: point.value,
      label: point.label
    }));
  }
}