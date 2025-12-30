import { promises as fs } from 'fs';
import { join } from 'path';
import puppeteer from 'puppeteer';
import handlebars from 'handlebars';
import { PDFGenerator } from './generators/PDFGenerator.js';
import { MarkdownGenerator } from './generators/MarkdownGenerator.js';
import { ReportSanitizer } from './utils/sanitizer.js';
import { ReportFormatter } from './utils/formatter.js';

/**
 * Enhanced Report Manager - Professional report generation with templates
 */
export class ReportManager {
  constructor(results, llmAnalysis = null, options = {}) {
    // Validate inputs
    if (!results) {
      throw new Error('ReportManager requires analysis results');
    }

    this.results = results;
    this.llmAnalysis = llmAnalysis;
    this.options = {
      reportsDir: './reports',
      templateDir: './src/report/templates',
      styleDir: './src/report/styles',
      retentionDays: 90,
      defaultTemplate: 'executive',
      ...options
    };
    this.timestamp = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
    this.sanitizer = new ReportSanitizer();
    this.formatter = new ReportFormatter();
    this.pdfGenerator = new PDFGenerator(this.options);
    this.markdownGenerator = new MarkdownGenerator(this.options);
  }

  /**
   * Generate all requested report formats
   */
  async generateReports(formats = ['markdown', 'pdf']) {
    const savedFiles = [];
    const reportData = this.prepareReportData();

    // Create output directory structure
    await this.ensureReportDirectory();

    // Force generators to use the dated report directory
    this.markdownGenerator.options.reportsDir = this.reportDir;
    this.pdfGenerator.options.reportsDir = this.reportDir;

    // Generate reports in parallel
    const generationPromises = [];

    if (formats.includes('markdown')) {
      generationPromises.push(
        this.markdownGenerator.generate(reportData)
          .then(path => savedFiles.push({ type: 'markdown', path }))
      );
    }

    if (formats.includes('pdf')) {
      generationPromises.push(
        this.pdfGenerator.generate(reportData)
          .then(path => savedFiles.push({ type: 'pdf', path }))
          .catch(error => {
            console.warn(`PDF generation failed: ${error.message}`);
            return null;
          })
      );
    }

    await Promise.all(generationPromises);

    // Save report metadata
    await this.saveReportMetadata(savedFiles, reportData);

    // Cleanup old reports
    await this.cleanupOldReports();

    return savedFiles.filter(Boolean);
  }

  /**
   * Prepare comprehensive report data
   */
  prepareReportData() {
    // Validate results structure
    if (!this.results) {
      throw new Error('No analysis results available for report generation');
    }

    // Ensure summary exists and has required properties
    const summary = this.results.summary || {
      totalFindings: 0,
      highRiskFindings: 0,
      mediumRiskFindings: 0,
      lowRiskFindings: 0,
      agentSummaries: {},
      error: 'Summary data not available'
    };

    return {
      // System Information
      system: {
        hostname: this.results.hostname || 'Unknown',
        osVersion: this.results.osVersion || 'Unknown',
        timestamp: this.results.timestamp || new Date().toISOString(),
        mode: this.results.mode || 'unknown',
        analysisDepth: this.results.analysisDepth || 'comprehensive'
      },

      // Executive Summary
      summary: {
        ...summary,
        overallRisk: this.results.overallRisk || 'unknown',
        riskLevel: this.getRiskLevel(this.results.overallRisk || 'unknown'),
        analysisPhases: this.results.analysisPhases || [],
        adaptiveAnalysis: this.results.adaptiveAnalysis || {}
      },

      // Detailed Findings
      findings: this.processFindings(this.results.agents),

      // Sensitive data alerts (if any)
      sensitivePatterns: this.llmAnalysis?.securityCheck?.sensitivePatterns || [],
      sensitiveDataAlerts: this.llmAnalysis?.securityCheck?.detectedLocations || [],

      // LLM Analysis (if available)
      llmAnalysis: this.llmAnalysis,

      // Charts and Visualizations Data
      visualizations: this.prepareVisualizationData(),

      // Compliance Information
      compliance: this.prepareComplianceData(),

      // Recommendations
      recommendations: this.generateRecommendations(),

      // Report Metadata
      metadata: {
        generatedAt: new Date().toISOString(),
        version: '2.0.0',
        reportId: this.generateReportId()
      }
    };
  }

  /**
   * Process and sanitize findings for reporting
   */
  processFindings(agents) {
    const processedFindings = {};
    const perFinding = this.llmAnalysis?.perFinding || {};

    for (const [agentKey, agentResult] of Object.entries(agents)) {
      if (agentResult.error) {
        processedFindings[agentKey] = {
          name: agentResult.agent || agentKey,
          error: agentResult.error,
          overallRisk: 'unknown',
          findings: []
        };
        continue;
      }

      const findings = (agentResult.findings || []).map((finding, index) => {
        const findingId = `${agentKey}#${index}`;
        const llm = perFinding[findingId];
        const sanitizedDescription = this.sanitizer.sanitizeText(finding.description);

        const aiPurpose = llm ? this.sanitizer.sanitizeText(llm.purpose || '') : '';
        const aiRisk = llm ? this.sanitizer.sanitizeText(llm.risk || llm.analysis || '') : '';
        const aiAction = llm ? this.sanitizer.sanitizeText(llm.action || llm.remediation || '') : '';

        const withLlm = llm ? [
          sanitizedDescription,
          aiPurpose ? `AI Analysis: ${aiPurpose}` : null,
          aiRisk ? `Risk Assessment: ${aiRisk}` : null,
          aiAction ? `AI Recommended Action: ${aiAction}` : null
        ].filter(Boolean).join('\n') : sanitizedDescription;

        return {
          ...finding,
          id: findingId,
          description: withLlm,
          command: this.sanitizer.sanitizeText(finding.command),
          path: this.sanitizer.sanitizePath(finding.path),
          program: this.sanitizer.sanitizeText(finding.program),
          risks: finding.risks || [],
          llm
        };
      });

      const derivedRisk = this.deriveOverallRisk(findings, agentResult.overallRisk);

      processedFindings[agentKey] = {
        name: agentResult.agent,
        overallRisk: derivedRisk,
        riskLevel: this.getRiskLevel(derivedRisk),
        findings,
        summary: {
          total: findings.length,
          high: findings.filter(f => f.risk === 'high').length,
          medium: findings.filter(f => f.risk === 'medium').length,
          low: findings.filter(f => f.risk === 'low').length
        }
      };
    }

    return processedFindings;
  }

  /**
   * Prepare visualization data for charts
   */
  prepareVisualizationData() {
    const summary = this.results.summary || {
      totalFindings: 0,
      highRiskFindings: 0,
      mediumRiskFindings: 0,
      lowRiskFindings: 0,
      agentSummaries: {}
    };

    const total = summary.totalFindings || 1; // Avoid division by zero
    const high = summary.highRiskFindings || 0;
    const medium = summary.mediumRiskFindings || 0;
    const low = summary.lowRiskFindings || 0;

    return {
      riskDistribution: {
        high,
        medium,
        low,
        highPercentage: Math.round((high / total) * 100),
        mediumPercentage: Math.round((medium / total) * 100),
        lowPercentage: Math.round((low / total) * 100)
      },
      agentFindings: Object.entries(summary.agentSummaries || {})
        .filter(([_, data]) => !data.error)
        .map(([agent, data]) => ({
          agent: this.formatter.formatAgentName(agent),
          findings: data.findings,
          risk: data.risk
        }))
    };
  }

  /**
   * Prepare compliance data (deduped, normalized labels)
   */
  prepareComplianceData() {
    const frameworks = {
      'NIST CSF': new Set(),
      'ISO 27001': new Set(),
      'SOC 2': new Set(),
      'PCI DSS': new Set()
    };

    // Friendly labels for common finding types (fallback to raw type)
    const typeLabels = {
      launchdaemon: 'Persistence: LaunchDaemon',
      launchagent: 'Persistence: LaunchAgent',
      login_item: 'Persistence: Login Item',
      crontab: 'Persistence: Crontab',
      suspicious_process: 'Process: Suspicious execution',
      high_cpu_unusual_path: 'Process: High CPU (non-system)',
      high_memory_unusual_path: 'Process: High Memory (non-system)',
      long_running_background: 'Process: Long-running background',
      privacy_permission: 'Permissions: Sensitive access',
      listening: 'Network: Listening service',
      outbound: 'Network: External connection',
      blockchain_network_connection: 'Network: Blockchain/DeFi host',
      login_item: 'Persistence: Login Item'
    };

    for (const [, result] of Object.entries(this.results.agents || {})) {
      const findings = Array.isArray(result?.findings) ? result.findings : [];
      findings.forEach(finding => {
        const label = typeLabels[finding.type] || finding.type;
        if (finding.risk === 'high') {
          frameworks['NIST CSF'].add(label);
          frameworks['ISO 27001'].add(label);
          frameworks['PCI DSS'].add(label);
        }
        if (finding.risk === 'medium') {
          frameworks['SOC 2'].add(label);
        }
      });
    }

    // Convert sets to sorted arrays for stable output
    return Object.fromEntries(
      Object.entries(frameworks).map(([k, v]) => [k, Array.from(v).sort()])
    );
  }

  /**
   * Generate actionable recommendations
   */
  generateRecommendations() {
    const recommendations = [];
    const summary = this.results.summary || {
      highRiskFindings: 0,
      mediumRiskFindings: 0
    };

    if ((summary.highRiskFindings || 0) > 0) {
      recommendations.push({
        priority: 'high',
        title: 'Address High Risk Findings Immediately',
        description: `There are ${summary.highRiskFindings} high-risk findings that require immediate attention to prevent potential security incidents.`,
        actions: [
          'Review and remediate all high-risk findings',
          'Implement additional security controls',
          'Consider isolating affected systems',
          'Monitor for suspicious activity'
        ]
      });
    }

    if ((summary.mediumRiskFindings || 0) > 5) {
      recommendations.push({
        priority: 'medium',
        title: 'Improve Security Posture',
        description: 'Multiple medium-risk findings indicate opportunities to improve overall security posture.',
        actions: [
          'Implement regular security scanning',
          'Update security policies and procedures',
          'Provide security awareness training',
          'Consider security hardening measures'
        ]
      });
    }

    if (this.results.adaptiveAnalysis?.blockchainAnalysisEnabled) {
      recommendations.push({
        priority: 'medium',
        title: 'Blockchain Security Monitoring',
        description: 'Blockchain and cryptocurrency activities were detected. Implement specialized monitoring.',
        actions: [
          'Implement blockchain security monitoring',
          'Review wallet and DeFi application permissions',
          'Monitor for unusual crypto transactions',
          'Consider dedicated crypto security tools'
        ]
      });
    }

    return recommendations;
  }

  /**
   * Derive risk from findings to avoid inconsistent badges
   */
  deriveOverallRisk(findings, reportedRisk = 'unknown') {
    if (!Array.isArray(findings) || findings.length === 0) return 'low';
    if (findings.some(f => f && f.risk === 'high')) return 'high';
    if (findings.some(f => f && f.risk === 'medium')) return 'medium';
    return reportedRisk === 'unknown' ? 'low' : reportedRisk;
  }

  /**
   * Get formatted risk level
   */
  getRiskLevel(risk) {
    const levels = {
      high: { label: 'High', color: '#dc2626', icon: '🔴' },
      medium: { label: 'Medium', color: '#ca8a04', icon: '🟡' },
      low: { label: 'Low', color: '#16a34a', icon: '🟢' },
      unknown: { label: 'Unknown', color: '#6b7280', icon: '⚪' }
    };
    return levels[risk] || levels.unknown;
  }

  /**
   * Generate unique report ID
   */
  generateReportId() {
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(2, 8);
    return `RPT-${timestamp}-${random}`.toUpperCase();
  }

  /**
   * Ensure report directory structure exists
   */
  async ensureReportDirectory() {
    const today = new Date();
    const year = today.getFullYear();
    const month = today.toLocaleString('en-US', { month: 'long' });
    
    const reportDir = join(this.options.reportsDir, year.toString(), month);
    await fs.mkdir(reportDir, { recursive: true });
    
    this.reportDir = reportDir;
    return reportDir;
  }

  /**
   * Save report metadata for cataloging
   */
  async saveReportMetadata(savedFiles, reportData) {
    const metadata = {
      reportId: reportData.metadata.reportId,
      timestamp: reportData.metadata.generatedAt,
      system: reportData.system,
      summary: reportData.summary,
      files: savedFiles,
      riskScore: this.calculateRiskScore(reportData.summary)
    };

    const metadataPath = join(this.reportDir, `metadata-${this.timestamp}.json`);
    await fs.writeFile(metadataPath, JSON.stringify(metadata, null, 2));
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
   * Cleanup old reports based on retention policy
   */
  async cleanupOldReports() {
    // Implementation for report cleanup based on retentionDays
    // This would scan old report directories and remove files older than retentionDays
  }

  /**
   * Get list of available reports
   */
  static async listReports(reportsDir = './reports') {
    // Implementation for cataloging existing reports
    // Would scan report directories and return metadata for all reports
  }
}
