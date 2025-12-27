import { writeFileSync } from 'fs';
import { join } from 'path';
import markdownPdf from 'markdown-pdf';
import { promisify } from 'util';

const markdownPdfAsync = promisify(markdownPdf);

/**
 * Report Generator - Creates Markdown and PDF reports
 */
export class ReportGenerator {
  constructor(results, llmAnalysis = null) {
    this.results = results;
    this.llmAnalysis = llmAnalysis;
    this.timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  }

  /**
   * Generate Markdown report
   */
  generateMarkdown() {
    const sections = [];

    // Header
    sections.push(this.generateHeader());

    // Executive Summary
    sections.push(this.generateSummary());

    // LLM Analysis (if available)
    if (this.llmAnalysis) {
      sections.push(this.generateLLMSection());
    }

    // Agent Results
    sections.push(this.generateAgentResults());

    // Appendix - Raw Data
    sections.push(this.generateAppendix());

    return sections.join('\n\n---\n\n');
  }

  /**
   * Generate report header
   */
  generateHeader() {
    const riskBadge = this.getRiskBadge(this.results.overallRisk);

    return `# MacOS Security Analysis Report

**Generated:** ${new Date(this.results.timestamp).toLocaleString()}
**Hostname:** ${this.results.hostname}
**macOS Version:** ${this.results.osVersion}
**Analysis Mode:** ${this.results.mode}
**Overall Risk Level:** ${riskBadge}`;
  }

  /**
   * Generate summary section
   */
  generateSummary() {
    const { summary } = this.results;

    return `## Executive Summary

This report contains the results of a comprehensive ${this.results.mode} analysis of the system.

### Key Metrics

- **Total Findings:** ${summary.totalFindings}
- **High Risk:** ${summary.highRiskFindings} 🔴
- **Medium Risk:** ${summary.mediumRiskFindings} 🟡
- **Low Risk:** ${summary.lowRiskFindings} 🟢

### Agent Status

${Object.entries(summary.agentSummaries).map(([agent, data]) => {
  if (data.error) {
    return `- **${agent}:** ❌ Error - ${data.error}`;
  }
  return `- **${agent}:** ${data.findings} findings (${this.getRiskBadge(data.risk)})`;
}).join('\n')}`;
  }

  /**
   * Generate LLM analysis section
   */
  generateLLMSection() {
    return `## AI-Powered Analysis

**Provider:** ${this.llmAnalysis.provider}
**Model:** ${this.llmAnalysis.model}

${this.llmAnalysis.analysis}

---

**Analysis Metrics:**
${this.llmAnalysis.usage.promptTokens ? `- Prompt Tokens: ${this.llmAnalysis.usage.promptTokens}` : ''}
${this.llmAnalysis.usage.inputTokens ? `- Input Tokens: ${this.llmAnalysis.usage.inputTokens}` : ''}
${this.llmAnalysis.usage.completionTokens ? `- Completion Tokens: ${this.llmAnalysis.usage.completionTokens}` : ''}
${this.llmAnalysis.usage.outputTokens ? `- Output Tokens: ${this.llmAnalysis.usage.outputTokens}` : ''}`;
  }

  /**
   * Generate detailed agent results
   */
  generateAgentResults() {
    let output = '## Detailed Findings\n\n';

    for (const [agentKey, agentResult] of Object.entries(this.results.agents)) {
      if (agentResult.error) {
        output += `### ${agentKey} Agent\n\n❌ **Error:** ${agentResult.error}\n\n`;
        continue;
      }

      output += `### ${agentResult.agent}\n\n`;
      output += `**Risk Level:** ${this.getRiskBadge(agentResult.overallRisk)}\n\n`;

      if (!agentResult.findings || agentResult.findings.length === 0) {
        output += '✅ No significant findings.\n\n';
        continue;
      }

      output += `**Total Findings:** ${agentResult.findings.length}\n\n`;

      // Group by risk level
      const highRisk = agentResult.findings.filter(f => f.risk === 'high');
      const mediumRisk = agentResult.findings.filter(f => f.risk === 'medium');
      const lowRisk = agentResult.findings.filter(f => f.risk === 'low');

      if (highRisk.length > 0) {
        output += `#### 🔴 High Risk (${highRisk.length})\n\n`;
        output += this.formatFindings(highRisk);
      }

      if (mediumRisk.length > 0) {
        output += `#### 🟡 Medium Risk (${mediumRisk.length})\n\n`;
        output += this.formatFindings(mediumRisk);
      }

      if (lowRisk.length > 0) {
        output += `#### 🟢 Low Risk (${lowRisk.length})\n\n`;
        output += this.formatFindings(lowRisk);
      }

      output += '\n';
    }

    return output;
  }

  /**
   * Format findings into markdown
   */
  formatFindings(findings) {
    return findings.map((finding, idx) => {
      let output = `##### ${idx + 1}. ${finding.type}\n\n`;
      output += `${finding.description}\n\n`;

      // Add details
      const details = [];
      if (finding.pid) details.push(`**PID:** ${finding.pid}`);
      if (finding.command) details.push(`**Command:** \`${finding.command}\``);
      if (finding.path) details.push(`**Path:** \`${finding.path}\``);
      if (finding.program) details.push(`**Program:** \`${finding.program}\``);
      if (finding.plist) details.push(`**Plist:** \`${finding.plist}\``);
      if (finding.name) details.push(`**Name:** ${finding.name}`);
      if (finding.user) details.push(`**User:** ${finding.user}`);

      if (details.length > 0) {
        output += details.join('  \n') + '\n\n';
      }

      // Add risk details
      if (finding.risks && finding.risks.length > 0) {
        output += '**Risk Factors:**\n';
        output += finding.risks.map(r => `- ${r}`).join('\n') + '\n\n';
      }

      return output;
    }).join('---\n\n');
  }

  /**
   * Generate appendix with raw data
   */
  generateAppendix() {
    return `## Appendix: Raw Data

\`\`\`json
${JSON.stringify(this.results, null, 2)}
\`\`\``;
  }

  /**
   * Get risk badge emoji/text
   */
  getRiskBadge(risk) {
    switch (risk) {
      case 'high':
        return '🔴 **HIGH**';
      case 'medium':
        return '🟡 **MEDIUM**';
      case 'low':
        return '🟢 **LOW**';
      default:
        return '⚪ **UNKNOWN**';
    }
  }

  /**
   * Save Markdown report to file
   */
  async saveMarkdown(outputDir = '.') {
    const markdown = this.generateMarkdown();
    const filename = `security-report-${this.timestamp}.md`;
    const filepath = join(outputDir, filename);

    writeFileSync(filepath, markdown, 'utf-8');

    return filepath;
  }

  /**
   * Save PDF report to file
   */
  async savePDF(outputDir = '.') {
    const markdown = this.generateMarkdown();
    const filename = `Security-Report-${this.timestamp}.pdf`;
    const filepath = join(outputDir, filename);

    try {
      await markdownPdfAsync({
        cssPath: null,
        highlightCssPath: null,
        paperBorder: '2cm',
        renderDelay: 1000
      }).from.string(markdown).to(filepath);

      return filepath;
    } catch (error) {
      throw new Error(`PDF generation failed: ${error.message}. Try installing phantomjs: npm install -g phantomjs-prebuilt`);
    }
  }

  /**
   * Save both Markdown and PDF reports
   */
  async saveAll(outputDir = '.') {
    const mdPath = await this.saveMarkdown(outputDir);
    let pdfPath = null;

    try {
      pdfPath = await this.savePDF(outputDir);
    } catch (error) {
      console.error(`Warning: ${error.message}`);
    }

    return { markdown: mdPath, pdf: pdfPath };
  }
}
