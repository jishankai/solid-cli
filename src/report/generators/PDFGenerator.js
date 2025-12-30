import puppeteer from 'puppeteer';
import { promises as fs } from 'fs';
import { join } from 'path';
import { readFileSync } from 'fs';
import handlebars from 'handlebars';

/**
 * Enhanced PDF Generator using Puppeteer
 */
export class PDFGenerator {
  constructor(options = {}) {
    this.options = {
      styleDir: './src/report/styles',
      templateDir: './src/report/templates',
      ...options
    };
  }

  /**
   * Generate professional PDF report
   */
  async generate(reportData) {
    console.log('📑 Generating PDF report...');

    // Compile HTML template
    const html = await this.compileTemplate(reportData);
    
    // Generate PDF with Puppeteer
    const pdfBuffer = await this.createPDF(html);
    
    // Save to file
    const filename = `Security-Report-${reportData.metadata.reportId}.pdf`;
    const filepath = join(this.options.reportsDir || './reports', filename);
    
    await fs.writeFile(filepath, pdfBuffer);
    
    console.log(`✅ PDF report saved: ${filepath}`);
    return filepath;
  }

  /**
   * Compile Handlebars template with data
   */
  async compileTemplate(reportData) {
    const templatePath = join(this.options.templateDir, 'report.hbs');
    const templateSource = readFileSync(templatePath, 'utf-8');
    
    // Register custom Handlebars helpers
    this.registerHelpers();
    
    const template = handlebars.compile(templateSource);
    const html = template({ ...reportData, format: 'pdf' });

    // Add custom CSS styling
    const css = this.getReportCSS();
    return this.wrapHTML(html, css);
  }

  /**
   * Create PDF using Puppeteer
   */
  async createPDF(html) {
    const browser = await puppeteer.launch({
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--no-first-run',
        '--no-zygote',
        '--single-process',
        '--disable-gpu'
      ]
    });

    try {
      const page = await browser.newPage();
      
      // Set content and wait for loading
      await page.setContent(html, { waitUntil: 'networkidle0' });
      
      // Generate PDF with professional settings
      const pdfBuffer = await page.pdf({
        format: 'A4',
        margin: {
          top: '2cm',
          right: '2cm',
          bottom: '2cm',
          left: '2cm'
        },
        printBackground: true,
        displayHeaderFooter: true,
        headerTemplate: this.getHeaderTemplate(),
        footerTemplate: this.getFooterTemplate(),
        preferCSSPageSize: true
      });

      return pdfBuffer;
    } finally {
      await browser.close();
    }
  }

  /**
   * Get professional CSS styling (grayscale only)
   */
  getReportCSS() {
    return `
      @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
      
      * {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        box-sizing: border-box;
      }
      
      body {
        margin: 0;
        padding: 0;
        background: #ffffff;
        color: #111111;
        line-height: 1.6;
        font-size: 12px;
        display: flex;
        justify-content: center;
      }

      .report-container {
        width: 100%;
        max-width: 820px;
        margin: 0 auto;
        padding: 1.5rem 1rem 2rem;
      }
      
      .header {
        background: #000000;
        color: #ffffff;
        padding: 2rem;
        border-radius: 8px;
        margin-bottom: 2rem;
        text-align: center;
      }
      
      .header h1 {
        margin: 0;
        font-size: 24px;
        font-weight: 700;
      }
      
      .header .subtitle {
        margin: 0.5rem 0 0 0;
        font-size: 14px;
        opacity: 0.9;
      }
      
      .risk-badge {
        display: inline-block;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-size: 11px;
        font-weight: 600;
        text-transform: uppercase;
        margin-left: 0.5rem;
      }
      
      .risk-high { background: #111111; color: #ffffff; }
      .risk-medium { background: #555555; color: #ffffff; }
      .risk-low { background: #bbbbbb; color: #000000; }
      .risk-unknown { background: #e5e5e5; color: #000000; }

      code {
        font-family: 'SFMono-Regular', Menlo, Consolas, 'Liberation Mono', monospace;
        background: #f3f4f6;
        padding: 0.15rem 0.35rem;
        border-radius: 4px;
        word-break: break-all;
      }

      pre {
        font-family: 'SFMono-Regular', Menlo, Consolas, 'Liberation Mono', monospace;
        white-space: pre-wrap;
        word-break: break-word;
      }

      .agent-section {
        margin-bottom: 2rem;
      }

      .finding-summary {
        margin: 0.5rem 0 1rem 0;
        color: #374151;
      }

      .finding-error {
        color: #b91c1c;
        font-weight: 600;
        margin: 0.75rem 0;
      }

      .risk-label {
        font-size: 11px;
        color: #555555;
      }

      .llm-analysis-meta {
        background: #f0f9ff;
        border: 1px solid #0ea5e9;
        border-radius: 8px;
        padding: 1.25rem;
        margin-bottom: 1rem;
      }

      .llm-analysis-meta div {
        margin: 0.15rem 0;
      }

      .llm-analysis-body {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 6px;
        padding: 1rem;
        white-space: pre-wrap;
        word-break: break-word;
        line-height: 1.5;
      }

      .llm-analysis-body p {
        margin: 0.35rem 0;
      }

      .markdown-body ul { margin: 0.35rem 0 0.35rem 1.1rem; }
      .markdown-body ol { margin: 0.35rem 0 0.35rem 1.2rem; }
      .markdown-body li { margin: 0.1rem 0; }
      .markdown-body h1,
      .markdown-body h2,
      .markdown-body h3,
      .markdown-body h4 {
        margin: 0.4rem 0 0.25rem;
        line-height: 1.25;
      }
      .markdown-body code { background: #f3f4f6; padding: 0.15rem 0.35rem; border-radius: 4px; }

      .llm-analysis-usage {
        margin-top: 1rem;
        font-size: 10px;
        color: #64748b;
        line-height: 1.5;
      }
      
      .executive-summary {
        background: #f5f5f5;
        border: 1px solid #d4d4d4;
        border-radius: 8px;
        padding: 1.5rem;
        margin-bottom: 2rem;
      }
      
      .executive-summary h2 {
        margin: 0 0 1rem 0;
        color: #111111;
        font-size: 18px;
        border-bottom: 2px solid #000000;
        padding-bottom: 0.5rem;
      }
      
      .metrics-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
        gap: 1rem;
        margin: 1rem 0;
      }
      
      .metric-card {
        background: #ffffff;
        border: 1px solid #d4d4d4;
        border-radius: 6px;
        padding: 1rem;
        text-align: center;
      }
      
      .metric-value {
        font-size: 24px;
        font-weight: 700;
        color: #111111;
      }
      
      .metric-label {
        font-size: 10px;
        color: #555555;
        text-transform: uppercase;
        letter-spacing: 0.05em;
      }
      
      .section {
        margin-bottom: 2rem;
        page-break-inside: avoid;
      }
      
      .section h2 {
        color: #111111;
        font-size: 16px;
        border-left: 4px solid #000000;
        padding-left: 0.75rem;
        margin-bottom: 1rem;
      }
      
      .finding {
        background: #ffffff;
        border: 1px solid #d4d4d4;
        border-radius: 6px;
        padding: 1rem;
        margin-bottom: 1rem;
        page-break-inside: avoid;
      }
      
      .finding-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 0.5rem;
      }
      
      .finding-title {
        font-weight: 600;
        color: #111111;
      }
      
      .finding-risk {
        padding: 0.25rem 0.5rem;
        border-radius: 4px;
        font-size: 10px;
        font-weight: 600;
        text-transform: uppercase;
      }
      
      .finding-description {
        color: #333333;
        margin-bottom: 0.75rem;
        white-space: pre-line;
        word-break: break-word;
      }
      
      .finding-details {
        background: #f2f2f2;
        border-radius: 4px;
        padding: 0.5rem 0.75rem;
        font-size: 10px;
        white-space: pre-line;
        word-break: break-word;
        line-height: 1.4;
      }
      
      .detail-row {
        margin: 0.1rem 0;
      }
      
      .detail-label {
        font-weight: 600;
        color: #333333;
      }
      
      .recommendations {
        background: #f5f5f5;
        border: 1px solid #d4d4d4;
        border-radius: 8px;
        padding: 1.5rem;
        margin-top: 2rem;
      }
      
      .recommendations h3 {
        color: #111111;
        margin: 0 0 1rem 0;
      }
      
      .recommendation {
        background: #ffffff;
        border-left: 4px solid #000000;
        padding: 1rem;
        margin-bottom: 1rem;
      }
      
      .recommendation h4 {
        margin: 0 0 0.5rem 0;
        color: #111111;
      }
      
      .recommendation-actions {
        list-style: none;
        padding: 0;
        margin: 0.5rem 0 0 0;
      }
      
      .recommendation-actions li {
        padding: 0.25rem 0;
        color: #333333;
        font-size: 11px;
      }
      
      .recommendation-actions li:before {
        content: "→ ";
        font-weight: bold;
        color: #111111;
      }
      
      .chart-container {
        margin: 1rem 0;
        text-align: center;
      }
      
      .risk-distribution {
        display: flex;
        justify-content: space-around;
        align-items: center;
        height: 120px;
        background: #f5f5f5;
        border-radius: 8px;
        margin: 1rem 0;
      }
      
      .risk-segment {
        text-align: center;
        flex: 1;
        position: relative;
      }
      
      .risk-segment:not(:last-child):after {
        content: '';
        position: absolute;
        right: 0;
        top: 20%;
        height: 60%;
        width: 1px;
        background: #d4d4d4;
      }
      
      .risk-count {
        font-size: 20px;
        font-weight: 700;
        color: #111111;
      }
      
      .risk-percentage {
        font-size: 10px;
        color: #555555;
      }
      
      .footer {
        margin-top: 2rem;
        padding-top: 1rem;
        border-top: 1px solid #d4d4d4;
        font-size: 10px;
        color: #555555;
        text-align: center;
      }
      
      @media print {
        .section {
          page-break-inside: avoid;
        }
        
        .finding {
          page-break-inside: avoid;
        }
        
        .recommendations {
          page-break-inside: avoid;
        }
      }
    `;
  }

  /**
   * Wrap HTML with proper structure
   */
  wrapHTML(content, css) {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report</title>
    <style>
${css}
    </style>
</head>
<body>
    <div class="report-container">
      ${content}
    </div>
</body>
</html>
    `;
  }

  /**
   * Get PDF header template
   */
  getHeaderTemplate() {
    return `
      <div style="font-size: 10px; color: #555555; text-align: center; width: 100%;">
        <span>Security Analysis Report</span>
      </div>
    `;
  }

  /**
   * Get PDF footer template
   */
  getFooterTemplate() {
    return `
      <div style="font-size: 8px; color: #555555; text-align: center; width: 100%;">
        <span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span>
        <span style="margin-left: 2rem;">Generated: ${new Date().toLocaleDateString()}</span>
      </div>
    `;
  }

  /**
   * Register custom Handlebars helpers
   */
  registerHelpers() {
    // Format date helper
    handlebars.registerHelper('formatDate', (date) => {
      return new Date(date).toLocaleDateString();
    });

    // Format time helper
    handlebars.registerHelper('formatTime', (date) => {
      return new Date(date).toLocaleTimeString();
    });

    // Uppercase helper
    handlebars.registerHelper('uppercase', (str) => {
      if (str === undefined || str === null) return 'UNKNOWN';
      return str.toString().toUpperCase();
    });

    // Risk color helper (grayscale)
    handlebars.registerHelper('riskColor', (risk) => {
      const colors = {
        high: '#111111',
        medium: '#555555',
        low: '#999999',
        unknown: '#bbbbbb'
      };
      return colors[risk] || colors.unknown;
    });

    // Risk badge helper (monochrome)
    handlebars.registerHelper('riskBadge', (risk) => {
      const badges = {
        high: '● HIGH',
        medium: '● MEDIUM',
        low: '● LOW',
        unknown: '○ UNKNOWN'
      };
      return badges[risk] || badges.unknown;
    });

    // Agent name formatter
    handlebars.registerHelper('formatAgentName', (agent) => {
      return agent.charAt(0).toUpperCase() + agent.slice(1).replace(/([A-Z])/g, ' $1');
    });

    // Conditional helper
    handlebars.registerHelper('ifEquals', function(arg1, arg2, options) {
      return (arg1 == arg2) ? options.fn(this) : options.inverse(this);
    });

    // Greater than helper
    handlebars.registerHelper('ifGt', function(arg1, arg2, options) {
      return (arg1 > arg2) ? options.fn(this) : options.inverse(this);
    });

    // Array length helper
    handlebars.registerHelper('length', (array) => {
      return array ? array.length : 0;
    });

    // True if any of the provided values are "present"
    handlebars.registerHelper('hasAny', (...args) => {
      // Last arg is Handlebars options hash
      args.pop();

      return args.some((value) => {
        if (value === undefined || value === null) return false;
        if (typeof value === 'string') return value.trim().length > 0;
        if (Array.isArray(value)) return value.length > 0;
        return true;
      });
    });

    // Logical OR helper for template conditions
    handlebars.registerHelper('or', (...args) => {
      args.pop(); // options hash
      return args.some(Boolean);
    });

    // JSON stringify helper
    handlebars.registerHelper('json', (obj) => {
      return JSON.stringify(obj, null, 2);
    });

    // Calculate risk score helper
    handlebars.registerHelper('calculateRiskScore', (summary) => {
      const safeSummary = summary || { highRiskFindings: 0, mediumRiskFindings: 0, lowRiskFindings: 0 };
      const weights = { high: 10, medium: 5, low: 1 };
      const score = (safeSummary.highRiskFindings * weights.high) +
                   (safeSummary.mediumRiskFindings * weights.medium) +
                   (safeSummary.lowRiskFindings * weights.low);
      
      return Math.min(100, score);
    });
  }
}