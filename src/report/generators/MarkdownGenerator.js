import { promises as fs } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { readFileSync } from 'fs';
import handlebars from 'handlebars';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const DEFAULT_TEMPLATE_DIR = join(__dirname, '..', 'templates');

/**
 * Enhanced Markdown Generator with templates
 */
export class MarkdownGenerator {
  constructor(options = {}) {
    this.options = {
      templateDir: DEFAULT_TEMPLATE_DIR,
      ...options
    };
  }

  /**
   * Generate markdown report
   */
  async generate(reportData) {
    console.log('📄 Generating Markdown report...');

    // Compile Handlebars template
    const markdown = await this.compileTemplate(reportData);
    
    // Save to file
    const filename = `Security-Report-${reportData.metadata.reportId}.md`;
    const filepath = join(this.options.reportsDir || './reports', filename);
    
    await fs.writeFile(filepath, markdown, 'utf-8');
    
    console.log(`✅ Markdown report saved: ${filepath}`);
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
    return template({ ...reportData, format: 'markdown' });
  }

  /**
   * Register custom Handlebars helpers
   */
  registerHelpers() {
    // Risk badge helper for markdown
    handlebars.registerHelper('markdownRiskBadge', (risk) => {
      const badges = {
        high: '🔴 **HIGH**',
        medium: '🟡 **MEDIUM**',
        low: '🟢 **LOW**',
        unknown: '⚪ **UNKNOWN**'
      };
      return badges[risk] || badges.unknown;
    });

    // Format code blocks
    handlebars.registerHelper('codeBlock', (content, language = '') => {
      return `\`\`\`${language}\n${content || ''}\n\`\`\``;
    });

    // Format list items
    handlebars.registerHelper('listItem', (text, level = 1) => {
      const indent = '  '.repeat(level - 1);
      return `${indent}- ${text}`;
    });

    // Table header helper
    handlebars.registerHelper('tableHeader', (columns) => {
      const header = `| ${columns.join(' | ')} |`;
      const separator = `| ${columns.map(() => '---').join(' | ')} |`;
      return `${header}\n${separator}`;
    });

    // Table row helper
    handlebars.registerHelper('tableRow', (cells) => {
      return `| ${cells.join(' | ')} |`;
    });

    // Link helper
    handlebars.registerHelper('link', (text, url) => {
      return `[${text}](${url})`;
    });

    // Bold helper
    handlebars.registerHelper('bold', (text) => {
      return `**${text}**`;
    });

    // Italic helper
    handlebars.registerHelper('italic', (text) => {
      return `*${text}*`;
    });

    // Format agent name
    handlebars.registerHelper('formatAgentName', (agent) => {
      return agent.charAt(0).toUpperCase() + agent.slice(1).replace(/([A-Z])/g, ' $1');
    });

    // Uppercase helper
    handlebars.registerHelper('uppercase', (str) => {
      if (str === undefined || str === null) return 'UNKNOWN';
      return str.toString().toUpperCase();
    });

    // Date formatter
    handlebars.registerHelper('formatDate', (date) => {
      return new Date(date).toLocaleDateString();
    });

    // Time formatter
    handlebars.registerHelper('formatTime', (date) => {
      return new Date(date).toLocaleTimeString();
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

        // JSON stringify helper for debugging
        handlebars.registerHelper('json', (obj) => {
          return JSON.stringify(obj, null, 2);
        });
    
        // Logical OR helper for template conditions
        handlebars.registerHelper('or', (...args) => {
          args.pop(); // options hash
          return args.some(Boolean);
        });
    
        // Calculate risk score helper
        handlebars.registerHelper('calculateRiskScore', (summary) => {
          const weights = { high: 10, medium: 5, low: 1 };
          const score = (summary.highRiskFindings * weights.high) +
                       (summary.mediumRiskFindings * weights.medium) +
                       (summary.lowRiskFindings * weights.low);
          
          return Math.min(100, score);
        });
      }
    }