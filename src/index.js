#!/usr/bin/env node

import inquirer from 'inquirer';
import chalk from 'chalk';
import { Orchestrator } from './Orchestrator.js';
import { ReportManager } from './report/ReportManager.js';
import { LLMAnalyzer } from './llm/LLMAnalyzer.js';
import { log } from './logging/Logger.js';
import { getConfig } from './config/ConfigManager.js';
import ora from 'ora';

/**
 * Main CLI Application
 */
class SecurityAnalysisCLI {
  constructor() {
    this.results = null;
    this.llmAnalysis = null;
    log.userInteraction('cli_start', { timestamp: new Date().toISOString() });
  }

  /**
   * Display welcome banner
   */
  displayBanner() {
    console.clear();
    console.log(chalk.cyan.bold('\n╔═══════════════════════════════════════════════════════════╗'));
    console.log(chalk.cyan.bold('║   MacOS System & Security Analysis Agent CLI              ║'));
    console.log(chalk.cyan.bold('║   Powered by AI - Local-First Security Analysis           ║'));
    console.log(chalk.cyan.bold('╚═══════════════════════════════════════════════════════════╝\n'));
  }


  /**
   * Auto-detect LLM provider from available API keys
   */
  detectLLMProvider() {
    const hasOpenAI = process.env.OPENAI_API_KEY && process.env.OPENAI_API_KEY !== 'your_openai_api_key_here';
    const hasClaude = process.env.ANTHROPIC_API_KEY && process.env.ANTHROPIC_API_KEY !== 'your_anthropic_api_key_here';

    if (hasClaude) {
      console.log(chalk.green('✅ Claude (Anthropic) - API key detected'));
      return 'claude';
    } else if (hasOpenAI) {
      console.log(chalk.green('✅ OpenAI (GPT-4) - API key detected'));
      return 'openai';
    } else {
      console.log(chalk.yellow('⚠️  No LLM API keys found - generating report only'));
      console.log(chalk.gray('   Set OPENAI_API_KEY or ANTHROPIC_API_KEY in .env file'));
      return 'none';
    }
  }

  /**
   * Let user choose whether to use LLM analysis
   */
  async chooseLLMAnalysis(detectedProvider) {
    if (detectedProvider === 'none') {
      return 'none';
    }

    const { useLLM } = await inquirer.prompt([
      {
        type: 'list',
        name: 'useLLM',
        message: '🤖 AI Analysis Option:',
        choices: [
          { 
            name: `🧠 Use AI Analysis (${detectedProvider.toUpperCase()}) - Enhanced insights & recommendations`, 
            value: detectedProvider 
          },
          { 
            name: '📋 Generate Security Report Only - Maximum privacy protection', 
            value: 'none' 
          }
        ],
        default: detectedProvider
      }
    ]);

    // Provide privacy notice if user chooses LLM
    if (useLLM !== 'none') {
      console.log(chalk.yellow('\n🔒 Privacy Protection Active:'));
      console.log(chalk.gray('   • All private keys, addresses, and sensitive data are automatically redacted'));
      console.log(chalk.gray('   • Sensitive data is blocked from being sent to LLM'));
      console.log(chalk.gray('   • You will be prompted if any sensitive patterns are detected\n'));
    }

    return useLLM;
  }

  /**
   * Select report format
   */
  async selectReportFormat() {
    const defaultFormats = getConfig('reports.defaultFormats', ['markdown', 'pdf']);
    const defaultFormat = defaultFormats[0] || 'pdf';

    const { format } = await inquirer.prompt([
      {
        type: 'list',
        name: 'format',
        message: 'Select report format:',
        choices: [
          { name: 'PDF (.pdf)', value: 'pdf' },
          { name: 'Markdown (.md)', value: 'markdown' }
        ],
        default: defaultFormat
      }
    ]);

    // Keep downstream API the same (array of formats)
    return [format];
  }

  /**
   * Get geo lookup setting
   */
  getGeoLookupSetting() {
    const geoLookupEnabled = getConfig('security.enableGeoLookup', true);
    if (geoLookupEnabled) {
      console.log(chalk.green('✅ IP geolocation enabled'));
    } else {
      console.log(chalk.gray('⚫ IP geolocation disabled'));
    }
    return geoLookupEnabled;
  }

  /**
   * Confirm to proceed
   */
  async confirmProceed(llmProvider, reportFormats, geoLookupEnabled) {
    console.log(chalk.yellow('\n📋 Configuration Summary (auto-continue):'));
    console.log(chalk.gray('   Scan Mode: Comprehensive (automatic)'));
    console.log(chalk.gray('   Analysis: Unified Adaptive Analysis'));
    console.log(chalk.gray(`   LLM Provider: ${llmProvider === 'none' ? 'None (report only)' : llmProvider.toUpperCase()}`));
    console.log(chalk.gray(`   Report Format: ${reportFormats.join(', ')}`));
    console.log(chalk.gray(`   IP Geolocation: ${geoLookupEnabled ? 'enabled' : 'disabled'}`));
    console.log(chalk.gray('   Confirmation: skipped (auto start)'));
    console.log();

    // Auto-continue without user confirmation
    return true;
  }

/**
   * Run unified analysis
   */
  async runAnalysis(options = {}) {
    console.log(chalk.cyan('\n🔍 Starting unified adaptive analysis...\n'));

    const analysisDepth = 'comprehensive';
    const startTime = Date.now();

    log.analysisStart({
      mode: 'unified',
      depth: analysisDepth,
      geoLookup: options.geoLookupEnabled
    });

    const orchestrator = new Orchestrator({
      analysisDepth,
      enableGeoLookup: options.geoLookupEnabled,
      parallelExecution: getConfig('analysis.parallelExecution', true),
      maxParallelAgents: getConfig('analysis.maxParallelAgents', 3)
    });
    
    try {
      this.results = await orchestrator.runAnalysis();
      
      // Validate results before proceeding
      if (!this.results) {
        throw new Error('Analysis completed but no results were returned');
      }
      
      const duration = Date.now() - startTime;
      
      log.analysisComplete(this.results, duration);
      console.log(chalk.green('\n✅ Analysis completed!\n'));

      // Display summary
      this.displaySummary();
    } catch (error) {
      const duration = Date.now() - startTime;
      log.error('Analysis failed', { 
        duration, 
        error: error.message, 
        depth: analysisDepth,
        geoLookup: options.geoLookupEnabled
      });
      console.error(chalk.red(`\n❌ Analysis failed: ${error.message}`));
      if (process.env.DEBUG) {
        console.error(error.stack);
      }
      throw error;
    }
  }









  
  /**
   * Display analysis summary
   */
  displaySummary() {
    // Validate results and summary
    if (!this.results) {
      console.log(chalk.yellow('\n⚠️  No analysis results available to display'));
      return;
    }

    const { summary, overallRisk } = this.results;

    // Handle missing summary
    if (!summary) {
      console.log(chalk.yellow('\n⚠️  No summary data available'));
      return;
    }

    console.log(chalk.bold('\n📊 Analysis Summary:'));
    console.log(chalk.gray('─'.repeat(50)));

    const normalizedRisk = (overallRisk || 'unknown').toLowerCase();
    const riskColor = this.getRiskColor(normalizedRisk);
    console.log(`Overall Risk: ${riskColor(normalizedRisk.toUpperCase())}`);
    console.log(`Total Findings: ${summary.totalFindings || 0}`);

    const highRisk = summary.highRiskFindings || 0;
    const mediumRisk = summary.mediumRiskFindings || 0;
    const lowRisk = summary.lowRiskFindings || 0;

    if (highRisk > 0) {
      console.log(chalk.red(`  🔴 High Risk: ${highRisk}`));
    }
    if (mediumRisk > 0) {
      console.log(chalk.yellow(`  🟡 Medium Risk: ${mediumRisk}`));
    }
    if (lowRisk > 0) {
      console.log(chalk.green(`  🟢 Low Risk: ${lowRisk}`));
    }

    console.log(chalk.gray('─'.repeat(50)));
  }

  isLikelySeedPhrase(candidate) {
    if (!candidate) return false;
    const words = candidate.trim().toLowerCase().split(/\s+/);
    if (words.length < 12 || words.length > 24) return false;
    if (words.some(word => !/^[a-z]+$/.test(word))) return false;

    const stopwords = new Set([
      'the', 'and', 'that', 'with', 'from', 'this', 'have', 'will', 'your',
      'macos', 'analysis', 'system', 'security', 'process', 'service', 'launch',
      'agent', 'apple', 'icloud', 'profile'
    ]);
    const stopwordHits = words.filter(word => stopwords.has(word)).length;
    const uniqueWords = new Set(words).size;

    return stopwordHits <= 2 && uniqueWords >= words.length - 2;
  }

  isLikelyApiKey(candidate) {
    if (!candidate) return false;
    if (candidate.length < 24 || candidate.length > 120) return false;
    if (candidate.includes('<key>') || candidate.includes('</key>')) return false;

    const hasUpper = /[A-Z]/.test(candidate);
    const hasLower = /[a-z]/.test(candidate);
    const hasDigit = /\d/.test(candidate);
    const uniqueRatio = new Set(candidate).size / candidate.length;

    if (!(hasDigit && (hasUpper || hasLower))) return false;
    if (uniqueRatio < 0.2) return false;
    if (/^(.)\1{10,}$/.test(candidate)) return false;

    return true;
  }

  detectSensitiveDataInResults(results) {
    const patterns = [
      { pattern: /0x[a-fA-F0-9]{40}/g, name: 'Ethereum address' },
      { pattern: /[a-fA-F0-9]{64,}/g, name: 'Potential private key' },
      { pattern: /(private|mnemonic|seed).*?[=:][a-zA-Z0-9+/]{8,}/gi, name: 'Private key phrase' },
      { pattern: /[a-zA-Z0-9+/]{32,}={0,2}/g, name: 'API key or token' },
      { pattern: /[6][a-km-zA-HJ-NP-Z1-9]{50,}/g, name: 'Wallet import format' },
      { pattern: /\b([a-z]+(\s+[a-z]+){11,})\b/gi, name: 'Potential seed phrase' },
      { pattern: /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g, name: 'Bitcoin address' },
      { pattern: /\b[a-fA-F0-9]{16,}\b/g, name: 'Long hex string' }
    ];

    const locations = [];
    if (!results?.agents) return locations;

    Object.entries(results.agents).forEach(([agentKey, agentResult]) => {
      const findings = Array.isArray(agentResult?.findings) ? agentResult.findings : [];
      findings.forEach((finding, index) => {
        const fields = [
          { field: 'description', value: finding.description },
          { field: 'command', value: finding.command },
          { field: 'path', value: finding.path },
          { field: 'program', value: finding.program },
          { field: 'plist', value: finding.plist }
        ];

        fields.forEach(({ field, value }) => {
          if (!value || typeof value !== 'string') return;
          patterns.forEach(({ pattern, name }) => {
            let matches = [];

            if (name === 'Potential seed phrase') {
              matches = [...value.matchAll(pattern)]
                .map(match => match[0])
                .filter(seq => this.isLikelySeedPhrase(seq));
            } else if (name === 'API key or token') {
              matches = [...value.matchAll(pattern)]
                .map(match => match[0])
                .filter(seq => this.isLikelyApiKey(seq));
            } else {
              matches = value.match(pattern) || [];
            }

            if (matches.length > 0) {
              locations.push({
                agent: agentResult.agent || agentKey,
                findingIndex: index,
                field,
                path: finding.path || finding.plist || finding.command || 'N/A',
                pattern: name,
                count: matches.length,
                samples: matches.slice(0, 2).map(m => (m.length > 20 ? `${m.slice(0, 20)}***` : m))
              });
            }
          });
        });
      });
    });

    return locations;
  }

  /**
   * Run LLM analysis (with user consent and privacy protection)
   */
  async runLLMAnalysis(provider) {
    if (provider === 'none') {
      console.log(chalk.gray('\n📋 Generating security report only (no AI analysis)\n'));
      return null;
    }

    console.log(chalk.cyan('\n🤖 Preparing AI Analysis...\n'));
    console.log(chalk.gray('🔒 Privacy Protection:'));
    console.log(chalk.gray('   • All private keys will be redacted'));
    console.log(chalk.gray('   • Sensitive data will be blocked from LLM'));
    console.log(chalk.gray('   • Analysis will be aborted if sensitive patterns detected\n'));

    const summary = this.results?.summary || {};
    const highRiskCount = summary.highRiskFindings || 0;
    const totalFindings = summary.totalFindings || 0;
    const minHighRisk = getConfig('llm.minHighRiskFindings', 1);
    const minTotalFindings = getConfig('llm.minTotalFindings', 5);
    const skipBelowThreshold = getConfig('llm.skipWhenBelowThreshold', true);
    const llmMode = getConfig('llm.mode', 'summary');

    if (skipBelowThreshold && highRiskCount < minHighRisk && totalFindings < minTotalFindings) {
      console.log(chalk.gray('⏩ Skipping AI analysis: findings below trigger thresholds'));
      console.log(chalk.gray(`   High risk: ${highRiskCount}/${minHighRisk}, Total: ${totalFindings}/${minTotalFindings}`));
      console.log(chalk.gray('   Adjust llm.minHighRiskFindings/minTotalFindings in config to change behavior\n'));

      this.llmAnalysis = {
        provider,
        skipped: true,
        reason: 'LLM skipped: below trigger thresholds',
        thresholds: {
          minHighRiskFindings: minHighRisk,
          minTotalFindings
        },
        summary: {
          highRiskFindings: highRiskCount,
          totalFindings
        },
        timestamp: new Date().toISOString()
      };
      return this.llmAnalysis;
    }

    // Build payload with privacy protection
    const analyzer = new LLMAnalyzer(provider, null, {
      enableLogging: true,
      logDir: './logs/llm-requests',
      mode: llmMode
    });
    const promptContent = analyzer.buildPrompt(this.results, { objective: 'unified', mode: llmMode });

    // Final security check before proceeding
    console.log(chalk.yellow('🔍 Performing security scan...'));
    const securityCheck = analyzer.performSecurityCheck(promptContent);
    
    if (securityCheck.hasSensitiveData) {
      console.log(chalk.red('\n🚨 SECURITY ALERT:'));
      console.log(chalk.red('   Sensitive data detected in analysis data!'));
      console.log(chalk.red('   AI analysis aborted to protect your privacy.'));
      
      console.log(chalk.yellow('\n📊 Detected Sensitive Patterns:'));
      securityCheck.sensitivePatterns.forEach(pattern => {
        console.log(chalk.yellow(`   • ${pattern.name}: ${pattern.count} occurrence(s)`));
      });
      
      console.log(chalk.cyan('\n💡 Recommendation:'));
      console.log(chalk.cyan('   1. Remove sensitive data from your system'));
      console.log(chalk.cyan('   2. Try analysis again after cleanup'));
      console.log(chalk.cyan('   3. Or continue with report-only analysis\n'));
      
      const detectedLocations = this.detectSensitiveDataInResults(this.results);

      if (detectedLocations.length > 0) {
        console.log(chalk.gray('📂 Location details (redacted for display):'));
        detectedLocations.forEach(location => {
          const sampleText = location.samples && location.samples.length > 0
            ? ` | samples: ${location.samples.join(', ')}`
            : '';
          console.log(chalk.gray(`   • [${location.pattern}] ${location.agent} → ${location.field} @ ${location.path}${sampleText}`));
        });
        console.log();
      } else {
        console.log(chalk.gray('ℹ️  No specific file or command path was flagged. Likely a formatting false positive (e.g., plist <key> tags or long sentences).\n'));
      }
      
      // Persist the security check into report data so users can triage
      this.llmAnalysis = {
        provider,
        skipped: true,
        reason: 'Sensitive data detected in analysis data',
        securityCheck: {
          ...securityCheck,
          detectedLocations
        },
        timestamp: new Date().toISOString()
      };
      return this.llmAnalysis;
    }

    const spinner = ora('Running AI analysis with privacy protection...').start();

    try {
      this.llmAnalysis = await analyzer.analyze(this.results, {
        objective: 'unified',
        promptOverride: promptContent
      });

      spinner.succeed('AI analysis completed (details logged).');

      console.log(chalk.green('\n✅ Privacy Protected AI analysis finished. Full details are stored in logs.'));
      console.log(chalk.green('\n🔒 All sensitive data was automatically redacted before analysis\n'));

      return this.llmAnalysis;
    } catch (error) {
      spinner.fail(`AI analysis failed: ${error.message}`);

      if (error.message.includes('SECURITY: Sensitive data detected')) {
        console.log(chalk.red('\n🚨 Privacy protection triggered!'));
        console.log(chalk.red('   Analysis was aborted to prevent sensitive data leakage'));
        console.log(chalk.cyan('\n💡 This is a safety feature to protect your private keys and sensitive information\n'));
        return null;
      }

      // Ask if user wants to continue without LLM
      const { continueWithout } = await inquirer.prompt([
        {
          type: 'confirm',
          name: 'continueWithout',
          message: 'Continue without AI analysis?',
          default: true
        }
      ]);

      if (!continueWithout) {
        process.exit(1);
      }

      return null;
    }
  }

/**
   * Generate and save reports
   */
  async generateReports(formats) {
    // Validate inputs
    if (!this.results) {
      console.log(chalk.yellow('\n⚠️  No analysis results available. Skipping report generation.'));
      return [];
    }

    const spinner = ora('Generating reports...').start();
    const startTime = Date.now();

    try {
      const reportManager = new ReportManager(this.results, this.llmAnalysis, {
        reportsDir: getConfig('reports.outputDir', './reports'),
        retentionDays: getConfig('reports.retentionDays', 90),
        defaultTemplate: getConfig('reports.defaultTemplate', 'executive'),
        pdfOptions: getConfig('reports.pdfOptions', {})
      });
      
      const savedFiles = await reportManager.generateReports(formats);
      const duration = Date.now() - startTime;
      
      log.reportGeneration(formats, savedFiles.map(f => f.path), duration);

      spinner.succeed('Reports generated!');

      console.log(chalk.bold('\n📁 Saved Reports:'));
      savedFiles.forEach(file => {
        const typeEmoji = file.type === 'pdf' ? '📑' : '📄';
        console.log(`   ${typeEmoji} ${file.type.charAt(0).toUpperCase() + file.type.slice(1)}: ${file.path}`);
      });
      
      const reportsDir = getConfig('reports.outputDir', './reports');
      console.log(chalk.cyan(`\n💡 All reports are organized in ${reportsDir}/ directory by year and month`));
    } catch (error) {
      log.error('Report generation failed', { error: error.message });
      spinner.fail(`Report generation failed: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get color for risk level
   */
  getRiskColor(risk) {
    const normalizedRisk = (risk || '').toLowerCase();
    switch (normalizedRisk) {
      case 'high':
        return chalk.red.bold;
      case 'medium':
        return chalk.yellow.bold;
      case 'low':
        return chalk.green;
      default:
        return chalk.gray;
    }
  }

  /**
   * Main application flow
   */
  async run() {
    try {
      this.displayBanner();

      // Step 1: Auto-detect LLM provider
      const detectedProvider = this.detectLLMProvider();

      // Step 2: Choose LLM analysis option
      const llmProvider = await this.chooseLLMAnalysis(detectedProvider);

      // Step 3: Select report format
      const reportFormats = await this.selectReportFormat();

      // Step 4: IP geolocation (always enabled)
      const geoLookupEnabled = this.getGeoLookupSetting();

      // Step 5: Confirm
      const proceed = await this.confirmProceed(llmProvider, reportFormats, geoLookupEnabled);

      if (!proceed) {
        console.log(chalk.yellow('\n👋 Analysis cancelled.\n'));
        process.exit(0);
      }

      // Step 6: Run unified analysis (comprehensive by default)
      await this.runAnalysis({ geoLookupEnabled });

      // Step 7: Run LLM analysis (if selected)
      if (llmProvider !== 'none') {
        await this.runLLMAnalysis(llmProvider);
      }

      // Step 8: Generate reports
      await this.generateReports(reportFormats);

      console.log(chalk.green.bold('\n✨ Analysis complete! Check your reports for details.\n'));
    } catch (error) {
      console.error(chalk.red(`\n❌ Error: ${error.message}\n`));
      if (process.env.DEBUG) {
        console.error(error.stack);
      }
      process.exit(1);
    }
  }
}

// Check for help flag
if (process.argv.includes('--help') || process.argv.includes('-h')) {
  console.log(`
MacOS Security Analysis CLI v2.0.0

USAGE:
  npm start                    # Run interactive analysis
  npm start -- --help         # Show this help message

EXAMPLES:
  npm start                    # Interactive mode with prompts
  
FEATURES:
  🔍 Unified Adaptive Analysis - Automatically detects and analyzes relevant areas
  📑 Professional PDF Reports - Enterprise-quality reporting
  🔗 Smart Blockchain Detection - Only runs blockchain agents when needed
  📊 Structured Logging - Comprehensive audit trails
  ⚙️  Configuration Management - Customizable behavior
  🔒 Privacy Protection - Advanced data sanitization
  
For more information, see the README.md file.
  `);
  process.exit(0);
}

// Run the CLI
const cli = new SecurityAnalysisCLI();
cli.run();

// Export for testing
export { SecurityAnalysisCLI };
