#!/usr/bin/env node

import inquirer from 'inquirer';
import chalk from 'chalk';
import { Orchestrator } from './Orchestrator.js';
import { LLMAnalyzer } from './llm/LLMAnalyzer.js';
import { ReportGenerator } from './report/ReportGenerator.js';
import ora from 'ora';

/**
 * Main CLI Application
 */
class SecurityAnalysisCLI {
  constructor() {
    this.results = null;
    this.llmAnalysis = null;
    this.geoLookupEnabled = true;
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
   * Main menu - Select analysis mode
   */
  async selectAnalysisMode() {
    const { mode } = await inquirer.prompt([
      {
        type: 'list',
        name: 'mode',
        message: 'Select analysis mode (resource and security are combined by default):',
        choices: [
          { name: '✅ Integrated Resource + Security Scan (Recommended)', value: 'integrated' },
          { name: '⭕ Deep Forensics Analysis (Time-Consuming)', value: 'forensics' }
        ],
        default: 'integrated'
      }
    ]);

    return mode;
  }

  /**
   * Auto-detect LLM provider from available API keys
   */
  detectLLMProvider() {
    const hasOpenAI = process.env.OPENAI_API_KEY && process.env.OPENAI_API_KEY !== 'your_openai_api_key_here';
    const hasClaude = process.env.ANTHROPIC_API_KEY && process.env.ANTHROPIC_API_KEY !== 'your_anthropic_api_key_here';

    if (hasClaude) {
      console.log(chalk.green('✅ Using Claude (Anthropic) - API key detected'));
      return 'claude';
    } else if (hasOpenAI) {
      console.log(chalk.green('✅ Using OpenAI (GPT-4) - API key detected'));
      return 'openai';
    } else {
      console.log(chalk.yellow('⚠️  No LLM API keys found - generating report only'));
      console.log(chalk.gray('   Set OPENAI_API_KEY or ANTHROPIC_API_KEY in .env file'));
      return 'none';
    }
  }

  /**
   * Select report format
   */
  async selectReportFormat() {
    const { format } = await inquirer.prompt([
      {
        type: 'checkbox',
        name: 'format',
        message: 'Select report format(s):',
        choices: [
          { name: 'Markdown (.md)', value: 'markdown', checked: true },
          { name: 'PDF (.pdf)', value: 'pdf', checked: false }
        ],
        validate: (answer) => {
          if (answer.length === 0) {
            return 'You must select at least one format.';
          }
          return true;
        }
      }
    ]);

    return format;
  }

  /**
   * Get geo lookup setting (always enabled)
   */
  getGeoLookupSetting() {
    console.log(chalk.green('✅ IP geolocation enabled by default'));
    return true;
  }

  /**
   * Confirm to proceed
   */
  async confirmProceed(mode, llmProvider, reportFormats, geoLookupEnabled) {
    console.log(chalk.yellow('\n📋 Configuration Summary:'));
    console.log(chalk.gray(`   Mode: ${mode}`));
    console.log(chalk.gray(`   LLM Provider: ${llmProvider === 'none' ? 'None (report only)' : llmProvider.toUpperCase()}`));
    console.log(chalk.gray(`   Report Format: ${reportFormats.join(', ')}`));
    console.log(chalk.gray(`   IP Geolocation: ${geoLookupEnabled ? 'enabled' : 'disabled'}`));
    console.log();

    const { proceed } = await inquirer.prompt([
      {
        type: 'confirm',
        name: 'proceed',
        message: 'Proceed with analysis?',
        default: true
      }
    ]);

    return proceed;
  }

  /**
   * Run the analysis
   */
  async runAnalysis(mode, options = {}) {
    console.log(chalk.cyan('\n🔍 Starting system analysis...\n'));

    const orchestrator = new Orchestrator({
      mode,
      enableGeoLookup: options.geoLookupEnabled
    });
    this.results = await orchestrator.runAnalysis();

    console.log(chalk.green('\n✅ Analysis completed!\n'));

    // Display summary
    this.displaySummary();
  }









  /**
   * Show full data preview (formatted JSON)
   */


  /**
   * Display analysis summary
   */
  displaySummary() {
    const { summary, overallRisk } = this.results;

    console.log(chalk.bold('\n📊 Analysis Summary:'));
    console.log(chalk.gray('─'.repeat(50)));

    const riskColor = this.getRiskColor(overallRisk);
    console.log(`Overall Risk: ${riskColor(overallRisk.toUpperCase())}`);
    console.log(`Total Findings: ${summary.totalFindings}`);

    if (summary.highRiskFindings > 0) {
      console.log(chalk.red(`  🔴 High Risk: ${summary.highRiskFindings}`));
    }
    if (summary.mediumRiskFindings > 0) {
      console.log(chalk.yellow(`  🟡 Medium Risk: ${summary.mediumRiskFindings}`));
    }
    if (summary.lowRiskFindings > 0) {
      console.log(chalk.green(`  🟢 Low Risk: ${summary.lowRiskFindings}`));
    }

    console.log(chalk.gray('─'.repeat(50)));
  }

  /**
   * Run LLM analysis
   */
  async runLLMAnalysis(provider) {
    if (provider === 'none') {
      return null;
    }

    // Build payload and send directly (no user review)
    const analyzer = new LLMAnalyzer(provider, null, {
      enableLogging: true,
      logDir: './logs/llm-requests'
    });
    const promptContent = analyzer.buildPrompt(this.results, { objective: 'integrated' });

    const spinner = ora('Running AI analysis...').start();

    try {
      this.llmAnalysis = await analyzer.analyze(this.results, {
        objective: 'integrated',
        promptOverride: promptContent
      });

      spinner.succeed('AI analysis completed!');

      console.log(chalk.cyan('\n🤖 AI Analysis:\n'));
      console.log(chalk.gray('─'.repeat(70)));
      console.log(this.llmAnalysis.analysis);
      console.log(chalk.gray('─'.repeat(70)));

      return this.llmAnalysis;
    } catch (error) {
      spinner.fail(`AI analysis failed: ${error.message}`);

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
    const spinner = ora('Generating reports...').start();

    try {
      const generator = new ReportGenerator(this.results, this.llmAnalysis);
      const savedFiles = [];

      if (formats.includes('markdown')) {
        const mdPath = await generator.saveMarkdown('./');
        savedFiles.push(chalk.green(`📄 Markdown: ${mdPath}`));
      }

      if (formats.includes('pdf')) {
        try {
          const pdfPath = await generator.savePDF('./');
          savedFiles.push(chalk.green(`📑 PDF: ${pdfPath}`));
        } catch (error) {
          spinner.warn(`PDF generation skipped: ${error.message}`);
        }
      }

      spinner.succeed('Reports generated!');

      console.log(chalk.bold('\n📁 Saved Reports:'));
      savedFiles.forEach(file => console.log(`   ${file}`));
    } catch (error) {
      spinner.fail(`Report generation failed: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get color for risk level
   */
  getRiskColor(risk) {
    switch (risk) {
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

      // Step 1: Select analysis mode
      const mode = await this.selectAnalysisMode();

      // Step 2: Auto-detect LLM provider
      const llmProvider = this.detectLLMProvider();

      // Step 3: Select report format
      const reportFormats = await this.selectReportFormat();

      // Step 4: IP geolocation (always enabled)
      const geoLookupEnabled = this.getGeoLookupSetting();

      // Step 5: Confirm
      const proceed = await this.confirmProceed(mode, llmProvider, reportFormats, geoLookupEnabled);

      if (!proceed) {
        console.log(chalk.yellow('\n👋 Analysis cancelled.\n'));
        process.exit(0);
      }

      // Step 6: Run analysis
      await this.runAnalysis(mode, { geoLookupEnabled });

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

// Run the CLI
const cli = new SecurityAnalysisCLI();
cli.run();
