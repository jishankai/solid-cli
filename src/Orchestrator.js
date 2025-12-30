import { ResourceAgent } from './agents/ResourceAgent.js';
import { SystemAgent } from './agents/SystemAgent.js';
import { PersistenceAgent } from './agents/PersistenceAgent.js';
import { ProcessAgent } from './agents/ProcessAgent.js';
import { NetworkAgent } from './agents/NetworkAgent.js';
import { PermissionAgent } from './agents/PermissionAgent.js';
import { BlockchainAgent } from './agents/BlockchainAgent.js';
import { DeFiSecurityAgent } from './agents/DeFiSecurityAgent.js';
import { executeShellCommand } from './utils/commander.js';
import { log } from './logging/Logger.js';
import ora from 'ora';
import chalk from 'chalk';

/**
 * Orchestrator - Coordinates all agents and aggregates results
 */
export class Orchestrator {
  constructor(options = {}) {
    this.enableGeoLookup = Boolean(options.enableGeoLookup);
    this.geoLookupLimit = options.geoLookupLimit || 10;
    this.analysisDepth = options.analysisDepth || 'comprehensive'; // 'fast', 'comprehensive', 'deep'
    this.parallelExecution = options.parallelExecution !== false;
    this.maxParallelAgents = options.maxParallelAgents || 3;
    this.agents = {};
    this.results = null;
  }

  /**
   * Initialize base agents for Phase 1 analysis
   */
  initializeBaseAgents() {
    return {
      resource: new ResourceAgent(),
      system: new SystemAgent(),
      persistence: new PersistenceAgent(),
      process: new ProcessAgent(),
      network: new NetworkAgent({
        enableGeoLookup: this.enableGeoLookup,
        geoLookupLimit: this.geoLookupLimit
      }),
      permission: new PermissionAgent()
    };
  }

  /**
   * Initialize conditional agents for extended analysis
   */
  initializeConditionalAgents() {
    return {
      blockchain: new BlockchainAgent(),
      defi: new DeFiSecurityAgent()
    };
  }

  /**
   * Check if blockchain indicators are present in initial results
   */
  hasBlockchainIndicators(initialResults) {
    return this.extractBlockchainIndicators(initialResults).length > 0;
  }

  /**
   * Extract specific blockchain indicators
   */
  extractBlockchainIndicators(initialResults) {
    const indicators = [];
    
    // Check process findings for blockchain indicators
    const processResult = initialResults.process;
    if (processResult && processResult.findings) {
      const blockchainKeywords = [
        'bitcoin', 'ethereum', 'crypto', 'blockchain', 'wallet', 'mining',
        'metamask', 'phantom', 'coinbase', 'binance', 'uniswap', 'defi'
      ];
      
      for (const finding of processResult.findings) {
        const searchText = `${finding.command || ''} ${finding.program || ''} ${finding.description || ''}`.toLowerCase();
        const matchedKeywords = blockchainKeywords.filter(keyword => searchText.includes(keyword));
        
        if (matchedKeywords.length > 0) {
          indicators.push({
            type: 'process',
            source: finding,
            keywords: matchedKeywords
          });
        }
      }
    }
    
    // Check network connections for blockchain domains
    const networkResult = initialResults.network;
    if (networkResult && networkResult.findings) {
      const blockchainDomains = [
        'etherscan', 'uniswap', 'opensea', 'pancakeswap', 'curve',
        'compound', 'aave', 'sushiswap', '1inch', 'metamask'
      ];
      
      for (const finding of networkResult.findings) {
        if (finding.remoteAddress) {
          const domain = finding.remoteAddress.toLowerCase();
          const matchedDomains = blockchainDomains.filter(d => domain.includes(d));
          
          if (matchedDomains.length > 0) {
            indicators.push({
              type: 'network',
              source: finding,
              domains: matchedDomains
            });
          }
        }
      }
    }
    
    return indicators;
  }

  /**
   * Check if extended forensics analysis should be triggered
   */
  needsExtendedForensics(initialResults) {
    const summary = this.generateSummary(initialResults);

    // Trigger extended analysis if high risk findings or many medium risk findings
    if ((summary?.highRiskFindings || 0) > 0) return true;
    if ((summary?.mediumRiskFindings || 0) >= 5) return true;

    return false;
  }

  /**
   * Run unified adaptive analysis
   */
  async runAnalysis() {
    console.log(chalk.cyan('\n🚀 Starting Unified Security Analysis...\n'));
    
    const results = {};
    const analysisPhases = [];

    // Phase 1: Base agents always run
    console.log(chalk.blue('Phase 1: Core Security Analysis'));
    const baseAgents = this.initializeBaseAgents();
    let totalAgents = Object.keys(baseAgents).length;
    let completedAgents = 0;
    
    if (this.parallelExecution) {
      // Run agents in parallel with limit
      const agentEntries = Object.entries(baseAgents);
      const chunks = [];
      
      for (let i = 0; i < agentEntries.length; i += this.maxParallelAgents) {
        chunks.push(agentEntries.slice(i, i + this.maxParallelAgents));
      }
      
      for (const chunk of chunks) {
        const chunkPromises = chunk.map(async ([key, agent]) => {
          const spinner = ora(`Running ${agent.name}...`).start();
          const startTime = Date.now();
          
          log.agentStart(agent.name, { parallel: true });
          
          try {
            const result = await agent.analyze();
            const duration = Date.now() - startTime;
            
            results[key] = result;
            log.agentComplete(agent.name, result, duration);
            
            const normalizedRisk = (result.overallRisk || 'unknown').toLowerCase();
            const riskColor = this.getRiskColor(normalizedRisk);
            completedAgents += 1;
            spinner.succeed(`${agent.name} completed - ${completedAgents}/${totalAgents} - Risk: ${riskColor(normalizedRisk.toUpperCase())}`);
            return result;
          } catch (error) {
            const duration = Date.now() - startTime;
            
            results[key] = {
              agent: agent.name,
              error: error.message,
              overallRisk: 'unknown'
            };
            
            log.agentError(agent.name, error, duration);
            completedAgents += 1;
            spinner.fail(`${agent.name} failed - ${completedAgents}/${totalAgents}: ${error.message}`);
            return results[key];
          }
        });
        
        await Promise.all(chunkPromises);
      }
    } else {
      // Run sequentially
      for (const [key, agent] of Object.entries(baseAgents)) {
        const spinner = ora(`Running ${agent.name}...`).start();
        const startTime = Date.now();
        
        log.agentStart(agent.name, { parallel: false });
        
        try {
          const result = await agent.analyze();
          const duration = Date.now() - startTime;
          
          results[key] = result;
          log.agentComplete(agent.name, result, duration);
          
          const normalizedRisk = (result.overallRisk || 'unknown').toLowerCase();
          const riskColor = this.getRiskColor(normalizedRisk);
          completedAgents += 1;
          spinner.succeed(`${agent.name} completed - ${completedAgents}/${totalAgents} - Risk: ${riskColor(normalizedRisk.toUpperCase())}`);
        } catch (error) {
          const duration = Date.now() - startTime;
          
          results[key] = {
            agent: agent.name,
            error: error.message,
            overallRisk: 'unknown'
          };
          
          log.agentError(agent.name, error, duration);
          completedAgents += 1;
          spinner.fail(`${agent.name} failed - ${completedAgents}/${totalAgents}: ${error.message}`);
        }
      }
    }
    
    analysisPhases.push({
      phase: 'Core Security Analysis',
      agents: Object.keys(baseAgents),
      completed: true
    });

    // Phase 2: Adaptive extension based on findings
    console.log(chalk.blue('\nPhase 2: Adaptive Analysis'));
    
    const extendedPhases = [];
    
    // Check for blockchain indicators
    if (this.hasBlockchainIndicators(results)) {
      console.log(chalk.yellow('🔗 Blockchain indicators detected - activating blockchain analysis'));
      extendedPhases.push('Blockchain Security Analysis');
      
      const indicators = this.extractBlockchainIndicators(results);
      log.blockchainDetection(indicators);
      
      const conditionalAgents = this.initializeConditionalAgents();
      totalAgents += Object.keys(conditionalAgents).length;
      
      for (const [key, agent] of Object.entries(conditionalAgents)) {
        const spinner = ora(`Running ${agent.name}...`).start();
        const startTime = Date.now();
        
        log.agentStart(agent.name, { triggered: 'blockchain_detection' });
        
        try {
          const result = await agent.analyze();
          const duration = Date.now() - startTime;
          
          results[key] = result;
          log.agentComplete(agent.name, result, duration);
          
          const normalizedRisk = (result.overallRisk || 'unknown').toLowerCase();
          const riskColor = this.getRiskColor(normalizedRisk);
          completedAgents += 1;
          spinner.succeed(`${agent.name} completed - ${completedAgents}/${totalAgents} - Risk: ${riskColor(normalizedRisk.toUpperCase())}`);
        } catch (error) {
          const duration = Date.now() - startTime;
          
          results[key] = {
            agent: agent.name,
            error: error.message,
            overallRisk: 'unknown'
          };
          
          log.agentError(agent.name, error, duration);
          completedAgents += 1;
          spinner.fail(`${agent.name} failed - ${completedAgents}/${totalAgents}: ${error.message}`);
        }
      }
    } else {
      console.log(chalk.gray('   No blockchain indicators detected - skipping blockchain analysis'));
    }
    
    // Check for extended forensics need
    if (this.needsExtendedForensics(results)) {
      console.log(chalk.yellow('🔍 Risk indicators detected - enabling extended analysis'));
      extendedPhases.push('Extended Forensics Analysis');
      
      // Future: Add extended forensics logic here
      console.log(chalk.gray('   Extended forensics capabilities will be added in future version'));
    }

    analysisPhases.push({
      phase: 'Adaptive Analysis',
      extensions: extendedPhases,
      completed: true
    });

    // Phase 3: Integration and correlation
    console.log(chalk.blue('\nPhase 3: Result Integration'));
    const correlatedResults = this.correlateFindings(results);
    this.updateProgress = () => {};
    console.log(chalk.green('✅ Analysis completed successfully!'));

    this.results = {
      mode: 'unified',
      analysisDepth: this.analysisDepth,
      timestamp: new Date().toISOString(),
      hostname: await this.getHostname(),
      osVersion: await this.getOSVersion(),
      agents: correlatedResults,
      overallRisk: this.calculateOverallRisk(correlatedResults),
      summary: this.generateSummary(correlatedResults),
      analysisPhases,
      adaptiveAnalysis: {
        blockchainAnalysisEnabled: this.hasBlockchainIndicators(results),
        extendedForensicsEnabled: this.needsExtendedForensics(results),
        totalAgentsRan: Object.keys(correlatedResults).length
      }
    };

    return this.results;
  }

  /**
   * Correlate findings across agents to identify patterns
   */
  correlateFindings(results) {
    const correlated = { ...results };
    
    // Future: Add sophisticated correlation logic
    // Example: Correlate process findings with network connections
    // Example: Correlate persistence mechanisms with startup items
    
    return correlated;
  }

  /**
   * Get system hostname
   */
  async getHostname() {
    return (await executeShellCommand('hostname')).trim();
  }

  /**
   * Get macOS version
   */
  async getOSVersion() {
    return (await executeShellCommand('sw_vers -productVersion')).trim();
  }

  /**
   * Calculate overall risk across all agents
   */
  calculateOverallRisk(results) {
    if (!results || typeof results !== 'object') {
      return 'unknown';
    }

    const risks = Object.values(results)
      .filter(result => result && result.overallRisk)
      .map(r => r.overallRisk);

    if (risks.length === 0) {
      return 'unknown';
    }

    if (risks.includes('high')) return 'high';
    if (risks.includes('medium')) return 'medium';
    return 'low';
  }

  /**
   * Generate summary of findings
   */
  generateSummary(results) {
    // Ensure results is a valid object
    if (!results || typeof results !== 'object') {
      return {
        totalFindings: 0,
        highRiskFindings: 0,
        mediumRiskFindings: 0,
        lowRiskFindings: 0,
        agentSummaries: {},
        error: 'Invalid results data'
      };
    }

    const summary = {
      totalFindings: 0,
      highRiskFindings: 0,
      mediumRiskFindings: 0,
      lowRiskFindings: 0,
      agentSummaries: {}
    };

    try {
      for (const [key, result] of Object.entries(results)) {
        // Ensure result exists and is valid
        if (!result) {
          summary.agentSummaries[key] = { error: 'Result is null or undefined' };
          continue;
        }

        if (result.error) {
          summary.agentSummaries[key] = { error: result.error };
          continue;
        }

        // Ensure findings is an array
        const findings = Array.isArray(result.findings) ? result.findings : [];
        const findingCount = findings.length;

        summary.totalFindings += findingCount;

        // Count by risk level
        for (const finding of findings) {
          if (finding && finding.risk === 'high') {
            summary.highRiskFindings++;
          } else if (finding && finding.risk === 'medium') {
            summary.mediumRiskFindings++;
          } else if (finding) {
            summary.lowRiskFindings++;
          }
        }

        const derivedRisk = this.deriveRiskFromFindings(findings, result.overallRisk);

        summary.agentSummaries[key] = {
          findings: findingCount,
          risk: derivedRisk
        };
      }
    } catch (error) {
      console.error(`Error generating summary: ${error.message}`);
      summary.error = error.message;
    }

    return summary;
  }

  /**
   * Derive risk from findings to keep agent badges consistent
   */
  deriveRiskFromFindings(findings, reportedRisk = 'unknown') {
    if (!Array.isArray(findings) || findings.length === 0) return 'low';
    if (findings.some(f => f && f.risk === 'high')) return 'high';
    if (findings.some(f => f && f.risk === 'medium')) return 'medium';
    return 'low';
  }

  /**
   * Get color function for risk level
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

  updateProgress(spinner, completed, total) {
    const text = `Progress: ${completed}/${total}`;
    if (spinner && spinner.isSpinning) {
      spinner.text = text;
    }
    console.log(chalk.gray(text));
  }

  /**
   * Get aggregated results
   */
  getResults() {
    return this.results;
  }
}
