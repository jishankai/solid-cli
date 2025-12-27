import { ResourceAgent } from './agents/ResourceAgent.js';
import { SystemAgent } from './agents/SystemAgent.js';
import { PersistenceAgent } from './agents/PersistenceAgent.js';
import { ProcessAgent } from './agents/ProcessAgent.js';
import { NetworkAgent } from './agents/NetworkAgent.js';
import { PermissionAgent } from './agents/PermissionAgent.js';
import { executeShellCommand } from './utils/commander.js';
import ora from 'ora';
import chalk from 'chalk';

/**
 * Orchestrator - Coordinates all agents and aggregates results
 */
export class Orchestrator {
  constructor(options = {}) {
    this.mode = options.mode || 'integrated'; // 'integrated', 'forensics'
    this.enableGeoLookup = Boolean(options.enableGeoLookup);
    this.geoLookupLimit = options.geoLookupLimit || 10;
    this.agents = this.initializeAgents();
    this.results = null;
  }

  /**
   * Initialize agents based on analysis mode
   */
  initializeAgents() {
    const agents = {
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

    // Define agent sets for different modes
    const modeSets = {
      integrated: ['resource', 'system', 'persistence', 'process', 'network', 'permission'],
      security: ['resource', 'system', 'persistence', 'process', 'network', 'permission'],
      forensics: ['resource', 'system', 'persistence', 'process', 'network', 'permission']
    };

    const enabledAgentKeys = modeSets[this.mode] || modeSets.integrated;
    const enabledAgents = {};

    for (const key of enabledAgentKeys) {
      enabledAgents[key] = agents[key];
    }

    return enabledAgents;
  }

  /**
   * Run all enabled agents
   */
  async runAnalysis() {
    const results = {};
    const agentNames = Object.keys(this.agents);

    console.log(`\nRunning ${agentNames.length} agent(s) in ${this.mode} mode...\n`);

    for (const [key, agent] of Object.entries(this.agents)) {
      const spinner = ora(`Running ${agent.name}...`).start();

      try {
        const result = await agent.analyze();
        results[key] = result;

        const riskColor = this.getRiskColor(result.overallRisk);
        spinner.succeed(`${agent.name} completed - Risk: ${riskColor(result.overallRisk.toUpperCase())}`);
      } catch (error) {
        spinner.fail(`${agent.name} failed: ${error.message}`);
        results[key] = {
          agent: agent.name,
          error: error.message,
          overallRisk: 'unknown'
        };
      }
    }

    this.results = {
      mode: this.mode,
      timestamp: new Date().toISOString(),
      hostname: await this.getHostname(),
      osVersion: await this.getOSVersion(),
      agents: results,
      overallRisk: this.calculateOverallRisk(results),
      summary: this.generateSummary(results)
    };

    return this.results;
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
    const risks = Object.values(results).map(r => r.overallRisk);

    if (risks.includes('high')) return 'high';
    if (risks.includes('medium')) return 'medium';
    return 'low';
  }

  /**
   * Generate summary of findings
   */
  generateSummary(results) {
    const summary = {
      totalFindings: 0,
      highRiskFindings: 0,
      mediumRiskFindings: 0,
      lowRiskFindings: 0,
      agentSummaries: {}
    };

    for (const [key, result] of Object.entries(results)) {
      if (result.error) {
        summary.agentSummaries[key] = { error: result.error };
        continue;
      }

      const findings = result.findings || [];
      const findingCount = findings.length;

      summary.totalFindings += findingCount;

      // Count by risk level
      for (const finding of findings) {
        if (finding.risk === 'high') summary.highRiskFindings++;
        else if (finding.risk === 'medium') summary.mediumRiskFindings++;
        else summary.lowRiskFindings++;
      }

      summary.agentSummaries[key] = {
        findings: findingCount,
        risk: result.overallRisk
      };
    }

    return summary;
  }

  /**
   * Get color function for risk level
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
   * Get aggregated results
   */
  getResults() {
    return this.results;
  }
}
