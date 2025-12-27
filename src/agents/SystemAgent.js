import { BaseAgent } from './BaseAgent.js';
import { executeShellCommand } from '../utils/commander.js';
import { existsSync, readFileSync } from 'fs';

/**
 * SystemAgent - Checks system integrity and security settings
 */
export class SystemAgent extends BaseAgent {
  constructor() {
    super('SystemAgent');
  }

  async analyze() {
    const sip = await this.checkSIP();
    const gatekeeper = await this.checkGatekeeper();
    const updates = await this.checkSystemUpdates();
    const sudoers = await this.checkSudoers();

    const findings = [];

    // Evaluate SIP
    if (!sip.enabled) {
      findings.push({
        type: 'sip_disabled',
        risk: 'high',
        description: 'System Integrity Protection (SIP) is disabled'
      });
    }

    // Evaluate Gatekeeper
    if (!gatekeeper.enabled) {
      findings.push({
        type: 'gatekeeper_disabled',
        risk: 'medium',
        description: 'Gatekeeper is disabled, allowing unsigned apps'
      });
    }

    // Evaluate updates
    if (updates.available > 0) {
      findings.push({
        type: 'updates_available',
        risk: 'medium',
        description: `${updates.available} system update(s) available`
      });
    }

    // Evaluate sudoers
    if (sudoers.risks.length > 0) {
      findings.push(...sudoers.risks);
    }

    this.results = {
      agent: this.name,
      timestamp: new Date().toISOString(),
      sip,
      gatekeeper,
      updates,
      sudoers: sudoers.rules,
      findings,
      overallRisk: this.calculateOverallRisk(findings)
    };

    return this.results;
  }

  /**
   * Check System Integrity Protection status
   */
  async checkSIP() {
    const output = await executeShellCommand('csrutil status');
    const enabled = output.toLowerCase().includes('enabled');

    return {
      enabled,
      status: output.trim()
    };
  }

  /**
   * Check Gatekeeper status
   */
  async checkGatekeeper() {
    const output = await executeShellCommand('spctl --status');
    const enabled = output.toLowerCase().includes('assessments enabled');

    return {
      enabled,
      status: output.trim()
    };
  }

  /**
   * Check for available system updates
   */
  async checkSystemUpdates() {
    const output = await executeShellCommand('softwareupdate -l 2>&1');

    // Parse update count
    const lines = output.split('\n');
    let updateCount = 0;
    const updates = [];

    for (const line of lines) {
      if (line.includes('*') || line.includes('Label:')) {
        updateCount++;
        updates.push(line.trim());
      }
    }

    // If output says "No new software available"
    if (output.toLowerCase().includes('no new software available')) {
      updateCount = 0;
    }

    return {
      available: updateCount,
      updates: updates.slice(0, 5), // Limit to first 5
      lastCheck: new Date().toISOString()
    };
  }

  /**
   * Check sudoers configuration for security issues
   */
  async checkSudoers() {
    const rules = [];
    const risks = [];

    // Check main sudoers file
    const sudoersPath = '/etc/sudoers';
    const sudoersDPath = '/etc/sudoers.d';

    try {
      // Read sudoers file (may require permissions)
      if (existsSync(sudoersPath)) {
        const content = readFileSync(sudoersPath, 'utf-8');
        const lines = content.split('\n');

        for (const line of lines) {
          if (line.trim() && !line.startsWith('#')) {
            rules.push(line.trim());

            // Check for NOPASSWD rules
            if (line.includes('NOPASSWD')) {
              risks.push({
                type: 'sudoers_nopasswd',
                rule: line.trim(),
                risk: 'medium',
                description: 'Sudoers rule allows passwordless sudo'
              });
            }

            // Check for overly permissive ALL rules
            if (line.includes('ALL=(ALL)') || line.includes('ALL = (ALL) ALL')) {
              risks.push({
                type: 'sudoers_all_permissions',
                rule: line.trim(),
                risk: 'high',
                description: 'Sudoers rule grants full permissions'
              });
            }
          }
        }
      }
    } catch (error) {
      // Permission denied or file doesn't exist
      rules.push('Unable to read sudoers file (permission denied)');
    }

    return { rules, risks };
  }
}
