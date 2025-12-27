import { BaseAgent } from './BaseAgent.js';
import { executeShellCommand } from '../utils/commander.js';
import { readdirSync, readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { parse } from 'path';

/**
 * PersistenceAgent - Detects persistence mechanisms on macOS
 * This is the core security agent
 */
export class PersistenceAgent extends BaseAgent {
  constructor() {
    super('PersistenceAgent');
    this.trustedPaths = ['/Applications', '/System', '/usr/bin', '/usr/sbin', '/usr/libexec'];
    this.suspiciousCommands = ['bash', 'sh', 'curl', 'wget', 'python', 'python3', 'perl', 'ruby'];
  }

  async analyze() {
    const launchAgents = await this.scanLaunchAgents();
    const launchDaemons = await this.scanLaunchDaemons();
    const loginItems = await this.scanLoginItems();
    const crontab = await this.scanCrontab();

    const allFindings = [
      ...launchAgents,
      ...launchDaemons,
      ...loginItems,
      ...crontab
    ];

    this.results = {
      agent: this.name,
      timestamp: new Date().toISOString(),
      launchAgents: launchAgents.length,
      launchDaemons: launchDaemons.length,
      loginItems: loginItems.length,
      crontabEntries: crontab.length,
      findings: allFindings,
      overallRisk: this.calculateOverallRisk(allFindings)
    };

    return this.results;
  }

  /**
   * Scan user LaunchAgents
   */
  async scanLaunchAgents() {
    const userHome = process.env.HOME;
    const paths = [
      join(userHome, 'Library/LaunchAgents'),
      '/Library/LaunchAgents'
    ];

    const findings = [];

    for (const basePath of paths) {
      if (!existsSync(basePath)) continue;

      try {
        const files = readdirSync(basePath);

        for (const file of files) {
          if (!file.endsWith('.plist')) continue;

          const fullPath = join(basePath, file);
          const finding = await this.analyzePlist(fullPath, 'LaunchAgent');

          if (finding) {
            findings.push(finding);
          }
        }
      } catch (error) {
        // Permission denied or directory doesn't exist
      }
    }

    return findings;
  }

  /**
   * Scan LaunchDaemons (system-wide)
   */
  async scanLaunchDaemons() {
    const paths = [
      '/Library/LaunchDaemons',
      '/System/Library/LaunchDaemons' // Read-only verification
    ];

    const findings = [];

    for (const basePath of paths) {
      if (!existsSync(basePath)) continue;

      try {
        const files = readdirSync(basePath);

        for (const file of files) {
          if (!file.endsWith('.plist')) continue;

          const fullPath = join(basePath, file);
          const finding = await this.analyzePlist(fullPath, 'LaunchDaemon');

          if (finding) {
            findings.push(finding);
          }
        }
      } catch (error) {
        // Permission denied
      }
    }

    return findings;
  }

  /**
   * Analyze a plist file for suspicious content
   */
  async analyzePlist(plistPath, type) {
    try {
      // Use plutil to convert plist to JSON
      const jsonOutput = await executeShellCommand(`plutil -convert json -o - "${plistPath}"`);

      if (!jsonOutput) return null;

      const plist = JSON.parse(jsonOutput);
      const risks = [];
      let riskLevel = 'low';

      // Extract program path
      let programPath = plist.Program || (plist.ProgramArguments && plist.ProgramArguments[0]) || '';

      if (!programPath) return null;

      // Check 1: Program path not in trusted locations
      const isTrustedPath = this.trustedPaths.some(trusted => programPath.startsWith(trusted));

      if (!isTrustedPath && !programPath.startsWith('/Library/Application Support')) {
        risks.push('Program path is not in trusted location');
        riskLevel = 'medium';
      }

      // Check 2: Uses suspicious commands
      const programName = parse(programPath).base.toLowerCase();
      if (this.suspiciousCommands.some(cmd => programName.includes(cmd))) {
        risks.push(`Uses potentially suspicious command: ${programName}`);
        riskLevel = 'medium';
      }

      // Check 3: Impersonates Apple services
      const fileName = parse(plistPath).name;
      if (fileName.startsWith('com.apple.') && !plistPath.startsWith('/System')) {
        risks.push('Potentially impersonates Apple service');
        riskLevel = 'high';
      }

      // Check 4: Runs on load or keeps alive
      if (plist.RunAtLoad || plist.KeepAlive) {
        risks.push('Configured to run at load or stay alive');
      }

      // Check 5: Has network listen sockets
      if (plist.Sockets) {
        risks.push('Has network listen sockets configured');
        if (!isTrustedPath) riskLevel = 'high';
      }

      // Check 6: Program in user home directory
      if (programPath.includes('/Users/')) {
        risks.push('Program located in user home directory');
        riskLevel = 'high';
      }

      // Only report if there are actual risks
      if (risks.length > 1 || riskLevel !== 'low') {
        return {
          type: type.toLowerCase(),
          plist: fileName,
          path: plistPath,
          program: programPath,
          label: plist.Label || fileName,
          risks,
          risk: riskLevel,
          description: `${type}: ${risks.join(', ')}`
        };
      }

      return null;
    } catch (error) {
      return null;
    }
  }

  /**
   * Scan Login Items using AppleScript
   */
  async scanLoginItems() {
    const script = `
      tell application "System Events"
        get name of every login item
      end tell
    `;

    try {
      const output = await executeShellCommand(`osascript -e '${script}'`, { quiet: true });

      if (!output) return [];

      const items = output.split(',').map(item => item.trim());
      const findings = [];

      for (const item of items) {
        // Try to find suspicious patterns
        const itemLower = item.toLowerCase();

        let risk = 'low';
        const risks = [];

        if (itemLower.includes('hidden') || itemLower.includes('crypto') || itemLower.includes('miner')) {
          risk = 'high';
          risks.push('Login item has suspicious name');
        }

        if (risk !== 'low' || risks.length > 0) {
          findings.push({
            type: 'login_item',
            name: item,
            risks,
            risk,
            description: `Login item: ${item}`
          });
        }
      }

      return findings;
    } catch (error) {
      return [];
    }
  }

  /**
   * Scan crontab entries
   */
  async scanCrontab() {
    try {
      const output = await executeShellCommand(
        'command -v crontab >/dev/null 2>&1 && crontab -l 2>/dev/null',
        { quiet: true }
      );

      if (!output || output.includes('no crontab')) return [];

      const lines = output.split('\n').filter(line => line.trim() && !line.startsWith('#'));
      const findings = [];

      for (const line of lines) {
        let risk = 'low';
        const risks = [];

        // Check for suspicious commands
        if (this.suspiciousCommands.some(cmd => line.toLowerCase().includes(cmd))) {
          risks.push('Uses shell command in crontab');
          risk = 'medium';
        }

        // Check for network operations
        if (line.includes('curl') || line.includes('wget')) {
          risks.push('Performs network operations');
          risk = 'high';
        }

        // Check for execution from user directories
        if (line.includes('/Users/') && !line.includes('/Applications')) {
          risks.push('Executes from user directory');
          risk = 'high';
        }

        if (risks.length > 0) {
          findings.push({
            type: 'crontab',
            entry: line,
            risks,
            risk,
            description: `Crontab entry: ${risks.join(', ')}`
          });
        }
      }

      return findings;
    } catch (error) {
      return [];
    }
  }
}
