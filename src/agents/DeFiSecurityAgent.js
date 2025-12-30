import { BaseAgent } from './BaseAgent.js';
import { executeShellCommand } from '../utils/commander.js';
import fs from 'fs/promises';
import path from 'path';

/**
 * DeFiSecurityAgent - Specialized agent for DeFi protocol security analysis (PRIVACY PROTECTED)
 */
export class DeFiSecurityAgent extends BaseAgent {
  constructor() {
    super('DeFiSecurityAgent');
    
    // Known DeFi protocol domains
    this.defiDomains = new Set([
      'uniswap.org', 'sushi.com', 'pancakeswap.finance', 'curve.fi',
      'balancer.finance', 'compound.finance', 'aave.com', 'makerdao.com',
      'yearn.finance', 'lido.fi', 'opensea.io', 'rarible.com',
      '1inch.io', '0x.org', 'paraswap.io', 'dydx.exchange'
    ]);

    // Suspicious DeFi scam indicators (filename only, not content)
    this.scamIndicators = new Set([
      'rugpull', 'honeypot', 'exit-scam', 'drain-wallet',
      'token-swap', 'airdrop-claim', 'claim-free-tokens',
      'connect-wallet', 'approve-token', 'unlimited-approval'
    ]);
  }

  async analyze() {
    const findings = [];
    
    // 1. Check browser history (metadata only)
    findings.push(...await this.checkBrowserHistory());
    
    // 2. Scan for DeFi-related downloads (filename only)
    findings.push(...await this.checkDefiDownloads());
    
    // 3. Check clipboard status (no content reading)
    findings.push(...await this.checkClipboard());
    
    // 4. Check for DeFi scam indicators (processes only)
    findings.push(...await this.checkDefiScams());
    
    // 5. Analyze network for DeFi connections
    findings.push(...await this.analyzeDefiNetwork());

    this.results = {
      agent: this.name,
      timestamp: new Date().toISOString(),
      findings,
      overallRisk: this.calculateOverallRisk(findings)
    };

    return this.results;
  }

  /**
   * Check browser history (metadata only, no content reading)
   */
  async checkBrowserHistory() {
    const findings = [];
    
    // Skip browser history scanning for privacy protection
    findings.push({
      type: 'browser_history_privacy_notice',
      risk: 'info',
      description: 'Browser history scanning disabled for privacy protection'
    });

    return findings;
  }

  /**
   * Scan for DeFi-related downloads (filename only, no content reading)
   */
  async checkDefiDownloads() {
    const findings = [];
    
    const downloadPaths = [
      '~/Downloads',
      '/tmp'
    ];

    for (const downloadPath of downloadPaths) {
      try {
        const expandedPath = downloadPath.replace('~', '/Users');
        
        if (await this.pathExists(expandedPath)) {
          const findOutput = await executeShellCommand(
            `find "${expandedPath}" -name "*.html" -o -name "*.js" 2>/dev/null | head -5`
          );
          
          const files = findOutput.split('\n').filter(f => f.trim());
          
          for (const file of files) {
            try {
              // SECURITY: Only check filename, not content
              const stats = await fs.stat(file);
              const filename = path.basename(file).toLowerCase();
              
              // Check filename for scam indicators
              for (const scam of this.scamIndicators) {
                if (filename.includes(scam)) {
                  findings.push({
                    type: 'defi_scam_download',
                    path: this.sanitizePath(file),
                    indicator: scam,
                    size: stats.size,
                    risk: 'high',
                    description: `Suspicious DeFi file detected: ${path.basename(file)}`,
                    securityNote: 'Content not read for privacy protection'
                  });
                  break;
                }
              }
              
            } catch (error) {
              // Skip files that can't be accessed
            }
          }
        }
      } catch (error) {
        // Ignore download path errors
      }
    }

    return findings;
  }

  /**
   * Check clipboard status (no content reading)
   */
  async checkClipboard() {
    const findings = [];
    
    // SECURITY: Do NOT read actual clipboard content
    findings.push({
      type: 'clipboard_security_notice',
      risk: 'info',
      description: 'Clipboard access disabled for privacy protection',
      securityNote: 'Content not read to protect sensitive data'
    });

    return findings;
  }

  /**
   * Check for DeFi scam indicators (processes only)
   */
  async checkDefiScams() {
    const findings = [];
    
    // Check running processes for scam indicators
    try {
      const psOutput = await executeShellCommand('ps -axo pid,ppid,user,comm');
      const lines = psOutput.split('\n');

      for (const line of lines) {
        if (!line.trim()) continue;
        
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 4) {
          const pid = parseInt(parts[0]);
          const user = parts[2];
          const command = parts.slice(3).join(' ').toLowerCase();
          
          for (const scam of this.scamIndicators) {
            if (command.includes(scam)) {
              findings.push({
                type: 'defi_scam_process',
                pid,
                command: parts.slice(3).join(' '),
                user,
                indicator: scam,
                risk: 'high',
                description: `Process with DeFi scam indicator: ${scam}`
              });
              break;
            }
          }
        }
      }
    } catch (error) {
      console.error('Error checking DeFi scams:', error.message);
    }

    return findings;
  }

  /**
   * Analyze network for DeFi connections
   */
  async analyzeDefiNetwork() {
    const findings = [];
    
    try {
      const netstatOutput = await executeShellCommand('netstat -an | grep -E "(ESTABLISHED|LISTEN)"');
      const lines = netstatOutput.split('\n');
      
      for (const line of lines) {
        if (!line.trim()) continue;
        
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 5) {
          const address = parts[4];
          
          // Extract domain from address if present
          if (address.includes(':') && !address.startsWith('127.') && !address.startsWith('::1')) {
            const hostPort = address.split(':');
            if (hostPort.length >= 2) {
              const host = hostPort[0];
              
              // Check for DeFi domain connections
              for (const domain of this.defiDomains) {
                if (host.includes(domain) || host.endsWith(domain)) {
                  findings.push({
                    type: 'defi_network_connection',
                    host,
                    address,
                    protocol: parts[0],
                    risk: 'low',
                    description: `DeFi protocol connection: ${host}`
                  });
                  break;
                }
              }
            }
          }
        }
      }
    } catch (error) {
      console.error('Error analyzing DeFi network:', error.message);
    }

    return findings;
  }

  /**
   * Helper function to check if a path exists
   */
  async pathExists(path) {
    try {
      await fs.access(path);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Sanitize path to protect privacy
   */
  sanitizePath(path) {
    if (!path) return path;
    return path.replace(/\/Users\/[^\/]+/g, '/Users/***REDACTED***');
  }
}