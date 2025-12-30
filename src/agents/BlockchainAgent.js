import { BaseAgent } from './BaseAgent.js';
import { executeShellCommand } from '../utils/commander.js';
import fs from 'fs/promises';
import path from 'path';

/**
 * BlockchainAgent - Analyzes blockchain, wallet, and DeFi security threats
 */
export class BlockchainAgent extends BaseAgent {
  constructor() {
    super('BlockchainAgent');
    
    // Known wallet applications and processes
    this.knownWallets = new Set([
      'MetaMask', 'phantom', 'solana', 'trust-wallet', 'coinbase-wallet',
      'ledger-live', 'trezor-bridge', 'exodus', 'atomic-wallet', 'myetherwallet',
      'metamask', 'phantom-wallet', 'brave-wallet', 'rainbow', 'argent',
      'gnosis-safe', 'imtoken', 'tokenpocket', 'mathwallet', 'safepal'
    ]);

    // Known DeFi platforms and protocols
    this.knownDeFi = new Set([
      'uniswap', 'sushiswap', 'pancakeswap', 'curve', 'balancer',
      'compound', 'aave', 'makerdao', 'yearn-finance', 'lido',
      'opensea', 'rarible', 'superrare', 'foundation', 'zora',
      '1inch', '0x', 'paraswap', 'dydx', 'perpetual-protocol',
      'synthetix', 'uma', 'kyber', 'bancor', 'thorchain'
    ]);

    // Suspicious blockchain-related processes
    this.suspiciousProcesses = new Set([
      'crypto-miner', 'coin-miner', 'xmr-miner', 'eth-miner',
      'bitcoin-miner', 'crypto-hijack', 'blockchain-malware',
      'wallet-stealer', 'seed-phrase', 'private-key', 'mnemonic'
    ]);

    // Common wallet file patterns
    this.walletFilePatterns = [
      /wallet\.json$/i,
      /keystore.*\.json$/i,
      /.*_private.*\.key$/i,
      /.*_mnemonic.*\.txt$/i,
      /.*_seed.*\.txt$/i,
      /.*_secret.*\.txt$/i,
      /metamask.*\.json$/i,
      /phantom.*\.json$/i
    ];

    // Browser extension paths
    this.browserExtensionPaths = [
      '/Library/Application Support/Google/Chrome/Default/Extensions',
      '/Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions',
      '/Library/Application Support/Microsoft Edge/Default/Extensions',
      '/Library/Application Support/Firefox/Profiles',
      '~/Library/Application Support/Google/Chrome/Default/Extensions',
      '~/Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions',
      '~/Library/Application Support/Microsoft Edge/Default/Extensions',
      '~/Library/Application Support/Firefox/Profiles'
    ];
  }

  async analyze() {
    const findings = [];
    
    // 1. Check for wallet processes
    findings.push(...await this.checkWalletProcesses());
    
    // 2. Scan for wallet files
    findings.push(...await this.scanWalletFiles());
    
    // 3. Check browser extensions
    findings.push(...await this.checkBrowserExtensions());
    
    // 4. Analyze network connections for DeFi/blockchain
    findings.push(...await this.analyzeBlockchainNetwork());
    
    // 5. Check for mining processes
    findings.push(...await this.checkMiningProcesses());
    
    // 6. Scan for suspicious wallet configurations
    findings.push(...await this.checkWalletConfigurations());

    this.results = {
      agent: this.name,
      timestamp: new Date().toISOString(),
      findings,
      overallRisk: this.calculateOverallRisk(findings)
    };

    return this.results;
  }

  /**
   * Check for running wallet processes
   */
  async checkWalletProcesses() {
    const findings = [];
    
    try {
      const psOutput = await executeShellCommand('ps -axo pid,ppid,user,comm');
      const lines = psOutput.split('\n').slice(1);

      for (const line of lines) {
        if (!line.trim()) continue;
        
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 4) {
          const pid = parseInt(parts[0]);
          const user = parts[2];
          const command = parts.slice(3).join(' ').toLowerCase();
          
          // Check for known wallet processes
          for (const wallet of this.knownWallets) {
            if (command.includes(wallet.toLowerCase())) {
              findings.push({
                type: 'wallet_process',
                pid,
                name: wallet,
                command: parts.slice(3).join(' '),
                user,
                risk: 'low',
                description: `Known wallet process detected: ${wallet}`
              });
              break;
            }
          }
          
          // Check for suspicious processes
          for (const suspicious of this.suspiciousProcesses) {
            if (command.includes(suspicious)) {
              findings.push({
                type: 'suspicious_blockchain_process',
                pid,
                name: suspicious,
                command: parts.slice(3).join(' '),
                user,
                risk: 'high',
                description: `Suspicious blockchain process detected: ${suspicious}`
              });
              break;
            }
          }
        }
      }
    } catch (error) {
      console.error('Error checking wallet processes:', error.message);
    }

    return findings;
  }

  /**
   * Scan for wallet files on the system (SECURITY: Only metadata, no content reading)
   */
  async scanWalletFiles() {
    const findings = [];
    const searchPaths = [
      '~/Downloads',
      '/tmp'
    ];

    for (const searchPath of searchPaths) {
      try {
        const findOutput = await executeShellCommand(
          `find "${searchPath.replace('~', '/Users')}" -type f -name "*.json" -o -name "*.key" 2>/dev/null | head -10`
        );
        
        const files = findOutput.split('\n').filter(f => f.trim());
        
        for (const file of files) {
          // Check if file matches wallet patterns
          for (const pattern of this.walletFilePatterns) {
            if (pattern.test(path.basename(file))) {
              try {
                const stats = await fs.stat(file);
                findings.push({
                  type: 'wallet_file',
                  path: file,
                  size: stats.size,
                  modified: stats.mtime.toISOString(),
                  pattern: pattern.source,
                  risk: 'medium',
                  description: `Potential wallet file found: ${path.basename(file)} (metadata only)`,
                  securityNote: 'Content not read for privacy protection'
                });
              } catch (error) {
                // File might not be accessible
                findings.push({
                  type: 'wallet_file',
                  path: file,
                  pattern: pattern.source,
                  risk: 'medium',
                  description: `Potential wallet file (inaccessible): ${path.basename(file)}`,
                  securityNote: 'Content not read for privacy protection'
                });
              }
              break;
            }
          }
        }
      } catch (error) {
        // Ignore search errors for paths that might not exist
      }
    }

    return findings;
  }

  /**
   * Check browser extensions for wallet-related extensions
   */
  async checkBrowserExtensions() {
    const findings = [];
    
    for (const extPath of this.browserExtensionPaths) {
      try {
        const expandedPath = extPath.replace('~', '/Users');
        
        if (await this.pathExists(expandedPath)) {
          const findOutput = await executeShellCommand(
            `find "${expandedPath}" -name "manifest.json" 2>/dev/null | head -20`
          );
          
          const manifests = findOutput.split('\n').filter(m => m.trim());
          
          for (const manifest of manifests) {
            try {
              const content = await fs.readFile(manifest, 'utf8');
              const manifestData = JSON.parse(content);
              
              // Check for wallet-related extensions
              const name = (manifestData.name || '').toLowerCase();
              const description = (manifestData.description || '').toLowerCase();
              
              for (const wallet of this.knownWallets) {
                if (name.includes(wallet.toLowerCase()) || 
                    description.includes(wallet.toLowerCase())) {
                  findings.push({
                    type: 'wallet_extension',
                    name: manifestData.name,
                    path: manifest,
                    version: manifestData.version,
                    risk: 'low',
                    description: `Wallet extension detected: ${manifestData.name}`
                  });
                  break;
                }
              }
              
              // Check for suspicious extensions
              if (name.includes('crypto') || name.includes('blockchain') || 
                  name.includes('wallet') || name.includes('defi')) {
                if (!this.knownWallets.has(name)) {
                  findings.push({
                    type: 'suspicious_blockchain_extension',
                    name: manifestData.name,
                    path: manifest,
                    version: manifestData.version,
                    risk: 'medium',
                    description: `Unknown blockchain-related extension: ${manifestData.name}`
                  });
                }
              }
            } catch (error) {
              // Skip invalid manifests
            }
          }
        }
      } catch (error) {
        // Ignore extension path errors
      }
    }

    return findings;
  }

  /**
   * Analyze network connections for blockchain/DeFi activity
   */
  async analyzeBlockchainNetwork() {
    const findings = [];
    
    try {
      const netstatOutput = await executeShellCommand('netstat -an | grep -E "(ESTABLISHED|LISTEN)"');
      const lines = netstatOutput.split('\n');
      
      const blockchainDomains = [
        'etherscan.io', 'bscscan.com', 'polygonscan.com', 'arbiscan.io',
        'uniswap.org', 'sushi.com', 'pancakeswap.finance', 'curve.fi',
        'compound.finance', 'aave.com', 'makerdao.com', 'yearn.finance',
        'opensea.io', 'rarible.com', '1inch.io', '0x.org',
        'metamask.io', 'phantom.app', 'solana.com', 'ethereum.org',
        'infura.io', 'alchemy.com', 'quicknode.com', 'moralis.io'
      ];
      
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
              
              for (const domain of blockchainDomains) {
                if (host.includes(domain) || host.endsWith(domain)) {
                  findings.push({
                    type: 'blockchain_network_connection',
                    host,
                    address,
                    protocol: parts[0],
                    risk: 'low',
                    description: `Blockchain/DeFi network connection: ${host}`
                  });
                  break;
                }
              }
            }
          }
        }
      }
    } catch (error) {
      console.error('Error analyzing blockchain network:', error.message);
    }

    return findings;
  }

  /**
   * Check for cryptocurrency mining processes
   */
  async checkMiningProcesses() {
    const findings = [];
    
    try {
      // Check CPU usage for potential mining
      const topOutput = await executeShellCommand('top -l 1 -n 10');
      const lines = topOutput.split('\n');
      
      const miningKeywords = [
        'miner', 'mining', 'xmr', 'monero', 'eth', 'ethereum',
        'btc', 'bitcoin', 'crypto', 'hash', 'pool'
      ];
      
      for (const line of lines) {
        const lowerLine = line.toLowerCase();
        
        for (const keyword of miningKeywords) {
          if (lowerLine.includes(keyword)) {
            // Check if process has high CPU usage
            const cpuMatch = line.match(/(\d+\.\d+)%/);
            const cpuUsage = cpuMatch ? parseFloat(cpuMatch[1]) : 0;
            
            if (cpuUsage > 10) { // High CPU usage threshold
              findings.push({
                type: 'crypto_mining_process',
                process: line.trim(),
                cpuUsage,
                risk: 'high',
                description: `Potential crypto mining process with ${cpuUsage}% CPU usage`
              });
            }
            break;
          }
        }
      }
      
      // Check for known mining executables
      const findOutput = await executeShellCommand(
        'find /Users /tmp /var/tmp -name "*miner*" -o -name "*xmr*" -o -name "*eth*" 2>/dev/null | head -10'
      );
      
      const miningFiles = findOutput.split('\n').filter(f => f.trim());
      
      for (const file of miningFiles) {
        findings.push({
          type: 'mining_executable',
          path: file,
          risk: 'high',
          description: `Potential mining executable found: ${path.basename(file)}`
        });
      }
      
    } catch (error) {
      console.error('Error checking mining processes:', error.message);
    }

    return findings;
  }

  /**
   * Check for suspicious wallet configurations (SECURITY: No sensitive content reading)
   */
  async checkWalletConfigurations() {
    const findings = [];
    
    // SECURITY: Do NOT read environment variables to prevent private key exposure
    // Instead, check for suspicious process arguments that might indicate key compromise
    try {
      const psOutput = await executeShellCommand('ps -axo command');
      const lines = psOutput.split('\n');
      
      const suspiciousArgs = [
        /--private-key/i,
        /--mnemonic/i,
        /--seed/i,
        /private.*key.*=/i,
        /seed.*=/i,
        /mnemonic.*=/i
      ];
      
      for (const line of lines) {
        if (!line.trim()) continue;
        
        for (const pattern of suspiciousArgs) {
          if (pattern.test(line)) {
            // Sanitize line to not include actual keys
            const sanitized = line.replace(/(private-key|mnemonic|seed|private.*key).*=[a-zA-Z0-9+/]+/gi, '$1=***REDACTED***');
            
            findings.push({
              type: 'sensitive_process_args',
              command: sanitized,
              risk: 'high',
              description: `Process with potential sensitive arguments detected`,
              securityNote: 'Sensitive content redacted for privacy'
            });
            break;
          }
        }
      }
    } catch (error) {
      console.error('Error checking wallet configurations:', error.message);
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
}