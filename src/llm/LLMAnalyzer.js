import OpenAI from 'openai';
import Anthropic from '@anthropic-ai/sdk';
import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';
import { ReportSanitizer } from '../report/utils/sanitizer.js';

/**
 * LLM Analyzer - Uses AI to analyze security findings and provide recommendations
 */
export class LLMAnalyzer {
  constructor(provider = 'openai', apiKey = null, options = {}) {
    this.provider = provider.toLowerCase();
    this.apiKey = apiKey || this.getApiKeyFromEnv();
    this.enableLogging = options.enableLogging !== false; // Default: true
    this.enabled = options.enabled !== false; // Default: true
    this.logDir = options.logDir || './logs/llm-requests';
    this.mode = options.mode || 'summary'; // 'summary' | 'full'
    this.maxTokens = options.maxTokens || 4000;
    this.minFindingsToAnalyze = options.minFindingsToAnalyze || 1;
    this.reportSanitizer = new ReportSanitizer({
      redactUserPaths: true,
      redactIPs: true,
      redactUsernames: true,
      preserveDomains: false
    });
    this.findingDelimiter = '::';

    if (this.provider === 'openai') {
      this.client = new OpenAI({ apiKey: this.apiKey });
        this.model = 'gpt-4.1';
    } else if (this.provider === 'claude') {
      this.client = new Anthropic({ apiKey: this.apiKey });
      this.model = 'claude-3-5-sonnet-20241022';
    }

    // Ensure log directory exists
    if (this.enableLogging) {
      this.ensureLogDirectory();
    }
  }

  /**
   * Ensure log directory exists
   */
  ensureLogDirectory() {
    if (!existsSync(this.logDir)) {
      mkdirSync(this.logDir, { recursive: true });
    }
  }

  /**
   * Get API key from environment variables
   */
  getApiKeyFromEnv() {
    if (this.provider === 'openai') {
      return process.env.OPENAI_API_KEY;
    } else if (this.provider === 'claude') {
      return process.env.ANTHROPIC_API_KEY;
    }
    return null;
  }

  /**
   * Analyze results using LLM (PRIVACY PROTECTED)
   */
  async analyze(results, options = {}) {
    if (!this.enabled) {
      return { provider: this.provider, model: this.model, analysis: 'LLM analysis disabled', usage: {} };
    }

    const totalFindings = results?.summary?.totalFindings || 0;
    if (totalFindings < this.minFindingsToAnalyze) {
      return { provider: this.provider, model: this.model, analysis: 'LLM skipped (no significant findings)', usage: {} };
    }

    if (!this.apiKey) {
      throw new Error(`API key not found for ${this.provider}. Set ${this.provider === 'openai' ? 'OPENAI_API_KEY' : 'ANTHROPIC_API_KEY'} environment variable.`);
    }

    const prompt = options.promptOverride || this.buildPrompt(results, options);
    
    // CRITICAL SECURITY CHECK: Scan for sensitive data before sending to LLM
    const securityCheck = this.performSecurityCheck(prompt);
    if (securityCheck.hasSensitiveData) {
      console.error('\n🚨 SECURITY ALERT: Sensitive data detected in LLM prompt!');
      console.error('🚨 Analysis aborted to prevent private key leakage.');
      console.error('🚨 Sensitive patterns found:', securityCheck.sensitivePatterns);
      
      throw new Error('SECURITY: Sensitive data detected - LLM analysis aborted to prevent privacy leakage');
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

    // Log the request BEFORE sending to LLM (with security note)
    if (this.enableLogging) {
      this.logRequest(prompt, timestamp, results, securityCheck);
    }

    try {
      let response;

          if (this.provider === 'openai') {
            response = await this.analyzeWithOpenAI(prompt);
          } else if (this.provider === 'claude') {
            response = await this.analyzeWithClaude(prompt);
          }

      // Log the response
      if (this.enableLogging) {
        this.logResponse(response, timestamp);
      }

      return response;
    } catch (error) {
      // Log the error
      if (this.enableLogging) {
        this.logError(error, timestamp);
      }

      throw new Error(`LLM analysis failed: ${error.message}`);
    }
  }

  /**
   * Perform security check on prompt to detect sensitive data
   */
  performSecurityCheck(prompt) {
    const sensitivePatterns = [
      // Ethereum addresses (0x + 40 hex chars)
      { 
        pattern: /0x[a-fA-F0-9]{40}/g, 
        name: 'Ethereum address',
        test: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb8'
      },
      // Private keys (64+ hex chars)
      { 
        pattern: /[a-fA-F0-9]{64,}/g, 
        name: 'Potential private key',
        test: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890'
      },
      // Private key phrases
      { 
        pattern: /(private|mnemonic|seed).*?[=:][a-zA-Z0-9+/]{8,}/gi, 
        name: 'Private key phrase',
        test: 'private=0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb8'
      },
      // API keys/tokens (32+ chars)
      { 
        pattern: /[a-zA-Z0-9+/]{32,}={0,2}/g, 
        name: 'API key or token',
        test: 'sk-1234567890abcdef1234567890abcdef12345678'
      },
      // Wallet import formats (50+ chars)
      { 
        pattern: /[6][a-km-zA-HJ-NP-Z1-9]{50,}/g, 
        name: 'Wallet import format',
        test: '6PRApM1x8E1p2p5rTPeBqnm9ewwGcM5DHN'
      },
      // Seed phrases (12+ words with spaces)
      { 
        pattern: /\b([a-z]+(\s+[a-z]+){11,})\b/gi, 
        name: 'Potential seed phrase',
        test: 'word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12'
      },
      // Bitcoin addresses (starts with 1 or 3)
      { 
        pattern: /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g, 
        name: 'Bitcoin address',
        test: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
      },
      // Long hex sequences
      { 
        pattern: /\b[a-fA-F0-9]{16,}\b/g, 
        name: 'Long hex string',
        test: 'abcdef1234567890abcdef'
      }
    ];

    const detectedPatterns = [];
    let hasSensitiveData = false;

    for (const { pattern, name, test } of sensitivePatterns) {
      // Test pattern with known examples first
      const testMatches = test.match(pattern);
      const matchIterator = prompt.matchAll(pattern);
      const filteredMatches = [];

      for (const match of matchIterator) {
        const value = match[0];
        if (name === 'Potential seed phrase' && !this.isLikelySeedPhrase(value)) {
          continue;
        }
        if (name === 'API key or token' && !this.isLikelyApiKey(value)) {
          continue;
        }
        filteredMatches.push(value);
      }
      
      if (filteredMatches.length > 0) {
        hasSensitiveData = true;
        detectedPatterns.push({
          name,
          count: filteredMatches.length,
          samples: filteredMatches.slice(0, 2).map(m => {
            // Truncate sensitive data for logging
            const truncated = m.length > 20 ? m.substring(0, 20) + '***' : m;
            return truncated.replace(/[a-fA-F0-9]/g, '*'); // Additional masking
          })
        });
      }
    }

    return {
      hasSensitiveData,
      sensitivePatterns: detectedPatterns,
      promptLength: prompt.length
    };
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
    const hasSymbol = /[+/=_-]/.test(candidate);
    const uniqueRatio = new Set(candidate).size / candidate.length;

    // Require mixed character classes and avoid low-entropy strings
    if (!(hasDigit && (hasUpper || hasLower))) return false;
    if (uniqueRatio < 0.2) return false;

    // Ignore obvious plist or XML-like tokens
    if (/^string$/i.test(candidate) || /^data$/i.test(candidate)) return false;

    // Skip long runs of a single character
    if (/^(.)\1{10,}$/.test(candidate)) return false;

    return true;
  }

  extractPerFinding(text) {
    if (!text) return {};

    // Try fenced JSON block first
    const fenceMatch = text.match(/```json\s*([\s\S]*?)```/);
    const candidate = fenceMatch ? fenceMatch[1] : text;

    try {
      const parsed = JSON.parse(candidate);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return parsed;
      }
    } catch (error) {
      // Ignore parse errors
    }

    return {};
  }

  /**
   * Log the request to LLM provider (PRIVACY PROTECTED)
   */
  logRequest(prompt, timestamp, results, securityCheck = null) {
    const logData = {
      timestamp: new Date().toISOString(),
      provider: this.provider,
      model: this.model,
      securityStatus: securityCheck ? {
        hasSensitiveData: securityCheck.hasSensitiveData,
        sensitivePatterns: securityCheck.sensitivePatterns,
        promptLength: securityCheck.promptLength
      } : null,
      privacyNotice: '🔒 PRIVACY PROTECTED: Sensitive data automatically redacted',
      systemInfo: {
        hostname: results.hostname,
        osVersion: results.osVersion,
        mode: results.mode,
        totalFindings: results.summary.totalFindings,
        highRisk: results.summary.highRiskFindings,
        mediumRisk: results.summary.mediumRiskFindings,
        lowRisk: results.summary.lowRiskFindings
      },
      prompt: {
        length: prompt.length,
        preview: prompt.substring(0, 500) + '...',
        fullContent: prompt,
        sanitizationApplied: true
      }
    };

    const filename = `request-${timestamp}.json`;
    const filepath = join(this.logDir, filename);

    try {
      writeFileSync(filepath, JSON.stringify(logData, null, 2), 'utf-8');
      console.log(`\n📝 LLM request logged to: ${filepath}`);
      console.log(`🔒 Privacy protection applied - sensitive data redacted\n`);
    } catch (error) {
      console.warn(`Warning: Failed to write request log: ${error.message}`);
    }
  }

  /**
   * Log the response from LLM provider
   */
  logResponse(response, timestamp) {
    const logData = {
      timestamp: new Date().toISOString(),
      provider: response.provider,
      model: response.model,
      analysis: response.analysis,
      usage: response.usage
    };

    const filename = `response-${timestamp}.json`;
    const filepath = join(this.logDir, filename);

    try {
      writeFileSync(filepath, JSON.stringify(logData, null, 2), 'utf-8');
      console.log(`📝 LLM response logged to: ${filepath}\n`);
    } catch (error) {
      console.warn(`Warning: Failed to write response log: ${error.message}`);
    }
  }

  /**
   * Log errors
   */
  logError(error, timestamp) {
    const logData = {
      timestamp: new Date().toISOString(),
      provider: this.provider,
      error: error.message,
      stack: error.stack
    };

    const filename = `error-${timestamp}.json`;
    const filepath = join(this.logDir, filename);

    try {
      writeFileSync(filepath, JSON.stringify(logData, null, 2), 'utf-8');
      console.log(`📝 Error logged to: ${filepath}\n`);
    } catch (writeError) {
      console.warn(`Warning: Failed to write error log: ${writeError.message}`);
    }
  }

  /**
   * Build the analysis prompt
   */
  buildPrompt(results, options) {
    const systemInfo = `
System Information:
- Hostname: ${results.hostname}
- macOS Version: ${results.osVersion}
- Analysis Mode: ${results.mode}
- Analysis Time: ${results.timestamp}
- Overall Risk Level: ${results.overallRisk}

Summary:
- Total Findings: ${results.summary.totalFindings}
- High Risk: ${results.summary.highRiskFindings}
- Medium Risk: ${results.summary.mediumRiskFindings}
- Low Risk: ${results.summary.lowRiskFindings}
`;

    const mode = options.mode || this.mode;
    const findingLimit = mode === 'summary' ? 10 : 20;

    const resourceSnapshot = this.formatResourceSnapshot(results.agents?.resource);
    const findingsData = this.formatFindings(results.agents, findingLimit);

    const objective = options.objective || 'integrated';
    let taskDescription = '';

    if (objective === 'security') {
      taskDescription = `Act as a macOS security responder. From the findings:
1) Identify likely malware/persistence/backdoor chains and any privilege escalation or data exfiltration paths.
2) Prioritize Critical/High issues with rationale and map to specific artifacts (plist, PID, path, socket).
3) Provide a validation playbook: exact commands to confirm or triage each issue (ps/lsof/launchctl/spctl/codesign/kill/quarantine).
4) Give containment + remediation steps per Critical/High: what to disable/kill/remove/quarantine, config/profile/tcc changes if needed, vendor update/uninstall, and a rollback note.
5) Flag legitimate-but-sensitive tools to avoid false positives.
6) For EACH finding (including medium/low) using the provided FindingID, produce purpose + risk + action in JSON for later attachment to that finding.`;
    } else if (objective === 'performance') {
      taskDescription = `Act as a macOS performance specialist. From the findings:
1) Identify processes consuming excessive resources and whether usage is justified.
2) Recommend actions to reduce load (disable services, limit background tasks, clean temp caches).
3) Provide commands or steps to validate improvements.`;
    } else {
      taskDescription = `Act as a macOS security responder with performance awareness. From the findings:
1) Identify likely malware/persistence/backdoor chains, privilege escalation, and data exfil paths.
2) Prioritize Critical/High issues with rationale mapped to artifacts (plist, PID, path, socket) and highlight any resource-heavy offenders.
3) Provide a validation playbook: commands to confirm/triage (ps/lsof/launchctl/spctl/codesign/kill/quarantine/systemextensionsctl/tccutil).
4) Give containment/remediation steps per Critical/High: what to disable/kill/remove/quarantine, config/profile/tcc changes if needed, vendor update/uninstall, and a rollback note.
5) Flag legitimate-but-sensitive tools to reduce false positives.
6) Offer performance optimizations (CPU/memory) and commands to verify improvements.`;
    }

    return `${taskDescription}

${systemInfo}

${resourceSnapshot ? `Resource Snapshot:\n${resourceSnapshot}\n` : ''}

Detailed Findings:
${findingsData}

Please provide structured markdown with sections:
1) Executive Summary (2-3 sentences)
2) Critical Issues (prioritized, map to PIDs/paths/plists/sockets)
3) Issue-wise Remediation Plan (Critical/High only): action, exact command(s) or steps, expected outcome, rollback note
4) Validation Playbook (evidence to collect before remediation, commands to confirm)
5) Containment & Clean-up (kill/disable/remove/quarantine; note required privileges)
6) Performance notes (if resource-heavy items exist)
7) Triage Checklist (concise, bullet list)

Then append a JSON block fenced with \`\`\`json named PER_FINDING mapping each FindingID to {"purpose": "what the program/config is typically used for (vendor/legit/malicious)", "risk": "concise risk assessment + why (persistence/listen socket/signing/behavior)", "action": "clear decision and commands (keep/monitor/disable/remove) with rollback note"}.
Example:
\`\`\`json
{
  "ResourceAgent#0": {"purpose": "menu bar monitor from vendor X", "risk": "low – signed, no persistence", "action": "keep; monitor CPU with 'top -o cpu'"},
  "PersistenceAgent#2": {"purpose": "auto-launch helper", "risk": "high – unsigned launchdaemon listening on 0.0.0.0:1234", "action": "disable: sudo launchctl bootout system /Library/LaunchDaemons/com.foo.plist; remove plist; rollback: launchctl bootstrap"}
}
\`\`\`
If you cannot map a finding, omit it. No extra prose after the JSON block.

Keep output concise; avoid repeating redacted data.

IMPORTANT: Include all risks (high/medium/low) in PER_FINDING.`;
  }

  /**
   * Format findings for the prompt (PRIVACY PROTECTED)
   */
  formatFindings(agents, limit = 20) {
    let output = '';

    for (const [agentKey, agentResult] of Object.entries(agents)) {
      if (agentResult.error) {
        output += `\n## ${agentKey} Agent: ERROR\n${agentResult.error}\n`;
        continue;
      }

      output += `\n## ${agentResult.agent}\n`;
      output += `Risk Level: ${agentResult.overallRisk}\n`;

      if (agentResult.findings && agentResult.findings.length > 0) {
        output += `Findings: ${agentResult.findings.length}\n\n`;

        agentResult.findings.slice(0, limit).forEach((finding, index) => {
          const findingId = `${agentKey}#${index}`;
          output += `### ${finding.type} [${finding.risk}]\n`;
          output += `- FindingID: ${findingId}\n`;
          
          // Deep sanitize using report sanitizer first, then apply LLM-specific redactions
          const safeDescription = this.reportSanitizer.sanitizeText(finding.description);
          const sanitizedDescription = this.sanitizeForLLM(safeDescription);
          output += `${sanitizedDescription}\n`;

          // Add relevant details with sanitization
          if (finding.pid) output += `- PID: ${finding.pid}\n`;
          if (finding.command) {
            const safeCommand = this.reportSanitizer.sanitizeText(finding.command);
            const sanitizedCommand = this.sanitizeForLLM(safeCommand);
            output += `- Command: ${sanitizedCommand}\n`;
          }
          if (finding.path) {
            const safePath = this.reportSanitizer.sanitizePath(finding.path);
            const sanitizedPath = this.sanitizePathForLLM(safePath);
            output += `- Path: ${sanitizedPath}\n`;
          }
          if (finding.program) {
            const safeProgram = this.reportSanitizer.sanitizeText(finding.program);
            const sanitizedProgram = this.sanitizeForLLM(safeProgram);
            output += `- Program: ${sanitizedProgram}\n`;
          }
          if (finding.plist) {
            const safePlist = this.reportSanitizer.sanitizePath(finding.plist);
            const sanitizedPlist = this.sanitizePathForLLM(safePlist);
            output += `- Plist: ${sanitizedPlist}\n`;
          }

          if (finding.risks && finding.risks.length > 0) {
            output += `- Risks: ${finding.risks.join(', ')}\n`;
          }

          // Add privacy protection note for sensitive findings
          if (this.isSensitiveFinding(finding)) {
            output += `- Privacy Note: Sensitive data redacted for security\n`;
          }

          output += '\n';
        });

        if (agentResult.findings.length > limit) {
          output += `...truncated ${agentResult.findings.length - limit} additional findings for brevity...\n\n`;
        }
      } else {
        output += 'No significant findings.\n\n';
      }
    }

    return output;
  }

  /**
   * Sanitize text for LLM to prevent private key exposure
   */
  sanitizeForLLM(text) {
    if (!text) return text;
    
    return text
      // Redact Ethereum addresses
      .replace(/0x[a-fA-F0-9]{40}/g, '0x***REDACTED***')
      // Redact potential private keys (64 hex chars)
      .replace(/[a-fA-F0-9]{64}/g, '***REDACTED***')
      // Redact private key phrases and values
      .replace(/(private|mnemonic|seed).*?[=:][a-zA-Z0-9+/]{8,}/gi, '$1***REDACTED***')
      // Redact API keys and tokens
      .replace(/[a-zA-Z0-9]{32,}={0,2}/g, '***REDACTED***')
      // Redact long hex strings
      .replace(/[a-fA-F0-9]{16,}/g, '***REDACTED***')
      // Redact potential wallet import formats
      .replace(/(6|5)[a-km-zA-HJ-NP-Z1-9]{50,}/g, '***WALLET-REDACTED***')
      // Redact potential seed phrases (12+ words)
      .replace(/([a-z]+\s){11,}[a-z]+/gi, '***SEED-PHRASE-REDACTED***')
      // Redact IPv4 addresses
      .replace(/\b(\d{1,3}\.){3}\d{1,3}\b/g, '***IP-REDACTED***')
      // Redact common domains/URLs
      .replace(/https?:\/\/[^\s]+/gi, '***URL-REDACTED***');
  }

  /**
   * Sanitize file paths for LLM
   */
  sanitizePathForLLM(path) {
    if (!path) return path;
    
    return path
      // Redact user directory
      .replace(/\/Users\/[^\/]+/g, '/Users/***REDACTED***')
      // Redact username from paths
      .replace(/\/home\/[^\/]+/g, '/home/***REDACTED***')
      // Redact potential wallet file paths
      .replace(/(wallet|keystore|private|seed|mnemonic)[^\/]*\/[^\/]*/gi, '***WALLET-PATH-REDACTED***')
      // Redact hostname fragments
      .replace(/\b([a-zA-Z0-9_-]+)\.local\b/gi, '***HOST-REDACTED***');
  }

  /**
   * Check if finding contains sensitive information
   */
  isSensitiveFinding(finding) {
    const sensitiveTypes = [
      'wallet_file',
      'wallet_key_environment',
      'sensitive_clipboard_content',
      'private_key_detected',
      'seed_phrase_detected',
      'mnemonic_detected'
    ];
    
    const sensitiveKeywords = [
      'private key', 'seed phrase', 'mnemonic', 'wallet key',
      'ethereum address', 'bitcoin address', 'crypto key'
    ];
    
    // Check type
    if (sensitiveTypes.includes(finding.type)) {
      return true;
    }
    
    // Check description
    if (finding.description) {
      const lowerDesc = finding.description.toLowerCase();
      for (const keyword of sensitiveKeywords) {
        if (lowerDesc.includes(keyword)) {
          return true;
        }
      }
    }
    
    return false;
  }

  /**
   * Summarize resource usage for the prompt
   */
  formatResourceSnapshot(resourceResult) {
    if (!resourceResult) return '';

    const { topCpuProcesses = [], topMemoryProcesses = [], memoryStats = {} } = resourceResult;

    const topCpu = topCpuProcesses.slice(0, 5).map(p => {
      const sanitizedCommand = this.sanitizePathForLLM(this.sanitizeForLLM(p.command));
      return `- ${sanitizedCommand} (PID ${p.pid}) CPU: ${p.cpu}% MEM: ${p.memory}MB Uptime: ${p.uptime}`;
    }).join('\n');

    const topMem = topMemoryProcesses.slice(0, 5).map(p => {
      const sanitizedCommand = this.sanitizePathForLLM(this.sanitizeForLLM(p.command));
      return `- ${sanitizedCommand} (PID ${p.pid}) MEM: ${p.memory}MB CPU: ${p.cpu}% Uptime: ${p.uptime}`;
    }).join('\n');

    return `Memory Stats (MB):
- Free: ${memoryStats.free ?? 'N/A'}
- Active: ${memoryStats.active ?? 'N/A'}
- Inactive: ${memoryStats.inactive ?? 'N/A'}
- Wired: ${memoryStats.wired ?? 'N/A'}
- Compressed: ${memoryStats.compressed ?? 'N/A'}

Top CPU Processes:
${topCpu || '- None captured'}

Top Memory Processes:
${topMem || '- None captured'}`;
  }

  /**
   * Analyze with OpenAI
   */
  async analyzeWithOpenAI(prompt) {
    const response = await this.client.chat.completions.create({
      model: this.model,
      messages: [
        {
          role: 'system',
          content: 'You are a macOS security expert specializing in system analysis, malware detection, and security auditing. Provide clear, actionable recommendations with specific file paths and commands.'
        },
        {
          role: 'user',
          content: prompt
        }
      ],
      temperature: 0.3,
      max_tokens: this.maxTokens
    });

    const rawText = response.choices[0].message.content;
    const perFinding = this.extractPerFinding(rawText);

    return {
      provider: 'openai',
      model: this.model,
      analysis: rawText,
      perFinding,
      usage: {
        promptTokens: response.usage.prompt_tokens,
        completionTokens: response.usage.completion_tokens,
        totalTokens: response.usage.total_tokens
      }
    };
  }

  /**
   * Analyze with Claude
   */
  async analyzeWithClaude(prompt) {
    const response = await this.client.messages.create({
      model: this.model,
      max_tokens: this.maxTokens,
      temperature: 0.3,
      system: 'You are a macOS security expert specializing in system analysis, malware detection, and security auditing. Provide clear, actionable recommendations with specific file paths and commands.',
      messages: [
        {
          role: 'user',
          content: prompt
        }
      ]
    });

    const rawText = response.content[0].text;
    const perFinding = this.extractPerFinding(rawText);

    return {
      provider: 'claude',
      model: this.model,
      analysis: rawText,
      perFinding,
      usage: {
        inputTokens: response.usage.input_tokens,
        outputTokens: response.usage.output_tokens
      }
    };
  }
}
