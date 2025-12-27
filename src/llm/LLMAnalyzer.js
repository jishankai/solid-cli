import OpenAI from 'openai';
import Anthropic from '@anthropic-ai/sdk';
import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';

/**
 * LLM Analyzer - Uses AI to analyze security findings and provide recommendations
 */
export class LLMAnalyzer {
  constructor(provider = 'openai', apiKey = null, options = {}) {
    this.provider = provider.toLowerCase();
    this.apiKey = apiKey || this.getApiKeyFromEnv();
    this.enableLogging = options.enableLogging !== false; // Default: true
    this.logDir = options.logDir || './logs/llm-requests';

    if (this.provider === 'openai') {
      this.client = new OpenAI({ apiKey: this.apiKey });
      this.model = 'gpt-4o-mini';
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
   * Analyze results using LLM
   */
  async analyze(results, options = {}) {
    if (!this.apiKey) {
      throw new Error(`API key not found for ${this.provider}. Set ${this.provider === 'openai' ? 'OPENAI_API_KEY' : 'ANTHROPIC_API_KEY'} environment variable.`);
    }

    const prompt = options.promptOverride || this.buildPrompt(results, options);
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

    // Log the request BEFORE sending to LLM
    if (this.enableLogging) {
      this.logRequest(prompt, timestamp, results);
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
   * Log the request to LLM provider
   */
  logRequest(prompt, timestamp, results) {
    const logData = {
      timestamp: new Date().toISOString(),
      provider: this.provider,
      model: this.model,
      warning: '⚠️  SENSITIVE DATA: This file contains system information sent to ' + this.provider.toUpperCase(),
      notice: 'Review this file to check for data leakage before sharing',
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
        fullContent: prompt
      }
    };

    const filename = `request-${timestamp}.json`;
    const filepath = join(this.logDir, filename);

    try {
      writeFileSync(filepath, JSON.stringify(logData, null, 2), 'utf-8');
      console.log(`\n📝 LLM request logged to: ${filepath}`);
      console.log(`⚠️  Review this file to check for sensitive data leakage\n`);
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

    const resourceSnapshot = this.formatResourceSnapshot(results.agents?.resource);
    const findingsData = this.formatFindings(results.agents);

    const objective = options.objective || 'integrated';
    let taskDescription = '';

    if (objective === 'security') {
      taskDescription = `Act as a macOS security responder. From the findings:
1) Identify likely malware/persistence/backdoor chains and any privilege escalation or data exfiltration paths.
2) Prioritize Critical/High issues with rationale and map to specific artifacts (plist, PID, path, socket).
3) Provide a validation playbook: exact commands to confirm or triage each issue (ps/lsof/launchctl/spctl/codesign/kill/quarantine).
4) Give containment steps (kill/disable/remove) and what evidence to collect before cleanup (logs/paths/plists/binaries).
5) Flag legitimate-but-sensitive tools to avoid false positives.`;
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
4) Give containment/remediation steps and what evidence to capture before cleanup (logs/plists/binaries/network captures).
5) Flag legitimate-but-sensitive tools to reduce false positives.
6) Offer performance optimizations (CPU/memory) and commands to verify improvements.`;
    }

    return `${taskDescription}

${systemInfo}

${resourceSnapshot ? `Resource Snapshot:\n${resourceSnapshot}\n` : ''}

Detailed Findings:
${findingsData}

Please provide:
1. Executive Summary (2-3 sentences)
2. Critical Issues (prioritized list with specific file paths/PIDs)
3. Recommended Actions (concrete commands or steps)
4. Risk Assessment for each major finding
5. Whether this system shows signs of compromise
6. Performance optimizations (CPU/memory) if applicable
7. Validation playbook (commands to confirm/collect evidence before remediation)

Format your response in clear markdown.`;
  }

  /**
   * Format findings for the prompt
   */
  formatFindings(agents) {
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

        for (const finding of agentResult.findings.slice(0, 20)) { // Limit to top 20
          output += `### ${finding.type} [${finding.risk}]\n`;
          output += `${finding.description}\n`;

          // Add relevant details
          if (finding.pid) output += `- PID: ${finding.pid}\n`;
          if (finding.command) output += `- Command: ${finding.command}\n`;
          if (finding.path) output += `- Path: ${finding.path}\n`;
          if (finding.program) output += `- Program: ${finding.program}\n`;
          if (finding.plist) output += `- Plist: ${finding.plist}\n`;

          if (finding.risks && finding.risks.length > 0) {
            output += `- Risks: ${finding.risks.join(', ')}\n`;
          }

          output += '\n';
        }
      } else {
        output += 'No significant findings.\n\n';
      }
    }

    return output;
  }

  /**
   * Summarize resource usage for the prompt
   */
  formatResourceSnapshot(resourceResult) {
    if (!resourceResult) return '';

    const { topCpuProcesses = [], topMemoryProcesses = [], memoryStats = {} } = resourceResult;

    const topCpu = topCpuProcesses.slice(0, 5).map(p =>
      `- ${p.command} (PID ${p.pid}) CPU: ${p.cpu}% MEM: ${p.memory}MB Uptime: ${p.uptime}`
    ).join('\n');

    const topMem = topMemoryProcesses.slice(0, 5).map(p =>
      `- ${p.command} (PID ${p.pid}) MEM: ${p.memory}MB CPU: ${p.cpu}% Uptime: ${p.uptime}`
    ).join('\n');

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
      max_tokens: 4000
    });

    return {
      provider: 'openai',
      model: this.model,
      analysis: response.choices[0].message.content,
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
      max_tokens: 4000,
      temperature: 0.3,
      system: 'You are a macOS security expert specializing in system analysis, malware detection, and security auditing. Provide clear, actionable recommendations with specific file paths and commands.',
      messages: [
        {
          role: 'user',
          content: prompt
        }
      ]
    });

    return {
      provider: 'claude',
      model: this.model,
      analysis: response.content[0].text,
      usage: {
        inputTokens: response.usage.input_tokens,
        outputTokens: response.usage.output_tokens
      }
    };
  }
}
