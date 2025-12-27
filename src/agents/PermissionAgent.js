import { BaseAgent } from './BaseAgent.js';
import { executeShellCommand } from '../utils/commander.js';

/**
 * PermissionAgent - Analyzes app permissions and privacy settings
 */
export class PermissionAgent extends BaseAgent {
  constructor() {
    super('PermissionAgent');
    this.criticalPermissions = [
      'kTCCServiceSystemPolicyAllFiles', // Full Disk Access
      'kTCCServiceScreenCapture', // Screen Recording
      'kTCCServiceAccessibility', // Accessibility
      'kTCCServiceCamera', // Camera
      'kTCCServiceMicrophone', // Microphone
    ];
    this.trustedPaths = ['/Applications', '/System', '/usr/bin', '/usr/sbin', '/usr/libexec'];
  }

  async analyze() {
    const tccPermissions = await this.scanTCCDatabase();
    const findings = this.analyzePermissions(tccPermissions);

    this.results = {
      agent: this.name,
      timestamp: new Date().toISOString(),
      totalPermissions: tccPermissions.length,
      criticalPermissions: tccPermissions.filter(p =>
        this.criticalPermissions.includes(p.service)
      ).length,
      findings,
      overallRisk: this.calculateOverallRisk(findings)
    };

    return this.results;
  }

  /**
   * Scan TCC (Transparency, Consent, and Control) database
   * Note: Uses system_profiler as TCC.db requires Full Disk Access
   */
  async scanTCCDatabase() {
    const permissions = [];

    // Use system_profiler to get privacy permissions
    const profilerOutput = await executeShellCommand('system_profiler SPPrivacyDataType 2>/dev/null');

    if (profilerOutput) {
      // Parse system_profiler output
      const lines = profilerOutput.split('\n');
      let currentService = '';

      for (const line of lines) {
        const trimmedLine = line.trim();

        // Service headers (no leading spaces, contains colon)
        if (line.match(/^[A-Z]/) && line.includes(':') && !line.includes('Privacy:')) {
          currentService = line.split(':')[0].trim();
        }
        // App entries (have leading spaces/dashes)
        else if (trimmedLine && (trimmedLine.startsWith('-') || trimmedLine.startsWith('•'))) {
          let app = trimmedLine.replace(/^[-•]\s*/, '').trim();

          // Remove any trailing descriptors
          app = app.split('(')[0].trim();

          if (app && currentService) {
            permissions.push({
              service: currentService,
              client: app,
              clientType: 0,
              allowed: true,
              promptCount: 0,
              source: 'system_profiler'
            });
          }
        }
      }
    }

    // Also check tccutil (macOS 13+)
    try {
      const tccOutput = await executeShellCommand('tccutil list 2>/dev/null', { quiet: true });
      if (tccOutput) {
        // Parse tccutil output if available
        const services = tccOutput.split('\n').filter(s => s.trim());
        // Note: tccutil list only shows service names, not granted apps
        // This is mainly for validation
      }
    } catch (error) {
      // tccutil not available or failed
    }

    return permissions;
  }

  /**
   * Analyze permissions for security risks
   */
  analyzePermissions(permissions) {
    const findings = [];

    for (const perm of permissions) {
      if (!perm.allowed) continue; // Only check granted permissions

      const risks = [];
      let riskLevel = 'low';

      // Check 1: Critical permissions granted
      if (this.criticalPermissions.includes(perm.service)) {
        risks.push(`Has critical permission: ${this.humanReadableService(perm.service)}`);
        riskLevel = 'medium';
      }

      // Check 2: Non-standard app paths with critical permissions
      const isTrustedPath = this.trustedPaths.some(path => perm.client.startsWith(path));

      if (!isTrustedPath && this.criticalPermissions.includes(perm.service)) {
        risks.push('Critical permission granted to non-standard location');
        riskLevel = 'high';
      }

      // Check 3: Apps in user directories with permissions
      if (perm.client.includes('/Users/') && !perm.client.includes('/Applications')) {
        risks.push('Permission granted to app in user directory');
        riskLevel = 'high';
      }

      // Check 4: Hidden apps with permissions
      const appName = perm.client.split('/').pop();
      if (appName.startsWith('.')) {
        risks.push('Permission granted to hidden application');
        riskLevel = 'high';
      }

      // Check 5: Suspicious app names
      const suspiciousKeywords = ['miner', 'crypto', 'hidden', 'backdoor', 'keylog'];
      const clientLower = perm.client.toLowerCase();

      for (const keyword of suspiciousKeywords) {
        if (clientLower.includes(keyword)) {
          risks.push(`Suspicious app name contains: ${keyword}`);
          riskLevel = 'high';
          break;
        }
      }

      // Only report if there are risks
      if (risks.length > 0) {
        findings.push({
          type: 'privacy_permission',
          app: perm.client,
          permission: this.humanReadableService(perm.service),
          service: perm.service,
          source: perm.source,
          risks,
          risk: riskLevel,
          description: `${perm.client}: ${risks.join(', ')}`
        });
      }
    }

    return findings;
  }

  /**
   * Convert TCC service names to human-readable format
   */
  humanReadableService(service) {
    const serviceMap = {
      'kTCCServiceSystemPolicyAllFiles': 'Full Disk Access',
      'kTCCServiceScreenCapture': 'Screen Recording',
      'kTCCServiceAccessibility': 'Accessibility',
      'kTCCServiceCamera': 'Camera',
      'kTCCServiceMicrophone': 'Microphone',
      'kTCCServicePhotos': 'Photos',
      'kTCCServiceContacts': 'Contacts',
      'kTCCServiceCalendar': 'Calendar',
      'kTCCServiceReminders': 'Reminders',
      'kTCCServiceAddressBook': 'Contacts',
      'kTCCServiceLocation': 'Location Services'
    };

    return serviceMap[service] || service;
  }
}
