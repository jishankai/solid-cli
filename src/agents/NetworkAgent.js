import { BaseAgent } from './BaseAgent.js';
import { executeShellCommand } from '../utils/commander.js';

/**
 * NetworkAgent - Analyzes network connections and listening ports
 */
export class NetworkAgent extends BaseAgent {
  constructor(options = {}) {
    super('NetworkAgent');
    this.suspiciousPorts = [
      1337, 31337, // Leet ports
      4444, 5555, 6666, 7777, 8888, 9999, // Common backdoor ports
      12345, 54321, // NetBus
      6667, 6668, 6669, // IRC
      1234, 3389, // Remote access
    ];
    this.trustedPaths = [
      '/Applications',
      '/System',
      '/System/Applications',
      '/System/Library',
      '/Library',
      '/Library/Apple',
      '/usr/bin',
      '/usr/sbin',
      '/usr/lib',
      '/usr/libexec',
      '/usr/local/bin'
    ];
    this.trustedCommands = new Set([
      'mDNSResponder', 'configd', 'systemstats', 'nsurlsessiond', 'rapportd',
      'apsd', 'trustd', 'ocspd', 'akd', 'netbiosd', 'netinfod', 'locationd',
      'powerd', 'tccd', 'coreaudiod', 'timed', 'bluetoothd', 'notifyd'
    ]);
    this.enableGeoLookup = Boolean(options.enableGeoLookup);
    this.geoLookupLimit = options.geoLookupLimit || 8;
    this.geoCache = {};
    this.geoipAvailable = null;
  }

  async analyze() {
    const connections = await this.getNetworkConnections();
    const geoLookup = this.enableGeoLookup ? await this.enrichGeoData(connections) : {};
    const findings = this.analyzeConnections(connections, geoLookup);

    this.results = {
      agent: this.name,
      timestamp: new Date().toISOString(),
      totalConnections: connections.length,
      listening: connections.filter(c => c.state === 'LISTEN').length,
      established: connections.filter(c => c.state === 'ESTABLISHED').length,
      geoLookupEnabled: this.enableGeoLookup,
      geoLookups: Object.keys(geoLookup).length,
      geolocation: geoLookup,
      findings,
      overallRisk: this.calculateOverallRisk(findings)
    };

    return this.results;
  }

  /**
   * Get network connections without triggering macOS privacy prompts
   */
  async getNetworkConnections() {
    const [tcpOutput, udpOutput] = await Promise.all([
      executeShellCommand('netstat -anv -p tcp', { quiet: true }),
      executeShellCommand('netstat -anv -p udp', { quiet: true })
    ]);

    return [
      ...this.parseNetstatOutput(tcpOutput, 'TCP'),
      ...this.parseNetstatOutput(udpOutput, 'UDP')
    ];
  }

  /**
   * Parse netstat output into connection objects
   */
  parseNetstatOutput(output, protocol) {
    const connections = [];
    if (!output) return connections;

    const lines = output.split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('Active') || trimmed.startsWith('Proto')) {
        continue;
      }

      const parts = trimmed.split(/\s+/);
      if (parts.length < 5) continue;

      const local = parts[3];
      const remote = parts[4];
      const state = parts[5] || (protocol === 'UDP' ? 'NONE' : 'UNKNOWN');

      const [localAddr, localPort] = this.parseAddress(local);
      const [remoteAddr, remotePort] = this.parseAddress(remote);

      connections.push({
        command: '(unknown)',
        pid: 0,
        user: 'unknown',
        type: protocol,
        localAddr,
        localPort: parseInt(localPort) || 0,
        remoteAddr,
        remotePort: parseInt(remotePort) || 0,
        state
      });
    }

    return connections;
  }

  /**
   * Parse address:port string
   */
  parseAddress(addr) {
    if (!addr) return ['', ''];

    if (addr === '*.*' || addr === '*') {
      return ['*', ''];
    }

    const separatorIndex = addr.lastIndexOf(':') !== -1
      ? addr.lastIndexOf(':')
      : addr.lastIndexOf('.');

    if (separatorIndex === -1) return [addr, ''];

    return [
      addr.substring(0, separatorIndex),
      addr.substring(separatorIndex + 1)
    ];
  }

  /**
   * Analyze connections for suspicious patterns
   */
  analyzeConnections(connections, geoLookup = {}) {
    const findings = [];

    for (const conn of connections) {
      const risks = [];
      let riskLevel = 'low';
      const hasAbsolutePath = conn.command && conn.command.startsWith('/');
      const isTrustedPath = hasAbsolutePath && this.trustedPaths.some(path => conn.command.startsWith(path));
      const isTrustedCommand = this.trustedCommands.has(conn.command);

      // Check 1: Suspicious port numbers
      if (this.suspiciousPorts.includes(conn.localPort) || this.suspiciousPorts.includes(conn.remotePort)) {
        risks.push(`Suspicious port detected: ${conn.localPort || conn.remotePort}`);
        riskLevel = 'high';
      }

      // Check 2: Get process path
      // Check 3: Non-system process with network activity
      const effectiveTrusted = isTrustedPath || (!hasAbsolutePath && isTrustedCommand);

      if (!effectiveTrusted && hasAbsolutePath && conn.state === 'ESTABLISHED') {
        risks.push('Non-system process with active connection');
        riskLevel = 'medium';

        // Check if remote IP is suspicious (not local, not common services)
        if (conn.remoteAddr && !this.isLocalAddress(conn.remoteAddr)) {
          risks.push(`External connection to ${conn.remoteAddr}:${conn.remotePort}`);

          // Elevate risk for non-standard ports
          if (conn.remotePort > 10000 && conn.remotePort < 65000) {
            riskLevel = 'high';
          }
        }
      }

      // Check 4: Listening on non-standard ports from user processes
      if (conn.state === 'LISTEN' && !effectiveTrusted && hasAbsolutePath) {
        risks.push(`Listening on port ${conn.localPort}`);

        if (conn.localAddr === '*' || conn.localAddr === '0.0.0.0') {
          risks.push('Listening on all interfaces');
          riskLevel = 'high';
        } else {
          riskLevel = 'medium';
        }
      }

      // Check 5: Hidden or obfuscated process names (reduce false positives)
      // lsof "COMMAND" is usually a short name (not a path), and many legitimate daemons are lowercase.
      // Only treat this as suspicious when the command is not trusted and matches strong obfuscation patterns.
      if (!effectiveTrusted) {
        if (conn.command.startsWith('.')) {
          risks.push('Hidden process name (starts with dot)');
          riskLevel = 'high';
        } else if (conn.command.match(/^[a-z]{1,2}[0-9]{6,}$/i)) {
          risks.push('Suspicious obfuscated process name pattern');
          riskLevel = 'high';
        } else if (conn.command.match(/^[0-9a-f]{16,}$/i)) {
          risks.push('Suspicious hex-like process name pattern');
          riskLevel = 'high';
        }
      }

      // Only report when we have strong enough signals to reduce false positives.
      // (high risk) OR (multiple risk indicators)
      const shouldReport = risks.length > 1 || riskLevel === 'high';
      if (shouldReport) {
        const connectionType = conn.state === 'LISTEN' ? 'listening' : 'outbound';
        const geo = conn.remoteAddr ? geoLookup[conn.remoteAddr] : undefined;
        if (geo && geo.summary) {
          risks.push(`Geo: ${geo.summary}`);
        }

        findings.push({
          type: connectionType,
          command: conn.command,
          pid: conn.pid,
          user: conn.user,
          protocol: conn.type,
          localAddr: conn.localAddr,
          localPort: conn.localPort,
          remoteAddr: conn.remoteAddr,
          remotePort: conn.remotePort,
          state: conn.state,
          geo,
          risks,
          risk: riskLevel,
          description: `${conn.command} (${conn.pid}): ${risks.join(', ')}`
        });
      }
    }

    return findings;
  }

  /**
   * Check if an address is local/private
   */
  isLocalAddress(addr) {
    if (!addr) return false;

    return (
      addr === 'localhost' ||
      addr === '127.0.0.1' ||
      addr.startsWith('192.168.') ||
      addr.startsWith('10.') ||
      addr.startsWith('172.16.') ||
      addr.startsWith('fe80:') ||
      addr === '::1'
    );
  }

  /**
   * Limit geo lookups to external IPs and add cached location info
   */
  async enrichGeoData(connections) {
    const externalIps = Array.from(new Set(
      connections
        .map(c => c.remoteAddr)
        .filter(ip => ip && !this.isLocalAddress(ip) && this.isPublicIP(ip))
    )).slice(0, this.geoLookupLimit);

    const geoLookup = {};

    for (const ip of externalIps) {
      const cached = this.geoCache[ip];
      if (cached) {
        geoLookup[ip] = cached;
        continue;
      }

      const geo = await this.lookupGeo(ip);
      if (geo) {
        this.geoCache[ip] = geo;
        geoLookup[ip] = geo;
      }
    }

    return geoLookup;
  }

  /**
   * Simple public IP check (excludes wildcard/unspecified)
   */
  isPublicIP(ip) {
    if (!ip) return false;
    if (ip === '*' || ip === '0.0.0.0') return false;
    return !this.isLocalAddress(ip);
  }

  /**
   * Lookup geo information using local geoip (if present) then ipinfo.io as fallback
   */
  async lookupGeo(ip) {
    if (this.geoipAvailable === null) {
      const available = await executeShellCommand('command -v geoiplookup >/dev/null 2>&1 && echo yes', { quiet: true });
      this.geoipAvailable = Boolean(available && available.trim() === 'yes');
    }

    // Try geoiplookup if available (no external call if DB exists)
    if (this.geoipAvailable) {
      try {
        const geoip = await executeShellCommand(`geoiplookup ${ip} 2>/dev/null`, { quiet: true });
        if (geoip) {
          const summary = geoip.split(':')[1]?.trim() || geoip.trim();
          return {
            ip,
            summary,
            source: 'geoiplookup'
          };
        }
      } catch (error) {
        // Ignore and fall through
      }
    }

    // Fallback to ipinfo.io (external); handle failures gracefully
    try {
      const output = await executeShellCommand(`curl -s --max-time 5 https://ipinfo.io/${ip}/json`, { quiet: true });
      const data = JSON.parse(output || '{}');

      if (Object.keys(data).length === 0) return null;

      const summaryParts = [data.city, data.region, data.country].filter(Boolean);
      const summary = summaryParts.join(', ') || data.country || 'Unknown';

      return {
        ip,
        city: data.city,
        region: data.region,
        country: data.country,
        org: data.org,
        source: 'ipinfo.io',
        summary
      };
    } catch (error) {
      return null;
    }
  }
}
