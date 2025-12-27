import { BaseAgent } from './BaseAgent.js';
import { executeShellCommand } from '../utils/commander.js';

/**
 * ResourceAgent - Analyzes CPU, Memory, and IO usage
 */
export class ResourceAgent extends BaseAgent {
  constructor() {
    super('ResourceAgent');
  }

  async analyze() {
    const processes = await this.getProcessInfo();
    const memory = await this.getMemoryInfo();
    const findings = this.analyzeFindings(processes);

    this.results = {
      agent: this.name,
      timestamp: new Date().toISOString(),
      topCpuProcesses: processes.cpu.slice(0, 10),
      topMemoryProcesses: processes.memory.slice(0, 10),
      memoryStats: memory,
      suspiciousProcesses: findings,
      overallRisk: this.calculateOverallRisk(findings)
    };

    return this.results;
  }

  /**
   * Get process information using ps and top
   */
  async getProcessInfo() {
    const psOutput = await executeShellCommand('ps -axo pid,ppid,comm,%cpu,rss,etime');
    const lines = psOutput.split('\n').slice(1); // Skip header

    const processes = [];
    for (const line of lines) {
      if (!line.trim()) continue;

      const parts = line.trim().split(/\s+/);
      if (parts.length >= 6) {
        const pid = parseInt(parts[0]);
        const ppid = parseInt(parts[1]);
        const command = parts[2];
        const cpu = parseFloat(parts[3]);
        const rss = parseInt(parts[4]); // KB
        const etime = parts[5];
        const uptimeSeconds = this.parseElapsedTime(etime);

        processes.push({
          pid,
          ppid,
          command,
          cpu,
          memory: Math.round(rss / 1024), // Convert to MB
          uptime: etime,
          uptimeSeconds
        });
      }
    }

    const cpuSorted = [...processes].sort((a, b) => b.cpu - a.cpu);
    const memorySorted = [...processes].sort((a, b) => b.memory - a.memory);

    return {
      cpu: cpuSorted,
      memory: memorySorted,
      all: processes
    };
  }

  /**
   * Get memory statistics using vm_stat
   */
  async getMemoryInfo() {
    const vmOutput = await executeShellCommand('vm_stat');
    const lines = vmOutput.split('\n');

    const stats = {};
    for (const line of lines) {
      if (line.includes(':')) {
        const [key, value] = line.split(':');
        const cleanKey = key.trim().replace(/[^a-zA-Z0-9]/g, '_');
        const numValue = parseInt(value.trim().replace('.', ''));
        if (!isNaN(numValue)) {
          stats[cleanKey] = numValue;
        }
      }
    }

    // Convert pages to MB (page size is typically 4096 bytes)
    const pageSize = 4096;
    const toMB = (pages) => Math.round((pages * pageSize) / (1024 * 1024));

    return {
      free: toMB(stats.Pages_free || 0),
      active: toMB(stats.Pages_active || 0),
      inactive: toMB(stats.Pages_inactive || 0),
      wired: toMB(stats.Pages_wired_down || 0),
      compressed: toMB(stats.Pages_occupied_by_compressor || 0)
    };
  }

  /**
   * Analyze processes for suspicious activity
   */
  analyzeFindings(processes) {
    const findings = [];
    const systemPaths = ['/Applications', '/System', '/usr/bin', '/usr/sbin', '/bin', '/sbin'];
    const longRunningReported = new Set();

    // Check high CPU processes not in system paths
    for (const proc of processes.cpu.slice(0, 20)) {
      if (proc.cpu > 50) {
        const isSystemPath = systemPaths.some(path => proc.command.startsWith(path));

        if (!isSystemPath && !proc.command.startsWith('/Library')) {
          findings.push({
            type: 'high_cpu_unusual_path',
            pid: proc.pid,
            command: proc.command,
            cpu: proc.cpu,
            memory: proc.memory,
            risk: proc.cpu > 80 ? 'high' : 'medium',
            description: `High CPU usage (${proc.cpu}%) from non-system path`
          });
        }
      }
    }

    // Check high memory processes
    for (const proc of processes.memory.slice(0, 20)) {
      if (proc.memory > 1000) { // > 1GB
        const isSystemPath = systemPaths.some(path => proc.command.startsWith(path));

        if (!isSystemPath) {
          findings.push({
            type: 'high_memory_unusual_path',
            pid: proc.pid,
            command: proc.command,
            cpu: proc.cpu,
            memory: proc.memory,
            risk: proc.memory > 2000 ? 'high' : 'medium',
            description: `High memory usage (${proc.memory}MB) from non-system path`
          });
        }
      }
    }

    // Check for processes with suspicious names
    const suspiciousNames = ['miner', 'crypto', 'xmrig', 'coinhive', 'malware', 'trojan'];
    for (const proc of processes.all) {
      const commandLower = proc.command.toLowerCase();
      for (const suspName of suspiciousNames) {
        if (commandLower.includes(suspName)) {
          findings.push({
            type: 'suspicious_name',
            pid: proc.pid,
            command: proc.command,
            cpu: proc.cpu,
            memory: proc.memory,
            risk: 'high',
            description: `Process name contains suspicious keyword: ${suspName}`
          });
        }
      }
    }

    // Check for long-running background processes from non-system paths
    for (const proc of processes.all) {
      if (!proc.uptimeSeconds || proc.uptimeSeconds < 86400) continue; // > 24h

      const isSystemPath = systemPaths.some(path => proc.command.startsWith(path));
      if (isSystemPath || proc.command.startsWith('/Library')) continue;

      const key = `${proc.pid}-long`;
      if (longRunningReported.has(key)) continue;

      longRunningReported.add(key);

      const hours = Math.round(proc.uptimeSeconds / 3600);
      findings.push({
        type: 'long_running_background',
        pid: proc.pid,
        command: proc.command,
        cpu: proc.cpu,
        memory: proc.memory,
        uptime: proc.uptime,
        risk: proc.uptimeSeconds > 259200 ? 'high' : 'medium', // >3d high
        description: `Process running ${hours}h from non-system path`
      });
    }

    return findings;
  }

  /**
   * Convert ps etime ([[dd-]hh:]mm:ss) to seconds
   */
  parseElapsedTime(etime) {
    if (!etime) return 0;

    const [dayPart, timePartRaw] = etime.includes('-') ? etime.split('-') : [null, etime];
    const timePart = timePartRaw || etime;
    const segments = timePart.split(':').map(seg => parseInt(seg, 10) || 0);

    while (segments.length < 3) {
      segments.unshift(0);
    }

    const [hours, minutes, seconds] = segments.slice(-3);
    const days = dayPart ? parseInt(dayPart, 10) || 0 : 0;

    return (days * 86400) + (hours * 3600) + (minutes * 60) + seconds;
  }
}
