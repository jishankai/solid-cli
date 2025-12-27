import { BaseAgent } from './BaseAgent.js';
import { executeShellCommand } from '../utils/commander.js';

/**
 * ProcessAgent - Analyzes running processes for anomalies
 */
export class ProcessAgent extends BaseAgent {
  constructor() {
    super('ProcessAgent');
    this.systemPaths = [
      // System directories
      '/Applications',
      '/System',
      '/System/Applications',
      '/System/Library',
      '/System/Library/CoreServices',
      '/System/Library/Frameworks',
      '/Library',
      '/Library/Apple',
      '/Library/Application Support',
      '/Library/Frameworks',
      '/Library/PreferencePanes',
      '/Library/LaunchAgents',
      '/Library/LaunchDaemons',
      
      // Standard Unix paths
      '/bin',
      '/sbin',
      '/usr/bin',
      '/usr/sbin',
      '/usr/lib',
      '/usr/libexec',
      '/usr/local/bin',
      '/usr/local/sbin',
      '/usr/local/lib',
      '/usr/local/share',
      '/opt/homebrew/bin',
      '/opt/local/bin',
      
      // Developer tools
      '/usr/bin/code',
      '/Applications/Visual Studio Code.app',
      '/Applications/Xcode.app',
      '/Applications/Atom.app',
      '/Applications/Sublime Text.app',
      '/Developer',
      '/Xcode',
      
      // Common application directories
      '/Applications/Microsoft Office',
      '/Applications/Adobe',
      '/Applications/Google Chrome.app',
      '/Applications/Google Chrome',
      '/Applications/Safari.app',
      '/Applications/Firefox.app',
      '/Applications/Opera.app',
      '/Applications/Slack.app',
      '/Applications/Discord.app',
      '/Applications/Zoom.app',
      '/Applications/Teams.app',
      '/Applications/Skype.app',
      '/Applications/Dropbox.app',
      '/Applications/Spotify.app',
      '/Applications/VLC.app',
      '/Applications/QuickTime Player.app',
      '/Applications/iTunes.app',
      '/Applications/Preview.app',
      '/Applications/TextEdit.app',
      '/Applications/Activity Monitor.app',
      '/Applications/Console.app',
      '/Applications/System Preferences.app',
      '/Applications/System Information.app',
      '/Applications/Utilities',
      '/Applications/Terminal.app',
      '/Applications/iTerm.app',
      
      // Homebrew paths
      '/opt/homebrew',
      '/usr/local/Cellar',
      '/usr/local/Caskroom',
      
      // Node.js and npm
      '/usr/local/bin/node',
      '/usr/local/bin/npm',
      '/opt/homebrew/bin/node',
      '/opt/homebrew/bin/npm',
      
      // Python paths
      '/usr/bin/python',
      '/usr/bin/python3',
      '/usr/local/bin/python',
      '/usr/local/bin/python3',
      '/opt/homebrew/bin/python',
      '/opt/homebrew/bin/python3',
      
      // Git
      '/usr/bin/git',
      '/usr/local/bin/git',
      '/opt/homebrew/bin/git',
      
      // Shell paths
      '/bin/bash',
      '/bin/zsh',
      '/bin/fish',
      '/bin/tcsh',
      '/usr/local/bin/bash',
      '/usr/local/bin/zsh',
      '/opt/homebrew/bin/bash',
      '/opt/homebrew/bin/zsh',
      
      // macOS specific
      '/System/Library/PrivateFrameworks',
      '/System/Library/CoreServices/Finder.app',
      '/System/Library/CoreServices/Dock.app',
      '/System/Library/CoreServices/Menu Extras',
      '/System/Library/CoreServices/Spotlight.app'
    ];
    this.systemProcessNames = [
      // Core system processes
      'kernel_task', 'launchd', 'loginwindow',
      
      // UI and desktop
      'Finder', 'SystemUIServer', 'WindowServer', 'Dock',
      'UserNotificationCenter', 'NotificationCenter', 'Spotlight',
      
      // System services
      'cfprefsd', 'mds', 'mdworker', 'mds_stores', 'distnoted',
      'notifyd', 'powerd', 'tccd', 'locationd', 'opendirectoryd',
      'syslogd', 'logd', 'mDNSResponder', 'configd', 'systemstats',
      'coreaudiod', 'bluetoothd', 'airportd', 'securityd', 'warmd',
      'hidd', 'fseventsd', 'pbs', 'pboard',
      
      // Network services
      'networkd', 'wifid', 'socketfilterfw',
      
      // Graphics and display
      'WindowManager', 'coreservicesd', 'SkyLight',
      
      // File system
      'diskarbitrationd', 'filecoordinationd',
      
      // Security
      'authd', 'trustd', 'amfid',
      
      // Development tools
      'node', 'python', 'python3', 'git', 'ssh',
      'bash', 'zsh', 'fish', 'tcsh',
      
      // Common applications
      'Chrome', 'Safari', 'firefox', 'VSCode', 'code',
      'iTerm', 'Terminal',
      
      // System utilities
      'Activity Monitor', 'Preview', 'Console'
    ];
    this.trustedSystemCommands = new Set([
      // Core system processes
      'launchd', 'kernel_task', 'kernelinit', 'kextd', 'kerneld',
      
      // macOS system services
      'WindowServer', 'SystemUIServer', 'Dock', 'Finder', 'loginwindow',
      'UserNotificationCenter', 'Spotlight', 'NotificationCenter',
      
      // Background services (daemons)
      'mds', 'mdworker', 'mds_stores', 'distnoted', 'notifyd', 'powerd',
      'cfprefsd', 'usernoted', 'tccd', 'locationd', 'opendirectoryd',
      'syslogd', 'logd', 'mDNSResponder', 'configd', 'systemstats',
      'coreaudiod', 'bluetoothd', 'airportd', 'securityd', 'warmd',
      'hidd', 'cmiodalassistants', 'launchservicesd', 'iconservicesagent',
      'lskdd', 'lsd', 'fseventsd', 'pbs', 'pboard', 'pasteboardd',
      
      // Network and connectivity
      'networkd', 'wifid', 'socketfilterfw', 'natd', 'pppd',
      'racoon', 'racoonctl', 'vpnd', 'netbiosd',
      
      // Graphics and display
      'WindowManager', 'coreservicesd', 'SkyLight', 'HIToolbox',
      'CGSession', 'ScreenSaverEngine', 'SystemPreferences',
      
      // File system and storage
      'fsapfs', 'hfs_mount', 'autodiskmount', 'diskarbitrationd',
      'diskmanagementd', 'filecoordinationd', 'synthesisd',
      
      // Security and authentication
      'authd', 'authorizationhost', 'ocspd', 'trustd', 'securityd',
      'codesign', 'taskgated', 'sandboxd', 'amfid',
      
// Development tools (commonly installed)
      'node', 'npm', 'npx', 'yarn', 'pnpm', 'pnpx',
      'pip', 'pip3', 'python', 'python3', 'pip3',
      'git', 'git-credential-manager', 'git-gui', 'gitk',
      'ssh', 'ssh-agent', 'ssh-add', 'scp', 'sftp', 'rsync',
      'curl', 'wget', 'http', 'https', 'ftp',
      'brew', 'ruby', 'perl', 'java', 'javac', 'gradle', 'maven',
      'docker', 'docker-compose', 'kubectl', 'helm', 'minikube',
      'make', 'cmake', 'gcc', 'clang', 'clang++',
      'go', 'gorun', 'gobuild', 'rust', 'rustc', 'cargo',
      'php', 'composer', 'laravel', 'symfony',
      'typescript', 'ts-node', 'tsc', 'tsx',
      'eslint', 'prettier', 'jest', 'mocha', 'chai',
      'webpack', 'vite', 'parcel', 'rollup',
      'nodemon', 'pm2', 'forever', 'supervisor',
      'redis-server', 'redis-cli', 'mongod', 'mongo', 'mysql',
      'psql', 'postgres', 'sqlite3', 'mongo-express',
      'nginx', 'apache2', 'httpd', 'caddy', 'traefik',
      
      // Common applications
      'Chrome', 'chromium', 'Safari', 'firefox', 'Opera',
      'Slack', 'Discord', 'Zoom', 'Teams', 'Skype',
      'VSCode', 'code', 'Xcode', 'Atom', 'Sublime_Text',
      'iTerm', 'Terminal', 'bash', 'zsh', 'fish', 'tcsh',
      
      // macOS utilities
      'Activity Monitor', 'Preview', 'TextEdit', 'QuickLook',
      'ArchiveUtility', 'DiskUtility', 'Keychain Access',
      'System Information', 'Console', 'Automator',
      
      // Third-party common software
      'Dropbox', 'GoogleDrive', 'OneDrive', 'Box',
      'Spotify', 'VLC', 'QuickTimePlayer', 'iTunes',
      'Microsoft Word', 'Microsoft Excel', 'Microsoft PowerPoint',
      'Adobe Acrobat', 'Adobe Reader', 'Photoshop',
      
      // System maintenance
      'periodic', 'daily', 'weekly', 'monthly', 'launchctl',
      'systemsetup', 'softwareupdate', 'pmset', 'caffeinate',
      
      // Input and peripherals
      'IOHIDSystem', 'IOHIDEventDriver', 'USBAgent',
      'BluetoothUIServer', 'AudioComponentRegistrar',
      
      // Time and sync
      'timed', 'clockd', 'ntpd', 'networktime',
      
      // Print and scanning
      'cupsd', 'cups-browsed', 'hpmud', 'ImageCaptureExtension',
      
      // Accessibility
      'VoiceOver', 'AXUIServer', 'accessibilityd',
      
      // Backup and recovery
      'TimeMachine', 'backupd', 'tmutil', 'rsync',
      
      // Additional macOS system daemons
      'mediaremoted', 'watchdogd', 'kernelmanagerd', 'thermalmonitord',
      'apsd', 'apsrelayd', 'applepushserviced', 'com.apple.CommCenter',
      'commcenter', 'commcenterd', 'mobileassetd', 'assetcache',
      'assetcachingd', 'cacheserverd', 'cached', 'cachecheck',
      'logind', 'logindisplay', 'loginwindow', 'screensharingd',
      'remoted', 'remotepairingd', 'remotepairingtool',
      'sharingd', 'screencaptured', 'screenshotd',
      'corebrightnessd', 'backlightd', 'brightnessd',
      'controlcenterd', 'controlcenter', 'spotlightd',
      'searchpartyd', 'searchindexer', 'mds_stores',
      'useractivityd', 'useractivityagent', 'useractivitymonitor',
      'timed', 'timed_sync', 'networkd', 'networkd_privileged',
      'wifid', 'wirelessprovisioningd', 'wirelessproxd',
      'bluetoothd', 'bluetoothaudiod', 'bluetoothUIServer',
      'audioaccessoryd', 'audioaccessoryd',
      'coreaudiod', 'coreaudiohelperd', 'coreaudioaopd',
      'hidd', 'hidd_helper', 'hidd_system',
      'universalaccessd', 'accessibilityd', 'AXUIServer',
      'voiceover', 'voiceoverd',
      'distnoted', 'distributednotificationcenter',
      'nsurlsessiond', 'nsurlstoraged', 'webkitnetworkprocess',
      'webkitwebcontentprocess', 'webkitpluginprocess',
      'plugind', 'pluginmanagerd',
      'launchservicesd', 'lsd', 'lskdd',
      'iconservicesagent', 'iconservicesd',
      'pasteboardd', 'pboard', 'pbs',
      'cfprefsd', 'preferencesd', 'systempreferencesd',
      'tccd', 'tccutil', 'privacyd',
      'locationd', 'locationservicesd', 'geod',
      'compassd', 'magnetometerd', 'accelerometerd',
      'gyroscoped', 'barometerd',
      'fseventsd', 'fsapfs', 'filecoordinationd',
      'synthesisd', 'syncdefaultsd', 'syncservicesd',
      'diskarbitrationd', 'diskmanagementd', 'diskimagesd',
      'hdiutil', 'hdid', 'hdihelperd',
      'authd', 'authorizationhost', 'authtrampoline',
      'securityd', 'securityagent', 'securityhelperd',
      'codesign', 'codesign_allocate', 'taskgated',
      'amfid', 'amfite', 'applemobilefileintegrity',
      'sandboxd', 'sandboxd_helper', 'seatbeltd',
      'trustd', 'trustevaluationagent',
      'ocspd', 'ocsp_helperd',
      'certificateauthorityd', 'certificated',
      'keychaind', 'keychainaccesshelperd',
      'smartcardservicesd', 'tokend',
      'biometrickitd', 'touchid', 'faced',
      'corecrypto', 'corecryptod',
      'kernelmanagerd', 'kextd', 'kextcache',
      'systemstats', 'systemstatsd',
      'powerd', 'powermanagementd', 'pmset',
      'thermalmonitord', 'thermalmonitord_helper',
      'warmd', 'warmd_helper',
      'configd', 'configd_helper',
      'networksetup', 'networksetup_helper',
      'scutil', 'scutil_helper',
      'ifconfig', 'ifconfig_helper',
      'netstat', 'netstat_helper',
      'ping', 'ping_helper',
      'traceroute', 'traceroute_helper',
      'nslookup', 'nslookup_helper',
      'dig', 'dig_helper',
      'host', 'host_helper'
    ]);
  }

  async analyze() {
    const processes = await this.getProcessDetails();
    const findings = this.analyzeProcesses(processes);

    this.results = {
      agent: this.name,
      timestamp: new Date().toISOString(),
      totalProcesses: processes.length,
      findings,
      overallRisk: this.calculateOverallRisk(findings)
    };

    return this.results;
  }

  /**
   * Get detailed process information
   */
  async getProcessDetails() {
    // Get process list with parent relationships
    const psOutput = await executeShellCommand('ps -axo pid,ppid,user,comm');
    const lines = psOutput.split('\n').slice(1); // Skip header

    const processes = [];

    for (const line of lines) {
      if (!line.trim()) continue;

      const parts = line.trim().split(/\s+/);
      if (parts.length >= 4) {
        const pid = parseInt(parts[0]);
        const ppid = parseInt(parts[1]);
        const user = parts[2];
        const command = parts.slice(3).join(' ');

        // Try to get executable path with multiple fallbacks
        const fullPath = await this.getExecutablePath(pid, command);

        processes.push({
          pid,
          ppid,
          user,
          name: command.split('/').pop().split(' ')[0],
          command,
          path: fullPath
        });
      }
    }

    return processes;
  }

  /**
   * Resolve executable path with fallbacks to reduce false positives
   */
  async getExecutablePath(pid, commandFallback) {
    // 1) lsof (often includes absolute path)
    try {
      const pathOutput = await executeShellCommand(
        `lsof -p ${pid} -Fn 2>/dev/null | grep '^n/' | head -1`,
        { quiet: true }
      );
      if (pathOutput) {
        const resolved = pathOutput.replace('n', '').trim();
        if (resolved.startsWith('/')) return resolved;
      }
    } catch (error) {
      // ignore
    }

    // 2) ps comm gives executable name (may include path)
    try {
      const commOutput = await executeShellCommand(
        `ps -p ${pid} -o comm= 2>/dev/null`,
        { quiet: true }
      );
      if (commOutput && commOutput.trim().startsWith('/')) {
        return commOutput.trim();
      }
    } catch (error) {
      // ignore
    }

    // 3) ps command column (may include args)
    try {
      const cmdOutput = await executeShellCommand(
        `ps -p ${pid} -o command= 2>/dev/null`,
        { quiet: true }
      );
      if (cmdOutput) {
        const candidate = cmdOutput.trim().split(' ')[0];
        if (candidate.startsWith('/')) return candidate;
      }
    } catch (error) {
      // ignore
    }

    // Fallback to the short command we already have
    return commandFallback;
  }

  /**
   * Analyze processes for suspicious patterns
   */
  analyzeProcesses(processes) {
    const findings = [];

    for (const proc of processes) {
      const risks = [];
      let riskLevel = 'low';
      const hasAbsolutePath = proc.path && proc.path.startsWith('/');
      const isTrustedPath = hasAbsolutePath && this.systemPaths.some(sysPath => proc.path.startsWith(sysPath));
      const isTrustedCommand = this.trustedSystemCommands.has(proc.name);
      const isUserPath = hasAbsolutePath && proc.path.includes('/Users/');

      // Check 1: System process name but running from user directory
      if (hasAbsolutePath && this.systemProcessNames.includes(proc.name)) {
        if (isUserPath) {
          risks.push('System process name running from user directory');
          riskLevel = 'high';
        }
      }

      // Check 2: Process name doesn't match path
      const pathBasename = hasAbsolutePath ? proc.path.split('/').pop().split(' ')[0] : '';
      if (hasAbsolutePath && pathBasename && proc.name !== pathBasename) {
        risks.push(`Process name mismatch (name: ${proc.name}, path: ${pathBasename})`);
        riskLevel = 'medium';
      }

      // Check 3: Non-system path execution
      if (hasAbsolutePath && !isTrustedPath && proc.path !== proc.command) {
        risks.push('Running from non-standard location');

        // Elevate risk if in hidden directory
        if (proc.path.includes('/.')) {
          risks.push('Running from hidden directory');
          riskLevel = 'high';
        } else if (isUserPath) {
          riskLevel = 'medium';
        } else {
          // keep as low unless combined with other risks
          riskLevel = riskLevel === 'low' ? 'medium' : riskLevel;
        }
      }

      // Check 4: Suspicious parent process
      const parent = processes.find(p => p.pid === proc.ppid);
      if (parent && hasAbsolutePath && !isTrustedPath) {
        if (parent.name === 'bash' || parent.name === 'sh' || parent.name === 'python') {
          risks.push(`Spawned by shell: ${parent.name}`);
          riskLevel = 'medium';
        }
      }

      // Check 5: Root/elevated processes from user paths
      if (hasAbsolutePath && (proc.user === 'root' || proc.user === '_coreaudiod') && proc.path.includes('/Users/')) {
        risks.push('Elevated privileges from user directory');
        riskLevel = 'high';
      }

      // Check 6: Hidden or obfuscated names
      if (proc.name.startsWith('.') && !isTrustedCommand) {
        risks.push('Hidden process name (starts with dot)');
        riskLevel = 'high';
      } else if (proc.name.match(/^[a-z]{1,2}[0-9]{6,}$/) && !isTrustedCommand) {
        // Pattern like "ab123456" - likely obfuscated
        risks.push('Suspicious obfuscated process name pattern');
        riskLevel = 'high';
      } else if (proc.name.match(/^[0-9a-f]{16,}$/i) && !isTrustedCommand) {
        // Hex-like pattern - likely obfuscated
        risks.push('Suspicious hex-like process name pattern');
        riskLevel = 'high';
      }

      // If we only have a trusted command name and no absolute path, avoid flagging
      if (!hasAbsolutePath && isTrustedCommand && risks.length === 0) {
        continue;
      }

      // Only report if there are meaningful risks (high risk or multiple signals)
      const shouldReport = risks.length > 1 || riskLevel === 'high';
      if (shouldReport) {
        findings.push({
          type: 'suspicious_process',
          pid: proc.pid,
          name: proc.name,
          path: proc.path,
          user: proc.user,
          ppid: proc.ppid,
          parentName: parent?.name || 'unknown',
          risks,
          risk: riskLevel,
          description: `Process ${proc.name} (${proc.pid}): ${risks.join(', ')}`
        });
      }
    }

    return findings;
  }
}
