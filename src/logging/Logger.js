import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import { join } from 'path';
import { promises as fs } from 'fs';

/**
 * Structured Logging System
 */
export class Logger {
  constructor(options = {}) {
    this.options = {
      logDir: './logs',
      level: 'info',
      consoleLevel: 'warn',
      maxSize: '20m',
      maxFiles: '14d',
      enableConsole: true,
      enableFiles: true,
      ...options
    };

    this.logger = this.createLogger();
  }

  /**
   * Create Winston logger with proper configuration
   */
  createLogger() {
    const transports = [];

    // Console transport for development
    if (this.options.enableConsole) {
      transports.push(
        new winston.transports.Console({
          level: this.options.consoleLevel,
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
            winston.format.printf(({ level, message, timestamp, ...meta }) => {
              const metaStr = Object.keys(meta).length ? ` ${JSON.stringify(meta)}` : '';
              return `${timestamp} [${level}]: ${message}${metaStr}`;
            })
          )
        })
      );
    }

    // File transport for production logs
    if (this.options.enableFiles) {
      // Ensure log directory exists
      this.ensureLogDirectory();

      // Application logs
      transports.push(
        new DailyRotateFile({
          filename: join(this.options.logDir, 'app-%DATE%.log'),
          datePattern: 'YYYY-MM-DD',
          maxSize: this.options.maxSize,
          maxFiles: this.options.maxFiles,
          format: winston.format.combine(
            winston.format.timestamp(),
            winston.format.json()
          )
        })
      );

      // Error logs
      transports.push(
        new DailyRotateFile({
          filename: join(this.options.logDir, 'error-%DATE%.log'),
          datePattern: 'YYYY-MM-DD',
          level: 'error',
          maxSize: this.options.maxSize,
          maxFiles: this.options.maxFiles,
          format: winston.format.combine(
            winston.format.timestamp(),
            winston.format.json()
          )
        })
      );

      // Security event logs
      transports.push(
        new DailyRotateFile({
          filename: join(this.options.logDir, 'security-%DATE%.log'),
          datePattern: 'YYYY-MM-DD',
          level: 'warn',
          maxSize: this.options.maxSize,
          maxFiles: '30d', // Keep security logs longer
          format: winston.format.combine(
            winston.format.timestamp(),
            winston.format.json()
          )
        })
      );
    }

    return winston.createLogger({
      level: this.options.level,
      defaultMeta: { 
        service: 'security-solid-cli',
        version: '2.0.0'
      },
      transports,
      exitOnError: false
    });
  }

  /**
   * Ensure log directory exists
   */
  async ensureLogDirectory() {
    try {
      await fs.mkdir(this.options.logDir, { recursive: true });
    } catch (error) {
      console.error(`Failed to create log directory: ${error.message}`);
    }
  }

  /**
   * Log analysis start
   */
  logAnalysisStart(options = {}) {
    this.logger.info('Analysis started', {
      event: 'analysis_start',
      mode: options.mode,
      depth: options.depth,
      geoLookup: options.geoLookup,
      hostname: options.hostname
    });
  }

  /**
   * Log analysis completion
   */
  logAnalysisComplete(results, duration) {
    this.logger.info('Analysis completed', {
      event: 'analysis_complete',
      duration,
      findings: results.summary.totalFindings,
      highRisk: results.summary.highRiskFindings,
      mediumRisk: results.summary.mediumRiskFindings,
      lowRisk: results.summary.lowRiskFindings,
      overallRisk: results.overallRisk,
      agentsRan: Object.keys(results.agents).length
    });
  }

  /**
   * Log agent execution
   */
  logAgentStart(agentName, options = {}) {
    this.logger.debug(`Agent started: ${agentName}`, {
      event: 'agent_start',
      agent: agentName,
      ...options
    });
  }

  /**
   * Log agent completion
   */
  logAgentComplete(agentName, results, duration) {
    this.logger.debug(`Agent completed: ${agentName}`, {
      event: 'agent_complete',
      agent: agentName,
      duration,
      findings: results.findings?.length || 0,
      risk: results.overallRisk,
      error: results.error ? true : false
    });
  }

  /**
   * Log agent error
   */
  logAgentError(agentName, error, duration) {
    this.logger.error(`Agent failed: ${agentName}`, {
      event: 'agent_error',
      agent: agentName,
      duration,
      error: error.message,
      stack: error.stack
    });
  }

  /**
   * Log security event
   */
  logSecurityEvent(event, details = {}) {
    this.logger.warn('Security event detected', {
      event: 'security_event',
      securityEvent: event,
      severity: details.severity || 'medium',
      ...details
    });
  }

  /**
   * Log report generation
   */
  logReportGeneration(formats, outputPaths, duration) {
    this.logger.info('Reports generated', {
      event: 'report_generation',
      formats,
      outputPaths,
      duration
    });
  }

  /**
   * Log LLM analysis
   */
  logLLMAnalysis(provider, model, tokens, duration) {
    this.logger.info('LLM analysis completed', {
      event: 'llm_analysis',
      provider,
      model,
      tokens,
      duration
    });
  }

  /**
   * Log blockchain detection
   */
  logBlockchainDetection(indicators) {
    this.logger.info('Blockchain activity detected', {
      event: 'blockchain_detection',
      indicators,
      action: 'blockchain_agents_activated'
    });
  }

  /**
   * Log performance metrics
   */
  logPerformance(operation, duration, metadata = {}) {
    this.logger.debug(`Performance: ${operation}`, {
      event: 'performance',
      operation,
      duration,
      ...metadata
    });
  }

  /**
   * Log user interaction
   */
  logUserInteraction(action, details = {}) {
    this.logger.debug('User interaction', {
      event: 'user_interaction',
      action,
      ...details
    });
  }

  /**
   * Log configuration changes
   */
  logConfigurationChange(setting, oldValue, newValue) {
    this.logger.info('Configuration changed', {
      event: 'config_change',
      setting,
      oldValue,
      newValue
    });
  }

  /**
   * Get logger instance
   */
  getLogger() {
    return this.logger;
  }

  /**
   * Set log level
   */
  setLevel(level) {
    this.logger.level = level;
    this.options.level = level;
  }

  /**
   * Add custom transport
   */
  addTransport(transport) {
    this.logger.add(transport);
  }

  /**
   * Remove transport
   */
  removeTransport(transport) {
    this.logger.remove(transport);
  }

  /**
   * Close logger
   */
  async close() {
    const transports = this.logger.transports;
    await Promise.all(
      transports.map(transport => {
        if (typeof transport.close === 'function') {
          return transport.close();
        }
        return Promise.resolve();
      })
    );
  }
}

/**
 * Global logger instance
 */
let globalLogger = null;

/**
 * Get or create global logger instance
 */
export function getLogger(options = {}) {
  if (!globalLogger) {
    globalLogger = new Logger(options);
  }
  return globalLogger;
}

/**
 * Log convenience functions
 */
export const log = {
  debug: (message, meta = {}) => getLogger().getLogger().debug(message, meta),
  info: (message, meta = {}) => getLogger().getLogger().info(message, meta),
  warn: (message, meta = {}) => getLogger().getLogger().warn(message, meta),
  error: (message, meta = {}) => getLogger().getLogger().error(message, meta),
  
  // Structured logging functions
  analysisStart: (options) => getLogger().logAnalysisStart(options),
  analysisComplete: (results, duration) => getLogger().logAnalysisComplete(results, duration),
  agentStart: (agent, options) => getLogger().logAgentStart(agent, options),
  agentComplete: (agent, results, duration) => getLogger().logAgentComplete(agent, results, duration),
  agentError: (agent, error, duration) => getLogger().logAgentError(agent, error, duration),
  securityEvent: (event, details) => getLogger().logSecurityEvent(event, details),
  reportGeneration: (formats, paths, duration) => getLogger().logReportGeneration(formats, paths, duration),
  llmAnalysis: (provider, model, tokens, duration) => getLogger().logLLMAnalysis(provider, model, tokens, duration),
  blockchainDetection: (indicators) => getLogger().logBlockchainDetection(indicators),
  performance: (operation, duration, meta) => getLogger().logPerformance(operation, duration, meta),
  userInteraction: (action, details) => getLogger().logUserInteraction(action, details),
  configChange: (setting, oldVal, newVal) => getLogger().logConfigurationChange(setting, oldVal, newVal)
};