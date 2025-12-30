import config from 'config';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join } from 'path';
import Joi from 'joi';

/**
 * Configuration Management System
 */
export class ConfigManager {
  constructor() {
    this.schema = this.createSchema();
    this.config = this.loadConfiguration();
    this.watchers = [];
  }

  /**
   * Create validation schema for configuration
   */
  createSchema() {
    return Joi.object({
      analysis: Joi.object({
        defaultDepth: Joi.string().valid('fast', 'comprehensive', 'deep').default('comprehensive'),
        adaptiveMode: Joi.boolean().default(true),
        blockchainDetection: Joi.boolean().default(true),
        deepForensicsThreshold: Joi.string().valid('low', 'medium', 'high').default('medium'),
        parallelExecution: Joi.boolean().default(true),
        maxParallelAgents: Joi.number().integer().min(1).max(10).default(3)
      }),

      reports: Joi.object({
        outputDir: Joi.string().default('./reports'),
        retentionDays: Joi.number().integer().min(1).max(365).default(90),
        defaultTemplate: Joi.string().default('executive'),
        defaultFormats: Joi.array().items(Joi.string().valid('markdown', 'pdf', 'html')).default(['markdown', 'pdf']),
        pdfOptions: Joi.object({
          format: Joi.string().default('A4'),
          margin: Joi.string().default('2cm'),
          displayHeaderFooter: Joi.boolean().default(true),
          printBackground: Joi.boolean().default(true)
        }),
        includeScreenshots: Joi.boolean().default(false),
        compressOldReports: Joi.boolean().default(true)
      }),

      logging: Joi.object({
        level: Joi.string().valid('error', 'warn', 'info', 'debug').default('info'),
        consoleLevel: Joi.string().valid('error', 'warn', 'info', 'debug').default('warn'),
        enableConsole: Joi.boolean().default(true),
        enableFiles: Joi.boolean().default(true),
        logDir: Joi.string().default('./logs'),
        maxFileSize: Joi.string().default('20m'),
        maxFiles: Joi.string().default('14d'),
        securityLogRetention: Joi.string().default('30d')
      }),

      llm: Joi.object({
        autoDetectProvider: Joi.boolean().default(true),
        enableLogging: Joi.boolean().default(true),
        logDir: Joi.string().default('./logs/llm-requests'),
        privacyLevel: Joi.string().valid('low', 'medium', 'high').default('high'),
        maxTokens: Joi.number().integer().min(100).max(8000).default(4000),
        temperature: Joi.number().min(0).max(2).default(0.1),
        minHighRiskFindings: Joi.number().integer().min(0).max(50).default(1),
        minTotalFindings: Joi.number().integer().min(0).max(200).default(5),
        skipWhenBelowThreshold: Joi.boolean().default(true)
      }),

      privacy: Joi.object({
        redactUserPaths: Joi.boolean().default(true),
        redactUsernames: Joi.boolean().default(true),
        redactIPs: Joi.boolean().default(false),
        preserveDomains: Joi.boolean().default(true),
        sanitizationLevel: Joi.string().valid('low', 'medium', 'high').default('high')
      }),

      performance: Joi.object({
        enableMetrics: Joi.boolean().default(true),
        slowQueryThreshold: Joi.number().integer().min(100).default(5000),
        memoryThreshold: Joi.number().integer().min(128).default(1024),
        enableProfiling: Joi.boolean().default(false)
      }),

      security: Joi.object({
        enableGeoLookup: Joi.boolean().default(true),
        geoLookupLimit: Joi.number().integer().min(1).max(50).default(10),
        trustedPaths: Joi.array().items(Joi.string()).default([
          '/System', '/usr/bin', '/usr/sbin', '/bin', '/sbin', '/Applications'
        ]),
        riskyPorts: Joi.array().items(Joi.number()).default([
          22, 23, 135, 139, 445, 1433, 3389, 5432, 6379, 27017, 8080, 8443
        ])
      }),

      compliance: Joi.object({
        frameworks: Joi.array().items(Joi.string()).default(['NIST CSF', 'ISO 27001', 'SOC 2']),
        enableMapping: Joi.boolean().default(true),
        reportCompliance: Joi.boolean().default(true)
      })
    });
  }

  /**
   * Load and validate configuration
   */
  loadConfiguration() {
    try {
      // Use config library for environment-specific configs
      let configData;
      
      try {
        configData = config.util.toObject();
      } catch (configError) {
        console.warn(`Config library failed, using defaults: ${configError.message}`);
        return this.getDefaultConfiguration();
      }

      // Validate against schema
      const { error, value } = this.schema.validate(configData, { 
        allowUnknown: true,
        stripUnknown: false 
      });

      if (error) {
        console.warn(`Configuration validation warnings: ${error.message}`);
        // Use defaults for invalid values
        return this.getDefaultConfiguration();
      }

      return value;
    } catch (error) {
      console.error(`Failed to load configuration: ${error.message}`);
      // Return hardcoded defaults as fallback
      return this.getDefaultConfiguration();
    }
  }

  /**
   * Get default configuration
   */
  getDefaultConfiguration() {
    return {
      analysis: {
        defaultDepth: 'comprehensive',
        adaptiveMode: true,
        blockchainDetection: true,
        deepForensicsThreshold: 'medium',
        parallelExecution: true,
        maxParallelAgents: 3
      },
      reports: {
        outputDir: './reports',
        retentionDays: 90,
        defaultTemplate: 'executive',
        defaultFormats: ['markdown', 'pdf'],
        pdfOptions: {
          format: 'A4',
          margin: '2cm',
          displayHeaderFooter: true,
          printBackground: true
        },
        includeScreenshots: false,
        compressOldReports: true
      },
      logging: {
        level: 'info',
        consoleLevel: 'warn',
        enableConsole: true,
        enableFiles: true,
        logDir: './logs',
        maxFileSize: '20m',
        maxFiles: '14d',
        securityLogRetention: '30d'
      },
      llm: {
        autoDetectProvider: true,
        enableLogging: true,
        logDir: './logs/llm-requests',
        privacyLevel: 'high',
        maxTokens: 4000,
        temperature: 0.1,
        minHighRiskFindings: 1,
        minTotalFindings: 5,
        skipWhenBelowThreshold: true
      },
      privacy: {
        redactUserPaths: true,
        redactUsernames: true,
        redactIPs: false,
        preserveDomains: true,
        sanitizationLevel: 'high'
      },
      performance: {
        enableMetrics: true,
        slowQueryThreshold: 5000,
        memoryThreshold: 1024,
        enableProfiling: false
      },
      security: {
        enableGeoLookup: true,
        geoLookupLimit: 10,
        trustedPaths: ['/System', '/usr/bin', '/usr/sbin', '/bin', '/sbin', '/Applications'],
        riskyPorts: [22, 23, 135, 139, 445, 1433, 3389, 5432, 6379, 27017, 8080, 8443]
      },
      compliance: {
        frameworks: ['NIST CSF', 'ISO 27001', 'SOC 2'],
        enableMapping: true,
        reportCompliance: true
      }
    };
  }

  /**
   * Get configuration value by path
   */
  get(path, defaultValue = undefined) {
    if (!path || typeof path !== 'string') {
      return defaultValue;
    }
    
    const keys = path.split('.');
    let value = this.config;

    for (const key of keys) {
      if (value && typeof value === 'object' && key in value) {
        value = value[key];
      } else {
        return defaultValue;
      }
    }

    return value;
  }

  /**
   * Set configuration value by path
   */
  set(path, value) {
    const keys = path.split('.');
    let current = this.config;

    // Navigate to parent object
    for (let i = 0; i < keys.length - 1; i++) {
      const key = keys[i];
      if (!(key in current) || typeof current[key] !== 'object') {
        current[key] = {};
      }
      current = current[key];
    }

    // Set value
    const finalKey = keys[keys.length - 1];
    const oldValue = current[finalKey];
    current[finalKey] = value;

    // Validate the updated configuration
    const { error } = this.schema.validate(this.config);
    if (error) {
      // Revert change if invalid
      current[finalKey] = oldValue;
      throw new Error(`Invalid configuration value for ${path}: ${error.message}`);
    }

    // Notify watchers
    this.notifyWatchers(path, oldValue, value);

    // Save to file if persistent
    this.saveConfiguration();
  }

  /**
   * Get entire configuration object
   */
  getAll() {
    return { ...this.config };
  }

  /**
   * Watch for configuration changes
   */
  watch(path, callback) {
    this.watchers.push({ path, callback });
  }

  /**
   * Remove configuration watcher
   */
  unwatch(path, callback) {
    this.watchers = this.watchers.filter(w => 
      !(w.path === path && w.callback === callback)
    );
  }

  /**
   * Notify watchers of changes
   */
  notifyWatchers(path, oldValue, newValue) {
    this.watchers
      .filter(w => w.path === path || w.path === '*')
      .forEach(w => {
        try {
          w.callback(path, oldValue, newValue);
        } catch (error) {
          console.error(`Configuration watcher error: ${error.message}`);
        }
      });
  }

  /**
   * Save configuration to file
   */
  async saveConfiguration() {
    try {
      const configPath = join(process.cwd(), 'config', 'default.json');
      writeFileSync(configPath, JSON.stringify(this.config, null, 2));
    } catch (error) {
      console.error(`Failed to save configuration: ${error.message}`);
    }
  }

  /**
   * Load configuration from environment variables
   */
  loadFromEnvironment() {
    const envMappings = {
      'ANALYSIS_DEPTH': 'analysis.defaultDepth',
      'ANALYSIS_ADAPTIVE': 'analysis.adaptiveMode',
      'ANALYSIS_BLOCKCHAIN': 'analysis.blockchainDetection',
      'REPORTS_OUTPUT_DIR': 'reports.outputDir',
      'REPORTS_RETENTION_DAYS': 'reports.retentionDays',
      'LOG_LEVEL': 'logging.level',
      'LOG_DIR': 'logging.logDir',
      'LLM_MAX_TOKENS': 'llm.maxTokens',
      'LLM_PRIVACY_LEVEL': 'llm.privacyLevel',
      'LLM_MIN_HIGH_RISK': 'llm.minHighRiskFindings',
      'LLM_MIN_TOTAL': 'llm.minTotalFindings',
      'LLM_SKIP_BELOW_THRESHOLD': 'llm.skipWhenBelowThreshold',
      'PRIVACY_REDACT_PATHS': 'privacy.redactUserPaths',
      'PRIVACY_REDACT_USERNAMES': 'privacy.redactUsernames',
      'SECURITY_GEO_LOOKUP': 'security.enableGeoLookup',
      'SECURITY_GEO_LIMIT': 'security.geoLookupLimit'
    };

    for (const [envVar, configPath] of Object.entries(envMappings)) {
      const value = process.env[envVar];
      if (value !== undefined) {
        // Convert string values to appropriate types
        let parsedValue = value;
        if (value === 'true') parsedValue = true;
        else if (value === 'false') parsedValue = false;
        else if (!isNaN(value) && value.includes('.')) parsedValue = parseFloat(value);
        else if (!isNaN(value)) parsedValue = parseInt(value);

        try {
          this.set(configPath, parsedValue);
        } catch (error) {
          console.warn(`Invalid environment variable ${envVar}: ${error.message}`);
        }
      }
    }
  }

  /**
   * Get configuration for a specific component
   */
  getComponentConfig(component) {
    return this.get(component, {});
  }

  /**
   * Merge user configuration with defaults
   */
  mergeWithUserConfig(userConfig) {
    const merged = this.deepMerge(this.getDefaultConfiguration(), userConfig);
    
    const { error, value } = this.schema.validate(merged);
    if (error) {
      console.warn(`Configuration merge warnings: ${error.message}`);
      return value;
    }
    
    return value;
  }

  /**
   * Deep merge objects
   */
  deepMerge(target, source) {
    const result = { ...target };

    for (const key in source) {
      if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
        result[key] = this.deepMerge(result[key] || {}, source[key]);
      } else {
        result[key] = source[key];
      }
    }

    return result;
  }

  /**
   * Reset configuration to defaults
   */
  reset() {
    this.config = this.getDefaultConfiguration();
    this.saveConfiguration();
    this.notifyWatchers('*', null, this.config);
  }

  /**
   * Validate current configuration
   */
  validate() {
    const { error, value } = this.schema.validate(this.config);
    return { valid: !error, errors: error?.details || [], value };
  }
}

/**
 * Global configuration manager instance
 */
let globalConfig = null;

/**
 * Get or create global configuration manager
 */
export function getConfigManager() {
  if (!globalConfig) {
    globalConfig = new ConfigManager();
  }
  return globalConfig;
}

/**
 * Convenience function to get configuration value
 */
export function getConfig(path, defaultValue) {
  return getConfigManager().get(path, defaultValue);
}

/**
 * Convenience function to set configuration value
 */
export function setConfig(path, value) {
  return getConfigManager().set(path, value);
}