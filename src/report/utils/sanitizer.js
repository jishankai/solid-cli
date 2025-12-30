/**
 * Report Sanitizer - Enhanced privacy protection
 */
export class ReportSanitizer {
  constructor(options = {}) {
    this.options = {
      redactUserPaths: true,
      redactIPs: false,
      redactUsernames: true,
      preserveDomains: true,
      ...options
    };
    
    // Initialize sensitive patterns
    this.sensitivePatterns = this.initializePatterns();
  }

  /**
   * Initialize all sensitive data patterns
   */
  initializePatterns() {
    return {
      // Cryptographic patterns
      privateKey: {
        pattern: /[a-fA-F0-9]{64}/g,
        replacement: '***REDACTED_PRIVATE_KEY***',
        name: 'Private Key'
      },
      
      // Ethereum addresses
      ethAddress: {
        pattern: /0x[a-fA-F0-9]{40}/g,
        replacement: '0x***REDACTED_ETH_ADDRESS***',
        name: 'Ethereum Address'
      },
      
      // Bitcoin addresses
      btcAddress: {
        pattern: /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/g,
        replacement: '***REDACTED_BTC_ADDRESS***',
        name: 'Bitcoin Address'
      },
      
      // API Keys and tokens
      apiKey: {
        pattern: /[a-zA-Z0-9]{32,}={0,2}/g,
        replacement: '***REDACTED_API_KEY***',
        name: 'API Key'
      },
      
      // Password/secret patterns
      password: {
        pattern: /(password|secret|key|token)[\s=:]+[a-zA-Z0-9+/]{8,}/gi,
        replacement: '$1***REDACTED***',
        name: 'Password/Secret'
      },
      
      // Mnemonic phrases
      mnemonic: {
        pattern: /\b(word|agree|letter|again|animal|already|between|certain|close|common|could|describe|engine|every|example|few|first|follow|group|have|important|inside|just|large|lead|letter|local|matter|might|never|number|open|order|place|point|question|right|second|see|small|sound|still|such|tell|thing|think|three|under|until|voice|water|where|which|world|write|year|yes|your|zone)\b.{0,200}/gi,
        replacement: '***REDACTED_MNEMONIC***',
        name: 'Seed Phrase'
      },
      
      // Long hex strings
      hexString: {
        pattern: /[a-fA-F0-9]{16,31}/g,
        replacement: '***REDACTED_HEX***',
        name: 'Hex String'
      },
      
      // Email addresses (if usernames should be redacted)
      email: {
        pattern: this.options.redactUsernames ? /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g : null,
        replacement: '***REDACTED_EMAIL***',
        name: 'Email Address'
      }
    };
  }

  /**
   * Sanitize text content
   */
  sanitizeText(text) {
    if (!text || typeof text !== 'string') {
      return text;
    }

    let sanitized = text;

    // Apply all patterns
    for (const [key, config] of Object.entries(this.sensitivePatterns)) {
      if (!config.pattern) continue;
      
      const matches = sanitized.match(config.pattern);
      if (matches) {
        sanitized = sanitized.replace(config.pattern, config.replacement);
      }
    }

    return sanitized;
  }

  /**
   * Sanitize file paths
   */
  sanitizePath(path) {
    if (!path || typeof path !== 'string') {
      return path;
    }

    let sanitized = path;

    // Redact user directories
    if (this.options.redactUserPaths) {
      sanitized = sanitized
        .replace(/\/Users\/[^\/]+/g, '/Users/***REDACTED***')
        .replace(/\/home\/[^\/]+/g, '/home/***REDACTED***')
        .replace(/C:\\Users\\[^\\]+/g, 'C:\\Users\\***REDACTED***')
        .replace(/\/private\/var\/folders\/[^\/]+/g, '/private/var/folders/***REDACTED***');
    }

    // Redact usernames from paths
    // NOTE: We already redact the username segment for common user-home roots above
    // (e.g., /Users/<name>, /home/<name>, C:\Users\<name>). Avoid broad path redaction here
    // because it can make the report unreadable by replacing most path components.

    // Sanitize any remaining sensitive data in path components
    const pathComponents = sanitized.split(/[\/\\]/);
    const sanitizedComponents = pathComponents.map(component => 
      this.sanitizePathComponent(component)
    );
    
    return sanitizedComponents.join('/');
  }

  /**
   * Sanitize individual path components
   */
  sanitizePathComponent(component) {
    if (!component) return component;

    // Apply text sanitization but preserve file extensions
    const lastDot = component.lastIndexOf('.');
    if (lastDot > 0) {
      const name = component.substring(0, lastDot);
      const ext = component.substring(lastDot);
      return this.sanitizeText(name) + ext;
    }

    return this.sanitizeText(component);
  }

  /**
   * Sanitize URLs
   */
  sanitizeURL(url) {
    if (!url || typeof url !== 'string') {
      return url;
    }

    let sanitized = url;

    // Parse URL components
    try {
      const urlObj = new URL(url);
      
      // Sanitize hostname (preserve domains if enabled)
      if (!this.options.preserveDomains) {
        urlObj.hostname = urlObj.hostname.replace(/[a-zA-Z0-9-]+/, '***REDACTED_DOMAIN***');
      }
      
      // Sanitize path
      urlObj.pathname = this.sanitizePath(urlObj.pathname);
      
      // Remove query parameters and fragments (often contain sensitive data)
      urlObj.search = '';
      urlObj.hash = '';
      
      sanitized = urlObj.toString();
    } catch (e) {
      // If URL parsing fails, apply text sanitization
      sanitized = this.sanitizeText(url);
    }

    return sanitized;
  }

  /**
   * Sanitize IP addresses
   */
  sanitizeIP(ip) {
    if (!this.options.redactIPs) return ip;
    
    if (!ip || typeof ip !== 'string') {
      return ip;
    }

    // IPv4 pattern
    const ipv4Pattern = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
    return ip.replace(ipv4Pattern, '***.***.***.***');
  }

  /**
   * Perform comprehensive sanitization check
   */
  performSecurityCheck(data) {
    const sensitivePatterns = [];
    let hasSensitiveData = false;

    // Convert data to string for pattern matching
    const dataString = JSON.stringify(data);

    // Check each sensitive pattern
    for (const [key, config] of Object.entries(this.sensitivePatterns)) {
      if (!config.pattern) continue;
      
      const matches = dataString.match(config.pattern);
      if (matches && matches.length > 0) {
        hasSensitiveData = true;
        sensitivePatterns.push({
          name: config.name,
          count: matches.length,
          pattern: key
        });
      }
    }

    return {
      hasSensitiveData,
      sensitivePatterns,
      totalSensitivePatterns: sensitivePatterns.length
    };
  }

  /**
   * Add custom sensitive pattern
   */
  addCustomPattern(name, pattern, replacement, description) {
    this.sensitivePatterns[name] = {
      pattern,
      replacement: replacement || '***REDACTED***',
      name: description || name
    };
  }

  /**
   * Remove sensitive pattern
   */
  removePattern(name) {
    delete this.sensitivePatterns[name];
  }

  /**
   * Get list of active patterns
   */
  getActivePatterns() {
    return Object.keys(this.sensitivePatterns).filter(key => 
      this.sensitivePatterns[key].pattern !== null
    );
  }

  /**
   * Configure sanitization options
   */
  configure(options) {
    this.options = { ...this.options, ...options };
    
    // Update patterns based on new configuration
    if (options.redactUsernames !== undefined) {
      this.sensitivePatterns.email.pattern = options.redactUsernames ? 
        /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g : null;
    }
  }
}