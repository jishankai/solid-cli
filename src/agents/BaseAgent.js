/**
 * Base Agent class that all specific agents extend
 */
export class BaseAgent {
  constructor(name) {
    this.name = name;
    this.results = null;
  }

  /**
   * Execute the agent's analysis
   * Must be implemented by subclasses
   */
  async analyze() {
    throw new Error(`${this.name}: analyze() must be implemented`);
  }

  /**
   * Get the analysis results
   */
  getResults() {
    return this.results;
  }

  /**
   * Determine risk level based on findings
   * @param {Array} findings - Array of findings with risk levels
   * @returns {string} - Overall risk level
   */
  calculateOverallRisk(findings) {
    if (findings.some(f => f.risk === 'high')) return 'high';
    if (findings.some(f => f.risk === 'medium')) return 'medium';
    return 'low';
  }
}
