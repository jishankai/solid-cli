# macOS System & Security Analysis Agent CLI

A **local-first** macOS security and performance analysis tool powered by AI. This CLI agent performs comprehensive system analysis and uses LLMs (OpenAI GPT-4 or Claude) to provide intelligent insights and recommendations.

## Features

- **Resource Usage Analysis**: Monitor CPU, memory, and I/O usage
- **Security Scanning**: Comprehensive security audit including:
  - System integrity checks (SIP, Gatekeeper)
  - Persistence mechanism detection (LaunchAgents, LaunchDaemons, crontab)
  - Process analysis for suspicious activity
  - Network connection monitoring
  - Privacy permission auditing
- **AI-Powered Analysis**: Get intelligent recommendations from OpenAI or Claude
- **Professional Reports**: Export findings as Markdown or PDF

## Architecture

```
┌─────────────┐
│   CLI UI    │  inquirer + chalk
└─────┬───────┘
      │
┌─────▼──────────────┐
│   Orchestrator     │  Agent coordination
└─────┬──────────────┘
      │
 ┌────▼────┐  ┌──────▼────────┐  ┌────────▼──────┐
 │Resource │  │ Security Stack │  │   LLM Engine  │
 │ Agent   │  │ (5 Agents)     │  │ OpenAI/Claude │
 └─────────┘  └────────────────┘  └───────────────┘
      │
┌─────▼───────────┐
│ Report Generator│ → Markdown / PDF
└─────────────────┘
```

## Requirements

- **macOS** 10.15 or later
- **Node.js** 20.0 or later
- **API Keys** (optional): OpenAI or Anthropic Claude

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd analysis-cli
```

2. Install dependencies:
```bash
npm install
```

3. Set up API keys (optional, for AI analysis):
```bash
cp .env.example .env
# Edit .env and add your API keys
```

4. Make the CLI executable:
```bash
chmod +x src/index.js
```

## Usage

### Quick Start

Run the interactive CLI:
```bash
npm start
```

Or directly:
```bash
node src/index.js
```

### Analysis Modes

The CLI will prompt you to select:

1. **Analysis Mode**:
   - ✅ Integrated Resource + Security Scan (Recommended)
   - ⭕ Deep Forensics Analysis (Time-consuming)

2. **LLM Provider**:
   - OpenAI (GPT-4)
   - Claude (Anthropic)
   - No LLM - Generate report only

3. **Report Format**:
    - Markdown (.md)
    - PDF (.pdf)
    - Both

### Optional Geo Enrichment

When prompted, enable outbound IP geolocation to tag external connections. The CLI first tries local `geoiplookup`, then `ipinfo.io` (requires network). Skip if you need an offline-only run.

### LLM Optimization Guidance

LLM analysis considers both security findings and resource usage (CPU/memory) to suggest performance optimizations alongside mitigations.

### Example Workflow

```
$ npm start

╔═══════════════════════════════════════════════════════════╗
║   macOS System & Security Analysis Agent CLI              ║
║   Powered by AI - Local-First Security Analysis           ║
╚═══════════════════════════════════════════════════════════╝

? Select analysis mode: Security Scan (Recommended)
? Select LLM provider: Claude (Anthropic)
? Select report format: Markdown, PDF
? Proceed with analysis? Yes

🔍 Starting system analysis...

✓ ResourceAgent completed - Risk: LOW
✓ SystemAgent completed - Risk: MEDIUM
✓ PersistenceAgent completed - Risk: HIGH
✓ ProcessAgent completed - Risk: MEDIUM
✓ NetworkAgent completed - Risk: LOW
✓ PermissionAgent completed - Risk: LOW

✅ Analysis completed!

📊 Analysis Summary:
──────────────────────────────────────────────────
Overall Risk: HIGH
Total Findings: 15
  🔴 High Risk: 3
  🟡 Medium Risk: 8
  🟢 Low Risk: 4
──────────────────────────────────────────────────

🤖 Running AI analysis...
✓ AI analysis completed!

📁 Saved Reports:
   📄 Markdown: ./security-report-2024-12-26.md
   📑 PDF: ./security-report-2024-12-26.pdf

✨ Analysis complete! Check your reports for details.
```

## Agents

### 1. ResourceAgent
Analyzes CPU, memory, and process resource usage.

**Detects**:
- High CPU/memory usage from non-system paths
- Suspicious process names
- Long-running background processes

### 2. SystemAgent
Checks system integrity and security settings.

**Detects**:
- SIP (System Integrity Protection) status
- Gatekeeper status
- Available system updates
- Sudoers misconfigurations

### 3. PersistenceAgent (Core Security)
Scans for persistence mechanisms.

**Detects**:
- Suspicious LaunchAgents/LaunchDaemons
- Login Items
- Crontab entries
- Programs in non-standard locations
- Potential impersonation of Apple services

### 4. ProcessAgent
Analyzes running processes.

**Detects**:
- Process name/path mismatches
- System processes running from user directories
- Hidden or obfuscated process names
- Elevated processes from user paths

### 5. NetworkAgent
Monitors network connections.

**Detects**:
- Suspicious port usage
- Non-system processes with network activity
- Listening on all interfaces
- External connections from unusual processes

### 6. PermissionAgent
Audits app permissions.

**Detects**:
- Critical permissions granted to non-standard apps
- Apps in user directories with permissions
- Hidden apps with permissions

## Configuration

Create a `config.json` from the example:
```bash
cp config.example.json config.json
```

Customize agent settings, thresholds, and trusted paths in the config file.

## API Keys Setup

### OpenAI
1. Get your API key from https://platform.openai.com/api-keys
2. Add to `.env`:
```
OPENAI_API_KEY=sk-...
```

### Anthropic Claude
1. Get your API key from https://console.anthropic.com/settings/keys
2. Add to `.env`:
```
ANTHROPIC_API_KEY=sk-ant-...
```

## Report Structure

Generated reports include:

1. **Executive Summary**: Overall risk assessment and key metrics
2. **AI Analysis** (if enabled): Intelligent insights and recommendations
3. **Detailed Findings**: Per-agent results with risk classifications
4. **Appendix**: Raw JSON data for further analysis

## Security Considerations

- **No Root Required**: All checks run with user permissions
- **Local-First**: Your data stays on your machine
- **API Usage**: LLM providers only receive analysis results (no raw system data)
- **Read-Only**: No system modifications are made

## Development

### Project Structure
```
analysis-cli/
├── src/
│   ├── agents/          # Analysis agents
│   │   ├── BaseAgent.js
│   │   ├── ResourceAgent.js
│   │   ├── SystemAgent.js
│   │   ├── PersistenceAgent.js
│   │   ├── ProcessAgent.js
│   │   ├── NetworkAgent.js
│   │   └── PermissionAgent.js
│   ├── llm/             # LLM integration
│   │   └── LLMAnalyzer.js
│   ├── report/          # Report generation
│   │   └── ReportGenerator.js
│   ├── utils/           # Utilities
│   │   └── commander.js
│   ├── Orchestrator.js  # Agent coordination
│   └── index.js         # CLI entry point
├── package.json
├── .env.example
└── README.md
```

### Adding Custom Agents

1. Create a new agent extending `BaseAgent`:
```javascript
import { BaseAgent } from './BaseAgent.js';

export class CustomAgent extends BaseAgent {
  constructor() {
    super('CustomAgent');
  }

  async analyze() {
    // Your analysis logic
    this.results = {
      agent: this.name,
      findings: [],
      overallRisk: 'low'
    };
    return this.results;
  }
}
```

2. Register in `Orchestrator.js`

## Troubleshooting

### Permission Errors
Some checks require specific permissions:
- **Full Disk Access**: For TCC database access
- **Accessibility**: For some process inspections

Grant these in System Preferences > Security & Privacy > Privacy

### PDF Generation Fails
If PDF generation fails, install phantomjs:
```bash
npm install -g phantomjs-prebuilt
```

### API Rate Limits
If you encounter rate limits:
- Use shorter analysis windows
- Select specific agents only
- Run in "No LLM" mode and analyze JSON manually

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

MIT License - See LICENSE file for details

## Disclaimer

This tool is for legitimate security analysis and system auditing only. Users are responsible for compliance with applicable laws and regulations. The authors assume no liability for misuse.

## Support

For issues, questions, or feature requests, please open an issue on GitHub.

---

**Built with**: Node.js, inquirer, chalk, execa, OpenAI, Anthropic Claude
