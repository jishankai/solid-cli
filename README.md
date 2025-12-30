# macOS System & Security Analysis Agent CLI (solid-cli)

A **local-first** macOS security and performance analysis CLI. It runs a unified, adaptive set of analysis agents on your machine and can (optionally) use an LLM (Claude or OpenAI) to generate structured recommendations.

> Note: LLM use is **optional**. When enabled, the CLI applies prompt sanitization and will **abort AI analysis** if sensitive patterns are detected.

## 快速开始（Quick Start）

```bash
# Run once (no install)
npx solid-cli

# Or install globally
npm install -g solid-cli
solid-cli

# Show help
solid-cli --help
```

Optional (enable AI analysis):
```bash
export ANTHROPIC_API_KEY=sk-ant-...
# or
export OPENAI_API_KEY=sk-...

solid-cli
```

Reports are written to `./reports/<YYYY>/<Month>/` by default.

## Features

- **Unified Adaptive Analysis**: runs a core set of agents every time, then conditionally expands analysis (e.g. blockchain/DeFi) when indicators are detected.
- **Core Security Coverage**:
  - System integrity checks (SIP, Gatekeeper, updates)
  - Persistence mechanism detection (LaunchAgents/LaunchDaemons, Login Items, crontab)
  - Process analysis for suspicious activity
  - Network connection analysis (optionally enriched with IP geolocation)
  - Privacy permission auditing
- **Blockchain/DeFi Safety Add-on (adaptive)**: triggers wallet/DeFi threat checks only when crypto indicators are found.
- **Privacy-protected AI insights (optional)**:
  - Provider auto-detection (Claude preferred when both keys exist)
  - Prompt sanitization + sensitive-pattern blocking
  - Threshold-based skipping when findings are below configured triggers
- **Professional Reports**: Markdown and/or PDF (Puppeteer) with templates.
- **Structured Logging**: operational logs under `./logs/`.

## Architecture

```
┌─────────────┐
│   CLI UI    │  inquirer + chalk
└─────┬───────┘
      │
┌─────▼────────────────────┐
│   Orchestrator (Unified) │  Phase 1 core + Phase 2 adaptive
└─────┬────────────────────┘
      │
 ┌────▼────┐  ┌───────────────▼───────────────┐
 │ Core    │  │ Adaptive Agents (conditional) │
 │ Agents  │  │ Blockchain / DeFi             │
 └────┬────┘  └───────────────┬───────────────┘
      │                        │
┌─────▼───────────┐     ┌─────▼───────────┐
│  LLM Analyzer    │     │ Report Manager  │
│  (optional)      │     │ Markdown / PDF  │
└──────────────────┘     └─────────────────┘
```

## Requirements

- **macOS** 10.15 or later
- **Node.js** 20.0 or later
- **API Keys** (optional): Anthropic Claude and/or OpenAI

## Installation

### Install from npm

```bash
npm install -g solid-cli
solid-cli
```

Run once without installing:
```bash
npx solid-cli
```

### Local development

```bash
npm install
npm start
```

Optional: make the entry executable:
```bash
chmod +x src/index.js
```

## Usage

Run the interactive CLI:

```bash
solid-cli
# or, in this repo
npm start
```

Show help:
```bash
solid-cli --help
# or
npm start -- --help
```

### What the CLI will ask (current flow)

1. **LLM auto-detection** (no manual provider picker)
   - If `ANTHROPIC_API_KEY` is present, the CLI uses **Claude**.
   - Else if `OPENAI_API_KEY` is present, it uses **OpenAI**.
   - Else it runs **report-only**.
2. **AI analysis option**: you can still choose **AI analysis** or **report-only**.
3. **Report format**: PDF or Markdown.
4. **IP geolocation**: controlled by config (`security.enableGeoLookup`) and shown in the run summary.
5. Analysis starts automatically (no extra confirmation prompt).

### Report output

- Default output root: `./reports` (configurable via `reports.outputDir`).
- Directory layout: `./reports/<YYYY>/<Month>/`
- Filenames:
  - `Security-Report-<REPORT_ID>.md`
  - `Security-Report-<REPORT_ID>.pdf`
  - `metadata-<YYYY-MM-DD>.json`

### Example run (illustrative)

```text
$ solid-cli

✅ Claude (Anthropic) - API key detected
? 🤖 AI Analysis Option: (Use arrow keys)
  🧠 Use AI Analysis (CLAUDE) - Enhanced insights & recommendations
  📋 Generate Security Report Only - Maximum privacy protection

? Select report format: PDF (.pdf)
✅ IP geolocation enabled

🔍 Starting unified adaptive analysis...

Phase 1: Core Security Analysis
✓ ResourceAgent completed - Risk: LOW
✓ SystemAgent completed - Risk: MEDIUM
...

Phase 2: Adaptive Analysis
   No blockchain indicators detected - skipping blockchain analysis

📁 Saved Reports:
   📑 Pdf: reports/2025/December/Security-Report-RPT-XXXXXX.pdf
```

## Agents

### Core agents (always run)

- `ResourceAgent`: CPU/memory/process resource usage heuristics.
- `SystemAgent`: SIP/Gatekeeper/updates and other system posture checks.
- `PersistenceAgent`: LaunchAgents/LaunchDaemons/Login Items/crontab.
- `ProcessAgent`: suspicious process patterns (paths, elevation, obfuscation).
- `NetworkAgent`: network connections and listening ports; optional IP geolocation enrichment.
- `PermissionAgent`: privacy permission auditing.

### Adaptive agents (only run when indicators are detected)

- `BlockchainAgent`: wallet processes/files, wallet-like browser extensions, mining indicators, and blockchain/DeFi network patterns.
- `DeFiSecurityAgent`: DeFi scam indicators (processes/download metadata/network) with privacy-protective behavior (no clipboard or browser-history content extraction).

## Configuration

This project uses the `config` (node-config) package.

- Defaults ship in `config/default.json`.
- You can override settings by providing your own config directory in one of these ways:
  - Create `./config/local.json` in the directory where you run `solid-cli`.
  - Or set `NODE_CONFIG_DIR` to a custom config folder.

Common settings:

- `reports.outputDir`: report output directory (default `./reports`).
- `analysis.parallelExecution` and `analysis.maxParallelAgents`: speed vs. load tradeoff.
- `security.enableGeoLookup` and `security.geoLookupLimit`: IP geolocation enrichment behavior.
- `llm.mode`: prompt mode (`summary` / `full`).
- `llm.minHighRiskFindings`, `llm.minTotalFindings`, `llm.skipWhenBelowThreshold`: when AI analysis should run.

## AI / LLM behavior (privacy-protected)

- **Provider auto-detection priority**: Claude → OpenAI → none.
- Before any LLM call, the CLI:
  - builds a prompt from analysis results,
  - runs a **sensitive pattern scan**,
  - and **skips AI analysis** (and records details into report metadata) if sensitive patterns are detected.
- When AI analysis runs, request/response payloads are logged under `./logs/llm-requests/`.

## Security Considerations

- **No Root Required**: checks run with user permissions.
- **Local-First**: analysis runs locally; AI is optional.
- **Read-only**: the tool does not modify system settings.
- **LLM Safety**: sensitive pattern detection can prevent accidental leakage of keys/tokens.

## Troubleshooting

### Permission prompts / incomplete results

Some checks may be limited without:
- **Full Disk Access** (e.g. some system databases)
- **Accessibility** (some process visibility)

### PDF generation fails

PDF uses Puppeteer. If Chromium cannot launch:
- reinstall dependencies so Puppeteer can fetch Chromium, or
- set `PUPPETEER_EXECUTABLE_PATH` to a local Chrome/Chromium.

## Development

### Project Structure

```text
solid-cli/
├── config/
│   └── default.json              # node-config defaults
├── src/
│   ├── agents/                   # analysis agents
│   ├── config/ConfigManager.js   # config access/validation
│   ├── llm/LLMAnalyzer.js        # LLM prompt building + safety checks
│   ├── logging/Logger.js         # structured logging
│   ├── report/                   # report generation (Handlebars + Puppeteer)
│   ├── utils/                    # shell helpers, signatures, etc.
│   ├── Orchestrator.js           # unified adaptive runner
│   └── index.js                  # CLI entry point
├── reports/                      # generated reports (gitignored typically)
├── logs/                         # generated logs (gitignored typically)
└── README.md
```

### Adding custom agents

1. Create a new agent extending `BaseAgent` and implement `analyze()`.
2. Register it in `src/Orchestrator.js` (core or conditional).

## Publishing to npm (maintainers)

1. Update `package.json` metadata (name/scope, version, repository, bugs, homepage).
2. Clean artifacts: remove generated `logs/` and `reports/` before packing.
3. Verify package contents: `npm pack --dry-run`.
4. Smoke tests (non-interactive helpers):
   - `node src/index.js --help`
   - `node test-llm-choice.js`
   - `node test-llm-blocking.js`
   - `node test-llm-privacy.js`
   - `node test-blockchain.js`
5. Publish: `npm publish --access public`.

## License

MIT License - see `LICENSE`.

## Disclaimer

This tool is for legitimate security analysis and system auditing only. Users are responsible for compliance with applicable laws and regulations. The authors assume no liability for misuse.
