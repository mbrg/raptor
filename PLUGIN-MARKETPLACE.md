# RAPTOR Plugin Marketplace

RAPTOR is now available as a Claude Code plugin marketplace. This means anyone can add RAPTOR's security tools to their Claude Code installation and use them in their projects.

## What Changed

Previously, RAPTOR was a standalone security framework. Now it's also a **plugin marketplace** that integrates directly with Claude Code.

## How to Use

### 1. Add the Marketplace

```bash
/plugin marketplace add mbrg/raptor
```

### 2. Install Plugins You Need

```bash
# Pick what you need
/plugin install raptor-scan@raptor-plugins      # Code scanning
/plugin install raptor-fuzz@raptor-plugins      # Binary fuzzing
/plugin install raptor-web@raptor-plugins       # Web app testing
/plugin install raptor-agentic@raptor-plugins   # Full autonomous mode
```

### 3. Use the Commands

```bash
/raptor-scan:scan ./my-code
/raptor-fuzz:fuzz ./my-binary
/raptor-web:web https://my-app.com
/raptor-agentic:agentic ./my-code
```

## Available Plugins

| Plugin | What It Does |
|--------|--------------|
| **raptor-scan** | Scans code with Semgrep for vulnerabilities |
| **raptor-fuzz** | Fuzzes binaries with AFL++ to find crashes |
| **raptor-web** | Tests web apps for OWASP Top 10 issues |
| **raptor-agentic** | Full autonomous scan + exploit + patch generation |
| **raptor-codeql** | Deep semantic analysis with CodeQL |
| **raptor-analyze** | LLM analysis on existing scan results |
| **raptor-crash-analysis** | Root-cause analysis for C/C++ crashes |
| **raptor-oss-forensics** | GitHub forensic investigation |
| **raptor-exploit** | Generate exploit PoCs (beta) |
| **raptor-patch** | Generate secure patches (beta) |

## For Teams

Add to your project's `.claude/settings.json`:

```json
{
  "extraKnownMarketplaces": {
    "raptor-plugins": {
      "source": {
        "source": "github",
        "repo": "mbrg/raptor"
      }
    }
  },
  "enabledPlugins": {
    "raptor-scan@raptor-plugins": true,
    "raptor-agentic@raptor-plugins": true
  }
}
```

Team members get prompted to enable plugins when they open the project.

## Backward Compatibility

The original commands (`/scan`, `/fuzz`, `/web`, etc.) still work exactly as before. The plugin system is additive.

## File Structure

```
.claude-plugin/
  marketplace.json      # Marketplace definition

plugins/
  raptor-scan/          # Each plugin is self-contained
    .claude-plugin/
      plugin.json       # Plugin manifest
    commands/
      scan.md           # Command definition
  raptor-fuzz/
  raptor-web/
  ... (10 plugins total)

  shared/
    safety-config.json  # Security settings
    error-messages.json # Error catalog

  raptor-deps-check.py  # Dependency validator
  README.md             # Full documentation
```

## Safety

All plugins run sandboxed by default. Network access is restricted. Dangerous operations require user approval.

## Dependencies

Each plugin declares its dependencies. Run the checker to see what you need:

```bash
python3 plugins/raptor-deps-check.py raptor-scan
python3 plugins/raptor-deps-check.py --all
```

## Support

Issues: https://github.com/mbrg/raptor/issues
